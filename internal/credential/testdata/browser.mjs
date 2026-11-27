import { pathToFileURL } from 'node:url';

const [modulePath, origin, operationId] = process.argv.slice(2);
const { chromium } = await import(pathToFileURL(modulePath));
const sentinel = 'synthetic-SENTINEL-39473-secret-value';
const browser = await chromium.launch({headless:true});
try {
  const context = await browser.newContext({ignoreHTTPSErrors:true});
  const page = await context.newPage();
  let valueRequests = 0;
  let unsafeRequest = false;
  let unsafeLog = false;
  page.on('request', request => {
    if (request.url().includes(sentinel)) unsafeRequest = true;
    if ((request.postData() || '').includes(sentinel)) {
      valueRequests++;
      if (request.url() !== origin + '/credential-api/api/operations/' + operationId + '/save') unsafeRequest = true;
    }
  });
  page.on('console', event => { if (event.text().includes(sentinel)) unsafeLog = true; });
  page.on('pageerror', error => { if (error.message.includes(sentinel)) unsafeLog = true; });
  await page.goto(origin + '/credentials/' + operationId);
  await page.locator('#form').waitFor({state:'visible'});
  await page.locator('input[name="client_id"]').fill('synthetic-client');
  await page.locator('input[name="client_secret"]').fill(sentinel);
  await page.locator('input[name="file"]').setInputFiles({name:'credential.json',mimeType:'application/json',buffer:Buffer.from('synthetic-file-contents')});
  await page.locator('#approve').check();
  await page.getByRole('button',{name:'Save',exact:true}).click();
  await page.getByRole('status').filter({hasText:'Operation: complete'}).waitFor();
  const stored = await page.evaluate(() => JSON.stringify({local:localStorage,session:sessionStorage}));
  const residual = await page.locator('#fields input').evaluateAll(inputs => inputs.some(input => input.value !== ''));
  const cookies = await context.cookies();
  const session = cookies.find(cookie => cookie.name === '__Host-credential-session');
  if (stored.includes(sentinel) || residual || unsafeLog || unsafeRequest || valueRequests !== 1 || !session?.httpOnly || !session?.secure) throw new Error('Browser credential isolation failed');
  console.log('Browser text, file, multiple fields, OAuth, cookies and value isolation passed');
} finally {
  await browser.close();
}
