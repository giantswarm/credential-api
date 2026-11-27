package credential

const page = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Save a credential</title><script defer src="/credential-api/app.js"></script></head>
<body><main><h1>Save a credential</h1><p id="message" role="status">Loading confirmation</p><section id="confirmation"></section><form id="form" hidden><fieldset id="fields"><legend>Credential values</legend></fieldset><label><input id="approve" type="checkbox" required>I confirm every consumer and exact destination shown above.</label><button type="submit">Save</button><button id="cancel" type="button">Cancel</button></form></main></body></html>`

const script = `'use strict';
const message = document.getElementById('message');
const form = document.getElementById('form');
const confirmation = document.getElementById('confirmation');
const fields = document.getElementById('fields');
const id = location.pathname.split('/').pop();
const endpoint = '/credential-api/api/operations/' + encodeURIComponent(id);
let operation, csrf;
function line(text) { const p = document.createElement('p'); p.textContent = text; confirmation.append(p); }
function clear() { form.reset(); for (const input of fields.querySelectorAll('input')) input.value = ''; }
async function call(action, body) {
  const response = await fetch(endpoint + '/' + action, {method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/json','X-CSRF-Token':csrf}, body:JSON.stringify(body)});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Save failed');
  return result;
}
async function start() {
  const response = await fetch(endpoint, {credentials:'same-origin', cache:'no-store'});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Operation unavailable');
  operation = result.operation; csrf = result.csrf;
  line('Installation: ' + operation.installation);
  line('Manager: ' + operation.manager);
  line('Started by: ' + (operation.actor ? operation.actor.issuer + ' / ' + operation.actor.subject + ' (verified by manager)' : operation.person.issuer + ' / ' + operation.person.subject));
  line('Secret: ' + operation.namespace + '/' + operation.secret);
  line(operation.replace ? 'This replaces all existing fields in the Secret.' : 'This creates a new Secret.');
  for (const consumer of operation.consumers) { line(consumer.kind + ' ' + consumer.name); for (const destination of consumer.destinations) line('Destination: ' + destination); }
  if (operation.description) line(operation.manager + ' says: ' + operation.description);
  if (operation.state !== 'pending') { message.textContent = 'Operation: ' + operation.state; return; }
  for (const [name, field] of Object.entries(operation.fields.properties)) {
    const label = document.createElement('label'); label.textContent = field.title || name;
    const input = document.createElement('input'); input.name = name; input.autocomplete = 'off';
    input.type = field.type === 'file' ? 'file' : field.type === 'boolean' ? 'checkbox' : field.type === 'number' || field.type === 'integer' ? 'number' : 'password';
    input.required = (operation.fields.required || []).includes(name) && field.type !== 'boolean';
    if (field.minLength) input.minLength = field.minLength;
    if (field.maxLength) input.maxLength = field.maxLength;
    if (field.minimum !== undefined) input.min = field.minimum;
    if (field.maximum !== undefined) input.max = field.maximum;
    if (field.type === 'number') input.step = 'any';
    label.append(input); fields.append(label);
    if (field.description) { const p = document.createElement('p'); p.textContent = field.description; fields.append(p); }
  }
  message.textContent = 'Check the host and every destination before entering values.'; form.hidden = false;
}
form.addEventListener('submit', async event => {
  event.preventDefault(); const values = Object.create(null);
  try {
    for (const [name, field] of Object.entries(operation.fields.properties)) {
      const input = fields.querySelector('input[name="' + CSS.escape(name) + '"]');
      if (field.type === 'file') { if (input.files.length) { if (input.files[0].size > 65536) throw new Error('File exceeds 64 KiB'); values[name] = await input.files[0].text(); } }
      else if (field.type === 'boolean') values[name] = input.checked;
      else if (input.value !== '') values[name] = field.type === 'number' || field.type === 'integer' ? Number(input.value) : input.value;
    }
    fields.disabled = true;
    const result = await call('save', {version:operation.version, confirmation:operation.confirmation, values});
    message.textContent = 'Operation: ' + result.state; form.hidden = true;
  } catch (error) { message.textContent = error.message; }
  finally { clear(); fields.disabled = false; for (const key of Object.keys(values)) delete values[key]; }
});
document.getElementById('cancel').addEventListener('click', async () => {
  clear(); try { await call('cancel', {version:operation.version}); message.textContent = 'Cancelled'; form.hidden = true; } catch (error) { message.textContent = error.message; }
});
window.addEventListener('pagehide',clear);
start().catch(error => { message.textContent = error.message; clear(); });
`
