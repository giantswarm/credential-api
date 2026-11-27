package credential

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/giantswarm/mcp-oauth/security"
	sharedk8s "github.com/giantswarm/mcp-toolkit/k8s"
	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

const managerIdentity = "system:serviceaccount:managers:models"
const otherManagerIdentity = "system:serviceaccount:managers:connectors"
const sentinel = "synthetic-SENTINEL-39473-secret-value"

type identityProvider struct {
	server  *httptest.Server
	signer  jose.Signer
	public  jose.JSONWebKey
	mu      sync.Mutex
	subject string
	codes   map[string]url.Values
}

func newIdentityProvider(t *testing.T) *identityProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "test-key"))
	require.NoError(t, err)
	provider := &identityProvider{signer: signer, public: jose.JSONWebKey{Key: &key.PublicKey, KeyID: "test-key", Algorithm: "RS256", Use: "sig"}, subject: "alice", codes: map[string]url.Values{}}
	provider.server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(writer).Encode(map[string]any{"issuer": provider.server.URL, "authorization_endpoint": provider.server.URL + "/authorize", "token_endpoint": provider.server.URL + "/token", "jwks_uri": provider.server.URL + "/keys", "userinfo_endpoint": provider.server.URL + "/userinfo", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			_ = json.NewEncoder(writer).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{provider.public}})
		case "/authorize":
			parameters := request.URL.Query()
			if parameters.Get("code_challenge_method") != "S256" || parameters.Get("code_challenge") == "" || parameters.Get("nonce") == "" {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			code := randomToken()
			provider.mu.Lock()
			parameters.Set("subject", provider.subject)
			provider.codes[code] = parameters
			provider.mu.Unlock()
			location := parameters.Get("redirect_uri") + "?code=" + code + "&state=" + url.QueryEscape(parameters.Get("state"))
			writer.Header().Set("Location", location)
			writer.WriteHeader(http.StatusFound)
		case "/token":
			if request.ParseForm() != nil {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			provider.mu.Lock()
			parameters, ok := provider.codes[request.Form.Get("code")]
			delete(provider.codes, request.Form.Get("code"))
			provider.mu.Unlock()
			sum := sha256.Sum256([]byte(request.Form.Get("code_verifier")))
			if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != parameters.Get("code_challenge") || request.Form.Get("redirect_uri") != parameters.Get("redirect_uri") {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			encoded := provider.token(t, parameters.Get("subject"), parameters.Get("nonce"))
			_ = json.NewEncoder(writer).Encode(map[string]any{"access_token": "synthetic-access", "token_type": "Bearer", "expires_in": 600, "id_token": encoded})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(provider.server.Close)
	return provider
}

func (p *identityProvider) token(t *testing.T, subject, nonce string) string {
	t.Helper()
	encoded, err := josejwt.Signed(p.signer).Claims(map[string]any{"iss": p.server.URL, "sub": subject, "aud": []string{"credential-api", "kubernetes"}, "azp": "credential-api", "iat": time.Now().Unix(), "exp": time.Now().Add(10 * time.Minute).Unix(), "nonce": nonce}).Serialize()
	require.NoError(t, err)
	return encoded
}

type protocolFixture struct {
	service      *Service
	browser      *Browser
	admin        kubernetes.Interface
	base         *rest.Config
	idp          *identityProvider
	standalone   *httptest.Server
	portal       *httptest.Server
	managerToken string
	otherToken   string
	redis        *miniredis.Miniredis
	rootCAs      *x509.CertPool
	requestsMu   sync.Mutex
	requests     []string
}

func protocolSetup(t *testing.T) *protocolFixture {
	t.Helper()
	if testing.Short() || os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires KUBEBUILDER_ASSETS and real API server")
	}
	f := &protocolFixture{idp: newIdentityProvider(t)}
	certificateFile := filepath.Join(t.TempDir(), "issuer-ca.pem")
	require.NoError(t, os.WriteFile(certificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.idp.server.Certificate().Raw}), 0600))
	environment := &envtest.Environment{}
	environment.ControlPlane.GetAPIServer().Configure().Set("oidc-issuer-url", f.idp.server.URL).Set("oidc-client-id", "kubernetes").Set("oidc-ca-file", certificateFile).Set("oidc-username-claim", "sub").Set("oidc-username-prefix", "oidc:")
	base, err := environment.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, environment.Stop()) })
	f.base = rest.CopyConfig(base)
	f.base.WrapTransport = func(next http.RoundTripper) http.RoundTripper {
		return transportFunc(func(request *http.Request) (*http.Response, error) {
			f.requestsMu.Lock()
			f.requests = append(f.requests, request.Method+" "+request.URL.Path)
			f.requestsMu.Unlock()
			return next.RoundTrip(request)
		})
	}
	f.admin, err = kubernetes.NewForConfig(base)
	require.NoError(t, err)
	for name, labels := range map[string]map[string]string{"agent-platform-credential-api": nil, "managers": nil, "tenant": {"agent-platform.giantswarm.io/organization": "example", "agent-platform.giantswarm.io/organization-uid": "organization-uid"}} {
		_, err := f.admin.CoreV1().Namespaces().Create(t.Context(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}, metav1.CreateOptions{})
		require.NoError(t, err)
	}
	_, err = f.admin.RbacV1().Roles("agent-platform-credential-api").Create(t.Context(), &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "managers"}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{"credential.giantswarm.io"}, Resources: []string{"operations"}, Verbs: []string{"create"}}}}, metav1.CreateOptions{})
	require.NoError(t, err)
	_, err = f.admin.RbacV1().RoleBindings("agent-platform-credential-api").Create(t.Context(), &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "managers"}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "managers"}, Subjects: []rbacv1.Subject{{Kind: "User", APIGroup: rbacv1.GroupName, Name: managerIdentity}, {Kind: "User", APIGroup: rbacv1.GroupName, Name: otherManagerIdentity}}}, metav1.CreateOptions{})
	require.NoError(t, err)
	_, err = f.admin.RbacV1().Roles("tenant").Create(t.Context(), &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "credential-writer"}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"create", "update"}}}}, metav1.CreateOptions{})
	require.NoError(t, err)
	_, err = f.admin.RbacV1().RoleBindings("tenant").Create(t.Context(), &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "credential-writer"}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "credential-writer"}, Subjects: []rbacv1.Subject{{Kind: "User", APIGroup: rbacv1.GroupName, Name: "oidc:alice"}, {Kind: "User", APIGroup: rbacv1.GroupName, Name: "oidc:admin"}}}, metav1.CreateOptions{})
	require.NoError(t, err)
	f.managerToken = f.manager(t, "models", "credential-api")
	f.otherToken = f.manager(t, "connectors", "credential-api")
	f.standalone = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		f.browser.Handler().ServeHTTP(writer, request)
	}))
	f.portal = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		f.browser.Handler().ServeHTTP(writer, request)
	}))
	t.Cleanup(f.standalone.Close)
	t.Cleanup(f.portal.Close)
	f.service, err = New(Config{Installation: "protocol-test", Origin: f.standalone.URL, PortalOrigin: f.portal.URL, Namespace: "agent-platform-credential-api", Audience: "credential-api", Managers: map[string][]string{managerIdentity: {"tenant-credential-model-"}, otherManagerIdentity: {"tenant-credential-connector-"}}, Tenancy: true, Capacity: 256}, f.base)
	require.NoError(t, err)
	f.service.users, err = sharedk8s.NewUserClients(f.base, f.base.WrapTransport)
	require.NoError(t, err)
	f.redis = miniredis.RunT(t)
	key, err := security.GenerateKey()
	require.NoError(t, err)
	f.rootCAs = x509.NewCertPool()
	f.rootCAs.AddCert(f.idp.server.Certificate())
	f.browser, err = NewBrowser(f.service, BrowserConfig{Issuer: f.idp.server.URL, ClientID: "credential-api", ClientSecret: "synthetic-client-secret", KubernetesAudience: "kubernetes", ValkeyURL: "redis://" + f.redis.Addr(), EncryptionKey: key, RootCAs: f.rootCAs})
	require.NoError(t, err)
	t.Cleanup(f.browser.Close)
	require.Eventually(t, func() bool { _, err := f.service.AuthenticateManager(t.Context(), f.managerToken); return err == nil }, 10*time.Second, 50*time.Millisecond)
	f.installAdmission(t)
	return f
}

func (f *protocolFixture) installAdmission(t *testing.T) {
	t.Helper()
	fail := admissionv1.Fail
	_, err := f.admin.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(t.Context(), &admissionv1.ValidatingAdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: "credential-contract"}, Spec: admissionv1.ValidatingAdmissionPolicySpec{FailurePolicy: &fail, MatchConstraints: &admissionv1.MatchResources{ResourceRules: []admissionv1.NamedRuleWithOperations{{RuleWithOperations: admissionv1.RuleWithOperations{Operations: []admissionv1.OperationType{admissionv1.Create, admissionv1.Update}, Rule: admissionv1.Rule{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"secrets"}}}}}}, Validations: []admissionv1.Validation{{Expression: "object.type == 'Opaque' && object.metadata.name.startsWith('tenant-credential-')", Message: "credential contract refused"}}}}, metav1.CreateOptions{})
	require.NoError(t, err)
	_, err = f.admin.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(t.Context(), &admissionv1.ValidatingAdmissionPolicyBinding{ObjectMeta: metav1.ObjectMeta{Name: "credential-contract"}, Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{PolicyName: "credential-contract", ValidationActions: []admissionv1.ValidationAction{admissionv1.Deny}}}, metav1.CreateOptions{})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		_, err := f.admin.CoreV1().Secrets("tenant").Create(t.Context(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "forbidden-probe"}, Type: corev1.SecretTypeOpaque}, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
		return apierrors.IsInvalid(err)
	}, 10*time.Second, 50*time.Millisecond)
}

func (f *protocolFixture) manager(t *testing.T, name, audience string) string {
	t.Helper()
	_, err := f.admin.CoreV1().ServiceAccounts("managers").Create(t.Context(), &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: name}}, metav1.CreateOptions{})
	if !apierrors.IsAlreadyExists(err) {
		require.NoError(t, err)
	}
	expires := int64(600)
	token, err := f.admin.CoreV1().ServiceAccounts("managers").CreateToken(t.Context(), name, &authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{Audiences: []string{audience}, ExpirationSeconds: &expires}}, metav1.CreateOptions{})
	require.NoError(t, err)
	return token.Status.Token
}

func (f *protocolFixture) client(t *testing.T) *http.Client {
	t.Helper()
	client := *f.standalone.Client()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client.Jar = jar
	return &client
}

func protocolRequest(t *testing.T, client *http.Client, method, address string, body any, headers map[string]string) (int, []byte, http.Header) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(t.Context(), method, address, reader)
	require.NoError(t, err)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := client.Do(request)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	raw, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	return response.StatusCode, raw, response.Header
}

func (f *protocolFixture) request(name, subject string) Create {
	return Create{RequestID: name, Person: Person{Issuer: f.idp.server.URL, Subject: subject}, Organization: "example", Namespace: "tenant", Secret: "tenant-credential-model-" + name, Mode: "apply", Fields: Fields{Type: "object", Properties: map[string]Field{"client_id": {Type: "string", WriteOnly: true}, "client_secret": {Type: "string", WriteOnly: true, MinLength: 1}, "file": {Type: "file", WriteOnly: true}}, Required: []string{"client_id", "client_secret", "file"}}, Consumers: []Consumer{{Kind: "Model", Name: name, Destinations: []string{"https://provider.example.test/v1"}}}}
}

func (f *protocolFixture) open(t *testing.T, creation Create) Status {
	t.Helper()
	status, body, _ := protocolRequest(t, f.client(t), http.MethodPost, f.standalone.URL+"/v1/operations", creation, map[string]string{"Authorization": "Bearer " + f.managerToken})
	require.Equal(t, http.StatusCreated, status, string(body))
	var operation Status
	require.NoError(t, json.Unmarshal(body, &operation))
	return operation
}

func (f *protocolFixture) login(t *testing.T, client *http.Client, origin, id, subject string) {
	t.Helper()
	f.idp.mu.Lock()
	f.idp.subject = subject
	f.idp.mu.Unlock()
	status, body, _ := protocolRequest(t, client, http.MethodGet, origin+browserPrefix+"/signin?operation="+id, nil, nil)
	require.Equal(t, http.StatusOK, status, string(body))
}

func (f *protocolFixture) confirmation(t *testing.T, client *http.Client, origin, id string) (Confirmation, string) {
	t.Helper()
	status, body, _ := protocolRequest(t, client, http.MethodGet, origin+browserPrefix+"/api/operations/"+id, nil, nil)
	require.Equal(t, http.StatusOK, status, string(body))
	var confirmation struct {
		Operation Confirmation `json:"operation"`
		CSRF      string       `json:"csrf"`
	}
	require.NoError(t, json.Unmarshal(body, &confirmation))
	return confirmation.Operation, confirmation.CSRF
}

func TestRealAuthenticatedProtocol(t *testing.T) {
	f := protocolSetup(t)
	t.Run("manager boundaries", func(t *testing.T) {
		for _, token := range []string{f.manager(t, "unlisted", "credential-api"), f.manager(t, "models", "wrong-audience")} {
			status, _, _ := protocolRequest(t, f.client(t), http.MethodPost, f.standalone.URL+"/v1/operations", f.request("manager-check", "alice"), map[string]string{"Authorization": "Bearer " + token})
			require.Equal(t, http.StatusForbidden, status)
		}
		creation := f.request("foreign", "alice")
		creation.Secret = "tenant-credential-connector-foreign"
		status, _, _ := protocolRequest(t, f.client(t), http.MethodPost, f.standalone.URL+"/v1/operations", creation, map[string]string{"Authorization": "Bearer " + f.managerToken})
		require.Equal(t, http.StatusForbidden, status)
		creation = f.request("commit", "alice")
		creation.Mode = "commit"
		status, body, _ := protocolRequest(t, f.client(t), http.MethodPost, f.standalone.URL+"/v1/operations", creation, map[string]string{"Authorization": "Bearer " + f.managerToken})
		require.Equal(t, http.StatusBadRequest, status)
		require.Contains(t, string(body), "only apply")
		operation := f.open(t, f.request("cross-manager", "alice"))
		status, _, _ = protocolRequest(t, f.client(t), http.MethodGet, f.standalone.URL+"/v1/operations/"+operation.ID, nil, map[string]string{"Authorization": "Bearer " + f.otherToken})
		require.Equal(t, http.StatusNotFound, status)
		creation = f.request("missing-org", "alice")
		creation.Organization = ""
		status, _, _ = protocolRequest(t, f.client(t), http.MethodPost, f.standalone.URL+"/v1/operations", creation, map[string]string{"Authorization": "Bearer " + f.managerToken})
		require.Equal(t, http.StatusBadRequest, status)
		revokedConfiguration := f.service.configuration
		revokedConfiguration.Managers = map[string][]string{otherManagerIdentity: {"tenant-credential-connector-"}}
		revoked, err := New(revokedConfiguration, f.base)
		require.NoError(t, err)
		_, err = revoked.Confirm(t.Context(), Person{Issuer: f.idp.server.URL, Subject: "alice"}, f.idp.token(t, "alice", ""), operation.ID)
		require.ErrorIs(t, err, errNotFound)
	})
	for _, portal := range []bool{false, true} {
		t.Run(fmt.Sprintf("browser apply portal=%t", portal), func(t *testing.T) {
			origin := f.standalone.URL
			name := "standalone"
			if portal {
				origin = f.portal.URL
				name = "portal"
			}
			creation := f.request(name, "alice")
			creation.Actor = &Actor{Issuer: f.idp.server.URL, Subject: "agent-builder"}
			creation.Description = "<script>alert('manager')</script>"
			operation := f.open(t, creation)
			require.True(t, strings.HasPrefix(operation.URL, f.standalone.URL+"/credentials/"))
			client := f.client(t)
			f.login(t, client, origin, operation.ID, "alice")
			confirmation, csrf := f.confirmation(t, client, origin, operation.ID)
			require.Equal(t, "agent-builder", confirmation.Actor.Subject)
			input := Save{Version: confirmation.Version, Confirmation: confirmation.Confirmation, Values: map[string]json.RawMessage{"client_id": json.RawMessage(`"synthetic-client"`), "client_secret": json.RawMessage(`"` + sentinel + `"`), "file": json.RawMessage(`"synthetic-file-contents"`)}}
			for _, headers := range []map[string]string{{"Origin": origin}, {"Origin": "https://evil.example.test", "X-CSRF-Token": csrf}} {
				status, body, _ := protocolRequest(t, client, http.MethodPost, origin+browserPrefix+"/api/operations/"+operation.ID+"/save", input, headers)
				require.Equal(t, http.StatusForbidden, status)
				require.NotContains(t, string(body), sentinel)
			}
			status, body, headers := protocolRequest(t, client, http.MethodPost, origin+browserPrefix+"/api/operations/"+operation.ID+"/save", input, map[string]string{"Origin": origin, "X-CSRF-Token": csrf})
			require.Equal(t, http.StatusOK, status, string(body))
			require.Contains(t, string(body), `"state":"complete"`)
			require.NotContains(t, string(body), sentinel)
			require.Contains(t, headers.Get("Cache-Control"), "no-store")
			require.Equal(t, "DENY", headers.Get("X-Frame-Options"))
			status, body, _ = protocolRequest(t, f.client(t), http.MethodGet, f.standalone.URL+"/v1/operations/"+operation.ID, nil, map[string]string{"Authorization": "Bearer " + f.managerToken})
			require.Equal(t, http.StatusOK, status)
			require.NotContains(t, string(body), sentinel)
			status, body, _ = protocolRequest(t, client, http.MethodPost, origin+browserPrefix+"/api/operations/"+operation.ID+"/save", input, map[string]string{"Origin": origin, "X-CSRF-Token": csrf})
			require.Equal(t, http.StatusOK, status, string(body))
		})
	}
	t.Run("browser DOM submissions", func(t *testing.T) {
		module := os.Getenv("CREDENTIAL_API_PLAYWRIGHT")
		if module == "" {
			t.Skip("set CREDENTIAL_API_PLAYWRIGHT to playwright-core/index.mjs")
		}
		for index, origin := range []string{f.standalone.URL, f.portal.URL} {
			operation := f.open(t, f.request(fmt.Sprintf("dom-%d", index), "alice"))
			f.idp.mu.Lock()
			f.idp.subject = "alice"
			f.idp.mu.Unlock()
			// #nosec G204 G702 -- The fixed executable receives test fixture addresses as separate arguments.
			command := exec.CommandContext(t.Context(), "node", "testdata/browser.mjs", module, origin, operation.ID)
			output, err := command.CombinedOutput()
			require.NoError(t, err, string(output))
			require.Contains(t, string(output), "isolation passed")
			status, err := f.service.ManagerStatus(t.Context(), managerIdentity, operation.ID)
			require.NoError(t, err)
			require.Equal(t, complete, status.State)
		}
	})
	t.Run("owner and RBAC", func(t *testing.T) {
		operation := f.open(t, f.request("editor", "editor"))
		client := f.client(t)
		f.login(t, client, f.standalone.URL, operation.ID, "editor")
		status, body, _ := protocolRequest(t, client, http.MethodGet, f.standalone.URL+browserPrefix+"/api/operations/"+operation.ID, nil, nil)
		require.Equal(t, http.StatusForbidden, status)
		require.Contains(t, string(body), "Ask an admin")
		stored, err := f.service.store.read(t.Context(), operation.ID)
		require.NoError(t, err)
		confirmation := Confirmation{Version: stored.Version, Confirmation: stored.Confirmation}
		input := Save{Version: confirmation.Version, Confirmation: confirmation.Confirmation, Values: map[string]json.RawMessage{"client_id": json.RawMessage(`"id"`), "client_secret": json.RawMessage(`"secret"`), "file": json.RawMessage(`"file"`)}}
		_, err = f.service.Save(t.Context(), stored.Person, f.idp.token(t, "editor", ""), operation.ID, input)
		require.ErrorIs(t, err, errForbidden)
		for _, person := range []Person{{Issuer: f.idp.server.URL, Subject: "admin"}, {Issuer: f.idp.server.URL + "/other", Subject: "editor"}} {
			_, err := f.service.Confirm(t.Context(), person, "", operation.ID)
			require.ErrorIs(t, err, errOwner)
		}
		users, err := sharedk8s.NewUserClients(f.base, nil)
		require.NoError(t, err)
		caller, err := users.ForToken(f.idp.token(t, "alice", ""))
		require.NoError(t, err)
		for _, verb := range []string{"get", "list", "watch", "patch"} {
			allowed, err := sharedk8s.ReviewAccess(t.Context(), caller.Clientset, authorizationv1.ResourceAttributes{Verb: verb, Resource: "secrets", Namespace: "tenant"})
			require.NoError(t, err)
			require.False(t, allowed)
		}
	})
	t.Run("browser host and OAuth state rejection", func(t *testing.T) {
		operation := f.open(t, f.request("oauth-state", "alice"))
		client := f.client(t)
		client.CheckRedirect = func(request *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
		status, _, headers := protocolRequest(t, client, http.MethodGet, f.standalone.URL+browserPrefix+"/signin?operation="+operation.ID, nil, nil)
		require.Equal(t, http.StatusFound, status)
		location, err := url.Parse(headers.Get("Location"))
		require.NoError(t, err)
		require.Equal(t, "S256", location.Query().Get("code_challenge_method"))
		require.NotEmpty(t, location.Query().Get("state"))
		status, body, _ := protocolRequest(t, client, http.MethodGet, f.standalone.URL+browserPrefix+"/callback?state=wrong&code=synthetic", nil, nil)
		require.Equal(t, http.StatusForbidden, status)
		require.NotContains(t, string(body), "tenant")
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.standalone.URL+"/credentials/"+operation.ID, nil)
		require.NoError(t, err)
		request.Host = "unlisted.example.test"
		response, err := client.Do(request)
		require.NoError(t, err)
		defer func() { _ = response.Body.Close() }()
		require.Equal(t, http.StatusBadRequest, response.StatusCode)
	})
	t.Run("encrypted sessions cannot be relocated", func(t *testing.T) {
		operation := f.open(t, f.request("session-binding", "alice"))
		owner := f.client(t)
		f.login(t, owner, f.standalone.URL, operation.ID, "alice")
		origin, err := url.Parse(f.standalone.URL)
		require.NoError(t, err)
		var ownerCookie string
		for _, cookie := range owner.Jar.Cookies(origin) {
			if cookie.Name == sessionCookie {
				ownerCookie = cookie.Value
			}
		}
		require.NotEmpty(t, ownerCookie)
		ciphertext, err := f.redis.Get(cacheKey("session", f.standalone.URL, ownerCookie))
		require.NoError(t, err)
		attackerCookie := randomToken()
		require.NoError(t, f.redis.Set(cacheKey("session", f.standalone.URL, attackerCookie), ciphertext))
		attacker := f.client(t)
		attacker.Jar.SetCookies(origin, []*http.Cookie{{Name: sessionCookie, Value: attackerCookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}})
		status, body, _ := protocolRequest(t, attacker, http.MethodGet, f.standalone.URL+browserPrefix+"/api/operations/"+operation.ID, nil, nil)
		require.Equal(t, http.StatusForbidden, status)
		require.NotContains(t, string(body), "csrf")
	})
	t.Run("expiry cancellation and stale confirmation", func(t *testing.T) {
		operation := f.open(t, f.request("cancel", "alice"))
		stored, err := f.service.store.read(t.Context(), operation.ID)
		require.NoError(t, err)
		require.ErrorIs(t, f.service.Cancel(t.Context(), stored.Person, stored.ID, "stale"), errConflict)
		require.NoError(t, f.service.Cancel(t.Context(), stored.Person, stored.ID, stored.Version))
		_, err = f.service.Save(t.Context(), stored.Person, f.idp.token(t, "alice", ""), stored.ID, Save{Version: stored.Version, Confirmation: stored.Confirmation})
		require.ErrorIs(t, err, errConflict)
		operation = f.open(t, f.request("expiry", "alice"))
		stored, err = f.service.store.read(t.Context(), operation.ID)
		require.NoError(t, err)
		stored.ExpiresAt = time.Now().Add(-time.Second)
		require.NoError(t, f.service.store.put(t.Context(), stored))
		_, err = f.service.Confirm(t.Context(), stored.Person, "", stored.ID)
		require.ErrorIs(t, err, errNotFound)
	})
	t.Run("concurrent saves and interrupted receipt", func(t *testing.T) {
		operation := f.open(t, f.request("concurrent", "alice"))
		stored, err := f.service.store.read(t.Context(), operation.ID)
		require.NoError(t, err)
		input := Save{Version: stored.Version, Confirmation: stored.Confirmation, Values: map[string]json.RawMessage{"client_id": json.RawMessage(`"id"`), "client_secret": json.RawMessage(`"` + sentinel + `"`), "file": json.RawMessage(`"file"`)}}
		token := f.idp.token(t, "alice", "")
		start := make(chan struct{})
		results := make(chan error, 2)
		for range 2 {
			go func() {
				<-start
				_, err := f.service.Save(t.Context(), stored.Person, token, stored.ID, input)
				results <- err
			}()
		}
		close(start)
		first, second := <-results, <-results
		require.True(t, first == nil || second == nil)
		for _, err := range []error{first, second} {
			require.True(t, err == nil || err == errConflict || err == errUncertain)
		}
		creation := f.request("lost-receipt", "alice")
		operation = f.open(t, creation)
		stored, err = f.service.store.read(t.Context(), operation.ID)
		require.NoError(t, err)
		interrupted, err := New(f.service.configuration, f.base)
		require.NoError(t, err)
		var writes atomic.Int32
		interrupted.users, err = sharedk8s.NewUserClients(f.base, func(next http.RoundTripper) http.RoundTripper {
			return transportFunc(func(request *http.Request) (*http.Response, error) {
				response, err := next.RoundTrip(request)
				if request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/secrets") && request.URL.Query().Get("dryRun") == "" {
					writes.Add(1)
					if response != nil {
						_ = response.Body.Close()
					}
					return nil, io.ErrUnexpectedEOF
				}
				return response, err
			})
		})
		require.NoError(t, err)
		input.Version = stored.Version
		input.Confirmation = stored.Confirmation
		_, err = interrupted.Save(t.Context(), stored.Person, token, stored.ID, input)
		require.ErrorIs(t, err, errUncertain)
		restarted, err := New(f.service.configuration, f.base)
		require.NoError(t, err)
		_, err = restarted.Save(t.Context(), stored.Person, token, stored.ID, input)
		require.ErrorIs(t, err, errUncertain)
		require.EqualValues(t, 1, writes.Load())
		status, err := restarted.ManagerStatus(t.Context(), managerIdentity, stored.ID)
		require.NoError(t, err)
		require.Equal(t, uncertain, status.State)
	})
	t.Run("replacement confirmation pins Secret version", func(t *testing.T) {
		creation := f.request("replacement", "alice")
		operation := f.open(t, creation)
		stored, err := f.service.store.read(t.Context(), operation.ID)
		require.NoError(t, err)
		token := f.idp.token(t, "alice", "")
		values := map[string]json.RawMessage{"client_id": json.RawMessage(`"id"`), "client_secret": json.RawMessage(`"original"`), "file": json.RawMessage(`"file"`)}
		_, err = f.service.Save(t.Context(), stored.Person, token, stored.ID, Save{Version: stored.Version, Confirmation: stored.Confirmation, Values: values})
		require.NoError(t, err)
		creation.RequestID = "replace-first"
		creation.Replace = true
		first := f.open(t, creation)
		creation.RequestID = "replace-second"
		second := f.open(t, creation)
		firstConfirmation, err := f.service.Confirm(t.Context(), stored.Person, token, first.ID)
		require.NoError(t, err)
		secondConfirmation, err := f.service.Confirm(t.Context(), stored.Person, token, second.ID)
		require.NoError(t, err)
		_, err = f.service.Save(t.Context(), stored.Person, token, first.ID, Save{Version: firstConfirmation.Version, Confirmation: firstConfirmation.Confirmation, Values: values})
		require.NoError(t, err)
		_, err = f.service.Save(t.Context(), stored.Person, token, second.ID, Save{Version: secondConfirmation.Version, Confirmation: secondConfirmation.Confirmation, Values: values})
		require.ErrorIs(t, err, errConflict)
	})
	t.Run("audit failure recovers without another Secret write", func(t *testing.T) {
		creation := f.request("audit-failure", "admin")
		operation := f.open(t, creation)
		stored, err := f.service.store.read(t.Context(), operation.ID)
		require.NoError(t, err)
		base := rest.CopyConfig(f.base)
		base.ContentType = "application/json"
		base.WrapTransport = func(next http.RoundTripper) http.RoundTripper {
			return transportFunc(func(request *http.Request) (*http.Response, error) {
				if request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/configmaps") {
					body, err := io.ReadAll(request.Body)
					if err != nil {
						return nil, err
					}
					request.Body = io.NopCloser(bytes.NewReader(body))
					var item corev1.ConfigMap
					if json.Unmarshal(body, &item) == nil && strings.Contains(item.Data["audit"], `"outcome":"complete"`) {
						return nil, io.ErrUnexpectedEOF
					}
				}
				return next.RoundTrip(request)
			})
		}
		interrupted, err := New(f.service.configuration, base)
		require.NoError(t, err)
		input := Save{Version: stored.Version, Confirmation: stored.Confirmation, Values: map[string]json.RawMessage{"client_id": json.RawMessage(`"id"`), "client_secret": json.RawMessage(`"` + sentinel + `"`), "file": json.RawMessage(`"file"`)}}
		token := f.idp.token(t, "admin", "")
		_, err = interrupted.Save(t.Context(), stored.Person, token, stored.ID, input)
		require.ErrorIs(t, err, errUncertain)
		stored, err = f.service.store.read(t.Context(), stored.ID)
		require.NoError(t, err)
		require.NotEmpty(t, stored.AppliedVersion)
		status, err := f.service.Save(t.Context(), stored.Person, token, stored.ID, input)
		require.NoError(t, err)
		require.Equal(t, complete, status.State)
	})
	t.Run("capacity reservation is shared across replicas", func(t *testing.T) {
		_, err := f.admin.CoreV1().Namespaces().Create(t.Context(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "quota-test"}}, metav1.CreateOptions{})
		require.NoError(t, err)
		configuration := f.service.configuration
		configuration.Namespace = "quota-test"
		configuration.Capacity = 2
		first, err := New(configuration, f.base)
		require.NoError(t, err)
		second, err := New(configuration, f.base)
		require.NoError(t, err)
		results := make(chan error, 3)
		start := make(chan struct{})
		for index, service := range []*Service{first, second, first} {
			go func() {
				<-start
				_, err := service.Open(t.Context(), managerIdentity, f.request(fmt.Sprintf("quota-%d", index), "alice"))
				results <- err
			}()
		}
		close(start)
		success := 0
		for range 3 {
			err := <-results
			if err == nil {
				success++
			} else {
				require.ErrorIs(t, err, errConflict)
			}
		}
		require.Equal(t, 2, success)
	})
	t.Run("rendered chart server dry run", func(t *testing.T) {
		// #nosec G204 -- The fixed executable receives loopback fixture addresses as separate arguments.
		command := exec.CommandContext(t.Context(), "helm", "--kube-context", "credential-api-envtest", "template", "credential-api", "../../helm/credential-api", "--namespace", "agent-platform-credential-api", "--set", "installation=protocol", "--set", "credentialOrigin=https://credentials.example.test", "--set", "portalOrigin=https://portal.example.test", "--set", "ingress.enabled=true", "--set", "ingress.tlsSecretName=credential-tls", "--set", "ingress.portalTlsSecretName=portal-tls", "--set", "oauth.issuer="+f.idp.server.URL)
		rendered, err := command.CombinedOutput()
		require.NoError(t, err, string(rendered))
		decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(rendered), 4096)
		client, err := dynamic.NewForConfig(f.base)
		require.NoError(t, err)
		count := 0
		for {
			var object unstructured.Unstructured
			err := decoder.Decode(&object)
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
			if object.GetKind() == "" {
				continue
			}
			resource, _ := meta.UnsafeGuessKindToResource(object.GroupVersionKind())
			_, err = client.Resource(resource).Namespace(object.GetNamespace()).Create(t.Context(), &object, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
			require.NoError(t, err, object.GetKind())
			count++
		}
		require.GreaterOrEqual(t, count, 10)
	})
	t.Run("metadata and session isolation", func(t *testing.T) {
		items, err := f.admin.CoreV1().ConfigMaps("agent-platform-credential-api").List(t.Context(), metav1.ListOptions{})
		require.NoError(t, err)
		body, err := json.Marshal(items)
		require.NoError(t, err)
		for _, value := range []string{sentinel, base64.StdEncoding.EncodeToString([]byte(sentinel)), f.managerToken, "synthetic-file-contents"} {
			require.NotContains(t, string(body), value)
		}
		require.Contains(t, string(body), `\"outcome\":\"complete\"`)
		require.Contains(t, string(body), `\"outcome\":\"refused\"`)
		for _, key := range f.redis.Keys() {
			value, err := f.redis.Get(key)
			require.NoError(t, err)
			require.NotContains(t, value, sentinel)
			require.NotContains(t, value, "synthetic-access")
			require.NotContains(t, value, `"token"`)
		}
		f.requestsMu.Lock()
		defer f.requestsMu.Unlock()
		for _, request := range f.requests {
			if strings.Contains(request, "/secrets") {
				require.True(t, strings.HasPrefix(request, "POST ") || strings.HasPrefix(request, "PUT "), request)
			}
		}
	})
}

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }
