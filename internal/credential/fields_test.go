package credential

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFieldLimitsAndGoogleFiles(t *testing.T) {
	fields := Fields{Type: "object", Properties: map[string]Field{"secret": {Type: "string", WriteOnly: true, MinLength: 1, MaxLength: 32}, "enabled": {Type: "boolean", WriteOnly: true}, "count": {Type: "integer", WriteOnly: true, Minimum: new(float64(0)), Maximum: new(float64(5))}}, Required: []string{"secret"}}
	require.NoError(t, validateFields(fields))
	for _, values := range []map[string]json.RawMessage{
		{}, {"secret": json.RawMessage(`null`)}, {"secret": json.RawMessage(`""`)},
		{"secret": json.RawMessage(`"` + strings.Repeat("x", 33) + `"`)},
		{"secret": json.RawMessage(`"value"`), "unknown": json.RawMessage(`"value"`)},
		{"secret": json.RawMessage(`"value"`), "enabled": json.RawMessage(`null`)},
		{"secret": json.RawMessage(`"value"`), "count": json.RawMessage(`1.5`)},
		{"secret": json.RawMessage(`"value"`), "count": json.RawMessage(`6`)},
	} {
		_, err := fieldValues(fields, values)
		require.ErrorIs(t, err, errInvalid)
	}
	data, err := fieldValues(fields, map[string]json.RawMessage{"secret": json.RawMessage(`"value"`), "enabled": json.RawMessage(`false`), "count": json.RawMessage(`2`)})
	require.NoError(t, err)
	require.Equal(t, []byte("false"), data["enabled"])
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	// #nosec G101 -- The test private key is generated in memory.
	google := map[string]string{"type": "service_account", "project_id": "example", "client_email": "service@example.iam.gserviceaccount.com", "private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})), "token_uri": "https://oauth2.googleapis.com/token"}
	body, err := json.Marshal(google)
	require.NoError(t, err)
	require.True(t, validGoogleCredential(string(body)))
	google["token_uri"] = "https://evil.example.test/token"
	body, err = json.Marshal(google)
	require.NoError(t, err)
	require.False(t, validGoogleCredential(string(body)))
	require.False(t, validGoogleCredential(`{"type":"service_account","project_id":"example","client_email":"service@example.test","private_key":"invalid"}`))
}

func TestOriginAndSchemaBoundaries(t *testing.T) {
	for _, origin := range []string{"http://credentials.example.test", "https://{host}.example.test", "https://credentials.example.test/path", "https://user:password@credentials.example.test", "https://credentials.example.test?other=host", "https://credentials.example.test#fragment"} {
		require.False(t, validOrigin(origin), origin)
	}
	require.True(t, validOrigin("https://credentials.example.test"))
	require.True(t, validIssuer("https://issuer.example.test/dex"))
	for _, field := range []Field{{Type: "object", WriteOnly: true}, {Type: "string"}, {Type: "file", WriteOnly: true, Format: "unknown"}, {Type: "number", WriteOnly: true, MinLength: 1}} {
		require.ErrorIs(t, validateFields(Fields{Type: "object", Properties: map[string]Field{"value": field}}), errInvalid)
	}
}

func TestBrowserRequiresSessionEncryption(t *testing.T) {
	browser, err := NewBrowser(&Service{}, BrowserConfig{ClientID: "credential-api", ClientSecret: "synthetic", KubernetesAudience: "kubernetes", ValkeyURL: "redis://127.0.0.1:1"})
	require.ErrorIs(t, err, errInvalid)
	require.Nil(t, browser)
}
