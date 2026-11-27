package credential

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"k8s.io/apimachinery/pkg/util/validation"
)

func validateFields(fields Fields) error {
	if fields.Type != "object" || fields.AdditionalProperties || len(fields.Properties) == 0 || len(fields.Properties) > 16 {
		return errInvalid
	}
	seen := map[string]bool{}
	for _, name := range fields.Required {
		if _, ok := fields.Properties[name]; !ok || seen[name] {
			return errInvalid
		}
		seen[name] = true
	}
	for name, field := range fields.Properties {
		if len(validation.IsConfigMapKey(name)) > 0 || !field.WriteOnly || field.MinLength < 0 || field.MaxLength < 0 || field.MaxLength > 64*1024 || (field.MaxLength > 0 && field.MinLength > field.MaxLength) || len(field.Title) > 256 || len(field.Description) > 2048 || len(field.Enum) > 64 {
			return errInvalid
		}
		if !slices.Contains([]string{fieldTypeString, fieldTypeFile, fieldTypeNumber, fieldTypeInteger, fieldTypeBoolean}, field.Type) {
			return errInvalid
		}
		if field.Format != "" && (field.Type != fieldTypeFile || field.Format != "google-service-account") {
			return errInvalid
		}
		if field.Minimum != nil && field.Maximum != nil && *field.Minimum > *field.Maximum {
			return errInvalid
		}
		if field.Type != fieldTypeString && field.Type != fieldTypeFile && (field.MinLength != 0 || field.MaxLength != 0 || len(field.Enum) != 0) {
			return errInvalid
		}
		if field.Type != fieldTypeNumber && field.Type != fieldTypeInteger && (field.Minimum != nil || field.Maximum != nil) {
			return errInvalid
		}
	}
	return nil
}

func fieldValues(fields Fields, values map[string]json.RawMessage) (map[string][]byte, error) {
	for _, name := range fields.Required {
		if raw, ok := values[name]; !ok || string(raw) == jsonNull || string(raw) == `""` {
			return nil, errInvalid
		}
	}
	data := make(map[string][]byte, len(values))
	for name, raw := range values {
		field, ok := fields.Properties[name]
		if !ok {
			return nil, errInvalid
		}
		var value string
		switch field.Type {
		case fieldTypeString, fieldTypeFile:
			if string(raw) == jsonNull || json.Unmarshal(raw, &value) != nil || len(value) > 64*1024 || !utf8.ValidString(value) {
				return nil, errInvalid
			}
			length := utf8.RuneCountInString(value)
			if length < field.MinLength || (field.MaxLength > 0 && length > field.MaxLength) || (len(field.Enum) > 0 && !slices.Contains(field.Enum, value)) {
				return nil, errInvalid
			}
			if field.Format == "google-service-account" && !validGoogleCredential(value) {
				return nil, errInvalid
			}
		case fieldTypeBoolean:
			var boolean bool
			if string(raw) == jsonNull || json.Unmarshal(raw, &boolean) != nil {
				return nil, errInvalid
			}
			value = strconv.FormatBool(boolean)
		case fieldTypeNumber, fieldTypeInteger:
			var number float64
			if string(raw) == jsonNull || json.Unmarshal(raw, &number) != nil || (field.Type == fieldTypeInteger && math.Trunc(number) != number) || (field.Minimum != nil && number < *field.Minimum) || (field.Maximum != nil && number > *field.Maximum) {
				return nil, errInvalid
			}
			value = string(raw)
		default:
			return nil, errInvalid
		}
		data[name] = []byte(value)
	}
	if len(data) == 0 {
		return nil, errInvalid
	}
	return data, nil
}

func validGoogleCredential(raw string) bool {
	var key struct {
		Type        string `json:"type"`
		ProjectID   string `json:"project_id"`
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
		TokenURI    string `json:"token_uri"`
	}
	if len(raw) > 64*1024 || json.Unmarshal([]byte(raw), &key) != nil || key.Type != "service_account" || key.ProjectID == "" || key.ClientEmail == "" {
		return false
	}
	if key.TokenURI != "" {
		endpoint, err := url.Parse(key.TokenURI)
		if err != nil || endpoint.Scheme != httpsScheme || endpoint.Host != "oauth2.googleapis.com" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "/token" {
			return false
		}
	}
	block, rest := pem.Decode([]byte(key.PrivateKey))
	if block == nil || strings.TrimSpace(string(rest)) != "" || block.Type != "PRIVATE KEY" {
		return false
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return false
	}
	privateKey, ok := parsed.(*rsa.PrivateKey)
	return ok && privateKey.Validate() == nil
}
