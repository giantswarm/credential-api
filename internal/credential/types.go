package credential

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

const (
	fieldTypeString     = "string"
	fieldTypeBoolean    = "boolean"
	fieldTypeNumber     = "number"
	fieldTypeInteger    = "integer"
	operationKey        = "operation"
	fieldTypeFile       = "file"
	jsonNull            = "null"
	httpsScheme         = "https"
	labelEnabled        = "true"
	lifetime            = 15 * time.Minute
	operationLabel      = "credential.giantswarm.io/operation"
	operationAnnotation = "credential.giantswarm.io/operation"
	pending             = "pending"
	saving              = "saving"
	uncertain           = "uncertain"
	complete            = "complete"
	cancelled           = "cancelled"
)

var (
	errInvalid     = errors.New("invalid credential request")
	errUnavailable = errors.New("credential service unavailable")
	errNotFound    = errors.New("operation unavailable; restart from the original request")
	errOwner       = errors.New("use the original sign-in; sharing a link does not transfer an operation")
	errConflict    = errors.New("operation changed; refresh the confirmation")
	errForbidden   = errors.New("credential authorization refused")
	errUncertain   = errors.New("save outcome is uncertain; no unconditional retry is permitted")
	errMode        = errors.New("unsupported mode: only apply is available")
)

type Person struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

type Actor struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

type Consumer struct {
	Kind         string   `json:"kind"`
	Name         string   `json:"name"`
	Destinations []string `json:"destinations"`
}

type Field struct {
	Type        string   `json:"type"`
	Title       string   `json:"title,omitempty"`
	Description string   `json:"description,omitempty"`
	WriteOnly   bool     `json:"writeOnly"`
	MinLength   int      `json:"minLength,omitempty"`
	MaxLength   int      `json:"maxLength,omitempty"`
	Minimum     *float64 `json:"minimum,omitempty"`
	Maximum     *float64 `json:"maximum,omitempty"`
	Enum        []string `json:"enum,omitempty"`
	Format      string   `json:"format,omitempty"`
}

type Fields struct {
	Type                 string           `json:"type"`
	Properties           map[string]Field `json:"properties"`
	Required             []string         `json:"required"`
	AdditionalProperties bool             `json:"additionalProperties"`
}

type Create struct {
	RequestID    string     `json:"requestId"`
	Person       Person     `json:"person"`
	Actor        *Actor     `json:"actor,omitempty"`
	Organization string     `json:"organization"`
	Namespace    string     `json:"namespace"`
	Secret       string     `json:"secret"`
	Mode         string     `json:"mode"`
	Replace      bool       `json:"replace"`
	Fields       Fields     `json:"fields"`
	Consumers    []Consumer `json:"consumers"`
	Description  string     `json:"description,omitempty"`
}

type Operation struct {
	Create
	ID              string    `json:"id"`
	Version         string    `json:"-"`
	Manager         string    `json:"manager"`
	NamespaceUID    string    `json:"namespaceUid"`
	ExpiresAt       time.Time `json:"expiresAt"`
	State           string    `json:"state"`
	Confirmation    string    `json:"confirmation"`
	ExpectedVersion string    `json:"expectedVersion,omitempty"`
	AppliedVersion  string    `json:"appliedVersion,omitempty"`
}

type Status struct {
	ID        string    `json:"id"`
	State     string    `json:"state"`
	ExpiresAt time.Time `json:"expiresAt"`
	URL       string    `json:"url"`
}

type Confirmation struct {
	Create
	ID           string    `json:"id"`
	Version      string    `json:"version"`
	Manager      string    `json:"manager"`
	Installation string    `json:"installation"`
	State        string    `json:"state"`
	ExpiresAt    time.Time `json:"expiresAt"`
	Confirmation string    `json:"confirmation"`
}

func digest(value any) string {
	body, _ := json.Marshal(value)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:24])
}

func identifier(manager string, request Create) string {
	return digest([]any{manager, request.Person, request.RequestID})
}
