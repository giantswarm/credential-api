package credential

import (
	"context"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/giantswarm/mcp-oauth/providers/oidc"
	sharedk8s "github.com/giantswarm/mcp-toolkit/k8s"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type Config struct {
	Installation      string              `json:"installation"`
	Origin            string              `json:"origin"`
	PortalOrigin      string              `json:"portalOrigin"`
	Namespace         string              `json:"namespace"`
	Audience          string              `json:"audience"`
	Managers          map[string][]string `json:"managers"`
	Tenancy           bool                `json:"tenancy"`
	PlatformNamespace string              `json:"platformNamespace"`
	Capacity          int64               `json:"capacity"`
}

type Service struct {
	configuration Config
	admin         kubernetes.Interface
	users         *sharedk8s.UserClients
	store         *Store
}

func (s *Service) Expire(ctx context.Context, interval time.Duration) { s.store.Expire(ctx, interval) }

func validOrigin(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme == httpsScheme && parsed.Host != "" && parsed.User == nil && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == "" && !strings.ContainsAny(parsed.Host, "{}*\\")
}

func validIssuer(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme == httpsScheme && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
}

func New(configuration Config, base *rest.Config) (*Service, error) {
	if base == nil || base.Host == "" {
		return nil, errInvalid
	}
	if !validOrigin(configuration.Origin) || (configuration.PortalOrigin != "" && !validOrigin(configuration.PortalOrigin)) || configuration.Origin == configuration.PortalOrigin || configuration.Installation == "" || configuration.Audience == "" || len(validation.IsDNS1123Label(configuration.Namespace)) > 0 || configuration.Capacity < 1 || configuration.Capacity > 256 || (!configuration.Tenancy && configuration.PlatformNamespace == "") {
		return nil, errInvalid
	}
	owners := map[string]string{}
	for manager, prefixes := range configuration.Managers {
		if !strings.HasPrefix(manager, "system:serviceaccount:") || len(strings.Split(manager, ":")) != 4 || len(prefixes) == 0 {
			return nil, errInvalid
		}
		for _, prefix := range prefixes {
			for existing, owner := range owners {
				if owner != manager && (strings.HasPrefix(existing, prefix) || strings.HasPrefix(prefix, existing)) {
					return nil, errInvalid
				}
			}
			owners[prefix] = manager
			kind := strings.TrimSuffix(strings.TrimPrefix(prefix, "tenant-credential-"), "-")
			if prefix != "tenant-credential-"+kind+"-" || kind == "" || len(validation.IsDNS1123Label(kind)) > 0 {
				return nil, errInvalid
			}
		}
	}
	base = rest.CopyConfig(base)
	base.WarningHandlerWithContext = rest.NoWarnings{}
	admin, err := kubernetes.NewForConfig(base)
	if err != nil {
		return nil, errUnavailable
	}
	users, err := sharedk8s.NewUserClients(base, nil)
	if err != nil {
		return nil, errUnavailable
	}
	return &Service{configuration: configuration, admin: admin, users: users, store: &Store{maps: admin.CoreV1().ConfigMaps(configuration.Namespace), capacity: configuration.Capacity}}, nil
}

func (s *Service) AuthenticateManager(ctx context.Context, token string) (string, error) {
	if token == "" {
		return "", errForbidden
	}
	review, err := s.admin.AuthenticationV1().TokenReviews().Create(ctx, &authenticationv1.TokenReview{Spec: authenticationv1.TokenReviewSpec{Token: token, Audiences: []string{s.configuration.Audience}}}, metav1.CreateOptions{})
	if err != nil || !review.Status.Authenticated || review.Status.Error != "" || !slices.Contains(review.Status.Audiences, s.configuration.Audience) {
		return "", errForbidden
	}
	manager := review.Status.User.Username
	claims, parseErr := oidc.ParseUnverifiedClaims(token)
	issuedAt, issuedOK := claims["iat"].(float64)
	expires, expiresOK := claims["exp"].(float64)
	if parseErr != nil || !issuedOK || !expiresOK || expires-issuedAt > 3600 || expires <= issuedAt {
		return "", errForbidden
	}
	if _, ok := s.configuration.Managers[manager]; !ok {
		return "", errForbidden
	}
	allowed, err := sharedk8s.ReviewSubjectAccess(ctx, s.admin, review.Status.User, authorizationv1.ResourceAttributes{Namespace: s.configuration.Namespace, Verb: "create", Group: "credential.giantswarm.io", Version: "v1", Resource: "operations"})
	if err != nil || !allowed {
		return "", errForbidden
	}
	return manager, nil
}

func (s *Service) target(ctx context.Context, request Create) (string, error) {
	if !s.configuration.Tenancy {
		if request.Organization != "" || request.Namespace != s.configuration.PlatformNamespace {
			return "", errInvalid
		}
	} else if request.Organization == "" {
		return "", errInvalid
	}
	namespace, err := s.admin.CoreV1().Namespaces().Get(ctx, request.Namespace, metav1.GetOptions{})
	if err != nil || namespace.DeletionTimestamp != nil {
		return "", errNotFound
	}
	if s.configuration.Tenancy && (namespace.Labels["agent-platform.giantswarm.io/organization"] != request.Organization || namespace.Labels["agent-platform.giantswarm.io/organization-uid"] == "") {
		return "", errInvalid
	}
	return string(namespace.UID) + ":" + namespace.Labels["agent-platform.giantswarm.io/organization-uid"], nil
}

func (s *Service) Open(ctx context.Context, manager string, request Create) (*Status, error) {
	prefixes, ok := s.configuration.Managers[manager]
	if !ok {
		return nil, errForbidden
	}
	if request.Mode != "apply" {
		return nil, errMode
	}
	if request.RequestID == "" || len(request.RequestID) > 256 || !validIssuer(request.Person.Issuer) || request.Person.Subject == "" || len(request.Person.Subject) > 512 || len(request.Description) > 2048 || len(request.Consumers) == 0 || len(request.Consumers) > 64 || len(validation.IsDNS1123Subdomain(request.Secret)) > 0 || len(validation.IsDNS1123Label(request.Namespace)) > 0 {
		return nil, errInvalid
	}
	if request.Actor != nil && (!validIssuer(request.Actor.Issuer) || request.Actor.Subject == "" || len(request.Actor.Subject) > 512) {
		return nil, errInvalid
	}
	if !slices.ContainsFunc(prefixes, func(prefix string) bool {
		return strings.HasPrefix(request.Secret, prefix) && len(request.Secret) > len(prefix)
	}) {
		return nil, errForbidden
	}
	if err := validateFields(request.Fields); err != nil {
		return nil, err
	}
	for _, consumer := range request.Consumers {
		if consumer.Kind == "" || len(consumer.Kind) > 128 || consumer.Name == "" || len(consumer.Name) > 253 || len(consumer.Destinations) == 0 || len(consumer.Destinations) > 64 {
			return nil, errInvalid
		}
		for _, destination := range consumer.Destinations {
			parsed, err := url.Parse(destination)
			if err != nil || parsed.Scheme != httpsScheme || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
				return nil, errInvalid
			}
		}
	}
	namespaceUID, err := s.target(ctx, request)
	if err != nil {
		return nil, err
	}
	operation := &Operation{Create: request, ID: identifier(manager, request), Manager: manager, NamespaceUID: namespaceUID, ExpiresAt: time.Now().Add(lifetime), State: pending, Confirmation: digest(request)}
	operation, err = s.store.prepare(ctx, operation)
	if err != nil {
		return nil, err
	}
	return s.status(operation), nil
}

func (s *Service) status(operation *Operation) *Status {
	state := operation.State
	if state == saving {
		state = uncertain
	}
	return &Status{ID: operation.ID, State: state, ExpiresAt: operation.ExpiresAt, URL: s.configuration.Origin + "/credentials/" + operation.ID}
}

func (s *Service) ManagerStatus(ctx context.Context, manager, id string) (*Status, error) {
	operation, err := s.store.read(ctx, id)
	if err != nil {
		return nil, err
	}
	if operation.Manager != manager {
		return nil, errNotFound
	}
	if !time.Now().Before(operation.ExpiresAt) {
		return nil, errNotFound
	}
	return s.status(operation), nil
}

func (s *Service) owned(ctx context.Context, person Person, id string) (*Operation, error) {
	operation, err := s.store.read(ctx, id)
	if err != nil {
		return nil, err
	}
	if operation.Person != person {
		return nil, errOwner
	}
	prefixes, listed := s.configuration.Managers[operation.Manager]
	if !listed || !slices.ContainsFunc(prefixes, func(prefix string) bool {
		return strings.HasPrefix(operation.Secret, prefix) && len(operation.Secret) > len(prefix)
	}) {
		return nil, errNotFound
	}
	if !time.Now().Before(operation.ExpiresAt) {
		return nil, errNotFound
	}
	uid, err := s.target(ctx, operation.Create)
	if err != nil {
		return nil, err
	}
	if uid != operation.NamespaceUID {
		return nil, errConflict
	}
	return operation, nil
}

func (s *Service) Confirm(ctx context.Context, person Person, token, id string) (*Confirmation, error) {
	operation, err := s.owned(ctx, person, id)
	if err != nil {
		return nil, err
	}
	if operation.State == pending {
		caller, err := s.users.ForToken(token)
		if err != nil {
			return nil, errForbidden
		}
		verb := "create"
		if operation.Replace {
			verb = "update"
		}
		allowed, err := sharedk8s.ReviewAccess(ctx, caller.Clientset, authorizationv1.ResourceAttributes{Verb: verb, Resource: "secrets", Namespace: operation.Namespace, Name: operation.Secret})
		if err != nil || !allowed {
			return nil, errForbidden
		}
		if operation.Replace && operation.ExpectedVersion == "" {
			secrets := caller.Clientset.CoreV1().Secrets(operation.Namespace)
			_, err := secrets.Create(ctx, secretFor(operation, nil), metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
			if !apierrors.IsAlreadyExists(err) {
				if err != nil {
					return nil, writeError(err)
				}
				return nil, errConflict
			}
			prepared, err := secrets.Update(ctx, secretFor(operation, nil), metav1.UpdateOptions{DryRun: []string{metav1.DryRunAll}})
			if err != nil {
				return nil, writeError(err)
			}
			if prepared.ResourceVersion == "" {
				return nil, errConflict
			}
			operation.ExpectedVersion = prepared.ResourceVersion
			if err := s.store.put(ctx, operation); err != nil {
				return nil, err
			}
		}
	}
	return &Confirmation{Create: operation.Create, ID: operation.ID, Version: operation.Version, Manager: operation.Manager, Installation: s.configuration.Installation, State: s.status(operation).State, ExpiresAt: operation.ExpiresAt, Confirmation: operation.Confirmation}, nil
}

func (s *Service) Cancel(ctx context.Context, person Person, id, version string) error {
	operation, err := s.owned(ctx, person, id)
	if err != nil {
		return err
	}
	if version == "" || operation.Version != version || operation.State != pending {
		return errConflict
	}
	operation.State = cancelled
	return s.store.put(ctx, operation)
}

type Save struct {
	Version      string                     `json:"version"`
	Confirmation string                     `json:"confirmation"`
	Values       map[string]json.RawMessage `json:"values"`
}

type audit struct {
	Operation string    `json:"operation"`
	At        time.Time `json:"at"`
	Person    Person    `json:"person"`
	Manager   string    `json:"manager"`
	Namespace string    `json:"namespace"`
	Name      string    `json:"name"`
	Mode      string    `json:"mode"`
	Outcome   string    `json:"outcome"`
}

func (s *Service) record(ctx context.Context, operation *Operation, person Person, outcome string) error {
	body, _ := json.Marshal(audit{Operation: operation.ID, At: time.Now(), Person: person, Manager: operation.Manager, Namespace: operation.Namespace, Name: operation.Secret, Mode: operation.Mode, Outcome: outcome})
	_, err := s.store.maps.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{GenerateName: "audit-", Labels: map[string]string{"credential.giantswarm.io/audit": labelEnabled}}, Immutable: new(true), Data: map[string]string{"audit": string(body)}}, metav1.CreateOptions{})
	if err != nil {
		return errUnavailable
	}
	return nil
}

func secretFor(operation *Operation, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: operation.Secret, Namespace: operation.Namespace, Annotations: map[string]string{operationAnnotation: operation.ID}}, Type: corev1.SecretTypeOpaque, Data: data}
}

func writeError(err error) error {
	if apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) {
		return errForbidden
	}
	if apierrors.IsConflict(err) || apierrors.IsAlreadyExists(err) || apierrors.IsNotFound(err) {
		return errConflict
	}
	if apierrors.IsInvalid(err) || apierrors.IsBadRequest(err) {
		return errInvalid
	}
	return errUncertain
}

func (s *Service) Save(ctx context.Context, person Person, token, id string, request Save) (result *Status, failure error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	operation, err := s.store.read(ctx, id)
	if err != nil {
		return nil, err
	}
	recordCtx, cancelRecord := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancelRecord()
	if err := s.record(recordCtx, operation, person, "attempt"); err != nil {
		return nil, errUncertain
	}
	auditOperation := operation
	defer func() {
		if failure == nil {
			return
		}
		outcome := "refused"
		if failure == errUncertain {
			outcome = uncertain
		}
		auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if s.record(auditCtx, auditOperation, person, outcome) != nil {
			result = nil
			failure = errUncertain
		}
	}()
	operation, err = s.owned(ctx, person, id)
	if err != nil {
		return nil, err
	}
	if operation.State == complete {
		if err := s.record(recordCtx, operation, person, complete); err != nil {
			return nil, errUncertain
		}
		return s.status(operation), nil
	}
	if operation.State == saving || operation.State == uncertain {
		if operation.AppliedVersion != "" {
			if err := s.record(recordCtx, operation, person, "complete"); err != nil {
				return nil, errUncertain
			}
			operation.State = complete
			if err := s.store.put(recordCtx, operation); err != nil {
				return nil, errUncertain
			}
			return s.status(operation), nil
		}
		return nil, errUncertain
	}
	if operation.State != pending || request.Version == "" || request.Version != operation.Version || request.Confirmation != operation.Confirmation {
		return nil, errConflict
	}
	if time.Until(operation.ExpiresAt) < 45*time.Second {
		return nil, errConflict
	}
	data, err := fieldValues(operation.Fields, request.Values)
	if err != nil {
		return nil, err
	}
	caller, err := s.users.ForToken(token)
	if err != nil {
		return nil, errForbidden
	}
	secrets := caller.Clientset.CoreV1().Secrets(operation.Namespace)
	secret := secretFor(operation, data)
	if operation.Replace {
		if operation.ExpectedVersion == "" {
			return nil, errConflict
		}
		secret.ResourceVersion = operation.ExpectedVersion
		_, err := secrets.Update(ctx, secret, metav1.UpdateOptions{DryRun: []string{metav1.DryRunAll}})
		if err != nil {
			return nil, writeError(err)
		}
	} else {
		if _, err := secrets.Create(ctx, secret, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}}); err != nil {
			return nil, writeError(err)
		}
	}
	if time.Until(operation.ExpiresAt) < 45*time.Second {
		return nil, errConflict
	}
	operation.State = saving
	if err := s.store.put(recordCtx, operation); err != nil {
		if err == errConflict {
			return nil, err
		}
		return nil, errUncertain
	}
	cancelRecord()
	recordCtx, cancelRecord = context.WithDeadline(context.WithoutCancel(ctx), operation.ExpiresAt)
	defer cancelRecord()
	writeCtx, cancelWrite := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancelWrite()
	var written *corev1.Secret
	if operation.Replace {
		written, err = secrets.Update(writeCtx, secret, metav1.UpdateOptions{})
	} else {
		written, err = secrets.Create(writeCtx, secret, metav1.CreateOptions{})
	}
	if err != nil {
		operation.State = uncertain
		_ = s.store.put(recordCtx, operation)
		answer := writeError(err)
		return nil, answer
	}
	operation.AppliedVersion = written.ResourceVersion
	if err := s.store.put(recordCtx, operation); err != nil {
		return nil, errUncertain
	}
	if err := s.record(recordCtx, operation, person, complete); err != nil {
		return nil, errUncertain
	}
	operation.State = complete
	if err := s.store.put(recordCtx, operation); err != nil {
		return nil, errUncertain
	}
	return s.status(operation), nil
}
