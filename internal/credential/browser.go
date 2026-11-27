package credential

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/dex"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/valkey-io/valkey-go"
	"golang.org/x/oauth2"
)

const browserPrefix = "/credential-api"
const sessionCookie = "__Host-credential-session"
const flowCookie = "__Host-credential-flow"

type BrowserConfig struct {
	Issuer             string
	ClientID           string
	ClientSecret       string
	KubernetesAudience string
	ValkeyURL          string
	EncryptionKey      []byte
	RootCAs            *x509.CertPool
}

type Browser struct {
	service       *Service
	providers     map[string]providers.JWKSProvider
	jwks          *oidc.JWKSClient
	cache         valkey.Client
	sealer        *security.Encryptor
	configuration BrowserConfig
}

type browserFlow struct {
	Origin    string `json:"origin"`
	State     string `json:"state"`
	Verifier  string `json:"verifier"`
	Nonce     string `json:"nonce"`
	Operation string `json:"operation"`
}

type browserSession struct {
	Origin  string    `json:"origin"`
	Person  Person    `json:"person"`
	Token   string    `json:"token"`
	CSRF    string    `json:"csrf"`
	Expires time.Time `json:"expires"`
}

func NewBrowser(service *Service, configuration BrowserConfig) (*Browser, error) {
	if configuration.ClientID == "" || configuration.ClientSecret == "" || configuration.KubernetesAudience == "" || configuration.ValkeyURL == "" {
		return nil, errInvalid
	}
	sealer, err := security.NewEncryptor(configuration.EncryptionKey)
	if err != nil || !sealer.IsEnabled() {
		return nil, errInvalid
	}
	options, err := valkey.ParseURL(configuration.ValkeyURL)
	if err != nil {
		return nil, errInvalid
	}
	options.DisableCache = true
	cache, err := valkey.NewClient(options)
	if err != nil {
		return nil, fmt.Errorf("initialize browser session cache: %w", err)
	}
	browser := &Browser{service: service, configuration: configuration, cache: cache, sealer: sealer, providers: map[string]providers.JWKSProvider{}, jwks: oidc.NewJWKSClientWithOptions(oidc.JWKSClientOptions{AllowPrivateIP: true, RootCAs: configuration.RootCAs})}
	for _, origin := range []string{service.configuration.Origin, service.configuration.PortalOrigin} {
		if origin == "" {
			continue
		}
		provider, err := dex.NewProvider(&dex.Config{IssuerURL: configuration.Issuer, ClientID: configuration.ClientID, ClientSecret: configuration.ClientSecret, RedirectURL: origin + browserPrefix + "/callback", Scopes: []string{"openid", "profile", "email", "groups", "audience:server:client_id:" + configuration.KubernetesAudience}, RootCAs: configuration.RootCAs})
		if err != nil {
			cache.Close()
			return nil, fmt.Errorf("initialize browser identity provider: %w", err)
		}
		browser.providers[origin] = provider
	}
	return browser, nil
}

func (b *Browser) Close() { b.cache.Close() }

func randomToken() string {
	var raw [32]byte
	_, _ = rand.Read(raw[:])
	return base64.RawURLEncoding.EncodeToString(raw[:])
}

func cookie(writer http.ResponseWriter, name, value string, seconds int) {
	http.SetCookie(writer, &http.Cookie{Name: name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: seconds})
}

func cacheKey(kind, origin, value string) string {
	return "credential-api:" + kind + ":" + digest([]string{origin, value})
}

func (b *Browser) keep(ctx context.Context, key string, value any, ttl time.Duration) error {
	body, err := json.Marshal(value)
	if err != nil {
		return errUnavailable
	}
	encrypted, err := b.sealer.Encrypt(string(body))
	if err != nil {
		return errUnavailable
	}
	if b.cache.Do(ctx, b.cache.B().Set().Key(key).Value(encrypted).ExSeconds(int64(ttl/time.Second)).Build()).Error() != nil {
		return errUnavailable
	}
	return nil
}

func (b *Browser) load(ctx context.Context, key string, value any, consume bool) error {
	var encrypted string
	var err error
	if consume {
		encrypted, err = b.cache.Do(ctx, b.cache.B().Getdel().Key(key).Build()).ToString()
	} else {
		encrypted, err = b.cache.Do(ctx, b.cache.B().Get().Key(key).Build()).ToString()
	}
	if err != nil {
		return errOwner
	}
	body, err := b.sealer.Decrypt(encrypted)
	if err != nil || json.Unmarshal([]byte(body), value) != nil {
		return errOwner
	}
	return nil
}

func (b *Browser) session(request *http.Request, origin string) (*browserSession, error) {
	sessionCookie, err := request.Cookie(sessionCookie)
	if err != nil || len(sessionCookie.Value) > 128 {
		return nil, errOwner
	}
	var session browserSession
	if b.load(request.Context(), cacheKey("session", origin, sessionCookie.Value), &session, false) != nil || session.Origin != origin || session.Person.Issuer != b.configuration.Issuer || !time.Now().Before(session.Expires) || session.Token == "" {
		return nil, errOwner
	}
	return &session, nil
}

func (b *Browser) signIn(writer http.ResponseWriter, request *http.Request, origin string) {
	operation := request.URL.Query().Get("operation")
	if len(operation) != 48 {
		respondError(writer, errInvalid)
		return
	}
	flow := browserFlow{Origin: origin, State: randomToken(), Verifier: oauth2.GenerateVerifier(), Nonce: randomToken(), Operation: operation}
	key := randomToken()
	if b.keep(request.Context(), cacheKey("flow", origin, key), flow, 5*time.Minute) != nil {
		respondError(writer, errUnavailable)
		return
	}
	cookie(writer, flowCookie, key, 300)
	location := b.providers[origin].AuthorizationURL(flow.State, oauth2.S256ChallengeFromVerifier(flow.Verifier), "S256", nil, &providers.AuthorizationURLOptions{Nonce: flow.Nonce})
	http.Redirect(writer, request, location, http.StatusFound)
}

func (b *Browser) callback(writer http.ResponseWriter, request *http.Request, origin string) {
	flowBinding, err := request.Cookie(flowCookie)
	if err != nil || len(flowBinding.Value) > 128 {
		respondError(writer, errOwner)
		return
	}
	var flow browserFlow
	if b.load(request.Context(), cacheKey("flow", origin, flowBinding.Value), &flow, true) != nil || flow.Origin != origin || subtle.ConstantTimeCompare([]byte(flow.State), []byte(request.URL.Query().Get("state"))) != 1 || request.URL.Query().Get("code") == "" || request.URL.Query().Has("error") {
		respondError(writer, errOwner)
		return
	}
	cookie(writer, flowCookie, "", -1)
	provider := b.providers[origin]
	token, err := provider.ExchangeCode(request.Context(), request.URL.Query().Get("code"), flow.Verifier)
	if err != nil {
		respondError(writer, errOwner)
		return
	}
	idToken, _ := token.Extra("id_token").(string)
	uri, err := provider.JWKSURI(request.Context())
	if err != nil {
		respondError(writer, errOwner)
		return
	}
	claims, err := oidc.ValidateIDToken(request.Context(), idToken, b.jwks, uri, provider.IssuerURL(), []string{b.configuration.ClientID, b.configuration.KubernetesAudience})
	if err != nil || claims.Subject == "" || claims.Act != nil || oidc.ValidateNonceClaim(claims.Nonce, flow.Nonce) != nil || !slices.Contains([]string(claims.Audience), b.configuration.KubernetesAudience) || (claims.AuthorizedParty != "" && claims.AuthorizedParty != b.configuration.ClientID) || (claims.AuthorizedParty == "" && !slices.Contains([]string(claims.Audience), b.configuration.ClientID)) {
		respondError(writer, errOwner)
		return
	}
	expires := time.Now().Add(lifetime)
	if claims.Expiry.Time().Before(expires) {
		expires = claims.Expiry.Time()
	}
	if !time.Now().Add(time.Second).Before(expires) {
		respondError(writer, errOwner)
		return
	}
	session := browserSession{Origin: origin, Person: Person{Issuer: claims.Issuer, Subject: claims.Subject}, Token: idToken, CSRF: randomToken(), Expires: expires}
	if _, err := b.service.owned(request.Context(), session.Person, flow.Operation); err != nil {
		respondError(writer, err)
		return
	}
	key := randomToken()
	if b.keep(request.Context(), cacheKey("session", origin, key), session, time.Until(expires)) != nil {
		respondError(writer, errUnavailable)
		return
	}
	cookie(writer, sessionCookie, key, int(time.Until(expires)/time.Second))
	http.Redirect(writer, request, origin+"/credentials/"+flow.Operation, http.StatusSeeOther)
}

func (b *Browser) origin(request *http.Request) (string, bool) {
	for origin := range b.providers {
		parsed, _ := url.Parse(origin)
		if request.Host == parsed.Host {
			return origin, true
		}
	}
	return "", false
}

func validWrite(request *http.Request, session *browserSession, origin string) bool {
	return request.Header.Get("Origin") == origin && subtle.ConstantTimeCompare([]byte(request.Header.Get("X-CSRF-Token")), []byte(session.CSRF)) == 1 && session.CSRF != "" && (request.Header.Get("Sec-Fetch-Site") == "" || request.Header.Get("Sec-Fetch-Site") == "same-origin")
}

func jsonContent(request *http.Request) bool {
	return strings.Split(request.Header.Get("Content-Type"), ";")[0] == "application/json"
}
