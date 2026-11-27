package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/giantswarm/mcp-oauth/security"
	"k8s.io/client-go/rest"

	"github.com/giantswarm/credential-api/internal/credential"
)

type configuration struct {
	Service            credential.Config `json:"service"`
	Issuer             string            `json:"issuer"`
	ClientID           string            `json:"clientId"`
	KubernetesAudience string            `json:"kubernetesAudience"`
	CleanupInterval    string            `json:"cleanupInterval"`
	IssuerCAFile       string            `json:"issuerCaFile"`
}

func main() {
	configurationFile := flag.String("config", "/etc/credential-api/config.json", "Service configuration file")
	secretDirectory := flag.String("secret-directory", "/etc/credential-api/secrets", "OAuth and session secret directory")
	address := flag.String("listen", ":8080", "HTTP listen address")
	flag.Parse()
	if err := run(*configurationFile, *secretDirectory, *address); err != nil {
		slog.Error("credential service stopped")
		os.Exit(1)
	}
}

func run(configurationFile, secretDirectory, address string) error {
	body, err := readRuntimeFile(configurationFile)
	if err != nil {
		return err
	}
	var configuration configuration
	if err := json.Unmarshal(body, &configuration); err != nil {
		return err
	}
	clientSecret, err := readRuntimeFile(filepath.Join(secretDirectory, "client-secret"))
	if err != nil {
		return err
	}
	sessionKey, err := readRuntimeFile(filepath.Join(secretDirectory, "session-key"))
	if err != nil {
		return err
	}
	key, err := security.DecodeKey(strings.TrimSpace(string(sessionKey)))
	if err != nil {
		return err
	}
	valkeyURL, err := readRuntimeFile(filepath.Join(secretDirectory, "valkey-url"))
	if err != nil {
		return err
	}
	interval, err := time.ParseDuration(configuration.CleanupInterval)
	if err != nil || interval < time.Second || interval > time.Minute {
		return errors.New("cleanup interval must be between one second and one minute")
	}
	base, err := rest.InClusterConfig()
	if err != nil {
		return err
	}
	service, err := credential.New(configuration.Service, base)
	if err != nil {
		return err
	}
	var roots *x509.CertPool
	if configuration.IssuerCAFile != "" {
		certificate, err := readRuntimeFile(configuration.IssuerCAFile)
		if err != nil {
			return err
		}
		roots, err = x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(certificate) {
			return errors.New("identity provider CA is invalid")
		}
	}
	browser, err := credential.NewBrowser(service, credential.BrowserConfig{Issuer: configuration.Issuer, ClientID: configuration.ClientID, ClientSecret: strings.TrimSpace(string(clientSecret)), KubernetesAudience: configuration.KubernetesAudience, ValkeyURL: strings.TrimSpace(string(valkeyURL)), EncryptionKey: key, RootCAs: roots})
	if err != nil {
		return err
	}
	defer browser.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	go service.Expire(ctx, interval)
	server := &http.Server{Addr: address, Handler: browser.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 32 * 1024}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	err = server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func readRuntimeFile(name string) ([]byte, error) {
	root, err := os.OpenRoot(filepath.Dir(name))
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return root.ReadFile(filepath.Base(name))
}
