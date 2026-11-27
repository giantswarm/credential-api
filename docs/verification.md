# Delivery and verification

This implements the apply-mode service for giantswarm/giantswarm#39473. It does not migrate a consumer, implement commit-mode encryption, merge a pull request or deploy an installation.

## Dependency order

1. [devctl draft declarations](https://github.com/giantswarm/devctl/pull/3789) add the draft option used to prepare repository provisioning. Its local command and repository API tests pass, as do its pre-commit checks.
2. [Repository provisioning](https://github.com/giantswarm/github/pull/7386) declared the Bumblebee-owned public Go service and Helm chart. Its merged declaration created this repository from `giantswarm/template` and `giantswarm/template-app`.
3. Manager authorization uses the pinned `client-go` SubjectAccessReview client directly, preserving the TokenReview subject's username, UID, groups and extra attributes. Errors, evaluation errors, denials and contradictory decisions fail closed. Published `mcp-toolkit/k8s v0.1.1` supplies person-scoped clients and self-access reviews; no unreleased helper or local workspace override is required.
4. The service's intended implementation release is 0.2.0; provisioning's initial 0.1.0 scaffold is not a credential service release.
5. The [agent-platform integration](https://github.com/giantswarm/agent-platform/pull/1519) is disabled by default, using its existing `UNRELEASED` gate for credential-api 0.2.0. Consumers retain their current credential flows. Model credentials belong directly to model-manager in their migration; giantswarm/giantswarm#39475 still contains conflicting agent-manager ownership wording.

## Protocol evidence

The Go suite starts a real Kubernetes 1.37.0 API server and etcd through controller-runtime envtest, with RBAC, OIDC authentication and a credential admission policy. A TLS identity-provider fixture signs actual OIDC tokens and enforces S256 PKCE. Browser sessions use the production encrypted Valkey code against a protocol-compatible test store. Chromium driven by Playwright 1.63.0 drives both real HTTPS entry points, including text, file and multiple-field submission. No installation is deployed.

The checks cover authenticated and unlisted managers, incorrect token audience, foreign prefixes, cross-manager status, required organization context, delegated initiation metadata, both browser origins, ownership and another identity, editor refusal and an admin's own operation. They verify CSRF and origin rejection, expiry, cancellation, stale confirmations, concurrent saves, version-pinned replacements, interrupted Secret replies, audit failure recovery and reservation limits shared across replicas. An uncertain write cannot become an unconditional overwrite.

Synthetic sentinel values are checked against manager responses, operation metadata, audit records, encrypted session data, browser URLs, local and session storage, console output and network requests. Only the direct credential submission carries a value. Kubernetes credential transports issue no get, list, watch or patch on Secrets. The rendered service chart is validated with actual API-server dry-run requests, using an explicitly named render context.

Run the suite against the published dependencies:

```bash
GOWORK=off GOFLAGS=-p=2 \
KUBEBUILDER_ASSETS=/path/to/kubernetes-1.37.0-assets \
CREDENTIAL_API_PLAYWRIGHT=/path/to/playwright-core/index.mjs \
go test -race -count=1 -v ./...
```

The service includes the standard devctl-generated Go, Helm, release and CircleCI configuration plus a protocol workflow with pinned tools and actions. `pre-commit run --all-files` runs Go lint, schema and chart documentation checks. The service image, chart, SBOM, signatures and vulnerability results must be published and verified before enabling the component. Start giantswarm/giantswarm#39474 in a fresh session after those artifacts are available.
