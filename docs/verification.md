# Delivery and verification

This implements the apply-mode service for giantswarm/giantswarm#39473. It does not migrate a consumer, implement commit-mode encryption, merge a pull request or deploy an installation.

## Dependency order

1. [devctl draft declarations](https://github.com/giantswarm/devctl/pull/3789) add the draft option used to prepare repository provisioning. Its local command and repository API tests pass, as do its pre-commit checks.
2. [Repository provisioning](https://github.com/giantswarm/github/pull/7386) declares a Bumblebee-owned public Go service and Helm chart. The accepted dry run used `giantswarm/template` and `giantswarm/template-app`. The PR stays draft with no auto-merge request. Its workflow skips automatic approval and auto-merge for draft declarations.
3. [Named-subject authorization](https://github.com/giantswarm/mcp-toolkit/pull/184) adds `k8s.ReviewSubjectAccess`, with real API-server RBAC tests. Its published release is required before service adoption. The committed service module still pins published `k8s v0.1.1`; local verification uses an ignored Go workspace with that PR's checkout. Update the pin only after the containing release is available.
4. The service implementation needs a draft PR after the repository exists. The current provisioning workflow creates it only after its declaration merges. This task authorizes no merge, so the implementation is retained in this isolated worktree. Its intended implementation release is 0.2.0; provisioning's initial 0.1.0 scaffold is not a credential service release.
5. The agent-platform integration stays draft and disabled by default, using its existing `UNRELEASED` gate for credential-api 0.2.0. Consumers retain their current credential flows. Model credentials belong directly to model-manager in their migration; giantswarm/giantswarm#39475 still contains conflicting agent-manager ownership wording.

## Protocol evidence

The Go suite starts a real Kubernetes 1.37.0 API server and etcd through controller-runtime envtest, with RBAC, OIDC authentication and a credential admission policy. A TLS identity-provider fixture signs actual OIDC tokens and enforces S256 PKCE. Browser sessions use the production encrypted Valkey code against a protocol-compatible test store. Chromium driven by Playwright 1.63.0 drives both real HTTPS entry points, including text, file and multiple-field submission. No installation is deployed.

The checks cover authenticated and unlisted managers, incorrect token audience, foreign prefixes, cross-manager status, required organization context, delegated initiation metadata, both browser origins, ownership and another identity, editor refusal and an admin's own operation. They verify CSRF and origin rejection, expiry, cancellation, stale confirmations, concurrent saves, version-pinned replacements, interrupted Secret replies, audit failure recovery and reservation limits shared across replicas. An uncertain write cannot become an unconditional overwrite.

Synthetic sentinel values are checked against manager responses, operation metadata, audit records, encrypted session data, browser URLs, local and session storage, console output and network requests. Only the direct credential submission carries a value. Kubernetes credential transports issue no get, list, watch or patch on Secrets. The rendered service chart is validated with actual API-server dry-run requests, using an explicitly named render context.

Run the suite from a local workspace containing the shared-library change:

```bash
GOFLAGS=-p=2 \
KUBEBUILDER_ASSETS=/path/to/kubernetes-1.37.0-assets \
CREDENTIAL_API_PLAYWRIGHT=/path/to/playwright-core/index.mjs \
go test -race -count=1 -v ./...
```

The service includes the standard devctl-generated Go, Helm, release and CircleCI configuration plus a protocol workflow with pinned tools and actions. `pre-commit run --all-files` runs Go lint, schema and chart documentation checks. The service image, chart, SBOM, signatures and vulnerability results are not published or verified because repository provisioning and dependency releases remain pending. Standard release artifacts and their supply-chain evidence must be verified before enabling the component. Start giantswarm/giantswarm#39474 in a fresh session after those dependencies are available.
