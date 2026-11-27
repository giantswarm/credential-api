# credential-api

Person-bound credential submission and write-only Secret provisioning

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| image.registry | string | `"gsoci.azurecr.io"` |  |
| image.repository | string | `"giantswarm/credential-api"` |  |
| image.tag | string | `"0.2.0"` |  |
| replicas | int | `2` |  |
| installation | string | `""` |  |
| credentialOrigin | string | `""` |  |
| portalOrigin | string | `""` |  |
| audience | string | `"credential-api"` |  |
| tenancy | bool | `true` |  |
| platformNamespace | string | `"kagent"` |  |
| managers | object | `{}` |  |
| operationCapacity | int | `256` |  |
| cleanupInterval | string | `"1m"` |  |
| oauth.issuer | string | `""` |  |
| oauth.clientId | string | `"credential-api"` |  |
| oauth.kubernetesAudience | string | `"dex-k8s-authenticator"` |  |
| oauth.caSecretName | string | `""` |  |
| existingSecret | string | `"credential-api"` |  |
| serviceAccount.name | string | `"credential-api"` |  |
| ingress.enabled | bool | `false` |  |
| ingress.className | string | `"nginx"` |  |
| ingress.tlsSecretName | string | `""` |  |
| ingress.portalTlsSecretName | string | `""` |  |
| gatewayAPI.enabled | bool | `false` |  |
| gatewayAPI.parentRefs | list | `[]` |  |
| resources.requests.cpu | string | `"50m"` |  |
| resources.requests.memory | string | `"128Mi"` |  |
| resources.limits.memory | string | `"256Mi"` |  |
