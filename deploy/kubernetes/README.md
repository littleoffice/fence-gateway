# Kubernetes deployment

Manifests to run `fence-gateway` as the verifying front door to
`mcp-searxng-relay` inside a cluster. The gateway is the only component clients
connect to; it forwards to the relay over the cluster network and verifies every
tool result before it reaches a model.

```
external MCP client ──▶ Ingress (TLS) ──▶ fence-gateway (Service) ──▶ mcp-searxng-relay (ClusterIP) ──▶ SearXNG
                                           verifies fences here
```

## Files

| File | Purpose |
|---|---|
| `deployment.yaml` | The gateway Deployment (non-root, read-only rootfs, dropped caps). |
| `service.yaml` | ClusterIP Service on port 8080. |
| `secret.example.yaml` | Template for client tokens + the upstream relay token. **Copy, fill, apply out-of-band.** |
| `ingress.example.yaml` | Optional TLS-terminating Ingress (cert-manager). **Cluster-specific; not in kustomize.** |
| `kustomization.yaml` | Bundles `deployment.yaml` + `service.yaml`. |

## Same namespace as the relay

The gateway reaches the relay by its in-cluster Service DNS. If both run in the
same namespace, the default `-upstream http://mcp-searxng:8080/mcp` in
`deployment.yaml` already works. Across namespaces, use the fully-qualified name:

```
-upstream http://mcp-searxng.<relay-namespace>.svc.cluster.local:8080/mcp
```

The fence public key is fetched from the same origin
(`…/fence/public-key`), so no separate wiring is needed. Nothing *requires*
co-location, but keeping the gateway↔relay hop on the internal network is where
the bearer token and the key fetch travel, so it is the recommended shape.

## Deploy

```bash
# 1. Create the auth Secret out-of-band (never commit real tokens).
cp secret.example.yaml secret.yaml
#    edit secret.yaml: client tokens (openssl rand -hex 32) + the relay's token
kubectl apply -f secret.yaml

# 2. Apply the Deployment + Service.
kubectl apply -k .

# 3. (optional) Expose it with TLS.
cp ingress.example.yaml ingress.yaml   # edit host / issuer / class
kubectl apply -f ingress.yaml
```

Point your MCP client at the gateway's URL (the Ingress host, or the Service
from inside the cluster) instead of the relay's.

## Notes

- **Auth is mandatory.** HTTP mode refuses to start with no credentials. Provide
  static tokens (the Secret), OAuth (`MCP_OAUTH_*`, see the repo README), or
  both.
- **TLS.** Terminate at the Ingress (recommended) or serve HTTPS in-pod by
  mounting a cert Secret and uncommenting the `MCP_TLS_*` block in
  `deployment.yaml`.
- **Pinning.** `-pin` detects a substituted relay but requires the relay to run
  a persistent fence signing key; otherwise it rotates per restart and the pin
  must change with it. It is left off by default (rotation-tolerant). See the
  repo README, "Ephemeral keys bound what verification proves".
- **Probes** are TCP because the gateway exposes no `/health` endpoint yet
  (planned). Switch the readiness probe to an `httpGet` on `/health` once that
  lands.
