# Deploying fence-gateway

The gateway is a verifying proxy that sits **in front of** `mcp-searxng-relay`:
clients connect to the gateway, it forwards to the relay over the internal
network, and it cryptographically verifies every tool result before a model can
see it. It is designed to run in the **same namespace / network as the relay**,
so the gateway↔relay hop (which carries the bearer token and the fence
public-key fetch) stays internal.

```
client ──▶ fence-gateway ──▶ mcp-searxng-relay ──▶ SearXNG / web
            verify · policy · audit
```

Two ready-to-adapt layouts:

- [`kubernetes/`](kubernetes/) — Deployment, Service, example Secret and
  Ingress, and a kustomization. Point `-upstream` at the relay's in-cluster
  Service.
- [`podman/`](podman/) — a Compose service that joins the relay stack's network
  and reaches it by container name.

Both mirror the relay's hardening (non-root, read-only rootfs, dropped
capabilities) and expect **auth** (static bearer tokens or OAuth/OIDC) and
**TLS** (at an Ingress/proxy, or in-pod) in front of the network endpoint — see
each subdirectory's README and the repo README's "Running remotely" section.

For a reproducible local build/push of the image, see [`build.sh`](../build.sh)
at the repo root; released images are published to GHCR by the release workflow
on a `v*` tag.
