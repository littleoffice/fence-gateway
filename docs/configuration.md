# Configuration

**Verification behaviour is set by command-line flags; deployment is set by
environment variables**, mirroring the relay's names. Flags go after the
entrypoint when running the container.

## Contents

- [Flags](#flags)
- [HTTP mode](#http-mode)
- [OAuth 2.0 / OIDC](#oauth-20--oidc)
- [Credentials for the relay](#credentials-for-the-relay)
- [Which credential reaches the relay](#which-credential-reaches-the-relay)
- [Stateless mode and upstream sessions](#stateless-mode-and-upstream-sessions)
- [Metrics](#metrics)

## Flags

| Flag | Default | Purpose |
|---|---|---|
| `-upstream` | `http://127.0.0.1:8080/mcp` | The relay's MCP endpoint. |
| `-key-url` | upstream origin + `/fence/public-key` | Where to fetch the relay's fence public key. |
| `-policy` | `reject` | What a verification failure leads to: `reject`, `annotate` or `audit`. See [Policies](verification.md#policies). |
| `-pin` | none | The relay's key fingerprint (16 hex characters, from its startup banner). See [Key trust](verification.md#key-trust). |
| `-tofu` | off | Pin the first key seen and refuse later changes, until the gateway restarts. Not a substitute for `-pin`. |
| `-fence-version` | `auto` | Oldest fence format accepted: `auto` (follow the relay's key endpoint), `1.0`, or `1.1`. See [Format versions](verification.md#format-versions). |
| `-max-age` | `10m` | Refuse fences older than this; `0` turns the age check off. See [Freshness](verification.md#freshness). |
| `-require-all-fenced` | off | Treat any unsigned text in a tool result as a failure, including the relay's unfenced no-results reply and error messages. |
| `-strip-signature` | off | Remove `signature` attributes from verified fences before forwarding. The nonce is kept, since the preamble names it. |
| `-paper-scheme` | off | Verify with the paper's literal `Ed25519(SHA-256(C ‖ M))` construction instead of the relay's. See [Design notes](design-notes.md#signature-construction). |
| `-token` | `$UPSTREAM_MCP_TOKEN` | The gateway's own credential for the relay. Prefer the environment variable: on the command line it shows in the process list and shell history, and the gateway warns. |
| `-version` | | Print the version and exit. |

## HTTP mode

Set `MCP_PORT` to serve the Streamable HTTP transport; clients then point at the
gateway's URL instead of the relay's. Authentication is **mandatory** in this
mode (the endpoint is network-reachable) — a static bearer token, an OAuth 2.0 /
OIDC provider, or both — and cross-origin (CSRF) and DNS-rebinding protections
are on by default.

| Variable | Purpose |
|---|---|
| `MCP_PORT` | Serve HTTP on this port (unset ⇒ stdio). |
| `MCP_AUTH_TOKEN` | Single bearer token clients must present to the gateway. |
| `MCP_AUTH_TOKENS` | Comma-separated `identity:token` pairs (a small fleet). |
| `MCP_AUTH_TOKEN_FILE` | File of tokens, one `identity:token` per line (`#` comments allowed). |
| `MCP_TLS_CERT` / `MCP_TLS_KEY` | Serve HTTPS directly (both or neither). Omit to terminate TLS at a reverse proxy. |
| `MCP_STATELESS` | No session-ID issuance, so replicas need no sticky routing. Must match the relay's setting — see [below](#stateless-mode-and-upstream-sessions). |
| `MCP_TRUST_FORWARDED_HEADERS` | Honour `X-Forwarded-For` for the login throttle, and `X-Forwarded-Proto`/`-Host` when building the OAuth metadata URL. Off by default. |

Static tokens must be ≥32 characters (`openssl rand -hex 32`).

`GET /health` answers `ok` without a credential, for liveness and readiness
probes; it says nothing else. A client session left idle for an hour is closed.
A client address with 30 failed logins in a minute is refused (429) until the
minute is up — counted per `X-Forwarded-For` client with
`MCP_TRUST_FORWARDED_HEADERS`, otherwise per connection address, so behind a
proxy without that setting all clients share one budget.

## OAuth 2.0 / OIDC

Optional, an alternative or addition to static tokens. The gateway acts as a
Resource Server — it verifies a presented JWT's signature and claims, never issues
tokens. Only asymmetric algorithms are accepted (the RS256→HS256 key-confusion class
is rejected by construction), and it serves the RFC 9728 protected-resource metadata
a spec-compliant MCP client uses to discover the issuer.

| Variable | Purpose |
|---|---|
| `MCP_OAUTH_ISSUER` | OIDC issuer URL. Its discovery document and JWKS are fetched at startup and rotated automatically. Setting this enables OAuth. |
| `MCP_OAUTH_AUDIENCE` | The `aud` tokens must carry (this gateway's identifier). Required with an issuer. Use an identifier of its own, not a client ID: ID tokens carry their client ID as `aud`. The gateway refuses tokens marked as ID, refresh or logout tokens, but not every provider marks them. |
| `MCP_OAUTH_JWKS_FILE` | Use a static JWKS file (hot-reloaded on change) instead of issuer discovery — for air-gapped deployments. |
| `MCP_OAUTH_IDENTITY_CLAIM` | Token claim to use as the audit identity (default `sub`). |
| `MCP_OAUTH_REQUIRED_SCOPE` | Require this scope (`scope` string or `scp` array) in the token. |
| `MCP_OAUTH_CA_ROOTS` | PEM file of CA roots for reaching a private issuer whose TLS cert is not in the system store. |

## Credentials for the relay

| Variable | Purpose |
|---|---|
| `UPSTREAM_MCP_AUTH_MODE` | `static` (default), `passthrough` or `exchange` — which credential tool calls carry upstream. Required when more than one caller can reach the gateway. See [below](#which-credential-reaches-the-relay). |
| `UPSTREAM_MCP_TOKEN` | The gateway's own bootstrap credential for the relay. One per gateway, not one per caller. |
| `UPSTREAM_MCP_TOKEN_FILE` | The same credential read from a mounted file. Set one of the two, not both. |
| `UPSTREAM_OAUTH_TOKEN_URL` | `exchange` only: the identity provider's token endpoint (https). |
| `UPSTREAM_OAUTH_CLIENT_ID` / `UPSTREAM_OAUTH_CLIENT_SECRET` (or `_FILE`) | `exchange` only: the gateway's client at the provider, allowed to exchange tokens. |
| `UPSTREAM_OAUTH_AUDIENCE` | `exchange` only, optional: the relay's client ID, sent as `audience`. Keycloak needs it. |
| `UPSTREAM_OAUTH_DELEGATION` | `exchange` only, optional: also send the gateway's own token as `actor_token`, so the relay's token records the gateway acting for the user (`act`). Off by default. |

## Which credential reaches the relay

The relay derives caller identity *only* from the token it receives, and files
per-caller state under `identity | session` — its fetch history
(`searxng_session_sources`) and its rate-limit buckets both hang off that key.
A gateway that authenticates a client and then presents one credential of its
own for everybody collapses that key: two callers behind it share a history and
a rate limit, and the first can read the URLs the second fetched. `UPSTREAM_MCP_AUTH_MODE`
decides which of those two things happens.

| Value | Tool calls carry | Use when |
|---|---|---|
| `static` (default) | the gateway's own credential | one caller, or callers you are content to treat as one |
| `passthrough` | the calling client's own `Authorization`, forwarded verbatim | more than one caller shares the gateway, and the relay is reachable only from it |
| `exchange` | a token the identity provider issued to the relay for that caller (RFC 8693) | more than one caller, logging in with OAuth: the clean end state |

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="diagrams/relay-credential-modes-dark.svg">
  <img alt="Three modes. static: the relay sees only the gateway; callers' tokens do not work at the relay. passthrough: the relay sees each caller, but their tokens also work at the relay directly. exchange: the gateway swaps each caller's token for a relay token, so the relay sees each caller and their own tokens do not work there." src="diagrams/relay-credential-modes-light.svg">
</picture>

The dashed line is a caller trying to reach the relay directly with their own token.

Whatever the mode, **only the gateway may reach the relay**; in `passthrough` that is what
keeps callers from skipping it. [Deployment](deployment.md) shows how, for
Podman/Compose and for the `searxng-helm` chart.

**`exchange`** closes the gap `passthrough` leaves. In `passthrough` the token a caller
holds for the gateway also works at the relay, so a caller who can reach the relay can skip
the gateway and its checks. In `exchange` the gateway trades each caller's OAuth token at the
identity provider for a token issued to the relay for the same user, and presents that. The
caller's own token is only good at the gateway. The relay needs no change: point its
`MCP_OAUTH_ISSUER` and `MCP_OAUTH_AUDIENCE` at the provider and client that issue the
exchanged tokens. Callers must log in with OAuth; a static-token caller is refused. The gateway
authenticates its own housekeeping with a client-credentials token from the same client, or
with `UPSTREAM_MCP_TOKEN` when that is set. Setup for authentik and Keycloak is in
[Token exchange](token-exchange.md).

With more than one caller (several static tokens, or OAuth, where every subject is a
caller), the gateway refuses to start until `UPSTREAM_MCP_AUTH_MODE` is set. Sharing one
relay identity is then a choice you made, not a default you missed.

Pass-through needs HTTP mode (stdio has no downstream credential to forward)
and keeps the relay unchanged: the tokens in the relay's table are the same
values the clients already present to the gateway, so it resolves each caller
to its own identity exactly as it does without a gateway in the way. A call
that arrives with nothing to forward is refused rather than sent under the
gateway's credential — falling back would quietly restore the collapse.

`UPSTREAM_MCP_TOKEN` (or `UPSTREAM_MCP_TOKEN_FILE`, for orchestrators that
mount secrets rather than inject them) is then the **bootstrap credential**:
one per gateway, never one per caller. It authenticates `initialize` and
`tools/list` at startup — both happen before any client exists — and the
housekeeping the SDK does with no caller attached: ping and session
DELETE. No tool call uses it in pass-through mode. So a deployment with
N callers holds N + 1 secrets, not 2N.

Because pass-through forwards whatever header the client sent, a JWT rides
through untouched: point both the gateway and the relay at the same OIDC issuer
and identity flows end to end in `sub` with no shared secrets at all, provided
the token's `aud` satisfies both sides' `MCP_OAUTH_AUDIENCE`.

## Stateless mode and upstream sessions

`MCP_STATELESS` mirrors the relay's variable of the same name — no session-ID
issuance, every request its own ephemeral session, so replicas need no sticky
routing. **Set it the same on both.** A stateless gateway in front of a
stateful relay breaks the affinity chain in the middle, leaving the relay's
session state stranded on whichever replica answered first.

Against a stateful relay, the gateway replaces its upstream session whenever the relay
drops it: after a relay restart, or when the relay's janitor closes the session
(`MCP_SESSION_MAX_AGE`, seven days by default). The call that finds the session gone
reconnects under the gateway's own bootstrap credential and is retried once, so callers
do not see it. The audit log records `upstream.session.lost`.

## Metrics

HTTP mode only. Every variable here also takes a `_FILE` form, except the URL.

| Variable | Purpose |
|---|---|
| `MCP_METRICS_TOKEN` | Bearer token for `/metrics/gateway` and `/metrics/relay`. ≥32 characters, and not one of the MCP auth tokens. Unset, both endpoints answer 401 to everyone. |
| `UPSTREAM_METRICS_TOKEN` | The relay's own `MCP_METRICS_TOKEN`. Setting it turns on `/metrics/relay`. |
| `UPSTREAM_METRICS_URL` | Where to fetch the relay's metrics. Default: the upstream origin + `/metrics`. Needs `UPSTREAM_METRICS_TOKEN`. |

What the endpoints serve: [Logging and metrics](observability.md#metrics).
