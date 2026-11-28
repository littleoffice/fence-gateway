# Logging and metrics

## Contents

- [Audit log](#audit-log)
- [Metrics](#metrics)

## Audit log

Every verification outcome is logged with the tool name and the caller identity:
each verified fence, each rejection with a short excerpt of its text, each layout
problem, unfenced block, oversized result, and policy decision. The excerpts are
attacker-controlled text, so they go only to the log, never to the model.

| Event | Meaning |
|---|---|
| `fence.verified`, `fence.ok` | a fence verified; a result passed |
| `fence.rejected` | a fence that claimed a signature failed; **alert on this** |
| `fence.layout` | a layout or downgrade failure |
| `fence.unfenced_block`, `fence.unsigned_text` | unsigned text |
| `fence.unverified_error` | an unfenced error result was admitted, shortened and labelled |
| `fence.unfenced_error` | unfenced error text beside a format 1.1 fence was refused |
| `fence.too_large` | the result was over the size limit |
| `fence.policy.reject` | the policy withheld a result |
| `fence.verify.nokey`, `fence.key.unavailable` | no usable key |
| `fence.key.loaded`, `fence.key.rotated`, `fence.key.unpinned` | key trust |
| `upstream.plaintext` | the relay is reached over plain HTTP because `-insecure-upstream` is set |
| `fence.version.mismatch` | the relay reports an older format than `-fence-version` requires |
| `upstream.session.lost` | the relay dropped the gateway's session, and it was replaced |
| `relay.confirm.forwarded` | the relay asked the user to confirm a fetch, and the question was passed on |
| `relay.confirm.refused` | the relay's question was not passed on: `cannot_ask` (the client has no elicitation), `unsupported_request` (not a bounded yes/no form) or `load_shedding` |
| `relay.confirm.mismatch` | an answer arrived for a call other than the one asked about |
| `gate.tainted` | a conversation read outside content, so gated tools now ask first |
| `gate.blocked`, `gate.declined`, `gate.confirmed`, `gate.confirmation_mismatch` | what the tool gate did with a call of another server's tool |
| `tools.server.connected`, `tools.server.synced`, `tools.registered`, `tools.server.error` | the servers from `-tools-config` |
| `proxy.tools.synced`, `proxy.tools.collision`, `proxy.tools.resync_failed` | the relay's tool list as the gateway mirrors it |

The rules behind each event: [enforcement profile §7](specification.md#7-audit).

## Metrics

HTTP mode only. The gateway serves its own Prometheus text at `GET /metrics/gateway`,
and the relay's at `GET /metrics/relay`. Both sit behind `MCP_METRICS_TOKEN`, a
credential of their own: the relay's page names the hosts fetched for every caller,
and a scraper is not a tenant. With the token unset, both endpoints answer 401 to
everyone, the same closed default the relay takes. `GET /metrics` answers 404 and
names the two paths.

Forwarding the relay's metrics lets the relay stay reachable from the gateway alone
([Deployment](deployment.md)): Prometheus scrapes two paths on the gateway and needs
no network path to the relay. They are separate paths, not one merged page, so each
Prometheus job reports its own `up`, and a relay that is down does not take the
gateway's series with it. Configuration: [Metrics variables](configuration.md#metrics).

| Series | Type | Labels | Meaning |
|---|---|---|---|
| `fence_gateway_build_info` | gauge | `version` | Build version of the running gateway; always 1 |
| `fence_gateway_tool_calls_total` | counter | `outcome` | Tool calls, by what happened to the result |
| `fence_gateway_verification_failures_total` | counter | `reason` | Results that failed verification, by reason; a result failing for several reasons counts under each |
| `fence_gateway_fences_verified_total` | counter | | Individual fences whose signature verified |
| `fence_gateway_key_rotations_total` | counter | | Changes of the relay's signing key seen by the gateway |
| `fence_gateway_upstream_sessions_lost_total` | counter | | Relay sessions found gone and replaced |
| `fence_gateway_auth_failures_total` | counter | `endpoint` | HTTP requests refused with 401 (`mcp`, `metrics`) |
| `fence_gateway_auth_throttled_total` | counter | | MCP requests refused with 429 after too many failed logins |
| `fence_gateway_relay_metrics_errors_total` | counter | | Failed fetches of the relay's `/metrics` |
| `fence_gateway_upstream_call_duration_seconds` | histogram | | Duration of tool calls to the relay and to `-tools-config` servers, including failed ones |
| `fence_gateway_tool_gate_total` | counter | `decision` | Calls to other servers' tools, by what the tool gate did |

Every label set is closed: values come from a fixed list in the code, never from a
request or a tool result.

| Label | Values |
|---|---|
| `outcome` | `verified`, `unfenced`, `rejected`, `annotated`, `passed_unverified`, `blocked`, `upstream_error`, `forwarded` (another server's tool ran), `asked` (a question went to the user) |
| `decision` | `allowed`, `confirmed`, `declined`, `blocked` |
| `reason` | `no_key`, `too_large`, `unsupported_content`, `invalid_fence`, `no_fence`, `unfenced_text`, `unsigned_text`, `layout`, `format` |
