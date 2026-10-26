# Architecture

How the gateway is put together, and what happens on one tool call.

## Contents

- [Components](#components)
- [How the proxy is wired](#how-the-proxy-is-wired)
- [One tool call](#one-tool-call)
- [Transports](#transports)

## Components

| | |
|---|---|
| `fenceverify` | Package: parsing, canonicalisation, signature verification, key acquisition. No I/O in the hot path. |
| `fence-gateway` (module root, `package main`) | MCP proxy. Verifies tool results in transit and enforces a policy. This is the binary the `Dockerfile` builds. |
| `interop` | Interop test package: verifies output from the relay's unmodified `fence.go`. See [Testing](testing.md). |

A standalone `fence-verify` CLI (read a fenced payload on stdin, exit 0/1/2, for
CI gates and incident triage) is described in the paper's tooling and is a
natural next addition on top of the `fenceverify` package, but is not yet
implemented in this repository.

## How the proxy is wired

The transport is delegated to the [MCP go-sdk](https://github.com/modelcontextprotocol/go-sdk)
— the same SDK the relay uses. The gateway is an **MCP server** to the
downstream client and an **MCP client** to the upstream relay, bridging the two
with fence verification injected on the return path. Verification itself
(`fenceverify`) is transport-agnostic and depends only on the standard library.

```mermaid
flowchart LR
    C["MCP client<br/>(Claude Desktop / Code / Cursor)"]

    subgraph GW["fence-gateway (one process)"]
        direction TB
        SRV["downstream MCP server<br/>(go-sdk)"]
        VER["verify()<br/>fenceverify: Ed25519,<br/>canonicalise, policy"]
        CL["upstream MCP client<br/>(go-sdk)"]
        KEYS["EndpointKeys<br/>pinning · rotation"]
        SRV --> VER --> CL
        KEYS -. supplies trusted keys .-> VER
    end

    subgraph R["mcp-searxng-relay"]
        RMCP["MCP server /mcp"]
        RKEY["/fence/public-key"]
    end

    C <-->|"MCP over stdio / Streamable HTTP"| SRV
    CL <-->|"MCP over Streamable HTTP<br/>(bearer token)"| RMCP
    KEYS -->|"HTTPS GET — not MCP"| RKEY
    RMCP --> WEB["SearXNG / web"]
```

The return-path check is the whole point (§7.4.3): the model cannot be its own
security verifier, so a component in the transport does the deterministic
signature check before any bytes reach the model.

## One tool call

```mermaid
sequenceDiagram
    autonumber
    participant C as MCP client
    participant G as fence-gateway
    participant R as relay MCP
    participant K as relay key endpoint

    Note over G: startup
    G->>K: GET /fence/public-key
    K-->>G: Ed25519 public key + fingerprint
    G->>R: initialize
    R-->>G: capabilities
    G->>R: tools/list
    R-->>G: tools
    Note over G: register a verifying proxy handler per tool

    Note over C,G: per tool call
    C->>G: tools/call
    G->>R: tools/call (raw args forwarded)
    R-->>G: result containing a signed fence

    alt signature valid
        G-->>C: result, optionally with signature stripped
    else verification fails, policy reject
        G-->>C: isError, content withheld, reason to audit log
    else key looks rotated
        G->>K: refetch key, verify once more
        K-->>G: current key
        G-->>C: result, or isError if it still fails
    end
```

What counts as "verification fails" is in [Verification](verification.md).

## Transports

The diagrams show the proxy's wiring. The client↔gateway leg runs over one of
two transports, sharing the same verifying proxy core:

- **stdio** (default) — a local subprocess of the MCP client. This is the
  per-workstation shape.
- **Streamable HTTP** (`MCP_PORT` set) — a network server, so one gateway can
  sit in front of the relay for a whole fleet instead of being installed on
  every workstation. Bearer or OAuth authentication and CSRF protection sit in
  front of the downstream server.

Configuration splits cleanly: **verification behaviour is set by flags**
(`-upstream`, `-policy`, `-pin`, `-max-age`, `-strip-signature`,
`-require-all-fenced`, `-fence-version`, `-paper-scheme`, `-tofu`, `-key-url`), and
**deployment is set by environment variables** (mirroring the relay's names).
The tokens clients present *to the gateway* in HTTP mode are the
`MCP_AUTH_TOKEN*` family. What the gateway presents *to the relay* depends on
`UPSTREAM_MCP_AUTH_MODE`: each caller's own credential, forwarded, an exchanged
token, or the gateway's `UPSTREAM_MCP_TOKEN` for everyone. Which one you want is
not a detail — see
[Which credential reaches the relay](configuration.md#which-credential-reaches-the-relay).
