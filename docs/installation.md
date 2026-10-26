# Installation

## Contents

- [Requirements](#requirements)
- [Building from source](#building-from-source)
- [Container](#container)
- [Using with Claude Desktop (stdio mode)](#using-with-claude-desktop-stdio-mode)
- [Building the container image](#building-the-container-image)
- [Deploying next to the relay](#deploying-next-to-the-relay)

## Requirements

- A running [mcp-searxng-relay](https://github.com/littleoffice/mcp-searxng-relay),
  reachable from the gateway over Streamable HTTP.
- Docker or Podman to run the published image, or the Go version named by the
  `go` directive in [`go.mod`](../go.mod) to build the binary.
- The relay's fence key fingerprint for `-pin`. The relay prints it in its
  startup banner; give the relay a persistent key (`FENCE_SIGNING_KEY_FILE`) so
  the pin survives its restarts. Why this matters: [Key trust](verification.md#key-trust).

## Building from source

```bash
# Build the gateway binary (module root). Uses the MCP go-sdk for transport.
go build -o fence-gateway .
./fence-gateway -version

# In-line gateway over stdio: point your MCP client at this instead of the relay
UPSTREAM_MCP_TOKEN="$RELAY_TOKEN" ./fence-gateway \
  -upstream http://relay.internal:8080/mcp \
  -pin 5fb07c6222c503de \
  -policy reject
```

Serving the gateway to remote clients over Streamable HTTP instead:

```bash
MCP_PORT=9090 \
MCP_AUTH_TOKEN="$(openssl rand -hex 32)" \
MCP_TLS_CERT=/etc/tls/tls.crt MCP_TLS_KEY=/etc/tls/tls.key \
UPSTREAM_MCP_TOKEN="$RELAY_TOKEN" \
./fence-gateway -upstream https://relay.internal:8080/mcp -policy reject -pin 5fb07c6222c503de
```

Every flag and variable: [Configuration](configuration.md).

## Container

The gateway ships as a minimal, reproducibly-built container image
(`FROM scratch`, non-root, statically linked). Over stdio, run it with an
attached stdin (`-i`); in HTTP mode, publish the port. Secrets come from the
runtime environment, never baked into the image:

```bash
# stdio
docker run --rm -i \
  -e UPSTREAM_MCP_TOKEN=… \
  ghcr.io/littleoffice/fence-gateway:latest \
  -upstream https://relay.internal:8080/mcp -policy reject -pin 5fb07c6222c503de

# Streamable HTTP (remote)
docker run --rm -p 9090:9090 \
  -e MCP_PORT=9090 -e MCP_AUTH_TOKEN=… -e UPSTREAM_MCP_TOKEN=… \
  ghcr.io/littleoffice/fence-gateway:latest \
  -upstream https://relay.internal:8080/mcp -policy reject -pin 5fb07c6222c503de
```

The image has no `HEALTHCHECK`: it has no shell or HTTP client to run one. In HTTP
mode, probe `GET /health` from the orchestrator; it needs no credential.

## Using with Claude Desktop (stdio mode)

Point the client at the gateway instead of the relay. In `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "searxng": {
      "command": "/path/to/fence-gateway",
      "args": [
        "-upstream", "https://relay.internal:8080/mcp",
        "-pin", "5fb07c6222c503de",
        "-policy", "reject"
      ],
      "env": {
        "UPSTREAM_MCP_TOKEN": "your-relay-token"
      }
    }
  }
}
```

## Building the container image

Build it yourself reproducibly with `./build.sh <version>` (podman). Two people
running it on the same tagged commit, with the same podman/buildah version, should get
byte-identical image manifests; `reproducibility.yml` proves this in CI. Edit the
`registry` line in the script for your registry first. The full build-provenance, reproducibility
and release-attestation story is in the [supply-chain statement](supply-chain.md).

## Deploying next to the relay

The gateway only protects what passes through it: **only the gateway may reach the
relay.** [Deployment](deployment.md) shows how, for Podman/Compose and for the
`searxng-helm` chart.
