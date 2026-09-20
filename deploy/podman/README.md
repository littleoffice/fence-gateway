# Podman / Docker Compose deployment

Runs `fence-gateway` alongside an existing `mcp-searxng-relay` stack, on the
same container network, so the gateway can reach the relay by container name and
verify its tool output before clients see it.

```
client ──▶ fence-gateway (:9090) ──▶ mcp-searxng-relay (:3000, same network) ──▶ SearXNG
                                      verifies fences here
```

## Prerequisites

- The relay's own podman stack running (see `mcp-searxng-relay/deploy/podman`).
  Its compose creates a network (called `edge`, prefixed by the project
  directory name) and runs the relay as container `mcp-searxng-relay` on
  `MCP_PORT=3000`.

## Wire it up

1. **Find the relay's network name** and set it in `docker-compose.yaml` under
   `networks.relay.name`:

   ```bash
   podman network ls        # look for something like <reldir>_edge
   ```

   (Or drop `external: true` to let this stack own a network and attach the
   relay container to it instead.)

2. **Fill in the env file** — copy in real secrets out-of-band:

   ```bash
   $EDITOR envs/.fence-gateway.env   # MCP_AUTH_TOKEN + UPSTREAM_MCP_TOKEN
   ```

   `MCP_AUTH_TOKEN` is what your clients present to the gateway;
   `UPSTREAM_MCP_TOKEN` is the relay's own token the gateway presents upstream.

3. **Start it:**

   ```bash
   podman compose up -d      # or: docker compose up -d
   ```

Point your MCP client at `http://<host>:9090/mcp` (put a TLS terminator in
front, or set `MCP_TLS_CERT`/`MCP_TLS_KEY`, for anything beyond localhost).

## Notes

- The gateway hardening mirrors the relay's containers: `cap_drop: [ALL]`,
  `no-new-privileges`, `read_only` rootfs, non-root (baked into the image).
- The relay listens on `:3000` in the podman env; the `-upstream` in the compose
  `command` matches. If you changed the relay's `MCP_PORT`, update it here too.
- `-policy reject` is the only setting that actually blocks a tampered result;
  `annotate`/`audit` only describe one.
