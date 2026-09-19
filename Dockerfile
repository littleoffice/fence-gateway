# ---------------------------------------------------------------------------
# Reproducible-build inputs.
#
# fence-gateway is a pure-Go program (standard library only, no cgo, no
# third-party modules), so the build is reproducible relative to a much
# smaller set of inputs than a cgo project needs:
#   * the builder base-image digest pinned below,
#   * the committed go.mod (there is no go.sum: the module has no
#     dependencies beyond the standard library),
#   * the SERVER_VERSION value passed in,
#   * SOURCE_DATE_EPOCH passed in.
#
# There are no native/static libraries to fetch and no digest-pinning file
# (native-deps.sha256) because nothing is downloaded during the build: with
# an empty require set, `go mod download` is a no-op and `go build` never
# touches the network. That removes an entire class of supply-chain surface.
#
# Canonical invocation (podman):
#   SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct HEAD)"
#   SERVER_VERSION="$(git describe --tags --always)"
#   podman build \
#     --build-arg SERVER_VERSION="${SERVER_VERSION}" \
#     --build-arg SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
#     --timestamp "${SOURCE_DATE_EPOCH}" \
#     -t fence-gateway:"${SERVER_VERSION}" .
#
# --timestamp is the podman/buildah equivalent of BuildKit's rewrite-timestamp:
# it forces all files in all layers to the given epoch, so the image envelope
# itself is reproducible, not just the binary inside. With BuildKit, pass
# `--output type=...,rewrite-timestamp=true` instead (see build.sh and the
# release/reproducibility workflows).
# ---------------------------------------------------------------------------
ARG SOURCE_DATE_EPOCH=0
ARG SERVER_VERSION=dev

# Pin the builder image by content digest, not by tag. Tags are mutable;
# digests are immutable. This digest is the multi-arch manifest-list digest
# for golang:1.27.1-trixie (the same version and pin mcp-searxng-relay uses),
# so the same Dockerfile builds reproducibly on amd64 and arm64. Resolve a
# fresh digest with, e.g.:
#   docker buildx imagetools inspect golang:1.27.1-trixie
# and copy the top-level index digest below. Bump deliberately as Go patch
# releases land; pin-consistency.yml enforces that the Go version in this
# FROM line matches the `go` directive in go.mod.
FROM docker.io/golang:1.27.1-trixie@sha256:9baa6b4187bbb98d240372a8a235ac0bb6b5ddd52bba1431dc2f7c0705862728 AS builder

# ARGs do not cross FROM boundaries — re-declare to bring them into scope.
ARG SOURCE_DATE_EPOCH
ARG SERVER_VERSION

WORKDIR /app

# Fetch dependencies as a separate, cache-friendly layer. go.mod is treated
# as a frozen input: -mod=readonly forbids `go mod download` from rewriting
# it. There is no go.sum to copy because the module has no external
# dependencies; if one is ever added, add `COPY go.sum ./` here too.
COPY go.mod ./
ENV GOFLAGS="-mod=readonly"
RUN go mod download

COPY . .

# Build a fully static, reproducible binary.
#
#   CGO_ENABLED=0            no cgo — a static binary with no libc dependency,
#                            so it runs on `scratch`. Also removes the C
#                            toolchain and its random per-link build id from
#                            the picture entirely.
#   -trimpath                strip absolute filesystem paths from the binary
#   -buildvcs=false          do not embed VCS state (version is stamped via -X),
#                            so .git is not needed in the build context
#   -ldflags -buildid=       zero out Go's internal build id, which is
#                            otherwise derived from inputs that can vary
#   -ldflags -X main.ServerVersion  stamp the human-readable version
#
# GOOS/GOARCH are inherited from the builder image's platform, so buildx can
# drive multi-arch builds without changes here.
RUN CGO_ENABLED=0 \
    go build \
        -trimpath \
        -buildvcs=false \
        -ldflags "-buildid= -X main.ServerVersion=${SERVER_VERSION}" \
        -o fence-gateway .

# ---------------------------------------------------------------------------
# Runtime image.
# ---------------------------------------------------------------------------
FROM scratch
ARG SOURCE_DATE_EPOCH

COPY --from=builder /app/fence-gateway /fence-gateway

# CA roots for verifying TLS to an HTTPS upstream relay or key endpoint. The
# gateway's default upstream is plain HTTP on localhost, but an operator can
# point -upstream / -key-url at an HTTPS endpoint, and without a trust store
# those handshakes would fail. Copied from the (digest-pinned) builder image
# rather than installed with apt-get: the bundle is then exactly whatever the
# pinned base ships, which is deterministic and needs no network access at
# build time.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Run as a non-root, non-zero UID. A numeric UID needs no /etc/passwd entry,
# so it works on scratch.
USER 1001:1001

# No HEALTHCHECK: fence-gateway is a stdio MCP proxy, not a network server. It
# does work only while a client is attached to its stdin/stdout, and it
# exposes no port or /health endpoint to probe. A HEALTHCHECK would have
# nothing meaningful to hit. Liveness is the responsibility of the parent MCP
# client (Claude Desktop/Code/Cursor) that spawns it.
#
# Configuration is by command-line flags (see README) appended after the
# entrypoint, e.g.:
#   docker run --rm -i fence-gateway \
#     -upstream https://relay.internal:8080/mcp -policy reject -pin <fp>
#
# Secrets (MCP_AUTH_TOKEN) are read from the runtime environment via
# os.Getenv and are deliberately NOT declared as ENV here: baking a
# secret-named ENV key into the image would persist it in image metadata and
# is flagged by BuildKit's SecretsUsedInArgOrEnv check. Provide it at run time
# with `-e MCP_AUTH_TOKEN=...` or your orchestrator's secret mechanism.
#
# -i (interactive stdin) is required because the proxy speaks JSON-RPC over
# stdio.
ENTRYPOINT ["/fence-gateway"]
