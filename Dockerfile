# ---------------------------------------------------------------------------
# Reproducible-build inputs.
#
# fence-gateway is a pure-Go program (no cgo). Its dependencies are the MCP
# go-sdk and a small set of pure-Go modules — all pinned by content hash in
# go.sum — so the build is reproducible relative to:
#   * the builder base-image digest pinned below,
#   * the committed go.mod / go.sum,
#   * the SERVER_VERSION value passed in,
#   * SOURCE_DATE_EPOCH passed in.
#
# There are no native/static libraries and no digest-pinning file
# (native-deps.sha256): every dependency is a Go module, verified against
# go.sum and the Go checksum database during `go mod download`. The download
# step needs network access to the module proxy; there is nothing fetched
# outside the go.sum-pinned set.
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
FROM docker.io/golang:1.27.1-trixie@sha256:433790e515d27dc6003e847e644cc0af956985cf315c1c58a3b73ee2dd305183 AS builder

# ARGs do not cross FROM boundaries — re-declare to bring them into scope.
ARG SOURCE_DATE_EPOCH
ARG SERVER_VERSION

WORKDIR /app

# Fetch dependencies as a separate, cache-friendly layer. go.mod and go.sum are
# treated as frozen inputs: -mod=readonly forbids `go mod download` from
# rewriting either, so the build cannot silently pull in an unpinned module.
COPY go.mod go.sum ./
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

# Two ways to run it. Over stdio (the default) the gateway is a subprocess
# of the MCP client, which owns its liveness: run it with -i. With MCP_PORT
# set it serves Streamable HTTP; publish the port.
#
# No HEALTHCHECK: the image is FROM scratch, with no shell or HTTP client for
# one to run, and over stdio there is nothing to probe. In HTTP mode, probe
# GET /health from the orchestrator; it needs no credential.
#
# Verification behaviour is set by command-line flags (see README) appended
# after the entrypoint; deployment by environment variables, e.g.:
#   docker run --rm -i fence-gateway \
#     -upstream https://relay.internal:8080/mcp -policy reject -pin <fp>
#
# Secrets (MCP_AUTH_TOKEN*, UPSTREAM_MCP_TOKEN, UPSTREAM_OAUTH_CLIENT_SECRET)
# are read from the runtime environment, or from the matching *_FILE
# variable, and are deliberately NOT declared as ENV here: baking a
# secret-named ENV key into the image would persist it in image metadata and
# is flagged by BuildKit's SecretsUsedInArgOrEnv check. Provide them at run
# time with -e, a mounted file, or your orchestrator's secret mechanism.
ENTRYPOINT ["/fence-gateway"]
