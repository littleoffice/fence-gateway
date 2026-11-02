# evilweb, the eval's fake web (fake SearXNG + attack pages). Eval-only: never
# deploy this anywhere a real relay or user could reach it.
#
# Build context is eval/:  docker build -f deploy/Dockerfile .
FROM docker.io/golang:1.27.3-trixie@sha256:c65ecfe613b539ac74c62a4c3b2c27e8f8a6076384c8f27e8a3c0f3be17cc385 AS builder
WORKDIR /src
# evilweb imports only the standard library and internal/corpus, so the build
# fetches no modules (no `go mod download`, which would pull the whole
# module's dependencies for nothing).
COPY . .
RUN CGO_ENABLED=0 GOPROXY=off go build -trimpath -o /evilweb ./cmd/evilweb

FROM scratch
COPY --from=builder /evilweb /evilweb
COPY corpus /corpus
USER 65532:65532
ENTRYPOINT ["/evilweb", "-corpus", "/corpus/cases"]
