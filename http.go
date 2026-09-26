package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// newHTTPHandler builds the downstream HTTP handler chain for the gateway's MCP
// server, from the outside in:
//
//	requireAuth → CrossOriginProtection → StreamableHTTPHandler
//
// The SDK's StreamableHTTPHandler owns the transport (POST/GET/DELETE, SSE
// framing, Mcp-Session-Id). It already applies DNS-rebinding/localhost
// protection and a request-body cap; cross-origin (CSRF) protection is NOT on
// by default in this SDK version, so it is added explicitly with the standard
// library's net/http.CrossOriginProtection — the same defence the relay gets.
// Bearer auth sits outermost so an unauthenticated request never reaches the
// session machinery.
func newHTTPHandler(server *mcp.Server, hc httpConfig, audit *log.Logger) http.Handler {
	// Stateless mirrors the relay's MCP_STATELESS: no session-ID issuance, every
	// request its own ephemeral session, so replicas need no sticky routing.
	// It has to match the relay's setting — see httpConfig.stateless.
	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{
			Stateless: hc.stateless,
			// A client that goes away without ending its session would
			// otherwise leave it, and the relay session held for it, open
			// for as long as the gateway runs.
			SessionTimeout: downstreamSessionIdle,
		},
	)
	// CrossOriginProtection rejects non-safe cross-origin browser requests
	// (checked via Sec-Fetch-Site, or Origin vs Host). Non-browser clients —
	// curl, Go http.Client, an MCP agent — send neither header and pass
	// through, so remote-agent traffic is unaffected.
	protected := http.NewCrossOriginProtection().Handler(mcpHandler)

	mux := http.NewServeMux()
	mux.Handle("/", requireAuth(hc, audit, protected))
	// Liveness for orchestrators: unauthenticated, and saying nothing but
	// that the process is serving. The image has no shell or HTTP client for
	// a container HEALTHCHECK, so the probe comes from outside.
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	// RFC 9728 protected-resource metadata — unauthenticated by design (a client
	// needs it *before* it can obtain a token), registered only when OAuth is on.
	// Its specific path takes routing precedence over the "/" MCP handler.
	if hc.oauth.enabled() {
		mux.HandleFunc(oauthMetadataPath, hc.oauth.metadataHandler())
	}
	return mux
}

// requireAuth gates a handler behind the configured credentials: the static
// bearer-token table first (a fixed-length digest lookup that cannot
// short-circuit on the first differing byte, and never logs the offered
// header), then — if configured — an OAuth/OIDC JWT. A request that satisfies
// neither gets 401; when OAuth is enabled the challenge points at the
// protected-resource metadata so a spec-compliant client can discover the
// issuer.
func requireAuth(hc httpConfig, audit *log.Logger, next http.Handler) http.Handler {
	failures := newAuthFailures(maxAuthFailures, authFailureWindow)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		staticOn := len(hc.authTokens) > 0
		oauthOn := hc.oauth.enabled()

		// No credential configured at all: open. runHTTP refuses to start in
		// this state, so this path is reachable only from tests.
		if !staticOn && !oauthOn {
			next.ServeHTTP(w, r)
			return
		}

		// Static digest table first — an O(1) fixed-length lookup, cheaper than
		// a JWT verification and the path most deployments use.
		if staticOn {
			if _, ok := hc.authTokens[sha256.Sum256([]byte(authz))]; ok {
				next.ServeHTTP(w, r)
				return
			}
		}

		// A client over its budget of failed attempts is refused before any
		// further verification. That matters most for OAuth: a token naming
		// an unknown key makes the verifier fetch the issuer's key set again,
		// so without a limit anyone could make the gateway hammer the
		// identity provider, one fetch per request. A valid static token has
		// already passed above, so it is never held up by this.
		client := clientAddr(r, hc.trustForwarded)
		if failures.exceeded(client) {
			if audit != nil {
				audit.Printf("auth.throttled method=%s path=%q remote=%s", r.Method, r.URL.Path, client)
			}
			w.Header().Set("Retry-After", strconv.Itoa(int(authFailureWindow.Seconds())))
			http.Error(w, "too many failed authentication attempts", http.StatusTooManyRequests)
			return
		}

		// Then OAuth: verify a presented Bearer JWT against the configured issuer.
		if oauthOn {
			if tok := bearerToken(authz); tok != "" {
				if _, err := hc.oauth.Verify(r.Context(), tok); err == nil {
					next.ServeHTTP(w, r)
					return
				}
			}
		}

		failures.record(client)
		if oauthOn {
			w.Header().Set("WWW-Authenticate",
				`Bearer realm="mcp", resource_metadata="`+resourceMetadataURL(r, hc.trustForwarded)+`"`)
		} else {
			w.Header().Set("WWW-Authenticate", `Bearer realm="mcp"`)
		}
		// One line per refusal, so a run of them is visible without turning on
		// anything. The offered header is never logged: a near-miss guess is
		// still a credential, and the audit log is not the place to collect
		// them.
		if audit != nil {
			audit.Printf("auth.denied method=%s path=%q remote=%s", r.Method, r.URL.Path, remoteHost(r))
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

// runHTTP serves the gateway's MCP server over the Streamable HTTP transport
// until a termination signal arrives, then drains in-flight requests.
func (g *gateway) runHTTP(ctx context.Context, server *mcp.Server, hc httpConfig) error {
	// Authentication is mandatory in HTTP mode: the endpoint is network-
	// reachable and has no other gate. Either the static token table or OAuth
	// must be configured. stdio mode is exempt because it is a local
	// subprocess pipe.
	if len(hc.authTokens) == 0 && !hc.oauth.enabled() {
		return errors.New("authentication is required when MCP_PORT is set: configure " +
			"MCP_AUTH_TOKEN / MCP_AUTH_TOKENS / MCP_AUTH_TOKEN_FILE (generate a token with `openssl rand -hex 32`), " +
			"or delegate to an OAuth 2.0 / OIDC provider with MCP_OAUTH_ISSUER (+ MCP_OAUTH_AUDIENCE)")
	}

	if !hc.tlsEnabled() {
		g.audit.Printf("http.plaintext port=%s hint=%q", hc.port,
			"serving plain HTTP; bearer tokens depend on an external TLS terminator, or set MCP_TLS_CERT+MCP_TLS_KEY")
	}

	srv := &http.Server{
		Addr:    ":" + hc.port,
		Handler: g.logRequests(newHTTPHandler(server, hc, g.audit)),
		// ReadHeaderTimeout guards against slow-header (Slowloris) clients,
		// ReadTimeout against slow bodies: a JSON-RPC request is small, and
		// one trickled in a byte at a time held a connection indefinitely.
		// WriteTimeout is 0: the SDK manages SSE streams with their own
		// deadlines, and a server-level write deadline would truncate them.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Cancel on SIGINT/SIGTERM for a clean drain.
	sctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	g.audit.Printf("http.listen addr=%q tls=%t auth_identities=%d oauth=%q",
		srv.Addr, hc.tlsEnabled(), len(hc.authTokens), hc.oauth.describe())

	errc := make(chan error, 1)
	go func() {
		var err error
		if hc.tlsEnabled() {
			err = srv.ListenAndServeTLS(hc.tlsCert, hc.tlsKey)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
			return
		}
		errc <- nil
	}()

	select {
	case err := <-errc:
		return err
	case <-sctx.Done():
		g.audit.Printf("http.shutdown reason=%q", "signal received, draining connections")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		return nil
	}
}

// logRequests logs one line per request at the audit level: method, path, and
// remote address. It never logs the Authorization header.
//
// The path is quoted with %q, not %s. r.URL.Path is the *decoded* path, so a
// request for "/a%0afence.verified..." puts a real newline in it: unquoted, an
// unauthenticated caller can append whatever lines they like to the audit log.
// That log is where this gateway records its verdicts and is the artefact an
// operator reads after an incident, so forging lines in it is an attack on the
// component's primary output. %q renders the newline as an escape and keeps
// one request to one line. The method needs no such treatment — net/http
// rejects a request line whose method is not a valid token — and the remote
// address comes from the connection, not the caller.
func (g *gateway) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		g.audit.Printf("http.request method=%s path=%q remote=%s elapsed_ms=%d",
			r.Method, r.URL.Path, remoteHost(r), time.Since(start).Milliseconds())
	})
}

const (
	// downstreamSessionIdle closes a client session left idle this long.
	downstreamSessionIdle = time.Hour
	// maxAuthFailures failed attempts per client within authFailureWindow
	// are allowed; past that, attempts are refused until the window ends.
	maxAuthFailures   = 30
	authFailureWindow = time.Minute
	// maxTrackedClients bounds the failure table; past it the table starts
	// over rather than growing without limit.
	maxTrackedClients = 10000
)

// authFailures counts failed authentication attempts per client address in a
// fixed window.
type authFailures struct {
	limit  int
	window time.Duration

	mu     sync.Mutex
	counts map[string]*failureWindow
}

type failureWindow struct {
	start time.Time
	n     int
}

func newAuthFailures(limit int, window time.Duration) *authFailures {
	return &authFailures{limit: limit, window: window, counts: make(map[string]*failureWindow)}
}

func (a *authFailures) exceeded(client string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	w, ok := a.counts[client]
	if !ok || time.Since(w.start) > a.window {
		return false
	}
	return w.n >= a.limit
}

func (a *authFailures) record(client string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	w, ok := a.counts[client]
	if !ok || now.Sub(w.start) > a.window {
		if len(a.counts) >= maxTrackedClients {
			a.counts = make(map[string]*failureWindow)
		}
		a.counts[client] = &failureWindow{start: now, n: 1}
		return
	}
	w.n++
}

// clientAddr is the address failed attempts are counted against: the
// connection's, or, when forwarded headers are trusted (the gateway sits
// behind a reverse proxy that sets them), the first X-Forwarded-For entry.
// Behind a proxy without that setting every client shares the proxy's
// address, so one client's failures can hold up another's OAuth logins.
func clientAddr(r *http.Request, trustForwarded bool) string {
	if trustForwarded {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if first := strings.TrimSpace(strings.Split(xff, ",")[0]); first != "" {
				return first
			}
		}
	}
	return remoteHost(r)
}

// remoteHost returns the request's remote address without any port, and never
// trusts client-supplied forwarding headers (which an attacker sets freely).
func remoteHost(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
