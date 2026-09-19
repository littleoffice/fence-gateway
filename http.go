package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os/signal"
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
func newHTTPHandler(server *mcp.Server, tokens map[tokenDigest]string) http.Handler {
	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		nil,
	)
	// CrossOriginProtection rejects non-safe cross-origin browser requests
	// (checked via Sec-Fetch-Site, or Origin vs Host). Non-browser clients —
	// curl, Go http.Client, an MCP agent — send neither header and pass
	// through, so remote-agent traffic is unaffected.
	protected := http.NewCrossOriginProtection().Handler(mcpHandler)
	return requireAuth(tokens, protected)
}

// requireAuth gates a handler behind the bearer-token table. The full
// Authorization header is hashed once and looked up among fixed-length digests,
// so the comparison cannot short-circuit on the first differing byte and the
// offered header is never logged.
func requireAuth(tokens map[tokenDigest]string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := sha256.Sum256([]byte(r.Header.Get("Authorization")))
		if _, ok := tokens[got]; !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="mcp"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// runHTTP serves the gateway's MCP server over the Streamable HTTP transport
// until a termination signal arrives, then drains in-flight requests.
func (g *gateway) runHTTP(ctx context.Context, server *mcp.Server, hc httpConfig) error {
	// Authentication is mandatory in HTTP mode: the endpoint is network-
	// reachable and has no other gate. stdio mode is exempt because it is a
	// local subprocess pipe.
	if len(hc.authTokens) == 0 {
		return errors.New("authentication is required when MCP_PORT is set: configure " +
			"MCP_AUTH_TOKEN, MCP_AUTH_TOKENS, or MCP_AUTH_TOKEN_FILE (generate a token with `openssl rand -hex 32`)")
	}

	if !hc.tlsEnabled() {
		g.audit.Printf("http.plaintext port=%s hint=%q", hc.port,
			"serving plain HTTP; bearer tokens depend on an external TLS terminator, or set MCP_TLS_CERT+MCP_TLS_KEY")
	}

	mux := http.NewServeMux()
	mux.Handle("/", newHTTPHandler(server, hc.authTokens))

	srv := &http.Server{
		Addr:    ":" + hc.port,
		Handler: g.logRequests(mux),
		// ReadHeaderTimeout guards against slow-header (Slowloris) clients.
		// WriteTimeout is 0: the SDK manages SSE streams with their own
		// deadlines, and a server-level write deadline would truncate them.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Cancel on SIGINT/SIGTERM for a clean drain.
	sctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	g.audit.Printf("http.listen addr=%q tls=%t auth_identities=%d", srv.Addr, hc.tlsEnabled(), len(hc.authTokens))

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
func (g *gateway) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		g.audit.Printf("http.request method=%s path=%s remote=%s elapsed_ms=%d",
			r.Method, r.URL.Path, remoteHost(r), time.Since(start).Milliseconds())
	})
}

// remoteHost returns the request's remote address without any port, and never
// trusts client-supplied forwarding headers (which an attacker sets freely).
func remoteHost(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
