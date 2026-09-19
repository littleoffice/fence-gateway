// Command fence-gateway is the security gateway of arXiv:2511.19727 §4.5,
// implemented as an MCP proxy.
//
// It speaks MCP to a client (Claude Desktop, Claude Code, Cursor) and forwards
// to an upstream MCP server — mcp-searxng-relay, or anything else emitting
// <sec:fence> elements. Every tool result passing back through is verified
// before the client can put it in front of a model.
//
//	client ──MCP──▶ fence-gateway ──MCP──▶ relay ──▶ SearXNG / web
//	                     │
//	                     └── verify signatures, apply policy, audit
//
// The placement is the whole point. The paper is emphatic (§7.4.3) that
// signature checking must happen somewhere that is not the model: an LLM
// processes tokens probabilistically and cannot be its own security verifier.
// A gateway sitting in the transport is the last place with a deterministic
// view of the bytes before they become context.
//
// The transport is delegated to github.com/modelcontextprotocol/go-sdk — the
// same SDK the relay uses. The gateway is an MCP client to the upstream relay
// and an MCP server to the downstream client, bridging the two with fence
// verification injected on the return path (see proxy.go). This file wires up
// configuration, key acquisition, and the stdio transport.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	fv "github.com/littleoffice/fence-gateway/fenceverify"
)

// ServerVersion is stamped at build time via
// -ldflags "-X main.ServerVersion=...". It is derived from `git describe` by
// build.sh and the release workflow, and left as "dev" for plain `go build`.
var ServerVersion = "dev"

// Policy decides what happens when a tool result fails verification.
type Policy string

const (
	// PolicyReject replaces the result with an error. This is Definition
	// 4.5 rule 4 — if any fence fails, the whole prompt is rejected — and
	// is the only policy that actually stops a boundary-escape attack
	// rather than describing it.
	PolicyReject Policy = "reject"

	// PolicyAnnotate passes the content through with a warning prepended
	// and isError set. Useful while rolling out, dangerous as a
	// destination: it puts unverified text in front of the model and
	// relies on the model to be careful with it.
	PolicyAnnotate Policy = "annotate"

	// PolicyAudit logs and passes through unchanged. Observation mode.
	PolicyAudit Policy = "audit"
)

type config struct {
	upstream   string
	token      string
	policy     Policy
	pin        string
	tofu       bool
	scheme     fv.SchemeMode
	maxAge     time.Duration
	stripSig   bool
	requireAll bool
}

func main() {
	var (
		upstream = flag.String("upstream", "http://127.0.0.1:8080/mcp", "upstream MCP endpoint")
		keyURL   = flag.String("key-url", "", "fence public key endpoint (default: upstream origin + /fence/public-key)")
		token    = flag.String("token", os.Getenv("UPSTREAM_MCP_TOKEN"), "bearer token the gateway presents to the upstream relay (env: UPSTREAM_MCP_TOKEN)")
		policy   = flag.String("policy", "reject", "on verification failure: reject|annotate|audit")
		pin      = flag.String("pin", "", "pinned fence key fingerprint (16 hex chars, from the relay's startup banner)")
		tofu     = flag.Bool("tofu", false, "pin the first key seen and refuse later changes")
		paper    = flag.Bool("paper-scheme", false, "verify using the paper's literal Ed25519(SHA-256(C||M)) construction")
		maxAge   = flag.Duration("max-age", 0, "reject fences older than this (0 disables)")
		stripSig = flag.Bool("strip-signature", false, "remove signature attributes from verified fences before forwarding")
		reqAll   = flag.Bool("require-all-fenced", false, "treat unsigned text in a tool result as a failure")
		version  = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *version {
		fmt.Println(ServerVersion)
		return
	}

	cfg := config{
		upstream: *upstream, token: *token, policy: Policy(*policy),
		pin: *pin, tofu: *tofu, maxAge: *maxAge,
		stripSig: *stripSig, requireAll: *reqAll,
	}
	if *paper {
		cfg.scheme = fv.SchemePaperLiteral
	}
	switch cfg.policy {
	case PolicyReject, PolicyAnnotate, PolicyAudit:
	default:
		fatal("unknown policy %q", cfg.policy)
	}

	// Parse HTTP-mode deployment config (MCP_PORT, downstream auth tokens, TLS)
	// before doing any work, so a misconfiguration fails fast rather than after
	// connecting upstream. Empty MCP_PORT means stdio mode.
	hc, err := httpConfigFromEnv()
	if err != nil {
		fatal("%v", err)
	}

	ku := *keyURL
	if ku == "" {
		ku = deriveKeyURL(*upstream)
	}

	audit := log.New(os.Stderr, "", log.LstdFlags|log.LUTC)
	keys := &fv.EndpointKeys{
		URL:               ku,
		PinnedFingerprint: cfg.pin,
		TOFU:              cfg.tofu,
		RetainPrevious:    true,
		OnKeyChange: func(old, nw string) {
			audit.Printf("fence.key.rotated old=%s new=%s", old, nw)
		},
	}

	ctx := context.Background()

	// Compile the optional OAuth/OIDC verifier (MCP_OAUTH_*). Issuer-discovery
	// mode performs OIDC discovery here — a bounded network call — so a
	// misconfiguration fails startup rather than the first authenticated
	// request. Nil when OAuth is unconfigured. Run in both transports so a
	// half-configuration surfaces even over stdio, where it is otherwise unused.
	oauth, err := newOAuthSettings(ctx)
	if err != nil {
		fatal("%v", err)
	}
	hc.oauth = oauth

	if _, err := keys.Refresh(ctx); err != nil {
		// Not fatal: the relay may not be serving its key endpoint yet.
		// Verification will fail closed until a key arrives, which under
		// PolicyReject is the safe direction.
		audit.Printf("fence.key.unavailable err=%q", err)
	} else {
		k, _ := keys.Keys(ctx)
		if len(k) > 0 {
			audit.Printf("fence.key.loaded fingerprint=%s policy=%s", fv.Fingerprint(k[0]), cfg.policy)
		}
	}

	g := &gateway{cfg: cfg, keys: keys, audit: audit}

	// Connect to the upstream relay as an MCP client. Unlike key acquisition
	// (which fails open above), this must succeed: the gateway enumerates the
	// upstream's tools to build its own tool surface, so it cannot serve a
	// client until the relay answers. Retry briefly to tolerate a relay that
	// is still coming up, then give up with a clear message.
	up, err := g.connectUpstream(ctx)
	if err != nil {
		fatal("connect upstream %q: %v", cfg.upstream, err)
	}
	defer func() { _ = up.Close() }()
	g.up = up

	// Build the downstream MCP server and register a verifying proxy handler
	// for every tool the upstream exposes (see proxy.go).
	server := mcp.NewServer(&mcp.Implementation{Name: "fence-gateway", Version: ServerVersion}, nil)
	if err := g.registerTools(ctx, server); err != nil {
		fatal("register tools: %v", err)
	}

	// Serve. MCP_PORT selects the Streamable HTTP transport (remote); otherwise
	// stdio (local subprocess). Both reuse the same verifying proxy server.
	if hc.httpMode() {
		if err := g.runHTTP(ctx, server, hc); err != nil {
			fatal("gateway http: %v", err)
		}
		return
	}
	// Server.Run blocks until the client closes stdin.
	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		fatal("gateway: %v", err)
	}
}

// connectUpstream dials the upstream relay over the Streamable HTTP transport,
// authenticating with the configured bearer token, and returns an initialized
// client session. It retries a few times with backoff so a relay that is still
// starting does not fail the gateway outright.
func (g *gateway) connectUpstream(ctx context.Context) (*mcp.ClientSession, error) {
	httpClient := &http.Client{
		Timeout:   120 * time.Second,
		Transport: &authTransport{token: g.cfg.token, base: http.DefaultTransport},
	}
	transport := &mcp.StreamableClientTransport{
		Endpoint:   g.cfg.upstream,
		HTTPClient: httpClient,
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "fence-gateway", Version: ServerVersion}, nil)

	var lastErr error
	backoff := 500 * time.Millisecond
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
			}
		}
		sess, err := client.Connect(ctx, transport, nil)
		if err == nil {
			g.audit.Printf("upstream.connected endpoint=%q", g.cfg.upstream)
			return sess, nil
		}
		lastErr = err
		g.audit.Printf("upstream.connect.retry attempt=%d err=%q", attempt+1, err)
	}
	return nil, lastErr
}

// authTransport injects an Authorization: Bearer header on every upstream
// request when a token is configured. It leaves requests untouched otherwise.
type authTransport struct {
	token string
	base  http.RoundTripper
}

func (a *authTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if a.token == "" {
		return a.base.RoundTrip(r)
	}
	// Clone before mutating: RoundTrip must not modify the caller's request.
	r2 := r.Clone(r.Context())
	r2.Header.Set("Authorization", "Bearer "+a.token)
	return a.base.RoundTrip(r2)
}

func deriveKeyURL(upstream string) string {
	if i := strings.Index(upstream, "://"); i >= 0 {
		if j := strings.Index(upstream[i+3:], "/"); j >= 0 {
			return upstream[:i+3+j] + "/fence/public-key"
		}
	}
	return strings.TrimRight(upstream, "/") + "/fence/public-key"
}

func fatal(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "fence-gateway: "+f+"\n", a...)
	os.Exit(1)
}
