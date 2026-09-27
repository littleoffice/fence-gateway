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
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	fv "github.com/littleoffice/fence-gateway/fenceverify"
)

// defaultMaxAge is -max-age unless set. The relay stamps every fence when it
// answers, cached reads included, so a genuine fence is seconds old when it
// arrives; ten minutes leaves room for slow tool calls and clock drift while
// keeping a captured response from being replayed indefinitely.
const defaultMaxAge = 10 * time.Minute

// fenceClockSkew bounds how far in the future a fence timestamp may be. Without
// it a fence dated ahead of the gateway's clock never ages past -max-age.
const fenceClockSkew = 2 * time.Minute

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
	policy     Policy
	pin        string
	tofu       bool
	scheme     fv.SchemeMode
	maxAge     time.Duration
	stripSig   bool
	requireAll bool
	// minFormat is the oldest fence format accepted (-fence-version), or ""
	// for auto: follow what the relay's key endpoint reports.
	minFormat string
}

func main() {
	var (
		upstream = flag.String("upstream", "http://127.0.0.1:8080/mcp", "upstream MCP endpoint")
		keyURL   = flag.String("key-url", "", "fence public key endpoint (default: upstream origin + /fence/public-key)")
		token    = flag.String("token", os.Getenv("UPSTREAM_MCP_TOKEN"), "the gateway's own bootstrap credential for the relay; in passthrough mode no tool call uses it (env: UPSTREAM_MCP_TOKEN, UPSTREAM_MCP_TOKEN_FILE)")
		policy   = flag.String("policy", "reject", "on verification failure: reject|annotate|audit")
		pin      = flag.String("pin", "", "pinned fence key fingerprint (16 hex chars, from the relay's startup banner)")
		tofu     = flag.Bool("tofu", false, "pin the first key seen and refuse later changes")
		paper    = flag.Bool("paper-scheme", false, "verify using the paper's literal Ed25519(SHA-256(C||M)) construction")
		maxAge   = flag.Duration("max-age", defaultMaxAge, "reject fences older than this; the relay stamps each fence when it answers (0 disables)")
		stripSig = flag.Bool("strip-signature", false, "remove signature attributes from verified fences before forwarding")
		fenceVer = flag.String("fence-version", "auto", "oldest fence format to accept: auto (follow the relay's key endpoint), 1.0, or 1.1 (require the signed preamble)")
		reqAll   = flag.Bool("require-all-fenced", false, "treat any unsigned text in a tool result as a failure, including the relay's unfenced no-results reply and error messages")
		version  = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	// A secret on the command line is visible to every local user in the
	// process list and lands in shell history. The flag keeps working, since
	// removing it would break existing deployments, but says so.
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "token" {
			fmt.Fprintln(os.Stderr, "fence-gateway: warning: -token puts the relay credential in the process "+
				"list and shell history; set UPSTREAM_MCP_TOKEN or UPSTREAM_MCP_TOKEN_FILE instead")
		}
	})

	if *version {
		fmt.Println(ServerVersion)
		return
	}

	cfg := config{
		upstream: *upstream, policy: Policy(*policy),
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
	pinned, err := normalizePin(cfg.pin)
	if err != nil {
		fatal("%v", err)
	}
	cfg.pin = pinned
	if cfg.minFormat, err = parseFenceVersion(*fenceVer); err != nil {
		fatal("%v", err)
	}

	// Parse HTTP-mode deployment config (MCP_PORT, downstream auth tokens, TLS)
	// before doing any work, so a misconfiguration fails fast rather than after
	// connecting upstream. Empty MCP_PORT means stdio mode.
	hc, err := httpConfigFromEnv()
	if err != nil {
		fatal("%v", err)
	}

	// How the gateway authenticates to the relay, and with whose credential.
	ua, err := upstreamAuthFromEnv(*token)
	if err != nil {
		fatal("%v", err)
	}
	if ua.perCaller() && !hc.httpMode() {
		fatal("UPSTREAM_MCP_AUTH_MODE=%s requires HTTP mode: set MCP_PORT, "+
			"or leave the mode at %q (stdio carries no caller credential)", ua.mode, upstreamAuthStatic)
	}
	xcfg, err := exchangeConfigFromEnv(ua.mode)
	if err != nil {
		fatal("%v", err)
	}

	ku := *keyURL
	if ku == "" {
		ku = deriveKeyURL(*upstream)
	}
	keyWarning, err := checkKeyTrust(ku, cfg.pin, cfg.tofu)
	if err != nil {
		fatal("%v", err)
	}

	audit := log.New(os.Stderr, "", log.LstdFlags|log.LUTC)
	if keyWarning != "" {
		audit.Printf("fence.key.unpinned url=%q hint=%q", ku, keyWarning)
	}
	keys := &fv.EndpointKeys{
		URL:               ku,
		PinnedFingerprint: cfg.pin,
		TOFU:              cfg.tofu,
		RetainPrevious:    true,
		// Keys a relay replica stops using drop out after a day; one in use
		// is kept alive by every fence it verifies.
		KeyTTL: 24 * time.Hour,
		// Fences naming a key the endpoint does not serve (a pin mismatch,
		// a misconfigured replica) cost one round of fetches per interval,
		// not one per call.
		MinRefreshInterval: 2 * time.Second,
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
	var exchanger *tokenExchanger
	if xcfg != nil {
		// Only an OAuth token can be exchanged: a static token is a shared
		// secret the identity provider has never seen.
		if !oauth.enabled() {
			fatal("UPSTREAM_MCP_AUTH_MODE=exchange needs callers to log in with OAuth: set MCP_OAUTH_ISSUER " +
				"(and MCP_OAUTH_AUDIENCE) to the provider whose tokens the gateway exchanges")
		}
		idp := &http.Client{Timeout: 30 * time.Second}
		if roots := strings.TrimSpace(os.Getenv("MCP_OAUTH_CA_ROOTS")); roots != "" {
			if idp, err = oauthHTTPClientWithRoots(roots); err != nil {
				fatal("MCP_OAUTH_CA_ROOTS %q: %v", roots, err)
			}
		}
		exchanger = newTokenExchanger(*xcfg, idp)
	}
	if err := checkSharedRelayIdentity(ua, hc); err != nil {
		fatal("%v", err)
	}

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
		// Every result will fail -fence-version: say so now, not per call.
		if v := keys.FormatVersion(); cfg.minFormat != "" && fv.OlderFormat(v, cfg.minFormat) {
			audit.Printf("fence.version.mismatch relay=%q required=%q hint=%q", v, cfg.minFormat,
				"the relay emits an older fence format than -fence-version requires, so every result "+
					"will be blocked: set FENCE_PREAMBLE=fenced on the relay, or lower -fence-version")
		}
	}

	g := &gateway{cfg: cfg, hc: hc, ua: ua, keys: keys, audit: audit, exchanger: exchanger}

	// Say, once, how callers reach the relay — and warn when several of them
	// reach it as one. In static mode every downstream identity arrives at the
	// relay under the bootstrap credential, so the relay files their fetch
	// history under a single key and meters them from a single rate-limit
	// bucket. That is invisible from either side at runtime; it belongs in the
	// startup log where an operator will see it.
	audit.Printf("upstream.auth mode=%s bootstrap=%t downstream_identities=%d stateless=%t",
		ua.mode, ua.token != "", len(hc.authTokens), hc.stateless)
	if w := passthroughExposure(ua); w != "" {
		audit.Printf("upstream.auth.passthrough hint=%q", w)
	}
	// Reached only when static was chosen on purpose: checkSharedRelayIdentity
	// refuses the unchosen case before this point.
	if !ua.perCaller() && hc.multiCaller() {
		audit.Printf("upstream.auth.collapse callers=%q hint=%q", describeCallers(hc),
			"all downstream callers reach the relay as one: its per-caller fetch history "+
				"(searxng_session_sources) and rate limits are shared between them. "+
				"Set UPSTREAM_MCP_AUTH_MODE=passthrough to keep them separate")
	}

	// Connect to the upstream relay as an MCP client. Unlike key acquisition
	// (which fails open above), this must succeed: the gateway enumerates the
	// upstream's tools to build its own tool surface, so it cannot serve a
	// client until the relay answers. Retry briefly to tolerate a relay that
	// is still coming up, then give up with a clear message.
	//
	// After that the session is replaced whenever the relay drops it (a
	// restart, or its idle-session janitor) — see upstream.go.
	g.up = &upstreamSession{connect: g.connectUpstream, audit: audit}
	if _, err := g.up.session(); err != nil {
		fatal("connect upstream %q: %v", cfg.upstream, err)
	}
	g.pool = &sessionPool{shared: g.up, connect: g.connectUpstream, audit: audit}
	defer func() { _ = g.pool.Close() }()

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

// upstreamConnectTimeout bounds one attempt to open a session with the relay.
const upstreamConnectTimeout = 30 * time.Second

// connectUpstream dials the upstream relay over the Streamable HTTP transport,
// authenticating with the configured bearer token, and returns an initialized
// client session. It retries a few times with backoff so a relay that is still
// starting does not fail the gateway outright.
func (g *gateway) connectUpstream(ctx context.Context) (*mcp.ClientSession, error) {
	transport := g.upstreamTransport()
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
		// Bounded per attempt: the upstream HTTP client has no timeout of its
		// own (see upstreamTransport), so a relay that accepts the connection
		// but never answers would otherwise hang here for good. The SDK
		// detaches the session from this context, so the deadline ends only
		// the handshake, not the session.
		actx, cancel := context.WithTimeout(ctx, upstreamConnectTimeout)
		sess, err := client.Connect(actx, transport, nil)
		cancel()
		if err == nil {
			g.audit.Printf("upstream.connected endpoint=%q", g.cfg.upstream)
			return sess, nil
		}
		lastErr = err
		g.audit.Printf("upstream.connect.retry attempt=%d err=%q", attempt+1, err)
	}
	return nil, lastErr
}

// upstreamTransport builds the Streamable HTTP client transport to the relay.
//
// The http.Client carries no Timeout. A client-wide timeout bounds the whole
// exchange, body included, so it cuts every response stream that outlives it —
// and against a stateful relay, whose streams carry no event IDs, the SDK
// counts each cut as a reconnect without progress and closes the session for
// good after five. The gateway then fails every tool call until restarted. Tool
// calls are bounded by the caller's context instead, and connection setup by
// http.DefaultTransport's dial and TLS handshake timeouts.
//
// The standalone SSE stream (the long-lived GET) is disabled. It carries
// server-initiated messages, and the gateway forwards none, so holding it open
// only adds a connection that can fail the session.
func (g *gateway) upstreamTransport() *mcp.StreamableClientTransport {
	return &mcp.StreamableClientTransport{
		Endpoint: g.cfg.upstream,
		HTTPClient: &http.Client{
			Transport: &authTransport{
				token: g.ua.token,
				own:   g.ownToken(),
				host:  upstreamHost(g.cfg.upstream),
				base:  http.DefaultTransport,
			},
		},
		DisableStandaloneSSE: true,
	}
}

// credentialKey types the context value carrying a caller's own Authorization
// header value through to the upstream request.
type credentialKey struct{}

// withUpstreamCredential returns a context whose upstream request will present
// authz — a complete Authorization header value, forwarded verbatim — instead
// of the gateway's bootstrap credential.
func withUpstreamCredential(ctx context.Context, authz string) context.Context {
	return context.WithValue(ctx, credentialKey{}, authz)
}

func upstreamCredential(ctx context.Context) string {
	v, _ := ctx.Value(credentialKey{}).(string)
	return v
}

// authTransport decides which credential each upstream request carries: the
// calling client's own, when one was put in the context by the proxy handler
// (passthrough mode), and otherwise the gateway's bootstrap credential. A
// request with neither goes out unauthenticated, which is correct against a
// relay that requires no credential and fails loudly against one that does.
type authTransport struct {
	token string // bootstrap credential, presented when the context carries none
	// own, when set and token is empty, fetches the gateway's own OAuth
	// token (exchange mode, client_credentials) as the bootstrap credential.
	own  func(context.Context) (string, error)
	host string // upstream authority; no credential is attached to any other
	base http.RoundTripper
}

func (a *authTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	// Never hand a credential to a host that is not the configured upstream.
	// RoundTrip is called again for each redirect hop, so without this a 302
	// from the relay to anywhere else collects the caller's bearer token.
	if a.host != "" && !strings.EqualFold(r.URL.Host, a.host) {
		return a.base.RoundTrip(r)
	}

	authz := upstreamCredential(r.Context())
	if authz == "" && a.token != "" {
		authz = "Bearer " + a.token
	}
	if authz == "" && a.own != nil {
		tok, err := a.own(r.Context())
		if err != nil {
			return nil, fmt.Errorf("gateway's own token for the relay: %w", err)
		}
		authz = "Bearer " + tok
	}
	// A stateless relay issues no session, so the SDK sends no
	// Mcp-Session-Id, and the relay reads the header as the client's
	// conversation ID to keep fetch histories apart. Set it from the
	// conversation the call belongs to. A stateful relay's requests always
	// carry the session it issued, and that is never overwritten.
	conv := conversationFrom(r.Context())
	if r.Header.Get("Mcp-Session-Id") != "" {
		conv = ""
	}
	if authz == "" && conv == "" {
		return a.base.RoundTrip(r)
	}
	// Clone before mutating: RoundTrip must not modify the caller's request.
	r2 := r.Clone(r.Context())
	if authz != "" {
		r2.Header.Set("Authorization", authz)
	}
	if conv != "" {
		r2.Header.Set("Mcp-Session-Id", conv)
	}
	return a.base.RoundTrip(r2)
}

// upstreamHost is the authority of the configured upstream endpoint, used to
// scope credentials to it. An unparseable endpoint yields "", which disables
// the host check rather than silently refusing to authenticate — connecting
// would fail at once anyway, with a clearer message.
func upstreamHost(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	return u.Host
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
