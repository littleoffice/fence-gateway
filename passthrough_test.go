package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	fv "github.com/littleoffice/fence-gateway/fenceverify"
)

// syncBuf is a mutex-guarded log sink. The audit logger is written from the
// handler goroutines of two concurrent-capable servers, so an unguarded
// bytes.Buffer races under -race.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// passthroughRig is both hops over real HTTP: an upstream relay recording the
// Authorization header of every tool call it serves, and a gateway in front of
// it. Only a real transport on both sides exercises authTransport, which is
// where the credential decision is made — the in-memory transports used
// elsewhere would skip it entirely.
type passthroughRig struct {
	gatewayURL string
	audit      *syncBuf

	mu   sync.Mutex
	seen []string
}

// upstreamSaw returns the Authorization headers the relay received on tool
// calls, in order. Housekeeping traffic (initialize, tools/list, the event
// stream) is deliberately not recorded: it has no caller and is expected to
// carry the bootstrap credential.
func (r *passthroughRig) upstreamSaw() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

func startPassthroughRig(t *testing.T, ctx context.Context, pub ed25519.PublicKey, fence string,
	ua upstreamAuth, tokens map[tokenDigest]string) *passthroughRig {
	t.Helper()

	rig := &passthroughRig{audit: &syncBuf{}}

	upSrv := mcp.NewServer(&mcp.Implementation{Name: "relay", Version: "test"}, nil)
	upSrv.AddTool(&mcp.Tool{
		Name:        "review",
		Description: "returns a fenced review",
		InputSchema: json.RawMessage(`{"type":"object"}`),
	}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		authz := ""
		if req.Extra != nil {
			authz = req.Extra.Header.Get("Authorization")
		}
		rig.mu.Lock()
		rig.seen = append(rig.seen, authz)
		rig.mu.Unlock()
		return textResult(fence), nil
	})
	relay := httptest.NewServer(mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return upSrv }, nil))
	t.Cleanup(relay.Close)

	g := &gateway{
		cfg:   config{policy: PolicyReject, upstream: relay.URL},
		hc:    httpConfig{authTokens: tokens},
		ua:    ua,
		keys:  &fv.StaticKeys{K: []ed25519.PublicKey{pub}},
		audit: log.New(rig.audit, "", 0),
	}
	up, err := g.connectUpstream(ctx)
	if err != nil {
		t.Fatalf("connect upstream: %v", err)
	}
	t.Cleanup(func() { _ = up.Close() })
	g.up = up

	dSrv := mcp.NewServer(&mcp.Implementation{Name: "fence-gateway", Version: "test"}, nil)
	if err := g.registerTools(ctx, dSrv); err != nil {
		t.Fatalf("register tools: %v", err)
	}
	hs := httptest.NewServer(newHTTPHandler(dSrv, g.hc, g.audit))
	t.Cleanup(hs.Close)

	rig.gatewayURL = hs.URL
	return rig
}

// callAs performs one tool call through the gateway as a client holding token.
func callAs(t *testing.T, ctx context.Context, gatewayURL, token string) *mcp.CallToolResult {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "test"}, nil)
	sess, err := c.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   gatewayURL,
		HTTPClient: &http.Client{Transport: &authTransport{token: token, base: http.DefaultTransport}},
	}, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer func() { _ = sess.Close() }()

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "review"})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	return res
}

func twoTokenTable(aliceTok, bobTok string) map[tokenDigest]string {
	return map[tokenDigest]string{
		tokenDigest(sha256.Sum256([]byte("Bearer " + aliceTok))): "alice",
		tokenDigest(sha256.Sum256([]byte("Bearer " + bobTok))):   "bob",
	}
}

// TestPassthroughForwardsEachCallersOwnCredential is the regression test for
// the collapse this mode exists to prevent: the relay keys per-caller state on
// the identity its token resolves to, so two callers behind one gateway must
// arrive as two credentials, not one.
func TestPassthroughForwardsEachCallersOwnCredential(t *testing.T) {
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	fence := mustFence(t, priv, "The risotto was divine.")

	aliceTok, bobTok := strings.Repeat("a", 64), strings.Repeat("b", 64)
	bootstrap := strings.Repeat("g", 64)
	rig := startPassthroughRig(t, ctx, pub, fence,
		upstreamAuth{mode: upstreamAuthPassthrough, token: bootstrap},
		twoTokenTable(aliceTok, bobTok))

	if _, isErr := resultText(callAs(t, ctx, rig.gatewayURL, aliceTok)); isErr {
		t.Fatal("alice's verified call came back as an error")
	}
	if _, isErr := resultText(callAs(t, ctx, rig.gatewayURL, bobTok)); isErr {
		t.Fatal("bob's verified call came back as an error")
	}

	saw := rig.upstreamSaw()
	if len(saw) != 2 {
		t.Fatalf("relay served %d tool calls, want 2", len(saw))
	}
	if saw[0] != "Bearer "+aliceTok {
		t.Errorf("relay saw %q for alice's call, want her own credential", saw[0])
	}
	if saw[1] != "Bearer "+bobTok {
		t.Errorf("relay saw %q for bob's call, want his own credential", saw[1])
	}
	if saw[0] == saw[1] {
		t.Error("both callers reached the relay as one credential: their fetch history and rate limits would be shared")
	}
	for _, got := range saw {
		if got == "Bearer "+bootstrap {
			t.Error("a tool call carried the bootstrap credential; it is for housekeeping only")
		}
	}

	// Attribution: the verification outcome names who it was for.
	audit := rig.audit.String()
	for _, want := range []string{`identity="alice"`, `identity="bob"`} {
		if !strings.Contains(audit, want) {
			t.Errorf("audit log missing %s\n%s", want, audit)
		}
	}
}

// TestStaticModeUsesBootstrapCredential locks in the default: every caller
// reaches the relay as the gateway. This is the behaviour the collapse warning
// at startup describes, and it must not change silently.
func TestStaticModeUsesBootstrapCredential(t *testing.T) {
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	fence := mustFence(t, priv, "The risotto was divine.")

	aliceTok, bobTok := strings.Repeat("a", 64), strings.Repeat("b", 64)
	bootstrap := strings.Repeat("g", 64)
	rig := startPassthroughRig(t, ctx, pub, fence,
		upstreamAuth{mode: upstreamAuthStatic, token: bootstrap},
		twoTokenTable(aliceTok, bobTok))

	callAs(t, ctx, rig.gatewayURL, aliceTok)
	callAs(t, ctx, rig.gatewayURL, bobTok)

	for i, got := range rig.upstreamSaw() {
		if got != "Bearer "+bootstrap {
			t.Errorf("call %d reached the relay as %q, want the bootstrap credential", i, got)
		}
	}
}

// TestPassthroughFailsClosedWithoutCredential covers the call the gateway must
// refuse: passthrough is configured, but the call carries nothing to forward.
// Substituting the bootstrap credential here would silently reintroduce the
// collapse, so the call must not reach the relay at all.
func TestPassthroughFailsClosedWithoutCredential(t *testing.T) {
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	fence := mustFence(t, priv, "The risotto was divine.")

	called := false
	upSrv := mcp.NewServer(&mcp.Implementation{Name: "relay", Version: "test"}, nil)
	upSrv.AddTool(&mcp.Tool{
		Name:        "review",
		InputSchema: json.RawMessage(`{"type":"object"}`),
	}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		called = true
		return textResult(fence), nil
	})
	upServerT, upClientT := mcp.NewInMemoryTransports()
	upSession, err := upSrv.Connect(ctx, upServerT, nil)
	if err != nil {
		t.Fatalf("upstream serve: %v", err)
	}
	t.Cleanup(func() { _ = upSession.Close() })
	up, err := mcp.NewClient(&mcp.Implementation{Name: "gw", Version: "test"}, nil).Connect(ctx, upClientT, nil)
	if err != nil {
		t.Fatalf("gateway upstream connect: %v", err)
	}
	t.Cleanup(func() { _ = up.Close() })

	g := testGateway(PolicyReject, pub)
	g.ua = upstreamAuth{mode: upstreamAuthPassthrough, token: strings.Repeat("g", 64)}
	g.up = up

	// An in-memory downstream call carries no HTTP request, so Extra is nil —
	// the same state as a tool call that arrived without an Authorization
	// header.
	dSrv := mcp.NewServer(&mcp.Implementation{Name: "fence-gateway", Version: "test"}, nil)
	if err := g.registerTools(ctx, dSrv); err != nil {
		t.Fatalf("register tools: %v", err)
	}
	dServerT, dClientT := mcp.NewInMemoryTransports()
	dSession, err := dSrv.Connect(ctx, dServerT, nil)
	if err != nil {
		t.Fatalf("downstream serve: %v", err)
	}
	t.Cleanup(func() { _ = dSession.Close() })
	client, err := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "test"}, nil).Connect(ctx, dClientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	res, err := client.CallTool(ctx, &mcp.CallToolParams{Name: "review"})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	txt, isErr := resultText(res)
	if !isErr {
		t.Fatalf("credential-less call was allowed through: %q", txt)
	}
	if called {
		t.Error("the call reached the relay; it should have been refused before leaving the gateway")
	}
}

// stubRT records the Authorization header of whatever reaches it.
type stubRT struct{ got http.Header }

func (s *stubRT) RoundTrip(r *http.Request) (*http.Response, error) {
	s.got = r.Header.Clone()
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: r}, nil
}

// TestAuthTransportScopesCredentialToUpstreamHost covers the redirect case:
// RoundTrip runs again for each hop, so without a host check a 302 from the
// relay to anywhere else would be handed the caller's bearer token.
func TestAuthTransportScopesCredentialToUpstreamHost(t *testing.T) {
	stub := &stubRT{}
	tr := &authTransport{token: "bootstrap-token", host: "relay.internal:8080", base: stub}

	req, _ := http.NewRequest(http.MethodPost, "http://relay.internal:8080/mcp", nil)
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if got := stub.got.Get("Authorization"); got != "Bearer bootstrap-token" {
		t.Errorf("upstream host got %q, want the credential", got)
	}

	stub.got = nil
	req, _ = http.NewRequest(http.MethodPost, "http://elsewhere.example/mcp", nil)
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if got := stub.got.Get("Authorization"); got != "" {
		t.Errorf("foreign host got %q, want no credential", got)
	}
}

func TestUpstreamAuthFromEnv(t *testing.T) {
	t.Run("defaults to static", func(t *testing.T) {
		t.Setenv("UPSTREAM_MCP_AUTH_MODE", "")
		t.Setenv("UPSTREAM_MCP_TOKEN_FILE", "")
		ua, err := upstreamAuthFromEnv("tok")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ua.passthrough() || ua.token != "tok" {
			t.Fatalf("got mode=%q token=%q, want static/tok", ua.mode, ua.token)
		}
	})

	t.Run("passthrough is recognised", func(t *testing.T) {
		t.Setenv("UPSTREAM_MCP_AUTH_MODE", "Passthrough")
		t.Setenv("UPSTREAM_MCP_TOKEN_FILE", "")
		ua, err := upstreamAuthFromEnv("tok")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !ua.passthrough() {
			t.Fatalf("got mode=%q, want passthrough", ua.mode)
		}
	})

	t.Run("unknown mode fails startup", func(t *testing.T) {
		t.Setenv("UPSTREAM_MCP_AUTH_MODE", "forward-ish")
		t.Setenv("UPSTREAM_MCP_TOKEN_FILE", "")
		if _, err := upstreamAuthFromEnv("tok"); err == nil {
			t.Fatal("an unknown mode was accepted")
		}
	})

	t.Run("file form, newline trimmed", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "bootstrap")
		if err := os.WriteFile(p, []byte("file-token\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("UPSTREAM_MCP_AUTH_MODE", "")
		t.Setenv("UPSTREAM_MCP_TOKEN_FILE", p)
		ua, err := upstreamAuthFromEnv("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ua.token != "file-token" {
			t.Fatalf("token = %q, want the file's contents without the trailing newline", ua.token)
		}
	})

	t.Run("both forms is a configuration error", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "bootstrap")
		if err := os.WriteFile(p, []byte("file-token"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("UPSTREAM_MCP_AUTH_MODE", "")
		t.Setenv("UPSTREAM_MCP_TOKEN_FILE", p)
		if _, err := upstreamAuthFromEnv("env-token"); err == nil {
			t.Fatal("both token forms were accepted; which one applies is then a guess")
		}
	})

	t.Run("empty file is a configuration error", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "bootstrap")
		if err := os.WriteFile(p, []byte("\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("UPSTREAM_MCP_AUTH_MODE", "")
		t.Setenv("UPSTREAM_MCP_TOKEN_FILE", p)
		if _, err := upstreamAuthFromEnv(""); err == nil {
			t.Fatal("an empty credential file was accepted")
		}
	})
}
