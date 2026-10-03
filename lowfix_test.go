package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	fv "github.com/littleoffice/fence-gateway/fenceverify"
)

// -strip-signature removes the signature from the fence's opening tag only.
// It used to search the whole text, including fenced page content, where
// double quotes are not escaped: a page mentioning signature="x" lost text.
func TestStripSignatureLeavesContentAlone(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	content := `the attr signature="x" is shown, and "quoted" text survives`
	g := testGateway(PolicyReject, pub)
	g.cfg.stripSig = true
	txt, isErr := resultText(g.verify(context.Background(), "review", "t", textResult(mustFence(t, priv, content))))
	if isErr {
		t.Fatalf("blocked: %q", txt)
	}
	if !strings.Contains(txt, content) {
		t.Errorf("page content was altered:\n%q", txt)
	}
	if strings.Count(txt, `signature="`) != 1 {
		t.Errorf("want only the content's own signature=\" left, got:\n%q", txt)
	}
}

// Both fences of a real 1.1 response lose their signatures, and nothing else.
func TestStripSignatureOnRelayVector(t *testing.T) {
	g := testGateway(PolicyReject, vectorKey(t))
	g.cfg.stripSig = true
	in := vector(t, "v1.1-escaped-ordinary")
	txt, isErr := resultText(g.verify(context.Background(), "t", "t", textResult(in)))
	if isErr {
		t.Fatalf("blocked: %q", txt)
	}
	if strings.Contains(txt, `signature="`) {
		t.Errorf("a signature survived: %q", txt)
	}
	if len(in)-len(txt) != 2*(len(` signature="`)+88+1) {
		t.Errorf("removed %d bytes, want exactly two signature attributes", len(in)-len(txt))
	}
}

// Freshness is on by default: a fence older than -max-age, or dated too far
// ahead of the gateway's clock, is refused.
func TestFreshnessDefaults(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	fenceAt := func(at time.Time) string {
		s, err := fv.Generate(priv, "news", fv.GenOptions{
			Type: fv.TypeContent, Rating: fv.RatingUntrusted, Scheme: fv.SchemeRelay,
			Timestamp: at.UTC().Format(time.RFC3339),
		})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	now := time.Now()
	cases := []struct {
		name    string
		at      time.Time
		blocked bool
	}{
		{"fresh", now.Add(-time.Minute), false},
		{"older than -max-age", now.Add(-defaultMaxAge - time.Minute), true},
		{"slightly ahead (clock drift)", now.Add(time.Minute), false},
		{"far in the future", now.Add(fenceClockSkew + 5*time.Minute), true},
	}
	for _, c := range cases {
		g := testGateway(PolicyReject, pub)
		g.cfg.maxAge = defaultMaxAge
		if _, isErr := resultText(g.verify(context.Background(), "t", "t", textResult(fenceAt(c.at)))); isErr != c.blocked {
			t.Errorf("%s: blocked = %v, want %v", c.name, isErr, c.blocked)
		}
	}
}

// When the call to the relay fails, the client gets a fixed message. The SDK's
// own error names upstream addresses and session IDs; that belongs in the
// audit log, not in front of the model.
func TestUpstreamFailureMessageIsFixed(t *testing.T) {
	ctx := context.Background()
	upSrv := mcp.NewServer(&mcp.Implementation{Name: "relay", Version: "test"}, nil)
	upSrv.AddTool(&mcp.Tool{Name: "review", InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) { return textResult("x"), nil })
	relay := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return upSrv }, nil))

	audit := &syncBuf{}
	g := &gateway{cfg: config{policy: PolicyReject, upstream: relay.URL}, keys: &fv.StaticKeys{}, audit: log.New(audit, "", 0)}
	g.up = &upstreamSession{connect: g.connectUpstream, audit: g.audit}
	dSrv := mcp.NewServer(&mcp.Implementation{Name: "fence-gateway", Version: "test"}, nil)
	if err := g.registerTools(ctx, dSrv); err != nil {
		t.Fatal(err)
	}
	relay.Close() // the relay goes away after startup
	_ = g.up.Close()

	st, ct := mcp.NewInMemoryTransports()
	if _, err := dSrv.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "t"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()
	_, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "review"})
	if err == nil {
		t.Fatal("call to a dead relay succeeded")
	}
	if !strings.Contains(err.Error(), errUpstreamCall.Error()) || strings.Contains(err.Error(), "127.0.0.1") {
		t.Errorf("client saw %q, want only the fixed message", err)
	}
	if !strings.Contains(audit.String(), "upstream.error") {
		t.Error("the failure detail was not logged")
	}
}

// The gateway requires every fence to say when it was made, and under the
// relay's construction to name its key. The paper's construction has no kid,
// so it is not held to that.
func TestGatewayRequiresTimestampAndKid(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC().Format(time.RFC3339)
	gen := func(o fv.GenOptions) string {
		t.Helper()
		o.Type, o.Rating = fv.TypeContent, fv.RatingUntrusted
		s, err := fv.Generate(priv, "news", o)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	cases := []struct {
		name        string
		scheme      fv.SchemeMode
		fence       string
		wantBlocked bool
	}{
		{"relay, complete", fv.SchemeRelay, gen(fv.GenOptions{Timestamp: now, Scheme: fv.SchemeRelay}), false},
		{"relay, no timestamp", fv.SchemeRelay, gen(fv.GenOptions{Scheme: fv.SchemeRelay}), true},
		{"relay, no kid", fv.SchemeRelay, gen(fv.GenOptions{Timestamp: now, Scheme: fv.SchemeRelay, OmitKid: true}), true},
		{"paper, no kid", fv.SchemePaperLiteral, gen(fv.GenOptions{Timestamp: now, Scheme: fv.SchemePaperLiteral}), false},
		{"paper, no timestamp", fv.SchemePaperLiteral, gen(fv.GenOptions{Scheme: fv.SchemePaperLiteral}), true},
	}
	for _, c := range cases {
		g := testGateway(PolicyReject, pub)
		g.cfg.scheme = c.scheme
		g.cfg.maxAge = defaultMaxAge
		_, blocked := resultText(g.verify(context.Background(), "t", "t", textResult(c.fence)))
		if blocked != c.wantBlocked {
			t.Errorf("%s: blocked = %v, want %v", c.name, blocked, c.wantBlocked)
		}
	}
}
