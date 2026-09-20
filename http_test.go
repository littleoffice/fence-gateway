package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	fv "github.com/littleoffice/fence-gateway/fenceverify"
)

// startHTTPGateway wires an in-memory upstream relay tool returning `fence`, a
// gateway verifying against `pub`, and the gateway's downstream MCP server
// behind newHTTPHandler on a real httptest server. It returns the server URL.
func startHTTPGateway(t *testing.T, ctx context.Context, pub ed25519.PublicKey, fence string, tokens map[tokenDigest]string) string {
	t.Helper()

	upSrv := mcp.NewServer(&mcp.Implementation{Name: "relay", Version: "test"}, nil)
	upSrv.AddTool(&mcp.Tool{
		Name:        "review",
		Description: "returns a fenced review",
		InputSchema: json.RawMessage(`{"type":"object"}`),
	}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return textResult(fence), nil
	})
	upServerT, upClientT := mcp.NewInMemoryTransports()
	upSession, err := upSrv.Connect(ctx, upServerT, nil)
	if err != nil {
		t.Fatalf("upstream serve: %v", err)
	}
	t.Cleanup(func() { _ = upSession.Close() })

	upClient := mcp.NewClient(&mcp.Implementation{Name: "gw-client", Version: "test"}, nil)
	up, err := upClient.Connect(ctx, upClientT, nil)
	if err != nil {
		t.Fatalf("gateway upstream connect: %v", err)
	}
	t.Cleanup(func() { _ = up.Close() })

	g := &gateway{
		cfg:   config{policy: PolicyReject},
		keys:  &fv.StaticKeys{K: []ed25519.PublicKey{pub}},
		audit: log.New(io.Discard, "", 0),
		up:    up,
	}
	dSrv := mcp.NewServer(&mcp.Implementation{Name: "fence-gateway", Version: "test"}, nil)
	if err := g.registerTools(ctx, dSrv); err != nil {
		t.Fatalf("register tools: %v", err)
	}

	hs := httptest.NewServer(newHTTPHandler(dSrv, httpConfig{authTokens: tokens}, nil))
	t.Cleanup(hs.Close)
	return hs.URL
}

func tokenTable(token, identity string) map[tokenDigest]string {
	return map[tokenDigest]string{
		tokenDigest(sha256.Sum256([]byte("Bearer " + token))): identity,
	}
}

func TestHTTPTransportAuthedCallVerifies(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	fence := mustFence(t, priv, "The risotto was divine.")
	token := strings.Repeat("a", 64)
	url := startHTTPGateway(t, ctx, pub, fence, tokenTable(token, "test"))

	client := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "test"}, nil)
	transport := &mcp.StreamableClientTransport{
		Endpoint:   url,
		HTTPClient: &http.Client{Transport: &authTransport{token: token, base: http.DefaultTransport}},
	}
	cs, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("authed connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "review", Arguments: map[string]any{}})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	txt, isErr := resultText(res)
	if isErr {
		t.Fatalf("valid result rejected over HTTP: %s", txt)
	}
	if !strings.Contains(txt, "risotto was divine") {
		t.Errorf("content not forwarded over HTTP: %q", txt)
	}
}

func TestHTTPTransportRejectsUnauthenticated(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	fence := mustFence(t, priv, "hi")
	token := strings.Repeat("a", 64)
	url := startHTTPGateway(t, ctx, pub, fence, tokenTable(token, "test"))

	// No Authorization header at all → 401 → the MCP handshake cannot complete.
	client := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "test"}, nil)
	if _, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: url}, nil); err == nil {
		t.Fatal("unauthenticated client connected; bearer auth not enforced")
	}

	// A wrong token is likewise rejected.
	wrong := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "test"}, nil)
	transport := &mcp.StreamableClientTransport{
		Endpoint:   url,
		HTTPClient: &http.Client{Transport: &authTransport{token: strings.Repeat("z", 64), base: http.DefaultTransport}},
	}
	if _, err := wrong.Connect(ctx, transport, nil); err == nil {
		t.Fatal("wrong-token client connected; bearer auth not enforced")
	}
}

// A bare unauthenticated POST returns 401 with a Bearer challenge, before any
// MCP machinery runs.
func TestHTTPUnauthorizedStatus(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	url := startHTTPGateway(t, ctx, pub, mustFence(t, priv, "hi"), tokenTable(strings.Repeat("a", 64), "test"))

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
	if !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Bearer") {
		t.Errorf("missing Bearer challenge: %q", resp.Header.Get("WWW-Authenticate"))
	}
}
