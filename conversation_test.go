package main

import (
	"bytes"
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
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	fv "github.com/littleoffice/fence-gateway/fenceverify"
)

// conversationRig is a relay recording the Mcp-Session-Id of every tool call
// and every session it is asked to close, with a gateway in front of it
// serving clients over HTTP.
type conversationRig struct {
	gatewayURL string
	token      string

	mu      sync.Mutex
	calls   []string // Mcp-Session-Id on each tools/call
	deleted []string // Mcp-Session-Id on each DELETE
}

func (r *conversationRig) toolCallSessions() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func startConversationRig(t *testing.T, statelessRelay bool) *conversationRig {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	rig := &conversationRig{token: strings.Repeat("t", 40)}

	upSrv := mcp.NewServer(&mcp.Implementation{Name: "relay", Version: "test"}, nil)
	upSrv.AddTool(&mcp.Tool{Name: "review", InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return textResult(mustFence(t, priv, "a review")), nil
		})
	sdk := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return upSrv },
		&mcp.StreamableHTTPOptions{Stateless: statelessRelay})
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		sid := req.Header.Get("Mcp-Session-Id")
		switch req.Method {
		case http.MethodPost:
			body, _ := io.ReadAll(req.Body)
			req.Body = io.NopCloser(bytes.NewReader(body))
			if bytes.Contains(body, []byte(`"method":"tools/call"`)) {
				rig.mu.Lock()
				rig.calls = append(rig.calls, sid)
				rig.mu.Unlock()
			}
		case http.MethodDelete:
			rig.mu.Lock()
			rig.deleted = append(rig.deleted, sid)
			rig.mu.Unlock()
		}
		sdk.ServeHTTP(w, req)
	}))
	t.Cleanup(relay.Close)

	audit := log.New(io.Discard, "", 0)
	g := &gateway{
		cfg:   config{policy: PolicyReject, upstream: relay.URL},
		hc:    httpConfig{authTokens: map[tokenDigest]string{sha256.Sum256([]byte("Bearer " + rig.token)): "alice"}},
		keys:  &fv.StaticKeys{K: []ed25519.PublicKey{pub}},
		audit: audit,
	}
	g.up = &upstreamSession{connect: g.connectUpstream, audit: audit}
	if _, err := g.up.session(); err != nil {
		t.Fatalf("connect upstream: %v", err)
	}
	t.Cleanup(func() { _ = g.up.Close() })

	dSrv := mcp.NewServer(&mcp.Implementation{Name: "fence-gateway", Version: "test"}, nil)
	if err := g.registerTools(context.Background(), dSrv); err != nil {
		t.Fatalf("register tools: %v", err)
	}
	hs := httptest.NewServer(newHTTPHandler(dSrv, g.hc, nil))
	t.Cleanup(hs.Close)
	rig.gatewayURL = hs.URL
	return rig
}

// client opens one conversation with the gateway.
func (r *conversationRig) client(t *testing.T) *mcp.ClientSession {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "test"}, nil)
	sess, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:   r.gatewayURL,
		HTTPClient: &http.Client{Transport: &authTransport{token: r.token, base: http.DefaultTransport}},
	}, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	return sess
}

func call(t *testing.T, s *mcp.ClientSession) {
	t.Helper()
	res, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: "review"})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if res.IsError {
		t.Fatalf("call was blocked: %+v", res.Content)
	}
}

// Two conversations of the same caller, two calls each. The relay must see two
// different session IDs, one per conversation, so it keeps two histories.
func assertOneRelaySessionPerConversation(t *testing.T, got []string) {
	t.Helper()
	if len(got) != 4 {
		t.Fatalf("relay saw %d tool calls, want 4", len(got))
	}
	a1, b1, a2, b2 := got[0], got[1], got[2], got[3]
	if a1 == "" || b1 == "" {
		t.Fatalf("tool calls carried no session ID: %q", got)
	}
	if a1 != a2 || b1 != b2 {
		t.Errorf("one conversation reached the relay under two session IDs: %q", got)
	}
	if a1 == b1 {
		t.Errorf("two conversations reached the relay as one session %q: they share one fetch history", a1)
	}
}

// A stateless relay issues no sessions and reads the conversation ID from the
// Mcp-Session-Id header. The gateway sets it from the downstream conversation.
func TestStatelessRelayGetsConversationID(t *testing.T) {
	rig := startConversationRig(t, true)
	a, b := rig.client(t), rig.client(t)
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	call(t, a)
	call(t, b)
	call(t, a)
	call(t, b)
	got := rig.toolCallSessions()
	assertOneRelaySessionPerConversation(t, got)
	if got[0] != a.ID() || got[1] != b.ID() {
		t.Errorf("relay saw %q, want the gateway's conversation IDs %q and %q", got[:2], a.ID(), b.ID())
	}
}

func TestConversationID(t *testing.T) {
	withHeader := func(v string) *mcp.CallToolRequest {
		h := http.Header{}
		if v != "" {
			h.Set("Mcp-Session-Id", v)
		}
		return &mcp.CallToolRequest{Extra: &mcp.RequestExtra{Header: h}}
	}
	cases := []struct {
		name string
		req  *mcp.CallToolRequest
		want string
	}{
		{"stdio: no session, no header", &mcp.CallToolRequest{}, ""},
		{"client-asserted header", withHeader("ABC123"), "ABC123"},
		{"header with a space", withHeader("a b"), ""},
		{"header with a newline", withHeader("a\nb"), ""},
		{"header too long", withHeader(strings.Repeat("x", maxConversationIDLen+1)), ""},
	}
	for _, c := range cases {
		if got := conversationID(c.req); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
