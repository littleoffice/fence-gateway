package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestUpstreamTransportHasNoClientTimeout pins the two properties that keep
// the upstream session alive against a stateful relay. A client-wide Timeout
// cuts every response stream that outlives it; the SDK counts each cut on the
// standalone stream as a reconnect without progress and, after five, closes
// the session for good — every tool call then fails until the gateway is
// restarted (about 12 minutes after start with the old 120s value).
func TestUpstreamTransportHasNoClientTimeout(t *testing.T) {
	g := &gateway{cfg: config{upstream: "http://relay.invalid/mcp"}}
	tr := g.upstreamTransport()
	if tr.HTTPClient == nil {
		t.Fatal("no HTTP client: the bootstrap credential would not be attached")
	}
	if tr.HTTPClient.Timeout != 0 {
		t.Errorf("HTTPClient.Timeout = %v, want 0: it cuts long-lived response streams", tr.HTTPClient.Timeout)
	}
	if !tr.DisableStandaloneSSE {
		t.Error("standalone SSE stream enabled: the gateway forwards no server-initiated messages")
	}
}

// TestUpstreamOpensNoStandaloneStream checks the same thing end to end against
// a stateful relay, which is the configuration that failed: after connecting
// and calling a tool, the relay must have seen no GET at all.
func TestUpstreamOpensNoStandaloneStream(t *testing.T) {
	ctx := context.Background()

	upSrv := mcp.NewServer(&mcp.Implementation{Name: "relay", Version: "test"}, nil)
	upSrv.AddTool(&mcp.Tool{
		Name:        "echo",
		InputSchema: json.RawMessage(`{"type":"object"}`),
	}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return textResult("ok"), nil
	})
	sdk := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return upSrv }, nil)

	var gets atomic.Int32
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gets.Add(1)
		}
		sdk.ServeHTTP(w, r)
	}))
	t.Cleanup(relay.Close)

	g := &gateway{cfg: config{upstream: relay.URL}, audit: log.New(io.Discard, "", 0)}
	up, err := g.connectUpstream(ctx)
	if err != nil {
		t.Fatalf("connect upstream: %v", err)
	}
	t.Cleanup(func() { _ = up.Close() })

	if _, err := up.CallTool(ctx, &mcp.CallToolParams{Name: "echo"}); err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if n := gets.Load(); n != 0 {
		t.Errorf("relay saw %d GET request(s), want 0: the standalone stream is still opened", n)
	}
}

// restartableRelay is a stateful relay whose process can be "restarted": the
// URL stays the same, but every session it issued is forgotten, which is what
// a relay restart or its idle-session janitor does to the gateway. It records
// the Authorization header of every initialize request.
type restartableRelay struct {
	url string

	cur atomic.Pointer[http.Handler]

	mu    sync.Mutex
	inits []string // Authorization header of each initialize
}

func newRestartableRelay(t *testing.T) *restartableRelay {
	t.Helper()
	r := &restartableRelay{}
	r.restart()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPost {
			body, _ := io.ReadAll(req.Body)
			req.Body = io.NopCloser(bytes.NewReader(body))
			if bytes.Contains(body, []byte(`"method":"initialize"`)) {
				r.mu.Lock()
				r.inits = append(r.inits, req.Header.Get("Authorization"))
				r.mu.Unlock()
			}
		}
		(*r.cur.Load()).ServeHTTP(w, req)
	}))
	t.Cleanup(srv.Close)
	r.url = srv.URL
	return r
}

// restart replaces the relay's MCP server, dropping every session.
func (r *restartableRelay) restart() {
	srv := mcp.NewServer(&mcp.Implementation{Name: "relay", Version: "test"}, nil)
	srv.AddTool(&mcp.Tool{
		Name:        "echo",
		InputSchema: json.RawMessage(`{"type":"object"}`),
	}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return textResult("ok"), nil
	})
	var h http.Handler = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
	r.cur.Store(&h)
}

func (r *restartableRelay) initializeAuth() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.inits...)
}

func newUpstreamRig(t *testing.T, relay *restartableRelay, ua upstreamAuth) (*gateway, *syncBuf) {
	t.Helper()
	audit := &syncBuf{}
	g := &gateway{cfg: config{upstream: relay.url}, ua: ua, audit: log.New(audit, "", 0)}
	g.up = &upstreamSession{connect: g.connectUpstream, audit: g.audit}
	if _, err := g.up.session(); err != nil {
		t.Fatalf("connect upstream: %v", err)
	}
	t.Cleanup(func() { _ = g.up.Close() })
	return g, audit
}

// A relay restart used to kill the gateway: the relay answers the old session
// ID with 404, the SDK treats that as final, and every later call failed until
// the gateway was restarted. The session is now replaced and the call retried,
// so the caller never sees the restart.
func TestUpstreamReconnectsAfterRelayRestart(t *testing.T) {
	ctx := context.Background()
	relay := newRestartableRelay(t)
	g, audit := newUpstreamRig(t, relay, upstreamAuth{mode: upstreamAuthStatic})

	if _, err := g.up.CallTool(ctx, &mcp.CallToolParams{Name: "echo"}); err != nil {
		t.Fatalf("call before restart: %v", err)
	}
	relay.restart()
	for i := 0; i < 3; i++ {
		if _, err := g.up.CallTool(ctx, &mcp.CallToolParams{Name: "echo"}); err != nil {
			t.Fatalf("call %d after restart: %v", i+1, err)
		}
	}
	if n := len(relay.initializeAuth()); n != 2 {
		t.Errorf("relay saw %d initialize requests, want 2 (startup + one reconnect)", n)
	}
	if !strings.Contains(audit.String(), "upstream.session.lost") {
		t.Error("the lost session was not logged")
	}
}

// Calls in flight when the session is lost all recover, through one shared
// reconnect rather than one each.
func TestUpstreamConcurrentCallsShareOneReconnect(t *testing.T) {
	ctx := context.Background()
	relay := newRestartableRelay(t)
	g, _ := newUpstreamRig(t, relay, upstreamAuth{mode: upstreamAuthStatic})

	relay.restart()
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := g.up.CallTool(ctx, &mcp.CallToolParams{Name: "echo"}); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("call after restart: %v", err)
	}
	if n := len(relay.initializeAuth()); n != 2 {
		t.Errorf("relay saw %d initialize requests, want 2 (startup + one shared reconnect)", n)
	}
}

// The reconnect is triggered from inside a tool call, whose context carries
// that caller's own credential in passthrough mode. The new session must still
// be opened under the gateway's bootstrap credential: the SDK keeps the
// context it was connected with, so connecting under the caller's would put
// every later housekeeping request under that one caller's identity.
func TestUpstreamReconnectUsesBootstrapCredential(t *testing.T) {
	relay := newRestartableRelay(t)
	bootstrap := strings.Repeat("b", 64)
	g, _ := newUpstreamRig(t, relay, upstreamAuth{mode: upstreamAuthPassthrough, token: bootstrap})

	relay.restart()
	ctx := withUpstreamCredential(context.Background(), "Bearer "+strings.Repeat("c", 64))
	if _, err := g.up.CallTool(ctx, &mcp.CallToolParams{Name: "echo"}); err != nil {
		t.Fatalf("call after restart: %v", err)
	}
	for i, got := range relay.initializeAuth() {
		if got != "Bearer "+bootstrap {
			t.Errorf("initialize %d carried %q, want the bootstrap credential", i+1, got)
		}
	}
}
