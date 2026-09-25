package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
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
