package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	testMCPToken     = "mcp-token-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testMetricsToken = "metrics-token-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// metricsHandler builds the gateway's HTTP handler with a metrics token (when
// metricsToken is not empty) and the given relay metrics source.
func metricsHandler(metricsToken string, rm *relayMetrics) (http.Handler, *metrics) {
	m := newMetrics()
	hc := httpConfig{authTokens: tokenTable(testMCPToken, "alice"), metrics: m, relayMetrics: rm}
	if metricsToken != "" {
		hc.metricsToken = sha256.Sum256([]byte("Bearer " + metricsToken))
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "t"}, nil)
	return newHTTPHandler(server, hc, nil), m
}

func get(t *testing.T, h http.Handler, path, authz string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// With no MCP_METRICS_TOKEN both endpoints are closed, even to a caller with
// a valid MCP token, and say which realm refused them rather than falling
// through to the MCP handler.
func TestMetricsClosedWithoutToken(t *testing.T) {
	h, m := metricsHandler("", nil)
	for _, path := range []string{"/metrics/gateway", "/metrics/relay"} {
		rr := get(t, h, path, "Bearer "+testMCPToken)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("GET %s = %d, want 401", path, rr.Code)
		}
		if got := rr.Header().Get("WWW-Authenticate"); got != `Bearer realm="metrics"` {
			t.Errorf("GET %s WWW-Authenticate = %q", path, got)
		}
	}
	if got := m.authFailures[authEndpointMetrics].Load(); got != 2 {
		t.Errorf("metrics auth failures = %d, want 2", got)
	}
}

func TestMetricsServedWithToken(t *testing.T) {
	h, _ := metricsHandler(testMetricsToken, nil)

	if rr := get(t, h, "/metrics/gateway", "Bearer "+testMCPToken); rr.Code != http.StatusUnauthorized {
		t.Fatalf("an MCP token on /metrics/gateway = %d, want 401", rr.Code)
	}
	// A refused scrape is itself counted, and the next one shows it.
	rr := get(t, h, "/metrics/gateway", "Bearer "+testMetricsToken)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /metrics/gateway = %d %q", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Errorf("Content-Type = %q", ct)
	}
	body := rr.Body.String()
	for _, want := range []string{
		"# TYPE fence_gateway_tool_calls_total counter",
		`fence_gateway_tool_calls_total{outcome="verified"} 0`,
		`fence_gateway_verification_failures_total{reason="invalid_fence"} 0`,
		`fence_gateway_auth_failures_total{endpoint="metrics"} 1`,
		`fence_gateway_upstream_call_duration_seconds_bucket{le="+Inf"} 0`,
		`fence_gateway_build_info{version="dev"} 1`,
	} {
		if !strings.Contains(body, want+"\n") {
			t.Errorf("/metrics/gateway lacks %q", want)
		}
	}
}

// Bare /metrics, Prometheus's default, points at the two real paths instead
// of falling through to the MCP handler.
func TestBareMetricsPathPointsOnward(t *testing.T) {
	h, _ := metricsHandler(testMetricsToken, nil)
	rr := get(t, h, "/metrics", "")
	if rr.Code != http.StatusNotFound || !strings.Contains(rr.Body.String(), "/metrics/gateway") {
		t.Fatalf("GET /metrics = %d %q, want 404 naming /metrics/gateway", rr.Code, rr.Body.String())
	}
}

// The metrics token is not an MCP token: holding it gets a scraper nothing on
// the MCP endpoint.
func TestMetricsTokenDoesNotOpenMCP(t *testing.T) {
	h, m := metricsHandler(testMetricsToken, nil)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+testMetricsToken)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("metrics token on / = %d, want 401", rr.Code)
	}
	if got := m.authFailures[authEndpointMCP].Load(); got != 1 {
		t.Errorf("mcp auth failures = %d, want 1", got)
	}
}

func TestMetricsTokenConfig(t *testing.T) {
	t.Run("too short", func(t *testing.T) {
		t.Setenv("MCP_METRICS_TOKEN", "short")
		if _, err := httpConfigFromEnv(); err == nil {
			t.Fatal("accepted a short MCP_METRICS_TOKEN")
		}
	})
	t.Run("same as an MCP token", func(t *testing.T) {
		t.Setenv("MCP_AUTH_TOKEN", testMCPToken)
		t.Setenv("MCP_METRICS_TOKEN", testMCPToken)
		if _, err := httpConfigFromEnv(); err == nil || !strings.Contains(err.Error(), "must not be one of") {
			t.Fatalf("err = %v, want a refusal to share the MCP token", err)
		}
	})
	t.Run("from files", func(t *testing.T) {
		dir := t.TempDir()
		mf := filepath.Join(dir, "metrics")
		rf := filepath.Join(dir, "relay")
		_ = os.WriteFile(mf, []byte(testMetricsToken+"\n"), 0o600)
		_ = os.WriteFile(rf, []byte("relay-secret\n"), 0o600)
		t.Setenv("MCP_METRICS_TOKEN_FILE", mf)
		t.Setenv("UPSTREAM_METRICS_TOKEN_FILE", rf)
		c, err := httpConfigFromEnv()
		if err != nil {
			t.Fatal(err)
		}
		if c.metricsToken != sha256.Sum256([]byte("Bearer "+testMetricsToken)) || c.relayMetricsToken != "relay-secret" {
			t.Fatalf("tokens not read from files: relay=%q", c.relayMetricsToken)
		}
	})
	t.Run("value and file", func(t *testing.T) {
		t.Setenv("UPSTREAM_METRICS_TOKEN", "x")
		t.Setenv("UPSTREAM_METRICS_TOKEN_FILE", "/nonexistent")
		if _, err := httpConfigFromEnv(); err == nil {
			t.Fatal("accepted both UPSTREAM_METRICS_TOKEN and its _FILE")
		}
	})
	t.Run("URL without token", func(t *testing.T) {
		t.Setenv("UPSTREAM_METRICS_URL", "http://relay:8080/metrics")
		if _, err := httpConfigFromEnv(); err == nil {
			t.Fatal("accepted UPSTREAM_METRICS_URL without UPSTREAM_METRICS_TOKEN")
		}
	})
	t.Run("bad URL", func(t *testing.T) {
		t.Setenv("UPSTREAM_METRICS_TOKEN", "x")
		t.Setenv("UPSTREAM_METRICS_URL", "relay:8080/metrics")
		if _, err := httpConfigFromEnv(); err == nil {
			t.Fatal("accepted a URL with no scheme")
		}
	})
}

func TestUpstreamPathForMetrics(t *testing.T) {
	if got := upstreamPath("https://relay.internal:8080/mcp", "/metrics"); got != "https://relay.internal:8080/metrics" {
		t.Fatalf("upstreamPath = %q", got)
	}
}

// fakeRelayMetrics serves /metrics behind token, as the relay does.
func fakeRelayMetrics(t *testing.T, token string) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/redirect":
			http.Redirect(w, r, "/metrics", http.StatusFound)
		case r.Header.Get("Authorization") != "Bearer "+token:
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		default:
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			_, _ = io.WriteString(w, "mcp_searches_total 7\n")
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func TestRelayMetricsForwarded(t *testing.T) {
	relay := fakeRelayMetrics(t, "relay-secret")
	m := newMetrics()
	h, _ := metricsHandler(testMetricsToken, newRelayMetrics(relay.URL+"/metrics", "relay-secret", nil, m))

	if rr := get(t, h, "/metrics/relay", "Bearer relay-secret"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("the relay's own token at the gateway = %d, want 401", rr.Code)
	}
	rr := get(t, h, "/metrics/relay", "Bearer "+testMetricsToken)
	if rr.Code != http.StatusOK || rr.Body.String() != "mcp_searches_total 7\n" {
		t.Fatalf("GET /metrics/relay = %d %q", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "text/plain; version=0.0.4" {
		t.Errorf("Content-Type = %q, want the relay's", ct)
	}
	if m.relayScrapes.Load() != 0 {
		t.Errorf("a good fetch counted as an error")
	}
}

func TestRelayMetricsFailures(t *testing.T) {
	relay := fakeRelayMetrics(t, "relay-secret")
	for name, rm := range map[string]func(*metrics) *relayMetrics{
		"wrong relay token": func(m *metrics) *relayMetrics {
			return newRelayMetrics(relay.URL+"/metrics", "wrong", nil, m)
		},
		"redirect not followed": func(m *metrics) *relayMetrics {
			return newRelayMetrics(relay.URL+"/redirect", "relay-secret", nil, m)
		},
		"relay down": func(m *metrics) *relayMetrics {
			return newRelayMetrics("http://127.0.0.1:1/metrics", "relay-secret", nil, m)
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := newMetrics()
			h, _ := metricsHandler(testMetricsToken, rm(m))
			rr := get(t, h, "/metrics/relay", "Bearer "+testMetricsToken)
			if rr.Code != http.StatusBadGateway {
				t.Fatalf("GET /metrics/relay = %d, want 502", rr.Code)
			}
			if strings.Contains(rr.Body.String(), "127.0.0.1") {
				t.Errorf("502 body leaks the relay address: %q", rr.Body.String())
			}
			if m.relayScrapes.Load() != 1 {
				t.Errorf("relay metrics errors = %d, want 1", m.relayScrapes.Load())
			}
		})
	}
}

func TestRelayMetricsNotConfigured(t *testing.T) {
	h, _ := metricsHandler(testMetricsToken, nil)
	if rr := get(t, h, "/metrics/relay", "Bearer "+testMetricsToken); rr.Code != http.StatusNotFound {
		t.Fatalf("GET /metrics/relay unconfigured = %d, want 404", rr.Code)
	}
}

// Each verification outcome lands under its own label, and a failure under
// the reason that caused it.
func TestVerifyOutcomesCounted(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	good := mustFence(t, priv, "The risotto was divine.")
	tampered := strings.Replace(good, "divine", "awful!", 1)
	ctx := context.Background()

	cases := []struct {
		policy  Policy
		pub     ed25519.PublicKey
		res     *mcp.CallToolResult
		outcome callOutcome
		reason  failReason // -1 for none
	}{
		{PolicyReject, pub, textResult(good), outcomeVerified, -1},
		{PolicyReject, pub, textResult(relayNoResults), outcomeUnfenced, -1},
		{PolicyReject, pub, textResult(tampered), outcomeRejected, reasonInvalidFence},
		{PolicyAnnotate, pub, textResult(tampered), outcomeAnnotated, reasonInvalidFence},
		{PolicyAudit, pub, textResult(tampered), outcomePassedUnverified, reasonInvalidFence},
		{PolicyReject, pub, textResult("plain text"), outcomeRejected, reasonUnfencedText},
		{PolicyReject, nil, textResult(good), outcomeRejected, reasonNoKey},
	}
	for i, c := range cases {
		t.Run(fmt.Sprintf("%d_%s_%s", i, c.policy, outcomeLabels[c.outcome]), func(t *testing.T) {
			g := testGateway(c.policy, c.pub)
			g.hc.metrics = newMetrics()
			g.verify(ctx, "review", "alice", c.res)
			for o := callOutcome(0); o < numOutcomes; o++ {
				want := int64(0)
				if o == c.outcome {
					want = 1
				}
				if got := g.hc.metrics.toolCalls[o].Load(); got != want {
					t.Errorf("outcome %s = %d, want %d", outcomeLabels[o], got, want)
				}
			}
			for r := failReason(0); r < numReasons; r++ {
				want := int64(0)
				if r == c.reason {
					want = 1
				}
				if got := g.hc.metrics.failures[r].Load(); got != want {
					t.Errorf("reason %s = %d, want %d", reasonLabels[r], got, want)
				}
			}
		})
	}
}

// The full path: a tool call shows up in the gateway metrics.
func TestToolCallShowsInMetrics(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	g := testGateway(PolicyReject, pub)
	g.hc.metrics = newMetrics()
	g.up = &upstreamSession{connect: func(ctx context.Context) (*mcp.ClientSession, error) {
		up := mcp.NewServer(&mcp.Implementation{Name: "relay", Version: "t"}, nil)
		up.AddTool(&mcp.Tool{Name: "review", InputSchema: map[string]any{"type": "object"}},
			func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return textResult(mustFence(t, priv, "fine")), nil
			})
		st, ct := mcp.NewInMemoryTransports()
		if _, err := up.Connect(ctx, st, nil); err != nil {
			return nil, err
		}
		return mcp.NewClient(&mcp.Implementation{Name: "gw", Version: "t"}, nil).Connect(ctx, ct, nil)
	}}
	if _, err := g.toolHandler("review")(context.Background(), &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{}}); err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	if err := g.hc.metrics.write(&sb); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`fence_gateway_tool_calls_total{outcome="verified"} 1`,
		"fence_gateway_fences_verified_total 1",
		"fence_gateway_upstream_call_duration_seconds_count 1",
		`fence_gateway_upstream_call_duration_seconds_bucket{le="+Inf"} 1`,
	} {
		if !strings.Contains(sb.String(), want+"\n") {
			t.Errorf("metrics lack %q", want)
		}
	}
}
