package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// ── Metrics ───────────────────────────────────────────────────────────────────
//
// The gateway serves Prometheus text at GET /metrics, and the relay's own
// metrics at GET /metrics/relay. Both sit behind MCP_METRICS_TOKEN, a
// credential of their own: the relay's endpoint names the hosts fetched for
// every caller, and a scraper is not a tenant. With the token unset both
// endpoints answer 401 to everyone, the same closed default the relay takes.
//
// Forwarding the relay's metrics is what lets the relay stay reachable from
// the gateway alone (docs/deployment.md): Prometheus scrapes two paths on the
// gateway and needs no network path to the relay. They are separate paths, not
// one merged page, so each Prometheus job reports its own `up` — a relay that
// is down does not take the gateway's series with it.
//
// Hand-written, like the relay's, rather than pulling in client_golang: the
// series are a handful of counters and one histogram, and every label set is
// closed, fixed here, never taken from a request or a tool result.

// callOutcome is what happened to one tool call. Closed set: the label values
// of fence_gateway_tool_calls_total{outcome=...}.
type callOutcome int

const (
	// outcomeVerified: every fence verified and the result was delivered.
	outcomeVerified callOutcome = iota
	// outcomeUnfenced: delivered with nothing to verify — the relay's
	// no-results reply, an image, or a labelled error message.
	outcomeUnfenced
	// outcomeRejected: verification failed and the result was withheld.
	outcomeRejected
	// outcomeAnnotated: verification failed and the result was delivered
	// with a warning (-policy annotate).
	outcomeAnnotated
	// outcomePassedUnverified: verification failed or could not run, and
	// the result was delivered unchanged (-policy audit, or no key outside
	// -policy reject).
	outcomePassedUnverified
	// outcomeBlocked: never forwarded — no credential to send, or a token
	// exchange that failed.
	outcomeBlocked
	// outcomeUpstreamError: the call to the relay itself failed.
	outcomeUpstreamError
	numOutcomes
)

var outcomeLabels = [numOutcomes]string{
	"verified", "unfenced", "rejected", "annotated", "passed_unverified", "blocked", "upstream_error",
}

// failReason classifies why a result failed verification. Closed set: the
// label values of fence_gateway_verification_failures_total{reason=...}. The
// verifier's own messages stay in the audit log; they carry offsets and
// attacker-chosen text, and would be an unbounded label.
type failReason int

const (
	reasonNoKey              failReason = iota // no public key to verify with
	reasonTooLarge                             // over maxResultText
	reasonUnsupportedContent                   // structured content, resources, audio
	reasonInvalidFence                         // a fence that did not verify: signature, age, key, syntax
	reasonNoFence                              // fenced-looking text with no verifiable fence
	reasonUnfencedText                         // a text block carrying no fence at all
	reasonUnsignedText                         // unsigned text beside a fence (-require-all-fenced)
	reasonLayout                               // fences that verify but do not fit together
	reasonFormat                               // older fence format than required, or a downgrade
	numReasons
)

var reasonLabels = [numReasons]string{
	"no_key", "too_large", "unsupported_content", "invalid_fence", "no_fence",
	"unfenced_text", "unsigned_text", "layout", "format",
}

// failReasons is the set of reasons one result failed for. Each is counted
// once per call, however many fences tripped it.
type failReasons uint16

func (s *failReasons) add(r failReason) { *s |= 1 << r }

// authEndpoint labels fence_gateway_auth_failures_total{endpoint=...}.
type authEndpoint int

const (
	authEndpointMCP authEndpoint = iota
	authEndpointMetrics
	numAuthEndpoints
)

var authEndpointLabels = [numAuthEndpoints]string{"mcp", "metrics"}

// upstreamDurationBuckets are the upper bounds, in seconds, of the relay call
// histogram: from a cached read to a slow page fetch. The relay's own fetch
// timeout is 30s.
var upstreamDurationBuckets = []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}

// metrics holds the gateway's counters. Every method is safe on a nil
// receiver and does nothing, so code paths and tests that build a gateway
// without one need no special case.
type metrics struct {
	toolCalls      [numOutcomes]atomic.Int64
	failures       [numReasons]atomic.Int64
	fencesVerified atomic.Int64
	keyRotations   atomic.Int64
	sessionsLost   atomic.Int64
	authFailures   [numAuthEndpoints]atomic.Int64
	authThrottled  atomic.Int64
	relayScrapes   atomic.Int64 // failed /metrics/relay fetches

	// upstream call latency: a cumulative histogram, one count per bucket
	// plus +Inf, with the sum kept in microseconds.
	durBuckets [10]atomic.Int64 // len(upstreamDurationBuckets)+1
	durSumUS   atomic.Int64
	durCount   atomic.Int64
}

func newMetrics() *metrics { return &metrics{} }

func (m *metrics) recordCall(o callOutcome, why failReasons) {
	if m == nil {
		return
	}
	m.toolCalls[o].Add(1)
	for r := failReason(0); r < numReasons; r++ {
		if why&(1<<r) != 0 {
			m.failures[r].Add(1)
		}
	}
}

func (m *metrics) fenceVerified() {
	if m != nil {
		m.fencesVerified.Add(1)
	}
}

func (m *metrics) keyRotated() {
	if m != nil {
		m.keyRotations.Add(1)
	}
}

func (m *metrics) sessionLost() {
	if m != nil {
		m.sessionsLost.Add(1)
	}
}

func (m *metrics) authFailed(e authEndpoint) {
	if m != nil {
		m.authFailures[e].Add(1)
	}
}

func (m *metrics) authThrottle() {
	if m != nil {
		m.authThrottled.Add(1)
	}
}

func (m *metrics) relayScrapeFailed() {
	if m != nil {
		m.relayScrapes.Add(1)
	}
}

// observeUpstream records how long one call to the relay took, failed or not.
func (m *metrics) observeUpstream(d time.Duration) {
	if m == nil {
		return
	}
	s := d.Seconds()
	i := len(upstreamDurationBuckets)
	for j, b := range upstreamDurationBuckets {
		if s <= b {
			i = j
			break
		}
	}
	m.durBuckets[i].Add(1)
	m.durSumUS.Add(d.Microseconds())
	m.durCount.Add(1)
}

// ServeHTTP writes the Prometheus text exposition format, version 0.0.4.
func (m *metrics) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	m.write(w)
}

func (m *metrics) write(w io.Writer) {
	if m == nil {
		m = newMetrics()
	}
	header := func(name, typ, help string) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}

	header("fence_gateway_build_info", "gauge", "Build version of the running gateway; always 1.")
	fmt.Fprintf(w, "fence_gateway_build_info{version=%q} 1\n", escapeLabel(ServerVersion))

	header("fence_gateway_tool_calls_total", "counter",
		"Tool calls through the gateway, by what happened to the result.")
	for i, l := range outcomeLabels {
		fmt.Fprintf(w, "fence_gateway_tool_calls_total{outcome=%q} %d\n", l, m.toolCalls[i].Load())
	}

	header("fence_gateway_verification_failures_total", "counter",
		"Tool results that failed verification, by reason; a result failing for several reasons counts under each.")
	for i, l := range reasonLabels {
		fmt.Fprintf(w, "fence_gateway_verification_failures_total{reason=%q} %d\n", l, m.failures[i].Load())
	}

	header("fence_gateway_fences_verified_total", "counter", "Individual fences whose signature verified.")
	fmt.Fprintf(w, "fence_gateway_fences_verified_total %d\n", m.fencesVerified.Load())

	header("fence_gateway_key_rotations_total", "counter", "Changes of the relay's fence signing key seen by the gateway.")
	fmt.Fprintf(w, "fence_gateway_key_rotations_total %d\n", m.keyRotations.Load())

	header("fence_gateway_upstream_sessions_lost_total", "counter",
		"Relay sessions found gone (relay restart or idle expiry) and replaced.")
	fmt.Fprintf(w, "fence_gateway_upstream_sessions_lost_total %d\n", m.sessionsLost.Load())

	header("fence_gateway_auth_failures_total", "counter", "HTTP requests refused with 401, by endpoint.")
	for i, l := range authEndpointLabels {
		fmt.Fprintf(w, "fence_gateway_auth_failures_total{endpoint=%q} %d\n", l, m.authFailures[i].Load())
	}

	header("fence_gateway_auth_throttled_total", "counter",
		"MCP requests refused with 429 after too many failed logins from one client.")
	fmt.Fprintf(w, "fence_gateway_auth_throttled_total %d\n", m.authThrottled.Load())

	header("fence_gateway_relay_metrics_errors_total", "counter",
		"Failed fetches of the relay's /metrics for /metrics/relay.")
	fmt.Fprintf(w, "fence_gateway_relay_metrics_errors_total %d\n", m.relayScrapes.Load())

	const h = "fence_gateway_upstream_call_duration_seconds"
	header(h, "histogram", "Duration of tool calls to the relay, including failed ones.")
	var cum int64
	for i, b := range upstreamDurationBuckets {
		cum += m.durBuckets[i].Load()
		fmt.Fprintf(w, "%s_bucket{le=\"%g\"} %d\n", h, b, cum)
	}
	cum += m.durBuckets[len(upstreamDurationBuckets)].Load()
	fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n", h, cum)
	fmt.Fprintf(w, "%s_sum %g\n", h, float64(m.durSumUS.Load())/1e6)
	fmt.Fprintf(w, "%s_count %d\n", h, m.durCount.Load())
}

// escapeLabel keeps a label value to characters that need no escaping in the
// exposition format. Only the build version passes through it, and that is
// set at build time, but %q's Go escapes are not Prometheus's.
func escapeLabel(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' || r < ' ' || r > '~' {
			return '_'
		}
		return r
	}, s)
}

// requireMetricsAuth gates /metrics and /metrics/relay behind
// MCP_METRICS_TOKEN. With none configured every request is refused, including
// one carrying a valid MCP token: a closed endpoint until a credential exists
// discloses nothing, where falling back to the MCP tokens would hand every
// tenant the relay's per-host fetch counts.
//
// Not throttled like requireAuth: a digest comparison is cheap, there is no
// identity provider behind it to hammer, and a scraper refused with 429 leaves
// gaps that look like outages.
func requireMetricsAuth(hc httpConfig, audit *log.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hc.metricsEnabled() && sha256.Sum256([]byte(r.Header.Get("Authorization"))) == hc.metricsToken {
			next.ServeHTTP(w, r)
			return
		}
		hc.metrics.authFailed(authEndpointMetrics)
		if audit != nil {
			audit.Printf("auth.denied method=%s path=%q remote=%s configured=%t",
				r.Method, r.URL.Path, remoteHost(r), hc.metricsEnabled())
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

const (
	// relayMetricsTimeout bounds one fetch of the relay's /metrics. Below
	// Prometheus's default scrape timeout (10s), so a slow relay surfaces as
	// a 502 from the gateway rather than a scrape timeout with no reason.
	relayMetricsTimeout = 8 * time.Second
	// maxRelayMetricsBytes caps the relay's page. Its largest series is
	// per-domain, bounded at 512 hosts; a few hundred KiB is normal.
	maxRelayMetricsBytes = 8 << 20
)

// relayMetrics fetches the relay's /metrics on behalf of a scraper.
type relayMetrics struct {
	url    string
	token  string // the relay's MCP_METRICS_TOKEN
	client *http.Client
	audit  *log.Logger
	m      *metrics
}

func newRelayMetrics(url, token string, audit *log.Logger, m *metrics) *relayMetrics {
	return &relayMetrics{
		url: url, token: token, audit: audit, m: m,
		client: &http.Client{
			Timeout: relayMetricsTimeout,
			// The relay's token goes to the configured URL and nowhere a
			// redirect points; a 3xx is reported as a failure instead.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// ServeHTTP answers with the relay's metrics page, or 502 with a fixed message
// when it cannot be fetched. The reason goes to the audit log, not to the
// scraper.
func (rm *relayMetrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if rm == nil {
		http.Error(w, "relay metrics are not configured: set UPSTREAM_METRICS_TOKEN", http.StatusNotFound)
		return
	}
	body, ctype, err := rm.fetch(r.Context(), r.Header.Get("Accept"))
	if err != nil {
		rm.m.relayScrapeFailed()
		if rm.audit != nil {
			rm.audit.Printf("metrics.relay.failed url=%q err=%q", rm.url, err)
		}
		http.Error(w, "relay metrics unavailable; see the gateway audit log", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", ctype)
	_, _ = w.Write(body)
}

func (rm *relayMetrics) fetch(ctx context.Context, accept string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rm.url, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+rm.token)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := rm.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, "", fmt.Errorf("relay answered 401: UPSTREAM_METRICS_TOKEN must equal the relay's MCP_METRICS_TOKEN")
		}
		return nil, "", fmt.Errorf("relay answered %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRelayMetricsBytes+1))
	if err != nil {
		return nil, "", err
	}
	if len(body) > maxRelayMetricsBytes {
		return nil, "", fmt.Errorf("relay metrics exceed %d bytes", maxRelayMetricsBytes)
	}
	ctype := resp.Header.Get("Content-Type")
	if ctype == "" {
		ctype = "text/plain; version=0.0.4; charset=utf-8"
	}
	return body, ctype, nil
}
