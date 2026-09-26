package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
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

// fakeIDP is a token endpoint implementing the two grants the gateway uses:
// token exchange (RFC 8693) and client credentials. It knows two callers'
// tokens, and mints "relay-for-<user>" for them.
type fakeIDP struct {
	srv       *httptest.Server
	expiresIn int

	mu       sync.Mutex
	requests []map[string]string
}

const (
	idpClientID = "fence-gateway"
	idpSecret   = "s3cret"
	ownToken    = "gateway-own-token"
)

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	idp := &fakeIDP{expiresIn: 300}
	users := map[string]string{"alice-token": "alice", "bob-token": "bob"}
	idp.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		rec := map[string]string{}
		for k := range r.PostForm {
			rec[k] = r.PostForm.Get(k)
		}
		idp.mu.Lock()
		idp.requests = append(idp.requests, rec)
		idp.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if id, secret, ok := r.BasicAuth(); !ok || id != idpClientID || secret != idpSecret {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"invalid_client"}`)
			return
		}
		switch rec["grant_type"] {
		case grantClientCredentials:
			_, _ = fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":%d}`, ownToken, idp.expiresIn)
		case grantTokenExchange:
			user, ok := users[rec["subject_token"]]
			if !ok || rec["subject_token_type"] != tokenTypeAccessToken {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"error":"invalid_grant","error_description":"subject token not trusted"}`)
				return
			}
			_, _ = fmt.Fprintf(w, `{"access_token":"relay-for-%s","issued_token_type":%q,"token_type":"Bearer","expires_in":%d}`,
				user, tokenTypeAccessToken, idp.expiresIn)
		default:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"unsupported_grant_type"}`)
		}
	}))
	t.Cleanup(idp.srv.Close)
	return idp
}

func (idp *fakeIDP) log() []map[string]string {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return append([]map[string]string(nil), idp.requests...)
}

func (idp *fakeIDP) exchanger(delegation bool) *tokenExchanger {
	return newTokenExchanger(exchangeConfig{
		tokenURL: idp.srv.URL, clientID: idpClientID, clientSecret: idpSecret,
		audience: "mcp-searxng-relay", delegation: delegation,
	}, nil)
}

func TestExchangeTradesAndCaches(t *testing.T) {
	idp := newFakeIDP(t)
	x := idp.exchanger(false)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		tok, err := x.Exchange(ctx, "alice-token")
		if err != nil || tok != "relay-for-alice" {
			t.Fatalf("Exchange(alice) = %q, %v", tok, err)
		}
	}
	if tok, err := x.Exchange(ctx, "bob-token"); err != nil || tok != "relay-for-bob" {
		t.Fatalf("Exchange(bob) = %q, %v", tok, err)
	}
	reqs := idp.log()
	if len(reqs) != 2 {
		t.Fatalf("token endpoint called %d times for 4 exchanges of 2 callers, want 2 (cached)", len(reqs))
	}
	r := reqs[0]
	if r["grant_type"] != grantTokenExchange || r["audience"] != "mcp-searxng-relay" ||
		r["requested_token_type"] != tokenTypeAccessToken {
		t.Errorf("unexpected exchange request: %v", r)
	}
	if _, ok := r["actor_token"]; ok {
		t.Error("impersonation sent an actor_token")
	}
}

// A token about to expire is exchanged again rather than handed to the relay.
func TestExchangeRenewsExpiringTokens(t *testing.T) {
	idp := newFakeIDP(t)
	idp.expiresIn = 1 // below the early-renewal margin: cached for half a second
	x := idp.exchanger(false)
	_, _ = x.Exchange(context.Background(), "alice-token")
	x.mu.Lock()
	for k, c := range x.byToken {
		c.expires = c.expires.Add(-exchangeDefaultLifetime)
		x.byToken[k] = c
	}
	x.mu.Unlock()
	_, _ = x.Exchange(context.Background(), "alice-token")
	if n := len(idp.log()); n != 2 {
		t.Errorf("token endpoint called %d times, want 2 (expired token renewed)", n)
	}
}

// Delegation sends the gateway's own token as actor_token, so the exchanged
// token names the gateway as acting for the user.
func TestExchangeDelegationSendsActorToken(t *testing.T) {
	idp := newFakeIDP(t)
	x := idp.exchanger(true)
	if _, err := x.Exchange(context.Background(), "alice-token"); err != nil {
		t.Fatal(err)
	}
	reqs := idp.log()
	if len(reqs) != 2 || reqs[0]["grant_type"] != grantClientCredentials {
		t.Fatalf("want a client_credentials request, then the exchange; got %v", reqs)
	}
	if reqs[1]["actor_token"] != ownToken || reqs[1]["actor_token_type"] != tokenTypeAccessToken {
		t.Errorf("exchange did not carry the gateway's token as actor: %v", reqs[1])
	}
}

func TestExchangeRefusalIsAnError(t *testing.T) {
	idp := newFakeIDP(t)
	_, err := idp.exchanger(false).Exchange(context.Background(), "mallory-token")
	if err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("want the provider's refusal, got %v", err)
	}
}

func TestExchangeConfigFromEnv(t *testing.T) {
	reset := func() {
		for _, k := range []string{"UPSTREAM_OAUTH_TOKEN_URL", "UPSTREAM_OAUTH_CLIENT_ID", "UPSTREAM_OAUTH_CLIENT_SECRET",
			"UPSTREAM_OAUTH_CLIENT_SECRET_FILE", "UPSTREAM_OAUTH_AUDIENCE", "UPSTREAM_OAUTH_DELEGATION"} {
			t.Setenv(k, "")
		}
	}

	t.Run("other modes ignore nothing", func(t *testing.T) {
		reset()
		if c, err := exchangeConfigFromEnv(upstreamAuthStatic); c != nil || err != nil {
			t.Fatalf("got %v, %v", c, err)
		}
		t.Setenv("UPSTREAM_OAUTH_CLIENT_ID", "x")
		if _, err := exchangeConfigFromEnv(upstreamAuthPassthrough); err == nil {
			t.Fatal("UPSTREAM_OAUTH_* outside exchange mode was accepted")
		}
	})

	t.Run("missing settings are named", func(t *testing.T) {
		reset()
		_, err := exchangeConfigFromEnv(upstreamAuthExchange)
		if err == nil || !strings.Contains(err.Error(), "UPSTREAM_OAUTH_TOKEN_URL") ||
			!strings.Contains(err.Error(), "UPSTREAM_OAUTH_CLIENT_SECRET") {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("plain http to another host is refused", func(t *testing.T) {
		reset()
		t.Setenv("UPSTREAM_OAUTH_TOKEN_URL", "http://auth.internal/application/o/token/")
		t.Setenv("UPSTREAM_OAUTH_CLIENT_ID", "gw")
		t.Setenv("UPSTREAM_OAUTH_CLIENT_SECRET", "s")
		if _, err := exchangeConfigFromEnv(upstreamAuthExchange); err == nil {
			t.Fatal("a plain-http token endpoint was accepted")
		}
	})

	t.Run("complete, secret from a file", func(t *testing.T) {
		reset()
		p := filepath.Join(t.TempDir(), "secret")
		if err := os.WriteFile(p, []byte("s3cret\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("UPSTREAM_OAUTH_TOKEN_URL", "https://auth.example.com/application/o/token/")
		t.Setenv("UPSTREAM_OAUTH_CLIENT_ID", "gw")
		t.Setenv("UPSTREAM_OAUTH_CLIENT_SECRET_FILE", p)
		t.Setenv("UPSTREAM_OAUTH_DELEGATION", "true")
		c, err := exchangeConfigFromEnv(upstreamAuthExchange)
		if err != nil || c.clientSecret != "s3cret" || !c.delegation {
			t.Fatalf("got %+v, %v", c, err)
		}
		t.Setenv("UPSTREAM_OAUTH_CLIENT_SECRET", "other")
		if _, err := exchangeConfigFromEnv(upstreamAuthExchange); err == nil {
			t.Fatal("both secret forms were accepted")
		}
	})
}

// exchangeRig: a relay recording the Authorization of every initialize and
// tools/call, a fake identity provider, and a gateway in exchange mode.
type exchangeRig struct {
	gatewayURL string
	idp        *fakeIDP

	mu    sync.Mutex
	inits []string
	calls []string
}

func startExchangeRig(t *testing.T, staticTokens map[tokenDigest]string) *exchangeRig {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	rig := &exchangeRig{idp: newFakeIDP(t)}

	upSrv := mcp.NewServer(&mcp.Implementation{Name: "relay", Version: "test"}, nil)
	upSrv.AddTool(&mcp.Tool{Name: "review", InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return textResult(mustFence(t, priv, "a review")), nil
		})
	sdk := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return upSrv }, nil)
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPost {
			body, _ := io.ReadAll(req.Body)
			req.Body = io.NopCloser(bytes.NewReader(body))
			rig.mu.Lock()
			switch {
			case bytes.Contains(body, []byte(`"method":"initialize"`)):
				rig.inits = append(rig.inits, req.Header.Get("Authorization"))
			case bytes.Contains(body, []byte(`"method":"tools/call"`)):
				rig.calls = append(rig.calls, req.Header.Get("Authorization"))
			}
			rig.mu.Unlock()
		}
		sdk.ServeHTTP(w, req)
	}))
	t.Cleanup(relay.Close)

	audit := log.New(io.Discard, "", 0)
	g := &gateway{
		cfg:       config{policy: PolicyReject, upstream: relay.URL},
		hc:        httpConfig{authTokens: staticTokens},
		ua:        upstreamAuth{mode: upstreamAuthExchange, explicit: true},
		keys:      &fv.StaticKeys{K: []ed25519.PublicKey{pub}},
		audit:     audit,
		exchanger: rig.idp.exchanger(false),
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

func (r *exchangeRig) callAs(t *testing.T, token string) *mcp.CallToolResult {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "test"}, nil)
	sess, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:   r.gatewayURL,
		HTTPClient: &http.Client{Transport: &authTransport{token: token, base: http.DefaultTransport}},
	}, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer func() { _ = sess.Close() }()
	res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{Name: "review"})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	return res
}

// End to end: each caller's token is exchanged, the relay only ever sees
// relay tokens (never a caller's own), and the gateway's own housekeeping
// uses its client_credentials token — no static secret shared with the relay.
func TestExchangeModeEndToEnd(t *testing.T) {
	rig := startExchangeRig(t, nil)
	for _, tok := range []string{"alice-token", "bob-token", "alice-token"} {
		if res := rig.callAs(t, tok); res.IsError {
			t.Fatalf("call as %s was blocked: %+v", tok, res.Content)
		}
	}
	rig.mu.Lock()
	defer rig.mu.Unlock()
	want := []string{"Bearer relay-for-alice", "Bearer relay-for-bob", "Bearer relay-for-alice"}
	if strings.Join(rig.calls, ",") != strings.Join(want, ",") {
		t.Errorf("relay saw tool calls with %q, want %q", rig.calls, want)
	}
	for _, a := range rig.inits {
		if a != "Bearer "+ownToken {
			t.Errorf("initialize carried %q, want the gateway's own token", a)
		}
	}
}

// Fail closed: a caller holding a static gateway token has nothing the
// provider can exchange, and is blocked rather than sent under any other
// credential. (A token the provider refuses is covered by
// TestExchangeRefusalIsAnError; the handler treats both the same way.)
func TestExchangeModeFailsClosed(t *testing.T) {
	static := strings.Repeat("s", 40)
	rig := startExchangeRig(t, map[tokenDigest]string{sha256.Sum256([]byte("Bearer " + static)): "ci"})

	if res := rig.callAs(t, static); !res.IsError {
		t.Error("a static-token caller was not blocked in exchange mode")
	}
	rig.mu.Lock()
	n := len(rig.calls)
	rig.mu.Unlock()
	if n != 0 {
		t.Errorf("relay received %d tool calls from refused callers, want 0", n)
	}
}

func TestExchangeCountsAsPerCaller(t *testing.T) {
	two := map[tokenDigest]string{{1}: "a", {2}: "b"}
	if err := checkSharedRelayIdentity(upstreamAuth{mode: upstreamAuthExchange, explicit: true},
		httpConfig{port: "9090", authTokens: two}); err != nil {
		t.Errorf("exchange mode refused as shared identity: %v", err)
	}
	if !(upstreamAuth{mode: upstreamAuthExchange}).perCaller() {
		t.Error("exchange is not per-caller")
	}
}
