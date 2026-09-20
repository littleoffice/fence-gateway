package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	jwt "github.com/go-jose/go-jose/v4/jwt"
)

const (
	oauthTestIssuer = "https://issuer.test"
	oauthTestAud    = "https://gateway.test"
)

// setOAuthEnv sets the MCP_OAUTH_* environment for a test (clearing any key not
// provided), restored automatically by t.Setenv at the end of the test.
func setOAuthEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for _, k := range []string{
		"MCP_OAUTH_ISSUER", "MCP_OAUTH_AUDIENCE", "MCP_OAUTH_JWKS_FILE",
		"MCP_OAUTH_IDENTITY_CLAIM", "MCP_OAUTH_REQUIRED_SCOPE", "MCP_OAUTH_CA_ROOTS",
	} {
		t.Setenv(k, kv[k])
	}
}

func oauthTestKey(t *testing.T, kid string) (*rsa.PrivateKey, jose.JSONWebKey) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k, jose.JSONWebKey{Key: &k.PublicKey, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"}
}

func oauthSignToken(t *testing.T, priv *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func oauthWriteJWKS(t *testing.T, path string, keys ...jose.JSONWebKey) {
	t.Helper()
	b, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func oauthBaseClaims() map[string]any {
	return map[string]any{
		"iss":   oauthTestIssuer,
		"aud":   oauthTestAud,
		"sub":   "user-123",
		"scope": "search read",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	}
}

// fileModeSettings builds an OAuth verifier in static-JWKS-file mode (no
// network) for tests, through the real newOAuthSettings constructor.
func fileModeSettings(t *testing.T, jwksPath string, extra map[string]string) *oauthSettings {
	t.Helper()
	setOAuthEnv(t, map[string]string{
		"MCP_OAUTH_ISSUER":         oauthTestIssuer,
		"MCP_OAUTH_AUDIENCE":       oauthTestAud,
		"MCP_OAUTH_JWKS_FILE":      jwksPath,
		"MCP_OAUTH_IDENTITY_CLAIM": extra["identity_claim"],
		"MCP_OAUTH_REQUIRED_SCOPE": extra["required_scope"],
	})
	o, err := newOAuthSettings(context.Background())
	if err != nil {
		t.Fatalf("newOAuthSettings: %v", err)
	}
	if !o.enabled() {
		t.Fatal("expected OAuth to be enabled")
	}
	return o
}

// ── newOAuthSettings validation matrix ────────────────────────────────────────

func TestNewOAuthSettings_OffByDefault(t *testing.T) {
	setOAuthEnv(t, nil)
	o, err := newOAuthSettings(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if o.enabled() {
		t.Fatal("OAuth should be off with no MCP_OAUTH_* set")
	}
}

func TestNewOAuthSettings_HalfConfiguredFails(t *testing.T) {
	setOAuthEnv(t, map[string]string{"MCP_OAUTH_AUDIENCE": oauthTestAud}) // audience, no issuer
	if _, err := newOAuthSettings(context.Background()); err == nil {
		t.Fatal("expected error when MCP_OAUTH_AUDIENCE is set without an issuer")
	}
}

func TestNewOAuthSettings_MissingAudienceFails(t *testing.T) {
	setOAuthEnv(t, map[string]string{"MCP_OAUTH_ISSUER": oauthTestIssuer})
	if _, err := newOAuthSettings(context.Background()); err == nil {
		t.Fatal("expected error when issuer is set without an audience")
	}
}

func TestNewOAuthSettings_BadIssuerURLFails(t *testing.T) {
	setOAuthEnv(t, map[string]string{"MCP_OAUTH_ISSUER": "not-a-url", "MCP_OAUTH_AUDIENCE": oauthTestAud})
	if _, err := newOAuthSettings(context.Background()); err == nil {
		t.Fatal("expected error for a non-absolute issuer URL")
	}
}

func TestNewOAuthSettings_UnreadableJWKSFileFails(t *testing.T) {
	setOAuthEnv(t, map[string]string{
		"MCP_OAUTH_ISSUER":    oauthTestIssuer,
		"MCP_OAUTH_AUDIENCE":  oauthTestAud,
		"MCP_OAUTH_JWKS_FILE": filepath.Join(t.TempDir(), "does-not-exist.json"),
	})
	if _, err := newOAuthSettings(context.Background()); err == nil {
		t.Fatal("expected error for a missing JWKS file")
	}
}

// ── file mode: verification, claims, hot reload ───────────────────────────────

func TestOAuthFileMode_VerifyAndClaims(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jwks.json")
	priv, pub := oauthTestKey(t, "k1")
	oauthWriteJWKS(t, path, pub)

	o := fileModeSettings(t, path, nil)
	ctx := context.Background()

	id, err := o.Verify(ctx, oauthSignToken(t, priv, "k1", oauthBaseClaims()))
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if id != "user-123" {
		t.Fatalf("identity = %q, want the sub", id)
	}

	// Wrong audience.
	bad := oauthBaseClaims()
	bad["aud"] = "https://elsewhere.test"
	if _, err := o.Verify(ctx, oauthSignToken(t, priv, "k1", bad)); err == nil {
		t.Fatal("token for another audience was accepted")
	}

	// Expired.
	exp := oauthBaseClaims()
	exp["exp"] = time.Now().Add(-time.Minute).Unix()
	if _, err := o.Verify(ctx, oauthSignToken(t, priv, "k1", exp)); err == nil {
		t.Fatal("expired token was accepted")
	}
}

func TestOAuthFileMode_CustomIdentityClaim(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jwks.json")
	priv, pub := oauthTestKey(t, "k1")
	oauthWriteJWKS(t, path, pub)

	o := fileModeSettings(t, path, map[string]string{"identity_claim": "email"})
	claims := oauthBaseClaims()
	claims["email"] = "alice@example.com"

	id, err := o.Verify(context.Background(), oauthSignToken(t, priv, "k1", claims))
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if id != "alice@example.com" {
		t.Fatalf("identity = %q, want the email claim", id)
	}
}

func TestOAuthFileMode_RequiredScope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jwks.json")
	priv, pub := oauthTestKey(t, "k1")
	oauthWriteJWKS(t, path, pub)

	o := fileModeSettings(t, path, map[string]string{"required_scope": "admin"})

	if _, err := o.Verify(context.Background(), oauthSignToken(t, priv, "k1", oauthBaseClaims())); err == nil {
		t.Fatal("token missing the required scope was accepted")
	}
	ok := oauthBaseClaims()
	ok["scope"] = "search admin"
	if _, err := o.Verify(context.Background(), oauthSignToken(t, priv, "k1", ok)); err != nil {
		t.Fatalf("token with required scope rejected: %v", err)
	}
}

func TestOAuthFileMode_HotReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jwks.json")
	priv1, pub1 := oauthTestKey(t, "k1")
	oauthWriteJWKS(t, path, pub1)

	o := fileModeSettings(t, path, nil)
	ctx := context.Background()

	if _, err := o.Verify(ctx, oauthSignToken(t, priv1, "k1", oauthBaseClaims())); err != nil {
		t.Fatalf("token from initial key rejected: %v", err)
	}

	// Rotate the JWKS file to a new key; bump mtime so the change is detected.
	priv2, pub2 := oauthTestKey(t, "k2")
	oauthWriteJWKS(t, path, pub2)
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}

	if _, err := o.Verify(ctx, oauthSignToken(t, priv1, "k1", oauthBaseClaims())); err == nil {
		t.Fatal("token from the retired key still verified after rotation")
	}
	if _, err := o.Verify(ctx, oauthSignToken(t, priv2, "k2", oauthBaseClaims())); err != nil {
		t.Fatalf("token from the rotated-in key rejected: %v", err)
	}
}

// ── issuer discovery mode ─────────────────────────────────────────────────────

func TestOAuthIssuerMode_Discovery(t *testing.T) {
	priv, pub := oauthTestKey(t, "kA")

	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 srv.URL,
			"jwks_uri":               srv.URL + "/jwks",
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
	})
	srv = httptest.NewServer(mux) // plain HTTP, so the default discovery client reaches it
	defer srv.Close()

	setOAuthEnv(t, map[string]string{"MCP_OAUTH_ISSUER": srv.URL, "MCP_OAUTH_AUDIENCE": oauthTestAud})
	o, err := newOAuthSettings(context.Background())
	if err != nil {
		t.Fatalf("discovery failed: %v", err)
	}
	if o.mode != "issuer" {
		t.Fatalf("mode = %q, want issuer", o.mode)
	}

	claims := oauthBaseClaims()
	claims["iss"] = srv.URL
	id, err := o.Verify(context.Background(), oauthSignToken(t, priv, "kA", claims))
	if err != nil {
		t.Fatalf("valid token rejected in issuer mode: %v", err)
	}
	if id != "user-123" {
		t.Fatalf("identity = %q", id)
	}
}

// ── requireAuth: coexistence of static tokens and OAuth ───────────────────────

func TestRequireAuth_StaticAndOAuthCoexist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jwks.json")
	priv, pub := oauthTestKey(t, "k1")
	oauthWriteJWKS(t, path, pub)
	oauth := fileModeSettings(t, path, nil)

	staticTok := strings.Repeat("a", 40)
	hc := httpConfig{
		authTokens: tokenTable(staticTok, "static-alice"),
		oauth:      oauth,
	}
	h := requireAuth(hc, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	do := func(authz string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		if authz != "" {
			req.Header.Set("Authorization", authz)
		}
		h.ServeHTTP(rr, req)
		return rr
	}

	if rr := do("Bearer " + staticTok); rr.Code != http.StatusOK {
		t.Fatalf("static token: code=%d, want 200", rr.Code)
	}
	if rr := do("Bearer " + oauthSignToken(t, priv, "k1", oauthBaseClaims())); rr.Code != http.StatusOK {
		t.Fatalf("oauth token: code=%d, want 200", rr.Code)
	}
	rr := do("Bearer not-a-jwt")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("garbage token: code=%d, want 401", rr.Code)
	}
	if wa := rr.Header().Get("WWW-Authenticate"); !strings.Contains(wa, "resource_metadata=") {
		t.Fatalf("WWW-Authenticate = %q, want a resource_metadata parameter", wa)
	}
}

func TestRequireAuth_OpenWhenNothingConfigured(t *testing.T) {
	called := false
	h := requireAuth(httpConfig{}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/", nil))
	if !called || rr.Code != http.StatusOK {
		t.Fatalf("expected open pass-through, got code=%d called=%v", rr.Code, called)
	}
}

// ── metadata endpoint ─────────────────────────────────────────────────────────

func TestOAuthMetadataHandler(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jwks.json")
	_, pub := oauthTestKey(t, "k1")
	oauthWriteJWKS(t, path, pub)
	o := fileModeSettings(t, path, nil)

	rr := httptest.NewRecorder()
	o.metadataHandler()(rr, httptest.NewRequest(http.MethodGet, oauthMetadataPath, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d", rr.Code)
	}
	var doc map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["resource"] != oauthTestAud {
		t.Fatalf("resource = %v, want the audience", doc["resource"])
	}
	as, ok := doc["authorization_servers"].([]any)
	if !ok || len(as) != 1 || as[0] != oauthTestIssuer {
		t.Fatalf("authorization_servers = %v, want [issuer]", doc["authorization_servers"])
	}
}

func TestOAuthMetadataHandler_NotFoundWhenDisabled(t *testing.T) {
	var o *oauthSettings // disabled
	rr := httptest.NewRecorder()
	o.metadataHandler()(rr, httptest.NewRequest(http.MethodGet, oauthMetadataPath, nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("code = %d, want 404 when OAuth is off", rr.Code)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func TestBearerToken(t *testing.T) {
	cases := map[string]string{
		"Bearer abc":  "abc",
		"bearer abc":  "abc", // case-insensitive scheme
		"BEARER  abc": "abc", // trimmed
		"Basic abc":   "",
		"":            "",
		"Bearer":      "",
	}
	for in, want := range cases {
		if got := bearerToken(in); got != want {
			t.Errorf("bearerToken(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResourceMetadataURL_HonoursForwardedHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://internal:8080/", nil)
	req.Host = "internal:8080"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "gateway.example.com")
	got := resourceMetadataURL(req, true)
	want := "https://gateway.example.com" + oauthMetadataPath
	if got != want {
		t.Fatalf("resourceMetadataURL = %q, want %q", got, want)
	}
}

// Without the operator opting in, the URL must describe the connection the
// client actually made, not the one its headers claim — an unauthenticated
// caller reaches this path on every 401, so the header must not nominate the
// issuer a client discovers.
func TestResourceMetadataURL_IgnoresForwardedHeadersByDefault(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://internal:8080/", nil)
	req.Host = "internal:8080"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "attacker.example.com")

	got := resourceMetadataURL(req, false)
	want := "http://internal:8080" + oauthMetadataPath
	if got != want {
		t.Fatalf("resourceMetadataURL = %q, want %q", got, want)
	}
	if strings.Contains(got, "attacker.example.com") {
		t.Error("forwarded host reached the advertised metadata URL without the operator opting in")
	}
}
