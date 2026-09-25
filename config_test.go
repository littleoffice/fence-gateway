package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	oidc "github.com/coreos/go-oidc/v3/oidc"
)

func TestParseAuthTokensSingle(t *testing.T) {
	t.Setenv("MCP_AUTH_TOKEN", strings.Repeat("a", 40))
	t.Setenv("MCP_AUTH_TOKENS", "")
	t.Setenv("MCP_AUTH_TOKEN_FILE", "")
	toks, err := parseAuthTokens()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(toks) != 1 {
		t.Fatalf("want 1 token, got %d", len(toks))
	}
}

func TestParseAuthTokensRejectsShort(t *testing.T) {
	t.Setenv("MCP_AUTH_TOKEN", "tooshort")
	t.Setenv("MCP_AUTH_TOKENS", "")
	t.Setenv("MCP_AUTH_TOKEN_FILE", "")
	if _, err := parseAuthTokens(); err == nil {
		t.Fatal("short token was accepted; minimum length not enforced")
	}
}

func TestParseAuthTokensList(t *testing.T) {
	t.Setenv("MCP_AUTH_TOKEN", "")
	t.Setenv("MCP_AUTH_TOKENS", "alice:"+strings.Repeat("a", 40)+",bob:"+strings.Repeat("b", 40))
	t.Setenv("MCP_AUTH_TOKEN_FILE", "")
	toks, err := parseAuthTokens()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(toks) != 2 {
		t.Fatalf("want 2 tokens, got %d", len(toks))
	}
	identities := map[string]bool{}
	for _, id := range toks {
		identities[id] = true
	}
	if !identities["alice"] || !identities["bob"] {
		t.Errorf("identities not parsed: %v", identities)
	}
}

func TestParseAuthTokensFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "tokens")
	if err := os.WriteFile(f, []byte("# a comment\ncarol:"+strings.Repeat("c", 40)+"\n\n"+strings.Repeat("d", 40)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MCP_AUTH_TOKEN", "")
	t.Setenv("MCP_AUTH_TOKENS", "")
	t.Setenv("MCP_AUTH_TOKEN_FILE", f)
	toks, err := parseAuthTokens()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(toks) != 2 {
		t.Fatalf("want 2 tokens (comment and blank skipped), got %d", len(toks))
	}
}

func TestHTTPConfigTLSPairing(t *testing.T) {
	t.Setenv("MCP_PORT", "")
	t.Setenv("MCP_AUTH_TOKEN", "")
	t.Setenv("MCP_AUTH_TOKENS", "")
	t.Setenv("MCP_AUTH_TOKEN_FILE", "")

	t.Setenv("MCP_TLS_CERT", "/tmp/cert.pem")
	t.Setenv("MCP_TLS_KEY", "")
	if _, err := httpConfigFromEnv(); err == nil {
		t.Fatal("cert without key should be a config error")
	}

	t.Setenv("MCP_TLS_CERT", "/tmp/cert.pem")
	t.Setenv("MCP_TLS_KEY", "/tmp/key.pem")
	c, err := httpConfigFromEnv()
	if err != nil {
		t.Fatalf("cert+key should parse: %v", err)
	}
	if !c.tlsEnabled() {
		t.Error("tlsEnabled should be true when both are set")
	}
}

func TestHTTPModeToggle(t *testing.T) {
	t.Setenv("MCP_TLS_CERT", "")
	t.Setenv("MCP_TLS_KEY", "")
	t.Setenv("MCP_AUTH_TOKEN", "")
	t.Setenv("MCP_AUTH_TOKENS", "")
	t.Setenv("MCP_AUTH_TOKEN_FILE", "")

	t.Setenv("MCP_PORT", "")
	if c, _ := httpConfigFromEnv(); c.httpMode() {
		t.Error("empty MCP_PORT should be stdio mode")
	}
	t.Setenv("MCP_PORT", "9090")
	if c, _ := httpConfigFromEnv(); !c.httpMode() {
		t.Error("MCP_PORT set should be HTTP mode")
	}
}

// Several callers may reach the relay as one only when that was chosen. Left at
// the default, static mode would give every caller the same relay identity:
// one fetch history (so searxng_session_sources shows each what the others
// read) and one rate limit.
func TestCheckSharedRelayIdentity(t *testing.T) {
	one := map[tokenDigest]string{{1}: "alice"}
	two := map[tokenDigest]string{{1}: "alice", {2}: "bob"}
	oauth := &oauthSettings{verifier: &oidc.IDTokenVerifier{}}
	implicitStatic := upstreamAuth{mode: upstreamAuthStatic}
	explicitStatic := upstreamAuth{mode: upstreamAuthStatic, explicit: true}
	passthrough := upstreamAuth{mode: upstreamAuthPassthrough, explicit: true}

	cases := []struct {
		name    string
		ua      upstreamAuth
		hc      httpConfig
		wantErr bool
	}{
		{"stdio", implicitStatic, httpConfig{}, false},
		{"one static identity", implicitStatic, httpConfig{port: "9090", authTokens: one}, false},
		{"two identities, mode left at default", implicitStatic, httpConfig{port: "9090", authTokens: two}, true},
		{"OAuth, mode left at default", implicitStatic, httpConfig{port: "9090", oauth: oauth}, true},
		{"one identity plus OAuth, mode left at default", implicitStatic, httpConfig{port: "9090", authTokens: one, oauth: oauth}, true},
		{"two identities, static chosen", explicitStatic, httpConfig{port: "9090", authTokens: two}, false},
		{"OAuth, static chosen", explicitStatic, httpConfig{port: "9090", oauth: oauth}, false},
		{"two identities, passthrough", passthrough, httpConfig{port: "9090", authTokens: two}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkSharedRelayIdentity(c.ua, c.hc)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, c.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "UPSTREAM_MCP_AUTH_MODE=passthrough") {
				t.Errorf("error does not say how to fix it: %v", err)
			}
		})
	}
}

// Setting UPSTREAM_MCP_AUTH_MODE, even to the default value, counts as a choice.
func TestUpstreamAuthModeExplicit(t *testing.T) {
	t.Setenv("UPSTREAM_MCP_TOKEN_FILE", "")
	for env, want := range map[string]bool{"": false, "static": true, "passthrough": true} {
		t.Setenv("UPSTREAM_MCP_AUTH_MODE", env)
		ua, err := upstreamAuthFromEnv("tok")
		if err != nil {
			t.Fatalf("%q: %v", env, err)
		}
		if ua.explicit != want {
			t.Errorf("UPSTREAM_MCP_AUTH_MODE=%q: explicit = %v, want %v", env, ua.explicit, want)
		}
	}
}
