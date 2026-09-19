package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
