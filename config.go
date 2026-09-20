package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
)

// minAuthTokenLen is the floor for a downstream bearer token. 32 characters is
// 128 bits at hex encoding — the standard floor for a token that must resist
// online brute force. `openssl rand -hex 32` yields 64. The minimum only rules
// out trivially weak values.
const minAuthTokenLen = 32

// tokenDigest is the SHA-256 of a full "Bearer <token>" header value. Storing
// digests keeps raw tokens out of process memory after parsing, and a
// fixed-length comparison cannot leak token length through timing.
type tokenDigest [32]byte

// httpConfig is the deployment configuration for HTTP (remote) mode. It is read
// from the environment, mirroring mcp-searxng-relay's variable names, and is
// separate from the verification flags (which configure what the gateway
// checks, not how it is served).
type httpConfig struct {
	// port is MCP_PORT. When empty the gateway runs over stdio; when set it
	// serves the Streamable HTTP transport on that port.
	port string
	// authTokens maps the digest of an accepted "Bearer <token>" header to a
	// human-readable identity, for authenticating downstream clients.
	authTokens map[tokenDigest]string
	// tlsCert / tlsKey are MCP_TLS_CERT / MCP_TLS_KEY. Both or neither.
	tlsCert string
	tlsKey  string
	// oauth is the compiled OAuth/OIDC verifier, or nil when OAuth is off. It
	// is populated in main() (not here) because issuer-discovery mode makes a
	// network call, which config parsing and tests should not.
	oauth *oauthSettings
	// trustForwarded is MCP_TRUST_FORWARDED_HEADERS: honour X-Forwarded-Proto /
	// X-Forwarded-Host when building the OAuth resource-metadata URL. Off by
	// default — an unauthenticated caller must not get to nominate the issuer.
	trustForwarded bool
}

func httpConfigFromEnv() (httpConfig, error) {
	c := httpConfig{
		port:           strings.TrimSpace(os.Getenv("MCP_PORT")),
		tlsCert:        strings.TrimSpace(os.Getenv("MCP_TLS_CERT")),
		tlsKey:         strings.TrimSpace(os.Getenv("MCP_TLS_KEY")),
		trustForwarded: parseBool(os.Getenv("MCP_TRUST_FORWARDED_HEADERS")),
	}
	if (c.tlsCert == "") != (c.tlsKey == "") {
		return c, fmt.Errorf("MCP_TLS_CERT and MCP_TLS_KEY must be set together (got cert=%t key=%t)",
			c.tlsCert != "", c.tlsKey != "")
	}
	tokens, err := parseAuthTokens()
	if err != nil {
		return c, err
	}
	c.authTokens = tokens
	return c, nil
}

func (c httpConfig) httpMode() bool   { return c.port != "" }
func (c httpConfig) tlsEnabled() bool { return c.tlsCert != "" && c.tlsKey != "" }

// parseAuthTokens builds the downstream bearer-token table from, in order,
// MCP_AUTH_TOKEN (a single token), MCP_AUTH_TOKENS (comma-separated, each
// optionally "identity:token"), and MCP_AUTH_TOKEN_FILE (one per line, "#"
// comments allowed). Any token shorter than minAuthTokenLen fails startup — the
// same fail-loud stance the relay takes, so a weak token is never silently
// accepted. An empty table is returned without error; runHTTP rejects it,
// because stdio mode legitimately has no downstream auth.
func parseAuthTokens() (map[tokenDigest]string, error) {
	out := map[tokenDigest]string{}

	add := func(identity, token string) error {
		token = strings.TrimSpace(token)
		if token == "" {
			return nil
		}
		if len(token) < minAuthTokenLen {
			return fmt.Errorf("auth token %q is %d characters; minimum is %d (generate one with `openssl rand -hex 32`)",
				identity, len(token), minAuthTokenLen)
		}
		if identity == "" {
			identity = "default"
		}
		out[sha256.Sum256([]byte("Bearer "+token))] = identity
		return nil
	}

	if v := strings.TrimSpace(os.Getenv("MCP_AUTH_TOKEN")); v != "" {
		if err := add("default", v); err != nil {
			return nil, err
		}
	}

	for _, entry := range splitCSV(os.Getenv("MCP_AUTH_TOKENS")) {
		identity, token := splitIdentityToken(entry)
		if err := add(identity, token); err != nil {
			return nil, err
		}
	}

	if f := strings.TrimSpace(os.Getenv("MCP_AUTH_TOKEN_FILE")); f != "" {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("read MCP_AUTH_TOKEN_FILE: %w", err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			identity, token := splitIdentityToken(line)
			if err := add(identity, token); err != nil {
				return nil, err
			}
		}
	}

	return out, nil
}

// splitIdentityToken splits an "identity:token" entry. With no colon the whole
// string is the token and the identity is left empty (defaulted by add).
func splitIdentityToken(s string) (identity, token string) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, ':'); i >= 0 {
		return strings.TrimSpace(s[:i]), s[i+1:]
	}
	return "", s
}

// parseBool reads a permissive boolean: 1/true/yes/on (any case) are true,
// everything else — including empty — is false.
func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// splitCSV splits on commas and drops empty fields after trimming.
func splitCSV(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}
