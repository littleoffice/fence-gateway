package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ── OAuth 2.0 Token Exchange (RFC 8693) ──────────────────────────────────────
//
// In exchange mode the gateway never forwards a caller's token. It trades it
// at the identity provider for a token issued to the relay, for the same user,
// and presents that instead. The caller's own token is only good at the
// gateway, so a caller who can reach the relay directly still cannot use it
// there: the side door passthrough leaves open is closed by the tokens
// themselves, not only by the network.
//
// This works against any provider implementing RFC 8693: authentik (the token
// exchange grant, and on-behalf-of delegation from 2026.8), Keycloak (standard
// token exchange), and others. The relay needs no change: it already verifies
// OAuth tokens, and only has to be pointed at the provider that issues the
// exchanged ones.

const (
	grantTokenExchange     = "urn:ietf:params:oauth:grant-type:token-exchange"
	grantClientCredentials = "client_credentials"
	tokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"

	// exchangeEarlyRenewal treats a token as expired this long before it
	// is, so one never expires between the cache and the relay.
	exchangeEarlyRenewal = 30 * time.Second
	// exchangeDefaultLifetime is assumed when the provider reports no
	// expires_in.
	exchangeDefaultLifetime = 60 * time.Second
	// maxExchangedTokens bounds the cache of exchanged tokens.
	maxExchangedTokens = 1024
)

// exchangeConfig is the gateway's client registration at the identity provider.
type exchangeConfig struct {
	tokenURL     string
	clientID     string
	clientSecret string
	// audience, when set, is sent as the audience parameter: the relay's
	// client ID at the provider. Keycloak uses it to pick the target; a
	// provider that issues for the requesting client can leave it unset.
	audience string
	// delegation sends the gateway's own token as actor_token, so the
	// exchanged token names both the user (sub) and the gateway acting for
	// them (act). RFC 8693 delegation; authentik supports it from 2026.8.
	// Off, the exchange is impersonation: sub only.
	delegation bool
}

// exchangeConfigFromEnv reads the UPSTREAM_OAUTH_* variables. They are
// required in exchange mode and refused in any other, so a half-configured
// exchange fails startup rather than quietly falling back to another mode.
func exchangeConfigFromEnv(mode upstreamAuthMode) (*exchangeConfig, error) {
	c := &exchangeConfig{
		tokenURL:   strings.TrimSpace(os.Getenv("UPSTREAM_OAUTH_TOKEN_URL")),
		clientID:   strings.TrimSpace(os.Getenv("UPSTREAM_OAUTH_CLIENT_ID")),
		audience:   strings.TrimSpace(os.Getenv("UPSTREAM_OAUTH_AUDIENCE")),
		delegation: parseBool(os.Getenv("UPSTREAM_OAUTH_DELEGATION")),
	}
	secret := strings.TrimSpace(os.Getenv("UPSTREAM_OAUTH_CLIENT_SECRET"))
	secretFile := strings.TrimSpace(os.Getenv("UPSTREAM_OAUTH_CLIENT_SECRET_FILE"))
	anySet := c.tokenURL != "" || c.clientID != "" || c.audience != "" || secret != "" || secretFile != "" ||
		strings.TrimSpace(os.Getenv("UPSTREAM_OAUTH_DELEGATION")) != ""

	if mode != upstreamAuthExchange {
		if anySet {
			return nil, fmt.Errorf("UPSTREAM_OAUTH_* is set but UPSTREAM_MCP_AUTH_MODE is %q: "+
				"set UPSTREAM_MCP_AUTH_MODE=exchange to use it, or unset them", mode)
		}
		return nil, nil
	}

	switch {
	case secret != "" && secretFile != "":
		return nil, errors.New("set UPSTREAM_OAUTH_CLIENT_SECRET or UPSTREAM_OAUTH_CLIENT_SECRET_FILE, not both")
	case secretFile != "":
		b, err := os.ReadFile(secretFile)
		if err != nil {
			return nil, fmt.Errorf("read UPSTREAM_OAUTH_CLIENT_SECRET_FILE: %w", err)
		}
		secret = strings.TrimSpace(string(b))
	}
	c.clientSecret = secret

	var missing []string
	if c.tokenURL == "" {
		missing = append(missing, "UPSTREAM_OAUTH_TOKEN_URL")
	}
	if c.clientID == "" {
		missing = append(missing, "UPSTREAM_OAUTH_CLIENT_ID")
	}
	if c.clientSecret == "" {
		missing = append(missing, "UPSTREAM_OAUTH_CLIENT_SECRET (or _FILE)")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("UPSTREAM_MCP_AUTH_MODE=exchange needs %s", strings.Join(missing, ", "))
	}
	u, err := url.Parse(c.tokenURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname()))) {
		return nil, fmt.Errorf("UPSTREAM_OAUTH_TOKEN_URL %q must be an https:// URL "+
			"(plain http only to this machine): it carries the gateway's client secret and users' tokens", c.tokenURL)
	}
	return c, nil
}

// tokenExchanger trades callers' tokens for relay tokens, and fetches the
// gateway's own token, caching both until shortly before they expire.
type tokenExchanger struct {
	cfg    exchangeConfig
	client *http.Client

	mu      sync.Mutex
	byToken map[[32]byte]cachedToken // exchanged, by SHA-256 of the caller's token
	own     cachedToken              // client_credentials
}

type cachedToken struct {
	token   string
	expires time.Time
}

func (c cachedToken) valid(now time.Time) bool {
	return c.token != "" && now.Before(c.expires)
}

func newTokenExchanger(cfg exchangeConfig, client *http.Client) *tokenExchanger {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &tokenExchanger{cfg: cfg, client: client, byToken: make(map[[32]byte]cachedToken)}
}

// Exchange returns a relay token for the caller whose token is subject.
func (x *tokenExchanger) Exchange(ctx context.Context, subject string) (string, error) {
	key := sha256.Sum256([]byte(subject))
	now := time.Now()
	x.mu.Lock()
	if c, ok := x.byToken[key]; ok && c.valid(now) {
		x.mu.Unlock()
		return c.token, nil
	}
	x.mu.Unlock()

	form := url.Values{
		"grant_type":           {grantTokenExchange},
		"subject_token":        {subject},
		"subject_token_type":   {tokenTypeAccessToken},
		"requested_token_type": {tokenTypeAccessToken},
	}
	if x.cfg.audience != "" {
		form.Set("audience", x.cfg.audience)
	}
	if x.cfg.delegation {
		actor, err := x.Own(ctx)
		if err != nil {
			return "", fmt.Errorf("actor token for delegation: %w", err)
		}
		form.Set("actor_token", actor)
		form.Set("actor_token_type", tokenTypeAccessToken)
	}
	tok, err := x.request(ctx, form)
	if err != nil {
		return "", err
	}

	x.mu.Lock()
	defer x.mu.Unlock()
	if len(x.byToken) >= maxExchangedTokens {
		for k, c := range x.byToken {
			if !c.valid(now) {
				delete(x.byToken, k)
			}
		}
		if len(x.byToken) >= maxExchangedTokens {
			clear(x.byToken)
		}
	}
	x.byToken[key] = tok
	return tok.token, nil
}

// Own returns the gateway's own token (client_credentials). It authenticates
// the gateway's housekeeping with the relay — initialize and tools/list at
// startup, before any caller exists — and is the actor token in delegation.
func (x *tokenExchanger) Own(ctx context.Context) (string, error) {
	now := time.Now()
	x.mu.Lock()
	if x.own.valid(now) {
		t := x.own.token
		x.mu.Unlock()
		return t, nil
	}
	x.mu.Unlock()

	form := url.Values{"grant_type": {grantClientCredentials}}
	if x.cfg.audience != "" {
		form.Set("audience", x.cfg.audience)
	}
	tok, err := x.request(ctx, form)
	if err != nil {
		return "", err
	}
	x.mu.Lock()
	x.own = tok
	x.mu.Unlock()
	return tok.token, nil
}

// request posts form to the token endpoint, authenticating the gateway as a
// confidential client (HTTP Basic, which authentik and Keycloak both accept).
func (x *tokenExchanger) request(ctx context.Context, form url.Values) (cachedToken, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, x.cfg.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return cachedToken{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(x.cfg.clientID), url.QueryEscape(x.cfg.clientSecret))

	started := time.Now()
	resp, err := x.client.Do(req)
	if err != nil {
		return cachedToken{}, fmt.Errorf("token endpoint: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return cachedToken{}, fmt.Errorf("token endpoint: %w", err)
	}

	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &out)
	if resp.StatusCode != http.StatusOK {
		// The provider's error code and description name the problem (a
		// client not allowed to exchange, an untrusted subject token). They
		// go to the audit log, never to the model.
		if out.Error != "" {
			return cachedToken{}, fmt.Errorf("token endpoint returned %s: %s %s", resp.Status, out.Error, out.Description)
		}
		return cachedToken{}, fmt.Errorf("token endpoint returned %s", resp.Status)
	}
	if out.AccessToken == "" {
		return cachedToken{}, errors.New("token endpoint returned no access_token")
	}
	life := exchangeDefaultLifetime
	if out.ExpiresIn > 0 {
		life = time.Duration(out.ExpiresIn) * time.Second
	}
	expires := started.Add(life - exchangeEarlyRenewal)
	if life <= exchangeEarlyRenewal {
		expires = started.Add(life / 2)
	}
	return cachedToken{token: out.AccessToken, expires: expires}, nil
}
