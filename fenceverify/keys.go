package fenceverify

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// ── Key acquisition ───────────────────────────────────────────────────────────
//
// What a fence signature actually proves depends entirely on how the verifier
// learned the public key, and it is worth being blunt about the three cases
// because they are not equally useful.
//
//  1. Key fetched from the same server that produced the fence.
//     Proves: this fence was produced by whoever is serving /fence/public-key.
//     Against the paper's threat model (§2.2) this is sufficient and not
//     circular — the adversary there controls *content* that the relay
//     fetches, not the relay process. A malicious web page cannot mint
//     signatures no matter how many fake fences it embeds in its own body,
//     which is exactly the boundary-escape defence of §6.3.2.
//     Against a compromised or impersonated relay it proves nothing.
//
//  2. Key pinned by fingerprint in gateway configuration.
//     Proves: this fence came from the specific relay instance the operator
//     provisioned. This is what an audit trail needs — signatures become
//     evidence attributable to a named key rather than to "whatever answered
//     the request".
//
//  3. Trust on first use.
//     A middle option: pin whatever is seen first, alarm on change. Detects
//     substitution after the first contact, not at it.
//
// The relay currently mints a fresh keypair on every start, so (2) requires
// operator action after each restart and (1) or (3) is what most deployments
// will actually run. That is a property of the relay's key lifecycle, not of
// this gateway, and it is the single biggest limiter on what the signatures
// are worth today.

// KeySource supplies public keys to a Verifier and can refresh them.
type KeySource interface {
	// Keys returns the currently trusted keys.
	Keys(ctx context.Context) ([]ed25519.PublicKey, error)
	// Refresh re-acquires keys, e.g. after a verification failure that a
	// key rotation would explain. Returns true if the key set changed.
	Refresh(ctx context.Context) (bool, error)
}

// StaticKeys is a fixed, operator-pinned key set.
type StaticKeys struct{ K []ed25519.PublicKey }

func (s *StaticKeys) Keys(context.Context) ([]ed25519.PublicKey, error) { return s.K, nil }
func (s *StaticKeys) Refresh(context.Context) (bool, error)             { return false, nil }

// ParsePublicKey decodes a base64 Ed25519 public key.
func ParsePublicKey(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("public key is not valid base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// Fingerprint is the relay's key fingerprint: first 8 bytes of SHA-256(pubkey),
// hex-encoded. Matches the value in the relay's startup banner so an operator
// can eyeball that gateway and relay agree.
func Fingerprint(pk ed25519.PublicKey) string {
	h := sha256.Sum256(pk)
	return hex.EncodeToString(h[:8])
}

// EndpointKeys fetches keys from a relay's /fence/public-key endpoint.
type EndpointKeys struct {
	URL    string
	Client *http.Client

	// PinnedFingerprint, when non-empty, causes any key whose fingerprint
	// does not match to be refused. This converts case (1) above into
	// case (2).
	PinnedFingerprint string

	// TOFU pins the first key seen and refuses silent substitution
	// thereafter. Ignored when PinnedFingerprint is set.
	TOFU bool

	// RetainPrevious keeps the prior key valid alongside the new one after
	// a rotation, per §7.4.1's requirement that both verify during the
	// rotation window.
	RetainPrevious bool

	// OnKeyChange is called whenever the active key changes. This is an
	// audit event, not a debug line: with the relay's per-restart key
	// lifecycle it is the only signal distinguishing "the relay restarted"
	// from "something else is answering on that address".
	OnKeyChange func(old, new string)

	mu      sync.Mutex
	current []ed25519.PublicKey
	fpSeen  string
	fetched time.Time
	version string
}

type fenceKeyDoc struct {
	Version     string `json:"version"`
	Algorithm   string `json:"algorithm"`
	PublicKey   string `json:"publicKey"`
	Fingerprint string `json:"fingerprint"`
}

func (e *EndpointKeys) client() *http.Client {
	if e.Client != nil {
		return e.Client
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (e *EndpointKeys) Keys(ctx context.Context) ([]ed25519.PublicKey, error) {
	e.mu.Lock()
	have := len(e.current) > 0
	cur := append([]ed25519.PublicKey(nil), e.current...)
	e.mu.Unlock()
	if have {
		return cur, nil
	}
	if _, err := e.Refresh(ctx); err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]ed25519.PublicKey(nil), e.current...), nil
}

func (e *EndpointKeys) Refresh(ctx context.Context) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.URL, nil)
	if err != nil {
		return false, err
	}
	resp, err := e.client().Do(req)
	if err != nil {
		return false, fmt.Errorf("fetching fence public key: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("fence public key endpoint returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if err != nil {
		return false, err
	}
	var doc fenceKeyDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return false, fmt.Errorf("fence public key endpoint returned non-JSON: %w", err)
	}
	if doc.Algorithm != "" && doc.Algorithm != "Ed25519" {
		return false, fmt.Errorf("unsupported fence signature algorithm %q", doc.Algorithm)
	}
	pk, err := ParsePublicKey(doc.PublicKey)
	if err != nil {
		return false, err
	}
	fp := Fingerprint(pk)

	// The endpoint reports its own fingerprint; if it disagrees with the
	// key it just served, something is wrong enough to stop.
	if doc.Fingerprint != "" && doc.Fingerprint != fp {
		return false, fmt.Errorf("fence key endpoint fingerprint %q does not match served key %q",
			doc.Fingerprint, fp)
	}
	if e.PinnedFingerprint != "" && fp != e.PinnedFingerprint {
		return false, fmt.Errorf("fence key fingerprint %q does not match pinned %q", fp, e.PinnedFingerprint)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.TOFU && e.fpSeen != "" && e.fpSeen != fp {
		return false, fmt.Errorf("fence key changed from %q to %q and TOFU pinning is on", e.fpSeen, fp)
	}
	changed := e.fpSeen != fp
	if changed && e.fpSeen != "" && e.OnKeyChange != nil {
		e.OnKeyChange(e.fpSeen, fp)
	}
	if changed && e.RetainPrevious && len(e.current) > 0 {
		e.current = append([]ed25519.PublicKey{pk}, e.current[0])
	} else {
		e.current = []ed25519.PublicKey{pk}
	}
	e.fpSeen = fp
	e.fetched = time.Now()
	e.version = doc.Version
	return changed, nil
}

// FormatVersion is the fence format version the endpoint reported at the last
// successful fetch ("" if it reported none, or before the first fetch). The
// relay reports the format it emits, so a verified fence of an older format is
// either a relay that has since rolled back — re-fetch to find out — or a
// downgrade.
func (e *EndpointKeys) FormatVersion() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.version
}
