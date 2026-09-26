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

	// RetainPrevious keeps keys valid after the endpoint has moved on to a
	// new one, per §7.4.1's requirement that old and new both verify during
	// a rotation window. Fences name the key that signed them (kid), so a
	// verifier holding several picks the right one rather than trying all.
	// That matters with several relay replicas on keys of their own: the
	// endpoint answers from whichever replica it reaches, and a verifier
	// that kept only the latest key or two would keep swapping them and
	// reject genuine fences at random. Without RetainPrevious only the
	// latest key is kept.
	RetainPrevious bool

	// MaxKeys bounds how many keys are retained; the least recently served
	// goes first. Zero means DefaultMaxKeys.
	MaxKeys int

	// KeyTTL drops a retained key the endpoint has not served for this
	// long, so a key that has left service does not stay trusted
	// indefinitely. The key the endpoint served last is never dropped. Zero
	// means keys are kept until MaxKeys pushes them out.
	KeyTTL time.Duration

	// MinRefreshInterval limits fetching. A Refresh sooner than this after
	// the last fetch is a no-op returning (false, nil), and RefreshFor looks
	// for any one key at most once per interval. So a run of fences naming a
	// key the endpoint does not serve — a pin mismatch, a misconfigured
	// replica — costs one round of fetches, not one per call, while keys of
	// different replicas are each looked for without waiting on the others.
	// Zero disables the limit.
	MinRefreshInterval time.Duration

	// OnKeyChange is called when the endpoint serves a key not held before.
	// This is an audit event, not a debug line: with the relay's per-restart
	// key lifecycle it is the only signal distinguishing "the relay
	// restarted" from "something else is answering on that address".
	OnKeyChange func(old, new string)

	mu        sync.Mutex
	ring      map[string]*heldKey  // by fingerprint
	fpSeen    string               // fingerprint the endpoint served last
	firstSeen string               // TOFU: the first fingerprint ever served
	fetched   time.Time            // last fetch attempt
	sought    map[string]time.Time // RefreshFor: when each key was last looked for
	version   string
}

// DefaultMaxKeys is how many keys EndpointKeys retains when MaxKeys is zero:
// enough for a handful of relay replicas plus a rotation.
const DefaultMaxKeys = 8

type heldKey struct {
	key    ed25519.PublicKey
	served time.Time // last time the endpoint served it
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
	if ks := e.held(); len(ks) > 0 {
		return ks, nil
	}
	if _, err := e.Refresh(ctx); err != nil {
		return nil, err
	}
	return e.held(), nil
}

// held returns the retained keys, the one served last first, after dropping
// any past KeyTTL.
func (e *EndpointKeys) held() []ed25519.PublicKey {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.expireLocked(time.Now())
	out := make([]ed25519.PublicKey, 0, len(e.ring))
	if k, ok := e.ring[e.fpSeen]; ok {
		out = append(out, k.key)
	}
	for fp, k := range e.ring {
		if fp != e.fpSeen {
			out = append(out, k.key)
		}
	}
	return out
}

func (e *EndpointKeys) expireLocked(now time.Time) {
	if e.KeyTTL <= 0 {
		return
	}
	for fp, k := range e.ring {
		if fp != e.fpSeen && now.Sub(k.served) > e.KeyTTL {
			delete(e.ring, fp)
		}
	}
}

// Refresh fetches the key the endpoint currently serves and adds it to the
// retained set. It reports whether that key is one not held before.
func (e *EndpointKeys) Refresh(ctx context.Context) (bool, error) {
	changed, _, err := e.fetch(ctx, true)
	return changed, err
}

// refreshForAttempts is how many fetches RefreshFor makes looking for one key.
// Behind a load balancer each fetch reaches one relay replica, so a single
// fetch finds a given replica's key only some of the time.
const refreshForAttempts = 4

// RefreshFor fetches until the key with fingerprint kid is held, up to
// refreshForAttempts times, and reports whether it is held afterwards. Each
// key is looked for at most once per MinRefreshInterval: a burst of fences
// naming an unknown key costs one round of fetches, not one per fence.
func (e *EndpointKeys) RefreshFor(ctx context.Context, kid string) (bool, error) {
	if e.holds(kid) {
		return true, nil
	}
	e.mu.Lock()
	now := time.Now()
	if last, ok := e.sought[kid]; ok && e.MinRefreshInterval > 0 && now.Sub(last) < e.MinRefreshInterval {
		e.mu.Unlock()
		return false, nil
	}
	if e.sought == nil || len(e.sought) >= maxSought {
		e.sought = make(map[string]time.Time)
	}
	e.sought[kid] = now
	e.mu.Unlock()

	for i := 0; i < refreshForAttempts; i++ {
		if _, _, err := e.fetch(ctx, false); err != nil {
			return e.holds(kid), err
		}
		if e.holds(kid) {
			return true, nil
		}
	}
	return false, nil
}

// maxSought bounds the memory of keys RefreshFor has looked for.
const maxSought = 256

// Touch marks the key with fingerprint kid as in use, so KeyTTL counts from
// now. A verifier calls it for keys that just verified a fence: behind a load
// balancer the endpoint may not serve a replica's key again for a long time,
// and a key still signing traffic should not expire for that.
func (e *EndpointKeys) Touch(kid string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if k, ok := e.ring[kid]; ok {
		k.served = time.Now()
	}
}

func (e *EndpointKeys) holds(kid string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.ring[kid]
	return ok
}

// fetch performs one fetch of the endpoint. With throttle set it does nothing
// within MinRefreshInterval of the last one, and reports fetched=false.
func (e *EndpointKeys) fetch(ctx context.Context, throttle bool) (changed, fetched bool, err error) {
	e.mu.Lock()
	if throttle && e.MinRefreshInterval > 0 && !e.fetched.IsZero() && time.Since(e.fetched) < e.MinRefreshInterval {
		e.mu.Unlock()
		return false, false, nil
	}
	e.fetched = time.Now()
	e.mu.Unlock()
	changed, err = e.fetchOnce(ctx)
	return changed, true, err
}

func (e *EndpointKeys) fetchOnce(ctx context.Context) (bool, error) {
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
	if e.TOFU && e.firstSeen != "" && e.firstSeen != fp {
		return false, fmt.Errorf("fence key changed from %q to %q and TOFU pinning is on", e.firstSeen, fp)
	}
	if e.firstSeen == "" {
		e.firstSeen = fp
	}
	now := time.Now()
	if e.ring == nil {
		e.ring = make(map[string]*heldKey)
	}
	_, held := e.ring[fp]
	if !held && e.fpSeen != "" && e.OnKeyChange != nil {
		e.OnKeyChange(e.fpSeen, fp)
	}
	if !e.RetainPrevious {
		clear(e.ring)
	}
	e.ring[fp] = &heldKey{key: pk, served: now}
	e.fpSeen = fp
	e.version = doc.Version
	e.expireLocked(now)
	e.trimLocked()
	return !held, nil
}

// trimLocked drops the least recently served keys beyond MaxKeys.
func (e *EndpointKeys) trimLocked() {
	max := e.MaxKeys
	if max <= 0 {
		max = DefaultMaxKeys
	}
	for len(e.ring) > max {
		oldest := ""
		for fp, k := range e.ring {
			if fp != e.fpSeen && (oldest == "" || k.served.Before(e.ring[oldest].served)) {
				oldest = fp
			}
		}
		if oldest == "" {
			return
		}
		delete(e.ring, oldest)
	}
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
