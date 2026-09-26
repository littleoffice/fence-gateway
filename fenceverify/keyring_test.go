package fenceverify

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// genKid signs a fence that names its key in kid, as the relay does.
func genKid(t *testing.T, priv ed25519.PrivateKey, content string) string {
	t.Helper()
	out, err := Generate(priv, content, GenOptions{
		Type: TypeContent, Rating: RatingUntrusted, Timestamp: ts, Scheme: SchemeRelay,
		Extra: map[string]string{"kid": Fingerprint(priv.Public().(ed25519.PublicKey))},
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return out
}

func TestVerifySelectsKeyByKid(t *testing.T) {
	pubA, _ := newKP(t)
	pubB, privB := newKP(t)
	s := genKid(t, privB, "hello")

	v := newVerifier(pubA)
	v.Keys = append(v.Keys, pubB)
	if got, _ := v.Verify(s); len(got.Fences) != 1 {
		t.Fatalf("fence not verified with its named key among several: %+v", got.Rejections)
	}

	got, _ := newVerifier(pubA).Verify(s)
	if len(got.Rejections) != 1 || got.Rejections[0].UnknownKey != Fingerprint(pubB) {
		t.Fatalf("want an unknown-key rejection naming %s, got %+v", Fingerprint(pubB), got.Rejections)
	}
}

// A forged fence naming a key the verifier holds is a bad signature, not an
// unknown key: the two must stay distinguishable in the audit log.
func TestForgedFenceNamingHeldKeyIsBadSignature(t *testing.T) {
	pubA, _ := newKP(t)
	_, privC := newKP(t)
	out, err := Generate(privC, "forged", GenOptions{
		Type: TypeContent, Rating: RatingUntrusted, Timestamp: ts, Scheme: SchemeRelay,
		Extra: map[string]string{"kid": Fingerprint(pubA)},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := newVerifier(pubA).Verify(out)
	if len(got.Fences) != 0 || len(got.Rejections) != 1 {
		t.Fatalf("got %d fences, rejections %+v", len(got.Fences), got.Rejections)
	}
	if rj := got.Rejections[0]; rj.UnknownKey != "" || !strings.Contains(rj.Reason, "signature") {
		t.Errorf("want a bad-signature rejection, got %+v", rj)
	}
}

// replicaEndpoint serves /fence/public-key from several "replicas" in turn, as
// a load balancer in front of relays with a key each would.
type replicaEndpoint struct {
	mu    sync.Mutex
	keys  []ed25519.PublicKey
	next  int
	calls int
	srv   *httptest.Server
}

func newReplicaEndpoint(t *testing.T, keys ...ed25519.PublicKey) *replicaEndpoint {
	t.Helper()
	r := &replicaEndpoint{keys: keys}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		r.mu.Lock()
		k := r.keys[r.next%len(r.keys)]
		r.next++
		r.calls++
		r.mu.Unlock()
		_, _ = fmt.Fprintf(w, `{"algorithm":"Ed25519","publicKey":%q,"fingerprint":%q}`,
			base64.StdEncoding.EncodeToString(k), Fingerprint(k))
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *replicaEndpoint) fetches() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func TestRefreshForFindsEachReplicaKey(t *testing.T) {
	a, _ := newKP(t)
	b, _ := newKP(t)
	c, _ := newKP(t)
	ep := newReplicaEndpoint(t, a, b, c)
	keys := &EndpointKeys{URL: ep.srv.URL, RetainPrevious: true}

	for _, k := range []ed25519.PublicKey{c, a, b} {
		held, err := keys.RefreshFor(context.Background(), Fingerprint(k))
		if err != nil || !held {
			t.Fatalf("RefreshFor(%s) = %v, %v", Fingerprint(k), held, err)
		}
	}
	if got, _ := keys.Keys(context.Background()); len(got) != 3 {
		t.Errorf("holding %d keys, want all 3 replicas'", len(got))
	}
	// Held already: no fetch.
	before := ep.fetches()
	if held, _ := keys.RefreshFor(context.Background(), Fingerprint(b)); !held || ep.fetches() != before {
		t.Error("RefreshFor fetched for a key already held")
	}
}

func TestRefreshForGivesUpOnAKeyNobodyServes(t *testing.T) {
	a, _ := newKP(t)
	ep := newReplicaEndpoint(t, a)
	keys := &EndpointKeys{URL: ep.srv.URL, RetainPrevious: true}
	held, err := keys.RefreshFor(context.Background(), "0000000000000000")
	if err != nil || held {
		t.Fatalf("RefreshFor = %v, %v; want false, nil", held, err)
	}
	if n := ep.fetches(); n != refreshForAttempts {
		t.Errorf("fetched %d times, want %d", n, refreshForAttempts)
	}
}

func TestMinRefreshIntervalLimitsFetches(t *testing.T) {
	a, _ := newKP(t)
	ep := newReplicaEndpoint(t, a)
	keys := &EndpointKeys{URL: ep.srv.URL, MinRefreshInterval: time.Hour}
	for i := 0; i < 5; i++ {
		_, _ = keys.Refresh(context.Background())
	}
	if n := ep.fetches(); n != 1 {
		t.Errorf("Refresh fetched %d times within the interval, want 1", n)
	}

	// One round of fetches per unknown key per interval, however many
	// fences name it...
	for i := 0; i < 5; i++ {
		_, _ = keys.RefreshFor(context.Background(), "0000000000000000")
	}
	if n := ep.fetches(); n != 1+refreshForAttempts {
		t.Errorf("fetched %d times, want %d", n, 1+refreshForAttempts)
	}
	// ...and a different key is looked for without waiting on that one.
	_, _ = keys.RefreshFor(context.Background(), "1111111111111111")
	if n := ep.fetches(); n != 1+2*refreshForAttempts {
		t.Errorf("fetched %d times, want %d", n, 1+2*refreshForAttempts)
	}
}

func TestMaxKeysKeepsTheMostRecent(t *testing.T) {
	var pubs []ed25519.PublicKey
	for i := 0; i < 4; i++ {
		p, _ := newKP(t)
		pubs = append(pubs, p)
	}
	ep := newReplicaEndpoint(t, pubs...)
	keys := &EndpointKeys{URL: ep.srv.URL, RetainPrevious: true, MaxKeys: 2}
	for range pubs {
		if _, err := keys.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if keys.holds(Fingerprint(pubs[0])) || keys.holds(Fingerprint(pubs[1])) {
		t.Error("oldest keys were not dropped")
	}
	if !keys.holds(Fingerprint(pubs[2])) || !keys.holds(Fingerprint(pubs[3])) {
		t.Error("most recent keys were dropped")
	}
}

// A key the endpoint has moved on from expires after KeyTTL, unless a fence it
// verified has touched it. The key served last never expires.
func TestKeyTTL(t *testing.T) {
	a, _ := newKP(t)
	b, _ := newKP(t)
	c, _ := newKP(t)
	ep := newReplicaEndpoint(t, a, b, c)
	keys := &EndpointKeys{URL: ep.srv.URL, RetainPrevious: true, KeyTTL: 50 * time.Millisecond}
	for i := 0; i < 3; i++ {
		if _, err := keys.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(80 * time.Millisecond)
	keys.Touch(Fingerprint(b))
	got, _ := keys.Keys(context.Background())
	if len(got) != 2 {
		t.Fatalf("holding %d keys, want 2 (b touched, c served last)", len(got))
	}
	if keys.holds(Fingerprint(a)) {
		t.Error("an unused key outlived KeyTTL")
	}
}

func TestTOFUStillRefusesASecondKey(t *testing.T) {
	a, _ := newKP(t)
	b, _ := newKP(t)
	ep := newReplicaEndpoint(t, a, b)
	keys := &EndpointKeys{URL: ep.srv.URL, RetainPrevious: true, TOFU: true}
	if _, err := keys.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Refresh(context.Background()); err == nil {
		t.Error("TOFU accepted a second key")
	}
}
