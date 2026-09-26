package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	fv "github.com/littleoffice/fence-gateway/fenceverify"
)

// Three relay replicas behind one address, each on a key of its own (the
// relay's default without FENCE_SIGNING_KEY). The key endpoint answers from
// whichever replica it reaches, and so do tool calls.
//
// The gateway used to keep the latest key or two and refetch on any failure:
// it swapped keys back and forth and blocked genuine results at random. It now
// selects the key a fence names (kid) and looks for that one when missing.
func TestGatewayBehindReplicasWithKeysOfTheirOwn(t *testing.T) {
	type replica struct {
		pub  ed25519.PublicKey
		priv ed25519.PrivateKey
	}
	var replicas []replica
	for i := 0; i < 3; i++ {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		replicas = append(replicas, replica{pub, priv})
	}

	var mu sync.Mutex
	next, fetches := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		r := replicas[next%len(replicas)]
		next++
		fetches++
		mu.Unlock()
		_, _ = fmt.Fprintf(w, `{"algorithm":"Ed25519","publicKey":%q,"fingerprint":%q}`,
			base64.StdEncoding.EncodeToString(r.pub), fv.Fingerprint(r.pub))
	}))
	t.Cleanup(srv.Close)

	// As main configures it.
	keys := &fv.EndpointKeys{URL: srv.URL, RetainPrevious: true, KeyTTL: 24 * time.Hour, MinRefreshInterval: 2 * time.Second}
	if _, err := keys.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	g := &gateway{cfg: config{policy: PolicyReject}, keys: keys, audit: log.New(io.Discard, "", 0)}

	for i := 0; i < 30; i++ {
		r := replicas[(i*7+1)%len(replicas)]
		fence, err := fv.Generate(r.priv, fmt.Sprintf("result %d", i), fv.GenOptions{
			Type: fv.TypeContent, Rating: fv.RatingUntrusted,
			Timestamp: time.Now().UTC().Format(time.RFC3339), Scheme: fv.SchemeRelay,
			Extra: map[string]string{"kid": fv.Fingerprint(r.pub)},
		})
		if err != nil {
			t.Fatal(err)
		}
		if out, isErr := resultText(g.verify(context.Background(), "tool", "test-caller", textResult(fence))); isErr {
			t.Fatalf("call %d, signed by a real replica, was blocked: %q", i, out)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if fetches > 1+2*4 {
		t.Errorf("fetched the key endpoint %d times for 30 calls: keys are not being kept", fetches)
	}
}
