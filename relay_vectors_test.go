package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	fv "github.com/littleoffice/fence-gateway/fenceverify"
)

// TestRelayVectorsThroughGateway runs the interop vectors — real output from
// the relay's fence.go, see interop/regen.sh — through the gateway's policy.
// Every relay tool must pass under the default -policy reject: before CDATA
// support, searxng_session_sources was blocked on every call. Under
// -require-all-fenced the 1.1 layout passes, and the 1.0 layout is blocked for
// its unsigned prose preamble, which is what that flag is for.
func TestRelayVectorsThroughGateway(t *testing.T) {
	dir := os.Getenv("INTEROP_VECTORS")
	if dir == "" {
		dir = filepath.Join("interop", "testdata", "relay")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "pub.b64"))
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	pk, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	manifest, err := os.ReadFile(filepath.Join(dir, "vectors.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var vs []struct{ Name, File, Layout string }
	if err := json.Unmarshal(manifest, &vs); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}

	for _, v := range vs {
		t.Run(v.Name, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join(dir, v.File))
			if err != nil {
				t.Fatalf("read vector: %v", err)
			}
			text := string(b)

			g := testGateway(PolicyReject, ed25519.PublicKey(pk))
			if out, isErr := resultText(g.verify(context.Background(), "tool", "test-caller", textResult(text))); isErr {
				t.Errorf("blocked under the default policy: %q", out)
			}

			strict := testGateway(PolicyReject, ed25519.PublicKey(pk))
			strict.cfg.requireAll = true
			_, isErr := resultText(strict.verify(context.Background(), "tool", "test-caller", textResult(text)))
			if want := v.Layout == "1.0"; isErr != want {
				t.Errorf("-require-all-fenced: blocked=%v, want %v for layout %s", isErr, want, v.Layout)
			}
		})
	}
}

// vectorKey and vector read one interop vector and its key for the tests below.
func vectorKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("interop", "testdata", "relay", "pub.b64"))
	if err != nil {
		t.Fatal(err)
	}
	pk, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

func vector(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("interop", "testdata", "relay", name+".txt"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Real 1.1 relay output with its trusted preamble cut out. The content fence
// still verifies on its own, and nothing is left unsigned, so this used to pass
// even under -policy reject -require-all-fenced — delivering the page without
// the text telling the model to treat it as data.
func TestGatewayBlocksStrippedPreamble(t *testing.T) {
	s := vector(t, "v1.1-escaped-ordinary")
	stripped := s[strings.LastIndex(s, "<sec:fence xmlns"):]
	for _, requireAll := range []bool{false, true} {
		g := testGateway(PolicyReject, vectorKey(t))
		g.cfg.requireAll = requireAll
		if _, isErr := resultText(g.verify(context.Background(), "tool", "test-caller", textResult(stripped))); !isErr {
			t.Errorf("stripped preamble passed (require-all-fenced=%v)", requireAll)
		}
	}
}

// A relay that reports format 1.1 at its key endpoint, answered with a 1.0
// response: the preamble is unsigned there, so this is a downgrade. But if the
// relay has really been rolled back, the endpoint says so on a re-read, and
// the response passes.
func TestGatewayDowngradeAndRollback(t *testing.T) {
	pk := vectorKey(t)
	var version atomic.Value
	version.Store("1.1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"version":%q,"algorithm":"Ed25519","publicKey":%q,"fingerprint":%q}`,
			version.Load(), base64.StdEncoding.EncodeToString(pk), fv.Fingerprint(pk))
	}))
	t.Cleanup(srv.Close)
	keys := &fv.EndpointKeys{URL: srv.URL, RetainPrevious: true}
	if _, err := keys.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	g := &gateway{cfg: config{policy: PolicyReject}, keys: keys, audit: log.New(io.Discard, "", 0)}
	old := textResult(vector(t, "v1.0-escaped-ordinary"))

	if _, isErr := resultText(g.verify(context.Background(), "tool", "test-caller", old)); !isErr {
		t.Error("a 1.0 response from a relay reporting 1.1 passed")
	}
	if _, isErr := resultText(g.verify(context.Background(), "tool", "test-caller", textResult(vector(t, "v1.1-escaped-ordinary")))); isErr {
		t.Error("a 1.1 response from a relay reporting 1.1 was blocked")
	}

	version.Store("1.0") // the relay was rolled back
	if out, isErr := resultText(g.verify(context.Background(), "tool", "test-caller", textResult(vector(t, "v1.0-escaped-ordinary")))); isErr {
		t.Errorf("a rolled-back relay's 1.0 response was blocked: %q", out)
	}
}
