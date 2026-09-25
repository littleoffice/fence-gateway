package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
