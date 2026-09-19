package interop

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	fv "github.com/littleoffice/fence-gateway/fenceverify"
)

// Verifies output produced by mcp-searxng-relay's actual fence.go, compiled
// unmodified. This is the only test that can catch a bug present in both the
// gateway and its own reference generator.
func TestAgainstRealRelayOutput(t *testing.T) {
	raw, err := os.ReadFile("/tmp/real_fence.txt")
	if err != nil {
		t.Skip("no real relay output available")
	}
	pubB64, err := os.ReadFile("/tmp/real_pub.txt")
	if err != nil {
		t.Skip("no real public key available")
	}
	pk, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(pubB64)))
	if err != nil {
		t.Fatalf("decode pubkey: %v", err)
	}

	v := &fv.Verifier{Keys: []ed25519.PublicKey{pk}, Scheme: fv.SchemeRelay, RequireNonce: true}
	res, err := v.Verify(string(raw))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(res.Fences) != 1 {
		t.Fatalf("want 1 verified fence, got %d; rejections=%+v", len(res.Fences), res.Rejections)
	}
	f := res.Fences[0]
	want := os.Getenv("CONTENT")
	if want != "" && f.Content != want {
		t.Errorf("content mismatch:\n got %q\nwant %q", f.Content, want)
	}
	if f.Rating != fv.RatingUntrusted {
		t.Errorf("rating = %q", f.Rating)
	}
	if f.Nonce == "" {
		t.Error("nonce not recovered")
	}
	if f.Source != "https://example.com/review" {
		t.Errorf("source = %q", f.Source)
	}
	t.Logf("verified: rating=%s type=%s nonce=%s source=%s contentlen=%d unsigned_regions=%d",
		f.Rating, f.Type, f.Nonce, f.Source, len(f.Content), len(res.UnsignedRegions))
	for _, u := range res.UnsignedRegions {
		t.Logf("unsigned region (%d bytes): %.60s...", len(u), u)
	}
}
