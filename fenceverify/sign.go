package fenceverify

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// ── Reference generator ───────────────────────────────────────────────────────
//
// A generator is not what a gateway needs at runtime, but a verifier with no
// generator can only be tested against fences someone else produced, which
// means a bug that is symmetric across both sides stays invisible. This
// mirrors mcp-searxng-relay's wrapFence byte-for-byte so the round trip is a
// real test rather than a tautology, and so anyone implementing a fence
// producer in another language has an executable reference to diff against.

// GenOptions configures fence generation.
type GenOptions struct {
	Type      string
	Rating    string
	Source    string // omitted from output when empty
	Nonce     string // generated when empty
	Timestamp string // RFC 3339; required
	Scheme    SchemeMode
	// Encoding is "" for an entity-escaped body (the relay's wrapFence) or
	// EncodingCDATA for a CDATA body (its wrapFenceCDATA).
	Encoding string
	// Extra attributes are canonicalised and signed alongside the core set.
	Extra map[string]string
}

// GenerateNonce returns 128 bits of hex-encoded randomness.
func GenerateNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Generate produces a signed fence element in the relay's wire format.
func Generate(priv ed25519.PrivateKey, content string, o GenOptions) (string, error) {
	if o.Nonce == "" {
		n, err := GenerateNonce()
		if err != nil {
			return "", err
		}
		o.Nonce = n
	}

	pairs := []string{
		`nonce="` + attrEscape(o.Nonce) + `"`,
		`rating="` + attrEscape(o.Rating) + `"`,
		`timestamp="` + attrEscape(o.Timestamp) + `"`,
		`type="` + attrEscape(o.Type) + `"`,
	}
	if o.Source != "" {
		pairs = append(pairs, `source="`+attrEscape(o.Source)+`"`)
	}
	if o.Encoding != "" {
		pairs = append(pairs, `encoding="`+attrEscape(o.Encoding)+`"`)
	}
	for k, val := range o.Extra {
		pairs = append(pairs, k+`="`+attrEscape(val)+`"`)
	}
	sort.Strings(pairs)
	canonical := strings.Join(pairs, " ")

	v := &Verifier{Scheme: o.Scheme}
	msg, err := v.signingInput(content, canonical)
	if err != nil {
		return "", err
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))

	var sb strings.Builder
	fmt.Fprintf(&sb, `<sec:fence xmlns:sec="%s" signature="%s" %s>`,
		attrEscape(FenceNamespace), attrEscape(sig), canonical)
	sb.WriteString("\n")
	if o.Encoding == EncodingCDATA {
		sb.WriteString(cdataOpen + cdataEscape(content) + cdataClose)
	} else {
		sb.WriteString(contentEscape(content))
	}
	sb.WriteString("\n</sec:fence>\n")
	return sb.String(), nil
}

// attrEscape mirrors the relay's xmlAttrEscape.
func attrEscape(s string) string {
	return strings.NewReplacer(
		`&`, `&amp;`, `<`, `&lt;`, `>`, `&gt;`, `"`, `&quot;`,
		"\n", " ", "\t", " ", "\r", " ",
	).Replace(s)
}

// cdataEscape mirrors the relay's cdataEscape: split the section at every
// "]]>" so the content cannot close it early.
func cdataEscape(s string) string {
	return strings.ReplaceAll(s, "]]>", "]]]]><![CDATA[>")
}

// contentEscape mirrors the relay's xmlContentEscape.
func contentEscape(s string) string {
	return strings.NewReplacer(`&`, `&amp;`, `<`, `&lt;`, `>`, `&gt;`).Replace(s)
}
