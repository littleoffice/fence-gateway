package fenceverify

import (
	"errors"
	"fmt"
	"strings"
)

// ── Fence parsing ─────────────────────────────────────────────────────────────
//
// We deliberately do NOT use encoding/xml here.
//
// The canonical metadata that the signature covers is a string of
// `key="value"` pairs in which the values are still XML-escaped (the generator
// escapes once and uses the same bytes for both the wire form and the signing
// input).  A conforming XML parser unescapes attribute values on the way out,
// so reconstructing the canonical form through encoding/xml would require
// re-implementing the generator's escape function byte-for-byte and hoping the
// two agree on every edge case.  Scanning the raw bytes and keeping attribute
// values exactly as they appear on the wire removes that entire class of
// verification failure: the canonical string is rebuilt from the same bytes the
// signer saw.
//
// The scanner is strict by design.  Anything it does not understand is an
// error, not a best-effort recovery — a verifier that guesses is a verifier
// that can be steered.

// openTagName is the literal byte sequence that begins a fence element.
const openTagName = "<sec:fence"

// closeTag is the literal byte sequence that ends a fence element.
const closeTag = "</sec:fence>"

// EncodingCDATA is the value of the `encoding` attribute on a fence whose body
// is carried in CDATA sections rather than entity-escaped. The relay uses it
// for searxng_session_sources, whose URLs must survive byte for byte. An
// absent `encoding` means entity-escaped; any other value is refused.
const EncodingCDATA = "cdata"

const (
	cdataOpen  = "<![CDATA["
	cdataClose = "]]>"
)

var (
	// ErrNoFence means no candidate fence element was found at all.
	ErrNoFence = errors.New("no <sec:fence> element found")
	// ErrMalformedFence means a candidate was found but is not well-formed.
	ErrMalformedFence = errors.New("malformed fence element")
)

// rawAttr is one attribute with its value left exactly as written on the wire,
// still XML-escaped.
type rawAttr struct {
	Name  string
	Value string // still escaped; do not unescape before canonicalising
}

// parsedFence is the syntactic result of scanning one fence element, before
// any cryptographic checking has happened.
type parsedFence struct {
	Attrs []rawAttr
	// Body is the element content exactly as it appeared between the
	// opening tag's '>' and the closing tag's '<', still encoded and still
	// carrying the generator's framing newlines.
	Body string
	// Encoding is the raw value of the `encoding` attribute: "" for an
	// entity-escaped body, EncodingCDATA for a CDATA body. It decides both
	// where the element ends and how the signed bytes are recovered.
	Encoding string
	// Start and End delimit the whole element within the source string,
	// so the caller can reason about what text sits outside the fence.
	Start, End int
}

// scanFenceAt attempts to parse a fence element beginning at the given offset,
// which must point at the '<' of an opening tag.
func scanFenceAt(s string, start int) (*parsedFence, error) {
	if !strings.HasPrefix(s[start:], openTagName) {
		return nil, ErrMalformedFence
	}
	i := start + len(openTagName)

	// The character after the tag name must be whitespace or '>'. Without
	// this check "<sec:fencex" would be accepted as a fence.
	if i >= len(s) {
		return nil, ErrMalformedFence
	}
	if !isXMLSpace(s[i]) && s[i] != '>' {
		return nil, ErrMalformedFence
	}

	attrs, tagEnd, err := scanAttributes(s, i)
	if err != nil {
		return nil, err
	}

	var encoding string
	for _, a := range attrs {
		if a.Name == "encoding" {
			encoding = a.Value
		}
	}

	bodyStart := tagEnd + 1 // one past '>'
	var bodyEnd int
	switch encoding {
	case "":
		rel := strings.Index(s[bodyStart:], closeTag)
		if rel < 0 {
			return nil, fmt.Errorf("%w: unterminated element", ErrMalformedFence)
		}
		bodyEnd = bodyStart + rel

		// Nesting is forbidden by the spec (Appendix A.4 rule 5). Because the
		// generator escapes '<' in content, a literal opening tag inside the
		// body can only mean the content was not escaped — a generator bug, or
		// output from something that is not the generator. Either way, refuse.
		if strings.Contains(s[bodyStart:bodyEnd], openTagName) {
			return nil, fmt.Errorf("%w: nested fence in body", ErrMalformedFence)
		}
	case EncodingCDATA:
		// A CDATA body escapes nothing, so fetched text — a page title, say —
		// can legitimately contain a literal <sec:fence or </sec:fence>. The
		// element therefore ends at the first closing tag that is not inside a
		// CDATA section, and the nesting rule does not apply: a literal tag in
		// the body is data, and the signature still covers every byte of it.
		end, err := cdataBodyEnd(s, bodyStart)
		if err != nil {
			return nil, err
		}
		bodyEnd = end
	default:
		// The body cannot be decoded, so the signed bytes cannot be recovered.
		// The attribute is signed, but that does not make an unknown value
		// safe to guess at.
		return nil, fmt.Errorf("%w: unsupported encoding %q", ErrMalformedFence, encoding)
	}

	return &parsedFence{
		Attrs:    attrs,
		Body:     s[bodyStart:bodyEnd],
		Encoding: encoding,
		Start:    start,
		End:      bodyEnd + len(closeTag),
	}, nil
}

// cdataBodyEnd returns the offset of the closing tag that ends a CDATA-encoded
// element whose body begins at i, skipping any closing tag that sits inside a
// CDATA section.
func cdataBodyEnd(s string, i int) (int, error) {
	for {
		end := strings.Index(s[i:], closeTag)
		if end < 0 {
			return 0, fmt.Errorf("%w: unterminated element", ErrMalformedFence)
		}
		open := strings.Index(s[i:], cdataOpen)
		if open < 0 || open > end {
			return i + end, nil
		}
		j := i + open + len(cdataOpen)
		k := strings.Index(s[j:], cdataClose)
		if k < 0 {
			return 0, fmt.Errorf("%w: unterminated CDATA section", ErrMalformedFence)
		}
		i = j + k + len(cdataClose)
	}
}

// scanAttributes reads `name="value"` pairs until the tag's closing '>'.
// It returns the attributes and the index of that '>'.
//
// Only double-quoted values are accepted. XML permits single quotes, but the
// generator emits double quotes and the canonical form is defined in terms of
// them; accepting both would mean two distinct wire forms canonicalise to the
// same string, which is exactly the kind of ambiguity a signature format
// should not have.
func scanAttributes(s string, i int) ([]rawAttr, int, error) {
	var attrs []rawAttr
	seen := make(map[string]bool)

	for {
		for i < len(s) && isXMLSpace(s[i]) {
			i++
		}
		if i >= len(s) {
			return nil, 0, fmt.Errorf("%w: unterminated opening tag", ErrMalformedFence)
		}
		if s[i] == '>' {
			return attrs, i, nil
		}
		if s[i] == '/' {
			// A self-closing fence has no content to sign. Reject rather
			// than treating it as an empty-bodied fence.
			return nil, 0, fmt.Errorf("%w: self-closing fence", ErrMalformedFence)
		}

		nameStart := i
		for i < len(s) && !isXMLSpace(s[i]) && s[i] != '=' && s[i] != '>' {
			i++
		}
		name := s[nameStart:i]
		if name == "" {
			return nil, 0, fmt.Errorf("%w: empty attribute name", ErrMalformedFence)
		}

		for i < len(s) && isXMLSpace(s[i]) {
			i++
		}
		if i >= len(s) || s[i] != '=' {
			return nil, 0, fmt.Errorf("%w: attribute %q has no value", ErrMalformedFence, name)
		}
		i++
		for i < len(s) && isXMLSpace(s[i]) {
			i++
		}
		if i >= len(s) || s[i] != '"' {
			return nil, 0, fmt.Errorf("%w: attribute %q not double-quoted", ErrMalformedFence, name)
		}
		i++
		valStart := i
		for i < len(s) && s[i] != '"' {
			// A raw '<' inside an attribute value is forbidden by XML and
			// would let a value swallow the rest of the tag.
			if s[i] == '<' {
				return nil, 0, fmt.Errorf("%w: raw '<' in attribute %q", ErrMalformedFence, name)
			}
			i++
		}
		if i >= len(s) {
			return nil, 0, fmt.Errorf("%w: unterminated value for %q", ErrMalformedFence, name)
		}
		val := s[valStart:i]
		i++ // past closing quote

		// Duplicate attributes are the classic canonicalisation attack: two
		// entries with the same name, one signed and one displayed.
		if seen[name] {
			return nil, 0, fmt.Errorf("%w: duplicate attribute %q", ErrMalformedFence, name)
		}
		seen[name] = true

		attrs = append(attrs, rawAttr{Name: name, Value: val})
	}
}

// isXMLSpace reports whether b is XML whitespace (production S, XML 1.0 §2.3).
func isXMLSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// claimsSignature reports whether the candidate beginning at off carries a
// signature attribute in its opening tag.
//
// This distinction decides whether a failed candidate is an attack or just
// text. The relay's awareness preamble discusses `<sec:fence rating="untrusted">`
// and `</sec:fence>` in prose, so every genuine response contains candidates
// that will never parse. Reporting those as rejections makes a reject-on-
// failure policy block all legitimate traffic — the classic detector that
// gets switched off in week one because it cries wolf.
//
// A candidate that claims a signature is asserting authenticity and failing:
// that is the boundary-escape attack of §2.3.2 and belongs in Rejections.
// A candidate with no signature attribute is not asserting anything; it is
// unsigned text, and it is accounted for as such.
func claimsSignature(s string, off int) bool {
	end := off + 2048 // opening tags are small; bound the scan
	if end > len(s) {
		end = len(s)
	}
	tag := s[off:end]
	if gt := strings.IndexByte(tag, '>'); gt >= 0 {
		tag = tag[:gt]
	}
	return strings.Contains(tag, `signature="`)
}

// candidateOffsets returns every index at which an opening tag could begin.
//
// The relay prepends a human-readable awareness preamble that itself mentions
// `<sec:fence rating="untrusted">` and `</sec:fence>` in prose, so the first
// textual occurrence is NOT the real fence. Rather than pattern-matching our
// way to the right one — which an attacker could influence — we hand every
// candidate to the verifier and let the signature decide. Forgery being
// infeasible, "the one that verifies" is the only selector that cannot be
// steered by content.
func candidateOffsets(s string) []int {
	var out []int
	for i := 0; ; {
		rel := strings.Index(s[i:], openTagName)
		if rel < 0 {
			return out
		}
		out = append(out, i+rel)
		i += rel + len(openTagName)
	}
}

// unescapeContent reverses the generator's content escaping.
//
// The generator escapes exactly three characters in element content — '&',
// '<', '>' — and signs the PRE-escape bytes. To recover the signed bytes we
// must apply precisely the inverse, in a single left-to-right pass.
//
// A general-purpose XML unescaper is the wrong tool here. Multi-pass or
// entity-table-driven decoding would turn the escaped form of the literal
// text "&lt;" (which is on the wire as "&amp;lt;") into "<" rather than
// "&lt;", silently producing different bytes from the ones that were signed.
// One pass, three entities, no lookbehind.
func unescapeContent(s string) (string, error) {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '&' {
			b.WriteByte(s[i])
			i++
			continue
		}
		switch {
		case strings.HasPrefix(s[i:], "&amp;"):
			b.WriteByte('&')
			i += len("&amp;")
		case strings.HasPrefix(s[i:], "&lt;"):
			b.WriteByte('<')
			i += len("&lt;")
		case strings.HasPrefix(s[i:], "&gt;"):
			b.WriteByte('>')
			i += len("&gt;")
		default:
			// Any other entity — or a bare '&' — cannot have been produced
			// by the generator, because the generator escapes every '&' it
			// emits. Its presence means the body is not what was signed.
			return "", fmt.Errorf("%w: unexpected entity or bare '&' in content at offset %d", ErrMalformedFence, i)
		}
	}
	return b.String(), nil
}

// decodeCDATA recovers the signed bytes from a CDATA-encoded body (framing
// newlines already removed) by concatenating the text of its CDATA sections.
//
// The generator writes one section and splits it wherever the content holds
// "]]>" — closing the section before the '>' and opening a new one after it —
// so adjacent sections concatenate back to the original. Nothing else is
// decoded: '&', '<' and '>' inside a section are literal, which is the reason
// this encoding exists. Text outside a section was not written by the
// generator and is refused rather than dropped, because dropping it would
// forward bytes the signature never covered.
func decodeCDATA(body string) (string, error) {
	if body == "" {
		return "", fmt.Errorf("%w: CDATA-encoded body has no CDATA section", ErrMalformedFence)
	}
	var b strings.Builder
	b.Grow(len(body))
	for body != "" {
		if !strings.HasPrefix(body, cdataOpen) {
			return "", fmt.Errorf("%w: text outside a CDATA section", ErrMalformedFence)
		}
		body = body[len(cdataOpen):]
		k := strings.Index(body, cdataClose)
		if k < 0 {
			return "", fmt.Errorf("%w: unterminated CDATA section", ErrMalformedFence)
		}
		b.WriteString(body[:k])
		body = body[k+len(cdataClose):]
	}
	return b.String(), nil
}

// stripFramingNewlines removes the single '\n' the generator writes after the
// opening tag and the single '\n' it writes before the closing tag.
//
// Exactly one from each end — never TrimSpace. Content legitimately beginning
// or ending with a newline is common (Markdown extraction produces it), and
// trimming greedily would delete bytes that were signed.
func stripFramingNewlines(body string) (string, error) {
	if !strings.HasPrefix(body, "\n") || !strings.HasSuffix(body, "\n") || len(body) < 2 {
		return "", fmt.Errorf("%w: body is missing the generator's framing newlines", ErrMalformedFence)
	}
	return body[1 : len(body)-1], nil
}
