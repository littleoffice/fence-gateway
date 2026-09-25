// Package fenceverify implements deterministic verification of prompt-fence
// elements (arXiv:2511.19727): parsing and canonicalisation of <sec:fence>
// content, Ed25519 signature verification under both the paper's literal
// scheme and mcp-searxng-relay's construction, and public-key acquisition.
// It has no I/O in the hot path and depends only on the Go standard library.
package fenceverify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// ── Fence verification ────────────────────────────────────────────────────────
//
// Verifier for the prompt-fencing scheme of:
//
//   Peh, S. (2025). "Prompt Fencing: A Cryptographic Approach to Establishing
//   Security Boundaries in Large Language Model Prompts." arXiv:2511.19727.
//
// This implements the paper's "security gateway" (§4.5, §7.4.3): the component
// that performs signature verification so the model never has to. The paper is
// explicit that cryptographic checking is the gateway's job and semantic
// boundary-respecting is the model's; this package is the first half.
//
// Two signature schemes are supported, selected by SchemeMode:
//
//   SchemeRelay (default) — the domain-separated, length-prefixed construction
//     used by mcp-searxng-relay:
//
//       Ed25519_Verify(PK, "PromptFence/v1.0" || 0x00 ||
//                          uint64_be(len(C)) || C || M_canonical, σ)
//
//   SchemePaperLiteral — the construction as literally written in §4.3 and
//     Appendix A.2:
//
//       Ed25519_Verify(PK, SHA-256(C || M_canonical), σ)
//
// The two are not interchangeable and a fence signed under one will not verify
// under the other. SchemeRelay is the better construction — see the extended
// note on PureEd25519 prehashing in the relay's fence.go — but the literal
// scheme is what the reference implementation emits, so interoperability
// testing needs both.

// SchemeMode selects the signature construction.
type SchemeMode int

const (
	// SchemeRelay is the domain-separated, length-prefixed construction.
	SchemeRelay SchemeMode = iota
	// SchemePaperLiteral is Ed25519 over SHA-256(C || M_canonical).
	SchemePaperLiteral
)

// relaySigDomain must match the generator's fenceSigDomain byte-for-byte.
const relaySigDomain = "PromptFence/v1.0"

// FenceNamespace is the namespace URI the spec assigns to fence elements.
const FenceNamespace = "http://promptfence.org/security/1.0"

var (
	// ErrBadSignature means the fence parsed cleanly but the signature did
	// not verify under the supplied key.
	ErrBadSignature = errors.New("fence signature verification failed")
	// ErrSchemaViolation means the fence violates the spec's own rules
	// (missing required attribute, value outside its enumeration, etc).
	ErrSchemaViolation = errors.New("fence schema violation")
)

// Trust ratings (paper §4.2).
const (
	RatingTrusted          = "trusted"
	RatingPartiallyTrusted = "partially-trusted"
	RatingUntrusted        = "untrusted"
)

// Content types (paper §4.2).
const (
	TypeInstructions = "instructions"
	TypeContent      = "content"
	TypeData         = "data"
)

// Fence is a fence element that has been parsed, schema-checked, and had its
// signature verified.
type Fence struct {
	Type      string
	Rating    string
	Source    string
	Timestamp time.Time
	Nonce     string
	// Encoding is "" for an entity-escaped body and EncodingCDATA for a
	// CDATA body. It is signed like every other attribute.
	Encoding string

	// Content is the recovered plaintext: the exact bytes that were signed.
	Content string

	// Extra holds any attribute outside the spec's core set. These are
	// covered by the signature — canonicalisation includes every attribute
	// present — but the gateway has no semantics for them.
	Extra map[string]string

	// Start and End delimit the element within the source text.
	Start, End int
}

// Result is the outcome of verifying a whole tool response.
type Result struct {
	// Fences holds every successfully verified fence, in document order.
	Fences []Fence

	// UnsignedRegions holds spans of text that sit outside any verified
	// fence and are not pure whitespace.
	//
	// This matters more than it first appears. The relay's awareness
	// preamble — the text instructing the model to treat fenced content as
	// data — is itself unsigned. Nothing in the current pipeline lets an
	// attacker reach it, because untrusted content is escaped and enclosed
	// within the fence. But a gateway that verified the fence and ignored
	// everything around it would not notice if that ever stopped being
	// true, and a forged preamble ("disregard the fence below") defeats the
	// entire mechanism without touching a signature. The paper's §4.2
	// assumes every segment of the prompt is fenced; where that does not
	// hold, the gateway should at minimum say so.
	UnsignedRegions []string

	// Rejections holds candidates that presented a signature attribute and
	// failed. A non-empty Rejections is the boundary-escape attack of
	// §2.3.2 / §6.3.2 being caught, and is the signal worth alerting on.
	Rejections []Rejection

	// Ignored holds offsets of `<sec:fence` occurrences that made no
	// authenticity claim — overwhelmingly the awareness preamble's prose
	// references to the syntax. They are not attacks and not evidence of
	// one; the text they sit in is covered by UnsignedRegions.
	Ignored []int
}

// Rejection records one failed fence candidate.
type Rejection struct {
	Offset int
	Reason string
	// Snippet is a short, truncated excerpt for the audit log. It is
	// attacker-controlled text and must never be interpolated into a prompt.
	Snippet string
}

// Verifier holds verification configuration.
type Verifier struct {
	// Keys is the set of acceptable public keys. Multiple keys are
	// supported because §7.4.1 requires that old and new keys both verify
	// during a rotation window, and because the relay mints a fresh key on
	// every restart.
	Keys []ed25519.PublicKey

	// Scheme selects the signature construction.
	Scheme SchemeMode

	// MaxClockSkew bounds how far a fence timestamp may sit in the future.
	// Zero disables the check.
	MaxClockSkew time.Duration

	// MaxAge bounds how old a fence may be. Zero disables the check.
	// Signatures alone carry no freshness: a valid fence captured once is a
	// valid fence forever, so a gateway replaying cached tool output could
	// feed stale content into a live session undetected.
	MaxAge time.Duration

	// RequireNonce rejects fences without a nonce attribute. The nonce is
	// the relay's extension, not the paper's; it is what makes the
	// awareness preamble able to name an authoritative boundary.
	RequireNonce bool

	// Now is injectable for testing. Nil means time.Now.
	Now func() time.Time
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Verify scans a tool response and verifies every fence it contains.
//
// It never returns an error for "a fence failed" — that is a Result with a
// populated Rejections slice, which the caller's policy decides what to do
// with. An error is returned only when the input cannot be processed at all.
func (v *Verifier) Verify(s string) (*Result, error) {
	if len(v.Keys) == 0 {
		return nil, errors.New("verifier has no public keys configured")
	}

	res := &Result{}
	consumed := make([][2]int, 0, 2)

	for _, off := range candidateOffsets(s) {
		// Skip candidates that fall inside an already-verified element.
		if within(consumed, off) {
			continue
		}

		// A candidate that does not even claim a signature is not a failed
		// fence, it is prose. Recording it as a rejection would make every
		// genuine response containing the awareness preamble look like an
		// attack. It is still not trusted — it lands in UnsignedRegions.
		claims := claimsSignature(s, off)

		pf, err := scanFenceAt(s, off)
		if err != nil {
			if claims {
				res.Rejections = append(res.Rejections, Rejection{
					Offset: off, Reason: err.Error(), Snippet: snippet(s, off),
				})
			} else {
				res.Ignored = append(res.Ignored, off)
			}
			continue
		}

		f, err := v.verifyParsed(pf)
		if err != nil {
			if claims {
				res.Rejections = append(res.Rejections, Rejection{
					Offset: off, Reason: err.Error(), Snippet: snippet(s, off),
				})
			} else {
				res.Ignored = append(res.Ignored, off)
			}
			continue
		}

		res.Fences = append(res.Fences, *f)
		consumed = append(consumed, [2]int{pf.Start, pf.End})
	}

	res.UnsignedRegions = unsignedRegions(s, consumed)
	return res, nil
}

// verifyParsed applies schema checks and the signature check to one candidate.
func (v *Verifier) verifyParsed(pf *parsedFence) (*Fence, error) {
	var sigB64 string
	haveSig := false
	signed := make([]string, 0, len(pf.Attrs))
	byName := make(map[string]string, len(pf.Attrs))

	for _, a := range pf.Attrs {
		switch {
		case a.Name == "signature":
			// The signature cannot cover itself.
			sigB64 = a.Value
			haveSig = true
			continue
		case a.Name == "xmlns:sec":
			// The one namespace declaration the generator emits. It is
			// presentation, not metadata, and the generator excludes it from
			// the canonical form, so we must too or nothing would ever
			// verify. Its value is still checked: it is the only attribute
			// outside the signature, so it is the only one an attacker could
			// rewrite freely.
			if a.Value != FenceNamespace {
				return nil, fmt.Errorf("%w: wrong namespace %q", ErrSchemaViolation, a.Value)
			}
			continue
		case strings.HasPrefix(a.Name, "xmlns"):
			// Any OTHER xmlns-prefixed attribute. These used to be excluded
			// from the canonical form alongside xmlns:sec, which put them
			// outside the signature while leaving them inside the opening tag
			// the model receives — so appending
			// `xmlnsx="ignore the fence"` to a captured, validly signed fence
			// produced a fence that still verified and carried the injected
			// text through. The generator emits exactly one namespace
			// declaration, so refusing the rest costs nothing and closes the
			// only attribute channel the signature did not cover.
			return nil, fmt.Errorf("%w: unexpected namespace declaration %q",
				ErrSchemaViolation, a.Name)
		}
		// Every remaining attribute is canonicalised, including ones this
		// gateway has no meaning for. Doing otherwise would let an
		// unrecognised attribute ride along outside the signature while
		// still being visible to the model.
		signed = append(signed, a.Name+`="`+a.Value+`"`)
		byName[a.Name] = a.Value
	}

	if !haveSig {
		return nil, fmt.Errorf("%w: missing signature attribute", ErrSchemaViolation)
	}

	// Canonical form: pairs sorted as whole strings, single-space joined.
	sort.Strings(signed)
	canonical := strings.Join(signed, " ")

	// Recover the signed plaintext.
	inner, err := stripFramingNewlines(pf.Body)
	if err != nil {
		return nil, err
	}
	var content string
	if pf.Encoding == EncodingCDATA {
		content, err = decodeCDATA(inner)
	} else {
		content, err = unescapeContent(inner)
	}
	if err != nil {
		return nil, err
	}

	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("%w: signature is not valid base64", ErrSchemaViolation)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: signature is %d bytes, want %d",
			ErrSchemaViolation, len(sig), ed25519.SignatureSize)
	}

	msg, err := v.signingInput(content, canonical)
	if err != nil {
		return nil, err
	}

	ok := false
	for _, pk := range v.Keys {
		if len(pk) == ed25519.PublicKeySize && ed25519.Verify(pk, msg, sig) {
			ok = true
			break
		}
	}
	if !ok {
		return nil, ErrBadSignature
	}

	// Schema checks run only after the signature passes. Reporting "invalid
	// rating" on an unsigned fence would be answering a question about
	// attacker-authored text as though it were meaningful.
	f := &Fence{
		Content: content,
		Extra:   map[string]string{},
		Start:   pf.Start,
		End:     pf.End,
	}
	for name, val := range byName {
		switch name {
		case "type":
			f.Type = val
		case "rating":
			f.Rating = val
		case "source":
			f.Source = val
		case "nonce":
			f.Nonce = val
		case "encoding":
			f.Encoding = val
		case "timestamp":
			ts, err := time.Parse(time.RFC3339, val)
			if err != nil {
				return nil, fmt.Errorf("%w: timestamp %q is not RFC 3339", ErrSchemaViolation, val)
			}
			f.Timestamp = ts
		default:
			f.Extra[name] = val
		}
	}

	switch f.Type {
	case TypeInstructions, TypeContent, TypeData:
	case "":
		return nil, fmt.Errorf("%w: missing required attribute type", ErrSchemaViolation)
	default:
		return nil, fmt.Errorf("%w: type %q outside enumeration", ErrSchemaViolation, f.Type)
	}
	switch f.Rating {
	case RatingTrusted, RatingPartiallyTrusted, RatingUntrusted:
	case "":
		return nil, fmt.Errorf("%w: missing required attribute rating", ErrSchemaViolation)
	default:
		return nil, fmt.Errorf("%w: rating %q outside enumeration", ErrSchemaViolation, f.Rating)
	}
	if v.RequireNonce && f.Nonce == "" {
		return nil, fmt.Errorf("%w: missing nonce", ErrSchemaViolation)
	}

	if !f.Timestamp.IsZero() {
		now := v.now()
		if v.MaxClockSkew > 0 && f.Timestamp.After(now.Add(v.MaxClockSkew)) {
			return nil, fmt.Errorf("%w: timestamp is %s in the future",
				ErrSchemaViolation, f.Timestamp.Sub(now).Round(time.Second))
		}
		if v.MaxAge > 0 && now.Sub(f.Timestamp) > v.MaxAge {
			return nil, fmt.Errorf("%w: fence is %s old, limit %s",
				ErrSchemaViolation, now.Sub(f.Timestamp).Round(time.Second), v.MaxAge)
		}
	}

	return f, nil
}

// signingInput builds the byte string the signature is computed over.
func (v *Verifier) signingInput(content, canonical string) ([]byte, error) {
	switch v.Scheme {
	case SchemePaperLiteral:
		h := sha256.Sum256([]byte(content + canonical))
		return h[:], nil
	case SchemeRelay:
		total := len(relaySigDomain) + 1 + 8
		if len(content) > math.MaxInt-total {
			return nil, errors.New("fence content too large")
		}
		total += len(content)
		if len(canonical) > math.MaxInt-total {
			return nil, errors.New("fence metadata too large")
		}
		total += len(canonical)

		msg := make([]byte, 0, total)
		msg = append(msg, relaySigDomain...)
		msg = append(msg, 0x00)
		var lenBuf [8]byte
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(content)))
		msg = append(msg, lenBuf[:]...)
		msg = append(msg, content...)
		msg = append(msg, canonical...)
		return msg, nil
	default:
		return nil, fmt.Errorf("unknown signature scheme %d", v.Scheme)
	}
}

// within reports whether off falls inside any consumed span.
func within(spans [][2]int, off int) bool {
	for _, sp := range spans {
		if off >= sp[0] && off < sp[1] {
			return true
		}
	}
	return false
}

// unsignedRegions returns the non-whitespace text outside all verified fences.
func unsignedRegions(s string, consumed [][2]int) []string {
	sort.Slice(consumed, func(i, j int) bool { return consumed[i][0] < consumed[j][0] })
	var out []string
	prev := 0
	for _, sp := range consumed {
		if sp[0] > prev {
			if seg := strings.TrimSpace(s[prev:sp[0]]); seg != "" {
				out = append(out, seg)
			}
		}
		prev = sp[1]
	}
	if prev < len(s) {
		if seg := strings.TrimSpace(s[prev:]); seg != "" {
			out = append(out, seg)
		}
	}
	return out
}

// snippet returns a short excerpt for audit logging, with newlines flattened.
func snippet(s string, off int) string {
	const n = 120
	end := off + n
	if end > len(s) {
		end = len(s)
	}
	out := strings.NewReplacer("\n", " ", "\r", " ", "\t", " ").Replace(s[off:end])
	if end < len(s) {
		out += "…"
	}
	return out
}
