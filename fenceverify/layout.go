package fenceverify

import (
	"fmt"
	"strconv"
	"strings"
)

// ── Response layout ───────────────────────────────────────────────────────────
//
// Signatures are checked one fence at a time, and each one proves only that its
// own bytes came from the relay. They say nothing about how fences were put
// together. Under format 1.1 (the relay's FENCE_PREAMBLE=fenced) a response is
// two fences: a trusted preamble telling the model to treat what follows as
// data, and the content it describes, linked by the content fence's nonce,
// which the preamble names. Remove the preamble, or splice a preamble from one
// response onto the content of another, and every remaining signature still
// verifies. So the linkage is checked separately, after verification — step 6
// of the relay's docs/fence-verification.md.

// AwarenessSource is the source attribute of the relay's 1.1 preamble fence.
const AwarenessSource = "mcp-searxng-relay:awareness"

// Fence format versions the relay emits (the `version` attribute).
const (
	// FormatProse is the 1.0 layout: an unsigned prose preamble, then one
	// content fence.
	FormatProse = "1.0"
	// FormatFenced is the 1.1 layout: the preamble in a signed trusted
	// fence of its own, then the content fence.
	FormatFenced = "1.1"
)

// Version returns the fence's format version, or "" when it carries none —
// output from a producer other than the relay, which predates the attribute.
func (f *Fence) Version() string { return f.Extra["version"] }

// CheckLayout checks how the verified fences of one tool response fit
// together, and returns what is wrong in plain words (nil when nothing is).
// It is called with a Result whose fences have all verified; it does not look
// at signatures.
//
// Rules:
//   - Every fence carries a known version, or none. An unknown version is a
//     layout this verifier does not implement, so it cannot be checked.
//   - All fences of one response share one version: a mix means responses were
//     spliced together.
//   - Under 1.1, each content fence is preceded by exactly one preamble fence
//     (rating trusted, type instructions, source AwarenessSource) that names
//     its nonce and shares its kid and timestamp; and every preamble describes
//     exactly one content fence.
//   - A trusted fence is only ever that preamble. The relay signs nothing else
//     as trusted, so any other is not something it produced as a response.
func CheckLayout(r *Result) []string {
	if len(r.Fences) == 0 {
		return nil
	}
	var problems []string

	version := r.Fences[0].Version()
	for i := range r.Fences {
		f := &r.Fences[i]
		switch v := f.Version(); v {
		case "", FormatProse, FormatFenced:
			if v != version {
				problems = append(problems, fmt.Sprintf(
					"fences of format %q and %q in one response: responses were spliced together",
					version, v))
				return problems
			}
		default:
			problems = append(problems, fmt.Sprintf("fence format %q is not one this gateway implements", v))
			return problems
		}
	}

	var preambles, content []*Fence
	for i := range r.Fences {
		f := &r.Fences[i]
		if f.Rating != RatingTrusted {
			content = append(content, f)
			continue
		}
		if version != FormatFenced || f.Type != TypeInstructions || f.Source != AwarenessSource {
			problems = append(problems, fmt.Sprintf(
				"trusted fence with type %q and source %q is not the relay's awareness preamble", f.Type, f.Source))
			continue
		}
		preambles = append(preambles, f)
	}
	if version != FormatFenced {
		return problems
	}

	used := make(map[*Fence]bool)
	for _, c := range content {
		var match *Fence
		for _, p := range preambles {
			if !used[p] && p.Start < c.Start && strings.Contains(p.Content, `nonce="`+c.Nonce+`"`) {
				match = p
				break
			}
		}
		if match == nil {
			problems = append(problems, fmt.Sprintf(
				"content fence (nonce %s) has no awareness preamble naming it: the preamble was removed or swapped",
				c.Nonce))
			continue
		}
		used[match] = true
		if match.Extra["kid"] != c.Extra["kid"] {
			problems = append(problems, fmt.Sprintf(
				"preamble and content fence (nonce %s) were signed by different keys (%q, %q)",
				c.Nonce, match.Extra["kid"], c.Extra["kid"]))
		}
		if !match.Timestamp.Equal(c.Timestamp) {
			problems = append(problems, fmt.Sprintf(
				"preamble and content fence (nonce %s) carry different timestamps", c.Nonce))
		}
	}
	for _, p := range preambles {
		if !used[p] {
			problems = append(problems, fmt.Sprintf(
				"awareness preamble (nonce %s) describes no content fence in this response", p.Nonce))
		}
	}
	return problems
}

// OlderFormat reports whether format a is older than b. Both should be
// versions CheckLayout accepts; "" (no version) sorts before any.
func OlderFormat(a, b string) bool {
	return formatRank(a) < formatRank(b)
}

func formatRank(v string) int {
	if v == "" {
		return 0
	}
	major, minor, ok := strings.Cut(v, ".")
	if !ok {
		return 0
	}
	ma, err1 := strconv.Atoi(major)
	mi, err2 := strconv.Atoi(minor)
	if err1 != nil || err2 != nil {
		return 0
	}
	return ma*1000 + mi + 1
}
