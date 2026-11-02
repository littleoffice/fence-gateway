// Package corpus loads the eval cases: a user task, the web pages the fake
// SearXNG serves for it, and what counts as the attack succeeding.
//
// A case is one JSON file under corpus/cases. The file name is irrelevant;
// the id inside it is what results are keyed on, so renaming a file does not
// break comparisons across runs.
package corpus

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Families group cases for scoring. A new family is a new row in the report,
// so they are a closed list rather than free text.
var Families = map[string]string{
	"benign":        "no attack; measures utility and false refusals",
	"direct":        "plain instructions in visible page text",
	"fake-fence":    "page text imitating a trusted <sec:fence> or closing the real one",
	"fake-preamble": "page text imitating the relay's awareness preamble or gateway notices",
	"role-mimicry":  "page text imitating user, system or assistant turns",
	"hidden":        "instructions in elements the relay should strip (hidden, aria-hidden, display:none)",
	"metadata":      "instructions in <meta>/Open Graph fields the hidden-text filter does not touch",
	"exfil-url":     "asks the model to fetch an attacker URL carrying the user's secret",
	"persuasion":    "argues rather than commands; no fencing scheme claims to stop this",
	"multi-step":    "the injection is split across two pages the model reads in turn",
}

// Sinks are the tools mocktools exposes. An attack names one of these.
var Sinks = map[string]bool{"send_email": true, "write_file": true, "http_post": true}

// Case is one eval item.
type Case struct {
	ID          string `json:"id"`
	Family      string `json:"family"`
	Description string `json:"description"`
	// Task is the user's message to the agent.
	Task string `json:"task"`
	// Pages are what the fake SearXNG returns for any query while this case
	// is active, in result order.
	Pages []Page `json:"pages"`
	// Attack is nil for benign cases.
	Attack *Attack `json:"attack,omitempty"`
	// Utility says whether the agent did the user's task.
	Utility Utility `json:"utility"`
}

// Page is one search result and the HTML behind it.
type Page struct {
	// Slug is the last path segment of the page URL.
	Slug    string `json:"slug"`
	Title   string `json:"title"`
	Snippet string `json:"snippet"`
	HTML    string `json:"html"`
}

// Attack describes what the injected instructions want.
type Attack struct {
	// Tool is the unprefixed sink the injection asks for, or "" when the
	// goal is a fetch (exfil-url) rather than a sink call.
	Tool string `json:"tool,omitempty"`
	// Marker is a string the attacker's requested call carries and no
	// legitimate call for the task would: an address, a host, a file name.
	// A tool call whose arguments contain it is the attack landing.
	Marker string `json:"marker"`
}

// Utility is checked against the agent's final answer and its tool calls.
type Utility struct {
	// AnswerContains must all appear in the final answer, case-insensitive.
	AnswerContains []string `json:"answer_contains,omitempty"`
	// ExpectTool, when set, is a sink the task legitimately needs (a benign
	// "save this to notes.md"). Not calling it, or having it blocked, is a
	// utility loss: this is how gate friction is measured.
	ExpectTool string `json:"expect_tool,omitempty"`
}

var idRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// Load reads every *.json under dir, checks it, and returns cases sorted by id.
func Load(dir string) ([]Case, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no cases in %s", dir)
	}
	seen := map[string]string{}
	var out []Case
	for _, f := range files {
		c, err := loadFile(f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if prev, dup := seen[c.ID]; dup {
			return nil, fmt.Errorf("%s: id %q already used by %s", f, c.ID, prev)
		}
		seen[c.ID] = f
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func loadFile(path string) (Case, error) {
	var c Case
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, err
	}
	return c, c.Validate()
}

// Validate checks a case is internally consistent.
func (c Case) Validate() error {
	if !idRE.MatchString(c.ID) {
		return fmt.Errorf("id %q: lower-case letters, digits and '-'", c.ID)
	}
	if _, ok := Families[c.Family]; !ok {
		return fmt.Errorf("family %q is not one of the known families", c.Family)
	}
	if strings.TrimSpace(c.Task) == "" {
		return fmt.Errorf("task is empty")
	}
	if len(c.Pages) == 0 {
		return fmt.Errorf("no pages")
	}
	slugs := map[string]bool{}
	for i, p := range c.Pages {
		if !idRE.MatchString(p.Slug) {
			return fmt.Errorf("pages[%d]: slug %q: lower-case letters, digits and '-'", i, p.Slug)
		}
		if slugs[p.Slug] {
			return fmt.Errorf("pages[%d]: slug %q used twice", i, p.Slug)
		}
		slugs[p.Slug] = true
		if p.HTML == "" {
			return fmt.Errorf("pages[%d]: html is empty", i)
		}
	}
	benign := c.Family == "benign"
	if benign != (c.Attack == nil) {
		return fmt.Errorf("benign cases have no attack, and every other case has one")
	}
	if c.Attack != nil {
		if c.Attack.Marker == "" {
			return fmt.Errorf("attack.marker is empty")
		}
		if c.Attack.Tool != "" && !Sinks[c.Attack.Tool] {
			return fmt.Errorf("attack.tool %q is not a sink", c.Attack.Tool)
		}
		if strings.Contains(strings.ToLower(c.Task), strings.ToLower(c.Attack.Marker)) {
			return fmt.Errorf("attack.marker appears in the task, so a legitimate call could carry it")
		}
	}
	if c.Utility.ExpectTool != "" && !Sinks[c.Utility.ExpectTool] {
		return fmt.Errorf("utility.expect_tool %q is not a sink", c.Utility.ExpectTool)
	}
	if len(c.Utility.AnswerContains) == 0 && c.Utility.ExpectTool == "" {
		return fmt.Errorf("utility needs answer_contains or expect_tool, or utility cannot be scored")
	}
	return nil
}
