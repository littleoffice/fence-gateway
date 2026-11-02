package corpus

import (
	"strings"
	"testing"
)

// The shipped corpus loads and every case validates.
func TestShippedCorpus(t *testing.T) {
	cs, err := Load("../../corpus/cases")
	if err != nil {
		t.Fatal(err)
	}
	fams := map[string]int{}
	for _, c := range cs {
		fams[c.Family]++
	}
	for f := range Families {
		if fams[f] == 0 {
			t.Errorf("family %q has no case", f)
		}
	}
}

// Every attack's marker must be in its pages, or no model could act on it
// and the case would measure nothing.
func TestMarkersAppearInPages(t *testing.T) {
	cs, err := Load("../../corpus/cases")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if c.Attack == nil {
			continue
		}
		found := false
		for _, p := range c.Pages {
			if strings.Contains(p.HTML, c.Attack.Marker) || strings.Contains(p.Snippet, c.Attack.Marker) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: marker %q is on none of its pages", c.ID, c.Attack.Marker)
		}
	}
}

func TestValidateRejects(t *testing.T) {
	ok := Case{ID: "a", Family: "direct", Task: "t", Pages: []Page{{Slug: "p", HTML: "x"}},
		Attack: &Attack{Tool: "send_email", Marker: "m@x"}, Utility: Utility{AnswerContains: []string{"y"}}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid case rejected: %v", err)
	}
	for name, mut := range map[string]func(*Case){
		"benign with attack": func(c *Case) { c.Family = "benign" },
		"attack without one": func(c *Case) { c.Attack = nil },
		"marker in task":     func(c *Case) { c.Task = "write to m@x" },
		"unknown sink":       func(c *Case) { c.Attack.Tool = "rm_rf" },
		"unknown family":     func(c *Case) { c.Family = "other" },
		"no utility":         func(c *Case) { c.Utility = Utility{} },
		"duplicate slug":     func(c *Case) { c.Pages = append(c.Pages, c.Pages[0]) },
		"bad id":             func(c *Case) { c.ID = "Has Spaces" },
	} {
		c := ok
		a := *ok.Attack
		c.Attack = &a
		c.Pages = append([]Page(nil), ok.Pages...)
		mut(&c)
		if c.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
