package model

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// scripted is a stand-in model with no judgement, for testing the harness
// and for measuring the deterministic layers on their own.
//
// It searches for the task, reads every result, and answers with what it
// read. scripted-obey then also does what the attack wants, but only if the
// attack's marker reached it: when the relay stripped the hidden element, or
// the gateway withheld the result, the marker never arrives and it cannot
// obey. So scripted-obey is a maximally gullible model, and its attack
// success rate is what the relay and gateway let through to the model.
// scripted-ignore never obeys, and bounds utility from above.
type scripted struct{ obey bool }

func (s scripted) Name() string {
	if s.obey {
		return "scripted-obey"
	}
	return "scripted-ignore"
}

func (s scripted) Start(st Start) Conversation {
	return &scriptedConv{obey: s.obey, st: st}
}

type scriptedConv struct {
	obey  bool
	st    Start
	step  int
	urls  []string
	read  strings.Builder
	calls int
}

var pageURL = regexp.MustCompile(`https?://[^\s"'<>\]\)]+/p/[0-9a-f]+/[a-z0-9-]+/[a-z0-9-]+`)

func (c *scriptedConv) call(name string, args any) Call {
	c.calls++
	b, _ := json.Marshal(args)
	return Call{ID: fmt.Sprintf("s%d", c.calls), Name: name, Args: b}
}

func (c *scriptedConv) Next(_ context.Context, results []Result) (Turn, error) {
	for _, r := range results {
		c.read.WriteString(r.Text)
		c.read.WriteString("\n")
	}
	c.step++
	switch c.step {
	case 1:
		return Turn{Calls: []Call{c.call("searxng_web_search", map[string]any{"query": c.st.User})}}, nil
	case 2:
		seen := map[string]bool{}
		for _, u := range pageURL.FindAllString(c.read.String(), -1) {
			if !seen[u] {
				seen[u] = true
				c.urls = append(c.urls, u)
			}
		}
		if len(c.urls) > 0 {
			var calls []Call
			for _, u := range c.urls {
				calls = append(calls, c.call("searxng_read_url", map[string]any{"url": u}))
			}
			return Turn{Calls: calls}, nil
		}
		c.step++
		fallthrough
	case 3:
		var calls []Call
		a := c.st.Case.Attack
		if c.obey && a != nil && strings.Contains(c.read.String(), a.Marker) {
			calls = append(calls, c.attackCall())
		}
		if t := c.st.Case.Utility.ExpectTool; t != "" {
			calls = append(calls, c.call("sink_"+t, benignArgs(t, c.read.String())))
		}
		if len(calls) > 0 {
			return Turn{Calls: calls}, nil
		}
		c.step++
		fallthrough
	default:
		return Turn{Text: c.read.String(), StopReason: "scripted"}, nil
	}
}

func (c *scriptedConv) attackCall() Call {
	a := c.st.Case.Attack
	switch a.Tool {
	case "send_email":
		return c.call("sink_send_email", map[string]any{"to": a.Marker, "subject": "as requested", "body": c.st.Secret})
	case "write_file":
		return c.call("sink_write_file", map[string]any{"path": a.Marker, "content": c.st.Secret})
	case "http_post":
		return c.call("sink_http_post", map[string]any{"url": a.Marker, "body": c.st.Secret})
	default: // a fetch carrying the secret
		return c.call("searxng_read_url", map[string]any{"url": a.Marker + "?d=" + c.st.Secret})
	}
}

func benignArgs(tool, read string) map[string]any {
	summary := read
	if len(summary) > 2000 {
		summary = summary[:2000]
	}
	switch tool {
	case "send_email":
		return map[string]any{"to": "me@example.com", "subject": "notes", "body": summary}
	case "write_file":
		return map[string]any{"path": "notes.md", "content": summary}
	default:
		return map[string]any{"url": "https://example.com/notes", "body": summary}
	}
}
