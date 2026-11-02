// Package agent runs one conversation: the model asks for tools, the tool set
// runs them, until the model answers or the turn limit is reached. Every step
// is recorded; scoring reads the record, not the model's own account.
package agent

import (
	"context"
	"time"

	"github.com/littleoffice/fence-gateway/eval/internal/model"
	"github.com/littleoffice/fence-gateway/eval/internal/toolset"
)

// Step is one tool call and what came back.
type Step struct {
	Turn    int           `json:"turn"`
	Call    model.Call    `json:"call"`
	Result  string        `json:"result"`
	IsError bool          `json:"is_error"`
	Elapsed time.Duration `json:"elapsed_ns"`
}

// Transcript is a whole run.
type Transcript struct {
	Steps      []Step                `json:"steps"`
	Turns      []model.Turn          `json:"turns"`
	Answer     string                `json:"answer"`
	StopReason string                `json:"stop_reason"`
	HitLimit   bool                  `json:"hit_limit"`
	Error      string                `json:"error,omitempty"`
	Asked      []toolset.Elicitation `json:"elicitations,omitempty"`
}

// Run drives conv against tools for at most maxTurns model turns.
func Run(ctx context.Context, conv model.Conversation, tools *toolset.Set, maxTurns int) Transcript {
	var tr Transcript
	var results []model.Result
	for turn := 1; ; turn++ {
		if turn > maxTurns {
			tr.HitLimit = true
			break
		}
		t, err := conv.Next(ctx, results)
		if err != nil {
			tr.Error = err.Error()
			break
		}
		tr.Turns = append(tr.Turns, t)
		tr.StopReason = t.StopReason
		if len(t.Calls) == 0 {
			tr.Answer = t.Text
			break
		}
		results = results[:0:0]
		for _, c := range t.Calls {
			start := time.Now()
			r := tools.Call(ctx, c.Name, c.Args)
			tr.Steps = append(tr.Steps, Step{Turn: turn, Call: c, Result: r.Text, IsError: r.IsError, Elapsed: time.Since(start)})
			results = append(results, model.Result{ID: c.ID, Text: r.Text, IsError: r.IsError})
		}
	}
	tr.Asked = tools.Elicitations()
	return tr
}
