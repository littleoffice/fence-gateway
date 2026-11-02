// Package model is the agent's language model behind one small interface, so
// the same corpus and conditions run against a hosted model, a self-hosted
// open-weight model, or a scripted stand-in that tests the harness itself.
package model

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/littleoffice/fence-gateway/eval/internal/corpus"
	"github.com/littleoffice/fence-gateway/eval/internal/toolset"
)

// Call is one tool call the model asked for.
type Call struct {
	ID   string          `json:"id"`
	Name string          `json:"name"`
	Args json.RawMessage `json:"args"`
}

// Turn is one model response: text, and the tool calls it wants run. No
// calls means the model is done and Text is its answer.
type Turn struct {
	Text  string `json:"text"`
	Calls []Call `json:"calls,omitempty"`
	// StopReason is the backend's own, recorded for debugging.
	StopReason string `json:"stop_reason,omitempty"`
}

// Result is a tool's output, returned to the model by Call ID.
type Result struct {
	ID      string
	Text    string
	IsError bool
}

// Start is what a conversation begins with.
type Start struct {
	System string
	User   string
	Tools  []toolset.Tool
	// Secret is the canary planted in System; the scripted backend uses it
	// to play an attacker-obedient model.
	Secret string
	// Case is given to the scripted backend only; real models never see it.
	Case corpus.Case
}

// Conversation is one agent run.
type Conversation interface {
	// Next sends the previous turn's tool results (none on the first call)
	// and returns the model's next turn.
	Next(ctx context.Context, results []Result) (Turn, error)
}

// Backend starts conversations.
type Backend interface {
	Name() string
	Start(s Start) Conversation
}

// Config selects a backend.
type Config struct {
	Backend string // anthropic | openai | scripted-obey | scripted-ignore
	Model   string
	// BaseURL is the OpenAI-compatible endpoint for self-hosted models
	// (vLLM, llama.cpp server, Ollama), e.g. http://127.0.0.1:8000/v1.
	BaseURL string
	APIKey  string
	Effort  string
}

// New builds the backend cfg names.
func New(cfg Config) (Backend, error) {
	switch cfg.Backend {
	case "anthropic":
		if cfg.Model == "" {
			cfg.Model = "claude-opus-5-5"
		}
		return newAnthropic(cfg), nil
	case "openai":
		if cfg.BaseURL == "" || cfg.Model == "" {
			return nil, fmt.Errorf("backend openai needs -base-url and -model")
		}
		return newOpenAI(cfg), nil
	case "scripted-obey", "scripted-ignore":
		return scripted{obey: cfg.Backend == "scripted-obey"}, nil
	default:
		return nil, fmt.Errorf("unknown backend %q: anthropic, openai, scripted-obey or scripted-ignore", cfg.Backend)
	}
}
