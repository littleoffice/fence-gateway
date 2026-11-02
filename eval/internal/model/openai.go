package model

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// openaiBackend speaks the OpenAI-compatible /chat/completions API that vLLM,
// llama.cpp's server, Ollama and most open-weight model servers expose. It
// is here for the models this eval exists to compare and later fine-tune:
// self-hosted open-weight ones, before and after training.
type openaiBackend struct {
	cfg Config
	hc  *http.Client
}

func newOpenAI(cfg Config) *openaiBackend {
	return &openaiBackend{cfg: cfg, hc: &http.Client{Timeout: 10 * time.Minute}}
}

func (b *openaiBackend) Name() string { return "openai:" + b.cfg.Model }

type oaMessage struct {
	Role       string       `json:"role"`
	Content    *string      `json:"content"`
	ToolCalls  []oaToolCall `json:"tool_calls,omitempty"`
	ToolCallID string       `json:"tool_call_id,omitempty"`
}

type oaToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type oaTool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Parameters  map[string]any `json:"parameters"`
	} `json:"function"`
}

func str(s string) *string { return &s }

func (b *openaiBackend) Start(s Start) Conversation {
	c := &openaiConv{b: b}
	for _, t := range s.Tools {
		var ot oaTool
		ot.Type = "function"
		ot.Function.Name = t.Name
		ot.Function.Description = t.Description
		ot.Function.Parameters = t.InputSchema
		c.tools = append(c.tools, ot)
	}
	c.msgs = []oaMessage{{Role: "system", Content: str(s.System)}, {Role: "user", Content: str(s.User)}}
	return c
}

type openaiConv struct {
	b     *openaiBackend
	tools []oaTool
	msgs  []oaMessage
}

func (c *openaiConv) Next(ctx context.Context, results []Result) (Turn, error) {
	for _, r := range results {
		text := r.Text
		if r.IsError {
			text = "ERROR: " + text
		}
		c.msgs = append(c.msgs, oaMessage{Role: "tool", Content: str(text), ToolCallID: r.ID})
	}
	body, _ := json.Marshal(map[string]any{"model": c.b.cfg.Model, "messages": c.msgs, "tools": c.tools})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.b.cfg.BaseURL, "/")+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return Turn{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.b.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.b.cfg.APIKey)
	}
	resp, err := c.b.hc.Do(req)
	if err != nil {
		return Turn{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode != http.StatusOK {
		return Turn{}, fmt.Errorf("chat/completions: %s: %.500s", resp.Status, raw)
	}
	var out struct {
		Choices []struct {
			Message      oaMessage `json:"message"`
			FinishReason string    `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || len(out.Choices) == 0 {
		return Turn{}, fmt.Errorf("chat/completions: unreadable response: %.500s", raw)
	}
	m := out.Choices[0].Message
	m.Role = "assistant"
	c.msgs = append(c.msgs, m)
	t := Turn{StopReason: out.Choices[0].FinishReason}
	if m.Content != nil {
		t.Text = *m.Content
	}
	for _, tc := range m.ToolCalls {
		t.Calls = append(t.Calls, Call{ID: tc.ID, Name: tc.Function.Name, Args: json.RawMessage(tc.Function.Arguments)})
	}
	return t, nil
}
