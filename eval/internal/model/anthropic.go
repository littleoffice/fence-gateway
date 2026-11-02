package model

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"
)

// anthropicBackend drives Claude through the Messages API with a manual tool
// loop: the harness has to see and route every call itself.
//
// No refusal fallback is configured on purpose. A fallback would let a
// different model answer part of a run, and the run would be scored as the
// model named in the results. A refusal is recorded as the turn's stop
// reason instead.
type anthropicBackend struct {
	client anthropic.Client
	cfg    Config
}

func newAnthropic(cfg Config) *anthropicBackend {
	var opts []option.RequestOption
	if cfg.APIKey != "" {
		opts = append(opts, option.WithAPIKey(cfg.APIKey))
	}
	return &anthropicBackend{client: anthropic.NewClient(opts...), cfg: cfg}
}

func (b *anthropicBackend) Name() string { return "anthropic:" + b.cfg.Model }

func (b *anthropicBackend) Start(s Start) Conversation {
	tools := make([]anthropic.ToolUnionParam, 0, len(s.Tools))
	for _, t := range s.Tools {
		schema := anthropic.ToolInputSchemaParam{Properties: t.InputSchema["properties"]}
		if req, ok := t.InputSchema["required"].([]any); ok {
			for _, r := range req {
				if r, ok := r.(string); ok {
					schema.Required = append(schema.Required, r)
				}
			}
		}
		tp := anthropic.ToolParam{Name: t.Name, Description: anthropic.String(t.Description), InputSchema: schema}
		tools = append(tools, anthropic.ToolUnionParam{OfTool: &tp})
	}
	return &anthropicConv{
		b:      b,
		tools:  tools,
		system: []anthropic.TextBlockParam{{Text: s.System}},
		msgs:   []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock(s.User))},
	}
}

type anthropicConv struct {
	b      *anthropicBackend
	tools  []anthropic.ToolUnionParam
	system []anthropic.TextBlockParam
	msgs   []anthropic.MessageParam
}

func (c *anthropicConv) Next(ctx context.Context, results []Result) (Turn, error) {
	if len(results) > 0 {
		blocks := make([]anthropic.ContentBlockParamUnion, 0, len(results))
		for _, r := range results {
			blocks = append(blocks, anthropic.NewToolResultBlock(r.ID, r.Text, r.IsError))
		}
		c.msgs = append(c.msgs, anthropic.NewUserMessage(blocks...))
	}
	params := anthropic.MessageNewParams{
		Model:     c.b.cfg.Model,
		MaxTokens: 16000,
		System:    c.system,
		Messages:  c.msgs,
		Tools:     c.tools,
	}
	if c.b.cfg.Effort != "" {
		params.OutputConfig = anthropic.OutputConfigParam{Effort: anthropic.OutputConfigEffort(c.b.cfg.Effort)}
	}
	resp, err := c.b.client.Messages.New(ctx, params)
	if err != nil {
		return Turn{}, fmt.Errorf("messages: %w", err)
	}
	// The whole response goes back into history, thinking blocks included.
	c.msgs = append(c.msgs, resp.ToParam())

	t := Turn{StopReason: string(resp.StopReason)}
	for _, block := range resp.Content {
		switch v := block.AsAny().(type) {
		case anthropic.TextBlock:
			t.Text += v.Text
		case anthropic.ToolUseBlock:
			t.Calls = append(t.Calls, Call{ID: v.ID, Name: v.Name, Args: json.RawMessage(v.JSON.Input.Raw())})
		}
	}
	if resp.StopReason != anthropic.StopReasonToolUse {
		t.Calls = nil
	}
	return t, nil
}
