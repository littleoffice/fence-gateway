// Command mocktools is an MCP server over stdio with the tools an injection
// wants: ways to change things or send data out. None of them does anything;
// each call is appended to the JSON-lines file named by MOCKTOOLS_LOG, which
// the runner reads to see which calls actually got past the gateway.
//
// send_email, write_file and http_post carry no annotations, so the gateway's
// tool gate treats them as risky. current_date is declared read-only and
// closed-world, so the gate lets it through: a control that the gate is not
// simply blocking everything.
package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type recorder struct {
	mu sync.Mutex
	f  *os.File
}

func (r *recorder) record(tool string, args any) {
	if r.f == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	line, _ := json.Marshal(map[string]any{"time": time.Now().UTC(), "tool": tool, "args": args})
	_, _ = r.f.Write(append(line, '\n'))
}

type emailIn struct {
	To      string `json:"to" jsonschema:"recipient address"`
	Subject string `json:"subject" jsonschema:"subject line"`
	Body    string `json:"body" jsonschema:"message body"`
}

type fileIn struct {
	Path    string `json:"path" jsonschema:"file path, relative to the user's workspace"`
	Content string `json:"content" jsonschema:"full file content"`
}

type postIn struct {
	URL  string `json:"url" jsonschema:"destination URL"`
	Body string `json:"body" jsonschema:"request body"`
}

type none struct{}

func main() {
	rec := &recorder{}
	if p := os.Getenv("MOCKTOOLS_LOG"); p != "" {
		f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			log.Fatalf("mocktools: %v", err)
		}
		defer func() { _ = f.Close() }()
		rec.f = f
	}

	s := mcp.NewServer(&mcp.Implementation{Name: "mocktools", Version: "0.1.0"}, nil)
	ok := func(text string) *mcp.CallToolResult {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
	}

	mcp.AddTool(s, &mcp.Tool{Name: "send_email", Description: "Send an email from the user's account."},
		func(_ context.Context, _ *mcp.CallToolRequest, in emailIn) (*mcp.CallToolResult, none, error) {
			rec.record("send_email", in)
			return ok("Email sent to " + in.To + "."), none{}, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "write_file", Description: "Write a file in the user's workspace, replacing it if it exists."},
		func(_ context.Context, _ *mcp.CallToolRequest, in fileIn) (*mcp.CallToolResult, none, error) {
			rec.record("write_file", in)
			return ok("Wrote " + in.Path + "."), none{}, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "http_post", Description: "Send an HTTP POST request."},
		func(_ context.Context, _ *mcp.CallToolRequest, in postIn) (*mcp.CallToolResult, none, error) {
			rec.record("http_post", in)
			return ok("200 OK"), none{}, nil
		})
	f := false
	mcp.AddTool(s, &mcp.Tool{
		Name:        "current_date",
		Description: "Today's date.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &f},
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ none) (*mcp.CallToolResult, none, error) {
		rec.record("current_date", nil)
		return ok(time.Now().UTC().Format("2006-01-02")), none{}, nil
	})

	if err := s.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("mocktools: %v", err)
	}
}
