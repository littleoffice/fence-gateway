// Package toolset connects the agent to its tools: either one fence-gateway
// started over stdio (which proxies the relay and mocktools), or, for the
// no-gateway baseline, the relay over HTTP and mocktools over stdio directly.
//
// Either way the agent sees the same tool names: the relay's own, and the
// sinks as sink_<tool>, which is how the gateway prefixes servers from
// -tools-config.
package toolset

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// SinkServer is the name mocktools is registered under; its tools appear as
// SinkServer + "_" + tool.
const SinkServer = "sink"

// Tool is what the model is told about one tool.
type Tool struct {
	Name        string
	Description string
	InputSchema map[string]any
}

// Elicitation is one question the gateway (or relay) put to "the user".
type Elicitation struct {
	Message string `json:"message"`
	Answer  string `json:"answer"`
}

// Result is one tool call's outcome as the model sees it.
type Result struct {
	Text    string
	IsError bool
}

// Set is a connected tool set.
type Set struct {
	sessions map[string]*mcp.ClientSession // tool name the model sees -> session
	upstream map[string]string             // tool name the model sees -> name at that session
	tools    []Tool

	mu          sync.Mutex
	elicitation []Elicitation
	closers     []func() error
}

// Options configure a connection.
type Options struct {
	// Confirm is how the simulated user answers a gate question: "accept" or
	// "decline". "decline" measures the gate as a stop; "accept" measures a
	// user who clicks through, which isolates the model.
	Confirm string
	// Stderr receives the gateway's and mocktools' stderr (audit log).
	Stderr *os.File
}

func (s *Set) elicit(confirm string) func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
	return func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		s.mu.Lock()
		s.elicitation = append(s.elicitation, Elicitation{Message: req.Params.Message, Answer: confirm})
		s.mu.Unlock()
		if confirm == "accept" {
			return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"remember": false}}, nil
		}
		return &mcp.ElicitResult{Action: "decline"}, nil
	}
}

// ViaGateway starts the gateway binary with args and connects to it over
// stdio. env is the gateway's complete environment.
func ViaGateway(ctx context.Context, gatewayBin string, args, env []string, o Options) (*Set, error) {
	s := &Set{sessions: map[string]*mcp.ClientSession{}, upstream: map[string]string{}}
	cmd := exec.Command(gatewayBin, args...)
	cmd.Env = env
	cmd.Stderr = o.Stderr
	cs, err := s.client(o).Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		return nil, fmt.Errorf("start gateway: %w", err)
	}
	s.closers = append(s.closers, cs.Close)
	if err := s.addTools(ctx, cs, ""); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

// Direct connects to the relay over HTTP and starts mocktools, with no
// gateway in between: no verification, no gate. The baseline.
func Direct(ctx context.Context, relayURL, relayToken, mocktoolsBin string, mocktoolsEnv []string, o Options) (*Set, error) {
	s := &Set{sessions: map[string]*mcp.ClientSession{}, upstream: map[string]string{}}
	hc := &http.Client{Transport: bearer{token: relayToken, base: http.DefaultTransport}}
	relay, err := s.client(o).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: relayURL, HTTPClient: hc, DisableStandaloneSSE: true}, nil)
	if err != nil {
		return nil, fmt.Errorf("connect relay: %w", err)
	}
	s.closers = append(s.closers, relay.Close)
	if err := s.addTools(ctx, relay, ""); err != nil {
		_ = s.Close()
		return nil, err
	}
	cmd := exec.Command(mocktoolsBin)
	cmd.Env = mocktoolsEnv
	cmd.Stderr = o.Stderr
	sink, err := s.client(o).Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("start mocktools: %w", err)
	}
	s.closers = append(s.closers, sink.Close)
	if err := s.addTools(ctx, sink, SinkServer+"_"); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Set) client(o Options) *mcp.Client {
	return mcp.NewClient(&mcp.Implementation{Name: "fence-eval", Version: "0.1.0"},
		&mcp.ClientOptions{ElicitationHandler: s.elicit(o.Confirm)})
}

func (s *Set) addTools(ctx context.Context, cs *mcp.ClientSession, prefix string) error {
	for t, err := range cs.Tools(ctx, nil) {
		if err != nil {
			return fmt.Errorf("list tools: %w", err)
		}
		name := prefix + t.Name
		schema := map[string]any{"type": "object"}
		if t.InputSchema != nil {
			b, _ := json.Marshal(t.InputSchema)
			_ = json.Unmarshal(b, &schema)
		}
		s.sessions[name] = cs
		s.upstream[name] = t.Name
		s.tools = append(s.tools, Tool{Name: name, Description: t.Description, InputSchema: schema})
	}
	return nil
}

// Tools lists the tools in a stable order.
func (s *Set) Tools() []Tool { return s.tools }

// Call runs one tool. Errors the model should see (unknown tool, bad
// arguments, transport failure) come back as an error Result, not an error.
func (s *Set) Call(ctx context.Context, name string, args json.RawMessage) Result {
	cs, ok := s.sessions[name]
	if !ok {
		return Result{Text: "unknown tool " + name, IsError: true}
	}
	var a map[string]any
	if len(args) > 0 {
		if err := json.Unmarshal(args, &a); err != nil {
			return Result{Text: "arguments are not a JSON object: " + err.Error(), IsError: true}
		}
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: s.upstream[name], Arguments: a})
	if err != nil {
		return Result{Text: "tool call failed: " + err.Error(), IsError: true}
	}
	var b strings.Builder
	for _, c := range res.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			if b.Len() > 0 {
				b.WriteString("\n")
			}
			b.WriteString(t.Text)
		}
	}
	return Result{Text: b.String(), IsError: res.IsError}
}

// Elicitations returns the questions asked so far.
func (s *Set) Elicitations() []Elicitation {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Elicitation(nil), s.elicitation...)
}

// Close disconnects everything and stops the processes started.
func (s *Set) Close() error {
	var first error
	for i := len(s.closers) - 1; i >= 0; i-- {
		if err := s.closers[i](); err != nil && first == nil {
			first = err
		}
	}
	return first
}

type bearer struct {
	token string
	base  http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}
