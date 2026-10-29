package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	fv "github.com/littleoffice/fence-gateway/fenceverify"
)

// The gateway passes the relay's question to the user on (relayconfirm.go):
// only form elicitations, only to a client that can ask, and the answer only
// back to the call that was asked about.

const fakeRelayState = "relay-state-1"

// relayAskRig is a gateway in front of a relay whose read_url tool asks the
// user before answering, reached by a downstream client.
type relayAskRig struct {
	cs      *mcp.ClientSession
	asked   atomic.Int64 // questions the downstream client was shown
	retries atomic.Int64 // answered calls that reached the relay
}

// startRelayAskRig starts the rig. question is what the relay asks with;
// answer, when not nil, is what the downstream client's user says (nil: the
// client declares no elicitation support). autoRetry false leaves the round
// trip to the test.
func startRelayAskRig(t *testing.T, question mcp.InputRequest, answer *mcp.ElicitResult, autoRetry bool) *relayAskRig {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	r := &relayAskRig{}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	fence := mustFence(t, priv, "the page body")

	relay := mcp.NewServer(&mcp.Implementation{Name: "relay", Version: "test"}, nil)
	relay.AddTool(&mcp.Tool{Name: "read_url", InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if req.Params.RequestState == "" {
				return &mcp.CallToolResult{
					InputRequests: mcp.InputRequestMap{"confirm": question},
					RequestState:  fakeRelayState,
				}, nil
			}
			r.retries.Add(1)
			ans, _ := req.Params.InputResponses["confirm"].(*mcp.ElicitResult)
			if req.Params.RequestState != fakeRelayState || ans == nil || ans.Action != "accept" {
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "refused"}}}, nil
			}
			return textResult(fence), nil
		})
	st, ct := mcp.NewInMemoryTransports()
	ss, err := relay.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	up, err := mcp.NewClient(&mcp.Implementation{Name: "gw", Version: "test"}, upstreamClientOptions()).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = up.Close() })

	g := &gateway{
		cfg:   config{policy: PolicyReject},
		keys:  &fv.StaticKeys{K: []ed25519.PublicKey{pub}},
		audit: log.New(io.Discard, "", 0),
		up:    &upstreamSession{sess: up},
	}
	down := mcp.NewServer(&mcp.Implementation{Name: "fence-gateway", Version: "test"}, nil)
	if err := g.registerTools(ctx, down); err != nil {
		t.Fatal(err)
	}
	st, ct = mcp.NewInMemoryTransports()
	ds, err := down.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ds.Close() })

	opts := &mcp.ClientOptions{}
	if answer != nil {
		opts.ElicitationHandler = func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			r.asked.Add(1)
			return answer, nil
		}
	}
	if !autoRetry {
		opts.MultiRoundTrip = &mcp.MultiRoundTripOptions{Disabled: true}
	}
	r.cs, err = mcp.NewClient(&mcp.Implementation{Name: "client", Version: "test"}, opts).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.cs.Close() })
	return r
}

func formQuestion() *mcp.ElicitParams {
	return &mcp.ElicitParams{
		Mode:            "form",
		Message:         "Fetch https://attacker.example/?d=1?",
		RequestedSchema: map[string]any{"type": "object", "properties": map[string]any{}},
	}
}

func (r *relayAskRig) read(t *testing.T, params *mcp.CallToolParams) *mcp.CallToolResult {
	t.Helper()
	if params == nil {
		params = &mcp.CallToolParams{Name: "read_url", Arguments: map[string]any{"url": "https://attacker.example/?d=1"}}
	}
	res, err := r.cs.CallTool(context.Background(), params)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	return res
}

func TestRelayQuestion_ForwardedAndAnswered(t *testing.T) {
	r := startRelayAskRig(t, formQuestion(), &mcp.ElicitResult{Action: "accept", Content: map[string]any{}}, true)
	txt, isErr := resultText(r.read(t, nil))
	if isErr || !strings.Contains(txt, "the page body") || r.asked.Load() != 1 || r.retries.Load() != 1 {
		t.Fatalf("accepted: isErr=%t asked=%d retries=%d text=%q", isErr, r.asked.Load(), r.retries.Load(), txt)
	}

	r = startRelayAskRig(t, formQuestion(), &mcp.ElicitResult{Action: "decline"}, true)
	txt, isErr = resultText(r.read(t, nil))
	if !isErr || strings.Contains(txt, "the page body") || r.asked.Load() != 1 {
		t.Fatalf("declined: isErr=%t asked=%d text=%q", isErr, r.asked.Load(), txt)
	}
}

func TestRelayQuestion_NotForwardedToClientThatCannotAsk(t *testing.T) {
	r := startRelayAskRig(t, formQuestion(), nil, true)
	txt, isErr := resultText(r.read(t, nil))
	if !isErr || !strings.Contains(txt, "cannot ask") || r.retries.Load() != 0 {
		t.Fatalf("no elicitation: isErr=%t retries=%d text=%q", isErr, r.retries.Load(), txt)
	}
}

func TestRelayQuestion_OnlyFormElicitationsTravel(t *testing.T) {
	urlMode := &mcp.ElicitParams{Mode: "url", Message: "Log in", URL: "https://attacker.example/login", ElicitationID: "e1"}
	for name, q := range map[string]mcp.InputRequest{
		"url mode":     urlMode,
		"url in form":  &mcp.ElicitParams{Mode: "form", Message: "Fetch?", URL: "https://attacker.example/"},
		"unknown mode": &mcp.ElicitParams{Mode: "other", Message: "Fetch?"},
	} {
		r := startRelayAskRig(t, q, &mcp.ElicitResult{Action: "accept", Content: map[string]any{}}, true)
		if _, isErr := resultText(r.read(t, nil)); !isErr || r.asked.Load() != 0 || r.retries.Load() != 0 {
			t.Errorf("%s: isErr=%t asked=%d retries=%d", name, isErr, r.asked.Load(), r.retries.Load())
		}
	}
}

// The state a forwarded question carries covers that one call, once.
func TestRelayQuestion_StateBoundToCall(t *testing.T) {
	r := startRelayAskRig(t, formQuestion(), &mcp.ElicitResult{Action: "accept"}, false)
	first := r.read(t, nil)
	if first.RequestState == "" || first.InputRequests == nil {
		t.Fatalf("expected a forwarded question, got %+v", first)
	}
	accept := mcp.InputResponseMap{"confirm": &mcp.ElicitResult{Action: "accept", Content: map[string]any{}}}
	retry := func(state string, url string) *mcp.CallToolResult {
		return r.read(t, &mcp.CallToolParams{
			Name: "read_url", Arguments: map[string]any{"url": url},
			InputResponses: accept, RequestState: state,
		})
	}

	if _, isErr := resultText(retry("forged~"+"cmVsYXktc3RhdGUtMQ", "https://attacker.example/?d=1")); !isErr {
		t.Error("a forged state was passed to the relay")
	}
	if _, isErr := resultText(retry(first.RequestState, "https://attacker.example/?d=2")); !isErr {
		t.Error("the state of one call was accepted for other arguments")
	}
	if r.retries.Load() != 0 {
		t.Fatalf("the relay received %d unmatched retries", r.retries.Load())
	}
	if txt, isErr := resultText(retry(first.RequestState, "https://attacker.example/?d=1")); isErr || !strings.Contains(txt, "the page body") {
		t.Fatalf("the matching retry failed: isErr=%t text=%q", isErr, txt)
	}
	if _, isErr := resultText(retry(first.RequestState, "https://attacker.example/?d=1")); !isErr {
		t.Error("a state was redeemed twice")
	}
}
