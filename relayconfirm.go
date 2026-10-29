package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ── The relay's questions to the user ────────────────────────────────────────
//
// The relay asks the user before it fetches an address it never showed and
// that carries data. It asks through a multi round-trip request (SEP-2322):
// an input-required result carrying an elicitation and the relay's own signed
// state, answered by retrying the call with the user's response and that
// state. It asks only a client that declares elicitation, which the gateway
// does upstream (upstreamClientOptions) so that the question reaches it.
//
// The gateway passes the question on rather than answering it, and keeps
// control of what it passes:
//
//   - only form elicitations travel; a url-mode one (which would send the user
//     to a page the relay chose), sampling or roots request is refused;
//   - a client that cannot ask the user gets a refusal, not the question;
//   - the relay's state is wrapped in a gateway token bound to the
//     conversation, the tool, the arguments and the relay state itself, and
//     redeemable once, so a retry reaches the relay only for the call that
//     was asked about.
//
// A stateless downstream client on a protocol older than 2026-07-28 cannot
// receive questions at all: the SDK's own elicitation fails there, and the
// call errors as it would for any tool that asks.

// relayStateSep separates the gateway token from the relay's state. It is not
// in the base64url alphabet, so neither half can contain it.
const relayStateSep = "~"

// upstreamClientOptions are the gateway's client options towards the relay.
// The elicitation handler only declares the capability, so the relay asks;
// with automatic round trips off, the question comes back as a result for
// forwardRelayQuestion. A relay on an older protocol elicits from inside the
// call instead, which reaches the handler, and is declined: there is no way
// to tell which downstream caller it belongs to.
func upstreamClientOptions() *mcp.ClientOptions {
	return &mcp.ClientOptions{
		ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			return &mcp.ElicitResult{Action: "decline"}, nil
		},
		MultiRoundTrip: &mcp.MultiRoundTripOptions{Disabled: true},
	}
}

// relayQuestionBinding is what a forwarded question's gateway token covers.
func relayQuestionBinding(identity, conv, tool string, args []byte, relayState string) string {
	a := sha256.Sum256(args)
	s := sha256.Sum256([]byte(relayState))
	return gateKey(identity, conv) + "\x00" + tool + "\x00" + string(a[:]) + string(s[:])
}

// forwardRelayQuestion turns the relay's input-required result into the one
// the downstream client gets: the same question with a wrapped state, or a
// refusal.
func (g *gateway) forwardRelayQuestion(req *mcp.CallToolRequest, identity, conv, tool string, res *mcp.CallToolResult) *mcp.CallToolResult {
	refuse := func(why, reason string) *mcp.CallToolResult {
		g.audit.Printf("relay.confirm.refused tool=%q identity=%q reason=%s", tool, identity, reason)
		g.hc.metrics.recordCall(outcomeBlocked, 0)
		return blocked(why)
	}
	if len(res.InputRequests) == 0 {
		return refuse("the relay is busy; try again shortly", "load_shedding")
	}
	for _, ir := range res.InputRequests {
		p, ok := ir.(*mcp.ElicitParams)
		if !ok || (p.Mode != "" && p.Mode != "form") || p.URL != "" {
			return refuse("the relay asked for input the gateway does not pass on", "unsupported_request")
		}
	}
	if !canElicit(req) {
		return refuse("the relay needs the user's confirmation for this call, and this client cannot ask the user",
			"cannot_ask")
	}
	token := g.relayConfirms.issue(relayQuestionBinding(identity, conv, tool, req.Params.Arguments, res.RequestState))
	g.audit.Printf("relay.confirm.forwarded tool=%q identity=%q", tool, identity)
	g.hc.metrics.recordCall(outcomeAsked, 0)
	return &mcp.CallToolResult{
		InputRequests: res.InputRequests,
		RequestState:  token + relayStateSep + base64.RawURLEncoding.EncodeToString([]byte(res.RequestState)),
	}
}

// unwrapRelayAnswer checks the state of a retry that answers a forwarded
// question, and returns the relay's own state to send on.
func (g *gateway) unwrapRelayAnswer(req *mcp.CallToolRequest, identity, conv, tool string) (string, bool) {
	token, wrapped, ok := strings.Cut(req.Params.RequestState, relayStateSep)
	if !ok {
		return "", false
	}
	relayState, err := base64.RawURLEncoding.DecodeString(wrapped)
	if err != nil {
		return "", false
	}
	if !g.relayConfirms.redeem(token, relayQuestionBinding(identity, conv, tool, req.Params.Arguments, string(relayState))) {
		return "", false
	}
	return string(relayState), true
}
