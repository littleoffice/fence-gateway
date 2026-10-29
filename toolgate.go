package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ── Other MCP servers, and the tool gate ──────────────────────────────────────
//
// Verifying fences proves where web content came from; it does not stop a
// model that has read hostile text from acting on it. The damage needs a tool
// that changes something or sends data out: write a file, send a mail, push a
// branch. So once a conversation has read outside content, the gateway asks
// the user before such a tool runs.
//
// That only works for tools the gateway can see, so it can now proxy other MCP
// servers too, listed in -tools-config. Their tools appear to the client as
// <server>_<tool>. Their results pass through unchanged: they carry no fences.
//
// Nobody has to list forbidden tools. A tool is let through without asking
// only when its server declares it read-only and closed-world (the MCP
// readOnlyHint and openWorldHint annotations), or the operator allow-lists it.
// Everything else, including a tool with no annotations, is gated. Those hints
// are the server's own claim, which is why the servers are the operator's
// choice and the allow-list exists.
//
// A conversation becomes tainted by any relay call (its results are web
// content) and by any other tool that is not declared closed-world.
//
// -tool-gate selects what happens to a gated call in a tainted conversation:
// ask (default) asks the user through MCP elicitation and blocks when the
// client cannot be asked; block always blocks; off turns the gate off.

const (
	gateAsk   = "ask"
	gateBlock = "block"
	gateOff   = "off"

	// maxGatedConversations bounds the taint table. The oldest conversation
	// goes first; one evicted is treated as untainted again, so the bound is
	// set well above what one gateway serves at once.
	maxGatedConversations = 10_000
	// gateIdle is how long a conversation's taint outlives its last call.
	gateIdle = 24 * time.Hour
	// gateConfirmID names the one input request a confirmation carries.
	gateConfirmID = "confirm"
	// maxShownArgs bounds the arguments shown in a confirmation.
	maxShownArgs = 800
)

// parseGateMode checks -tool-gate.
func parseGateMode(raw string) (string, error) {
	switch m := strings.ToLower(strings.TrimSpace(raw)); m {
	case gateAsk, gateBlock, gateOff:
		return m, nil
	default:
		return "", fmt.Errorf("-tool-gate %q: expected %q, %q or %q", raw, gateAsk, gateBlock, gateOff)
	}
}

// ── -tools-config ─────────────────────────────────────────────────────────────

// toolsConfig is the -tools-config file.
type toolsConfig struct {
	Servers []toolServerConfig `json:"servers"`
}

// toolServerConfig is one MCP server the gateway proxies besides the relay.
type toolServerConfig struct {
	// Name prefixes the server's tools: <name>_<tool>.
	Name string `json:"name"`
	// URL is a Streamable HTTP endpoint. Exactly one of URL and Command.
	URL string `json:"url,omitempty"`
	// TokenEnv names an environment variable holding a bearer token for URL.
	TokenEnv string `json:"token_env,omitempty"`
	// Command starts a local server speaking MCP over stdio.
	Command []string `json:"command,omitempty"`
	// Env names the environment variables passed to Command, besides PATH,
	// HOME, LANG and TMPDIR. Nothing else of the gateway's environment, which
	// holds its own secrets, reaches the process.
	Env []string `json:"env,omitempty"`
	// Allow lists tool names (path.Match patterns, unprefixed) that are never
	// gated, for tools whose annotations understate how harmless they are.
	Allow []string `json:"allow,omitempty"`
	// Shared acknowledges that, with several downstream callers, every one of
	// them uses this server as the same identity. Required in that case.
	Shared bool `json:"shared,omitempty"`
}

var serverNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// baseCommandEnv are passed to every Command, so it can find its interpreter.
var baseCommandEnv = []string{"PATH", "HOME", "LANG", "TMPDIR"}

// loadToolsConfig reads and checks -tools-config. Unknown fields fail, so a
// misspelt "allow" does not silently gate nothing or everything.
func loadToolsConfig(file string, multiCaller, insecure bool) (*toolsConfig, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	var tc toolsConfig
	if err := dec.Decode(&tc); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	seen := map[string]bool{}
	for i, s := range tc.Servers {
		if !serverNameRE.MatchString(s.Name) {
			return nil, fmt.Errorf("servers[%d]: name %q must be 1-32 lower-case letters, digits or '-'", i, s.Name)
		}
		if seen[s.Name] {
			return nil, fmt.Errorf("servers[%d]: name %q is used twice", i, s.Name)
		}
		seen[s.Name] = true
		if (s.URL == "") == (len(s.Command) == 0) {
			return nil, fmt.Errorf("server %q: set exactly one of url and command", s.Name)
		}
		if s.URL != "" {
			plain, err := plainRemote("server "+s.Name+" url", s.URL)
			if err != nil {
				return nil, err
			}
			if plain && !insecure {
				return nil, fmt.Errorf("server %q: url %q is plain HTTP to another host; use https://, or "+
					"-insecure-upstream on a network protected some other way", s.Name, s.URL)
			}
			if len(s.Env) > 0 {
				return nil, fmt.Errorf("server %q: env applies to command servers only", s.Name)
			}
		} else if s.TokenEnv != "" {
			return nil, fmt.Errorf("server %q: token_env applies to url servers only; pass it through env", s.Name)
		}
		if s.TokenEnv != "" && strings.TrimSpace(os.Getenv(s.TokenEnv)) == "" {
			return nil, fmt.Errorf("server %q: token_env %s is not set", s.Name, s.TokenEnv)
		}
		for _, p := range s.Allow {
			if _, err := path.Match(p, ""); err != nil {
				return nil, fmt.Errorf("server %q: allow pattern %q: %w", s.Name, p, err)
			}
		}
		if multiCaller && !s.Shared {
			return nil, fmt.Errorf("server %q: the gateway serves several callers, and every one of them "+
				"would use this server as the same identity, seeing what the others can. Set \"shared\": true "+
				"if that is intended", s.Name)
		}
	}
	return &tc, nil
}

// ── Connecting ────────────────────────────────────────────────────────────────

// toolServer is a connected server from -tools-config.
type toolServer struct {
	cfg toolServerConfig
	up  *upstreamSession
}

// connectToolServer builds the session to one server. The connection opens
// on first use; connectToolServers opens it at startup.
func (g *gateway) connectToolServer(sc toolServerConfig) *toolServer {
	connect := func(ctx context.Context) (*mcp.ClientSession, error) {
		client := mcp.NewClient(&mcp.Implementation{Name: "fence-gateway", Version: ServerVersion}, nil)
		var transport mcp.Transport
		if sc.URL != "" {
			hc := &http.Client{}
			if sc.TokenEnv != "" {
				u, _ := url.Parse(sc.URL)
				hc.Transport = &bearerTransport{
					token: strings.TrimSpace(os.Getenv(sc.TokenEnv)),
					host:  u.Host,
					base:  http.DefaultTransport,
				}
			}
			transport = &mcp.StreamableClientTransport{Endpoint: sc.URL, HTTPClient: hc, DisableStandaloneSSE: true}
		} else {
			cmd := exec.Command(sc.Command[0], sc.Command[1:]...)
			cmd.Env = commandEnv(sc.Env)
			cmd.Stderr = os.Stderr
			transport = &mcp.CommandTransport{Command: cmd}
		}
		cctx, cancel := context.WithTimeout(ctx, upstreamConnectTimeout)
		defer cancel()
		sess, err := client.Connect(cctx, transport, nil)
		if err == nil {
			g.audit.Printf("tools.server.connected server=%q", sc.Name)
		}
		return sess, err
	}
	return &toolServer{cfg: sc, up: &upstreamSession{connect: connect, audit: g.audit, metrics: g.hc.metrics}}
}

// commandEnv is the environment for a command server: the base variables and
// the ones its config names, taken from the gateway's own environment.
func commandEnv(names []string) []string {
	var env []string
	for _, n := range append(append([]string{}, baseCommandEnv...), names...) {
		if v, ok := os.LookupEnv(n); ok {
			env = append(env, n+"="+v)
		}
	}
	return env
}

// bearerTransport adds a server's token to requests for its own host only, so
// a redirect elsewhere does not carry it along.
type bearerTransport struct {
	token string
	host  string
	base  http.RoundTripper
}

func (b *bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host == b.host {
		r = r.Clone(r.Context())
		r.Header.Set("Authorization", "Bearer "+b.token)
	}
	return b.base.RoundTrip(r)
}

// registerToolServers connects every configured server and registers its
// tools on the downstream server. A server that cannot be reached, or a tool
// name already taken, fails startup.
func (g *gateway) registerToolServers(ctx context.Context, server *mcp.Server, tc *toolsConfig) error {
	servers := make([]*toolServer, 0, len(tc.Servers))
	for _, sc := range tc.Servers {
		servers = append(servers, g.connectToolServer(sc))
	}
	return g.registerServers(ctx, server, servers)
}

// registerServers registers the tools of already-built servers.
func (g *gateway) registerServers(ctx context.Context, server *mcp.Server, servers []*toolServer) error {
	g.toolsMu.Lock()
	taken := make(map[string]bool, len(g.tools))
	for name := range g.tools {
		taken[name] = true
	}
	g.toolsMu.Unlock()

	g.extraTools = map[string]bool{}
	for _, ts := range servers {
		sc := ts.cfg
		sess, err := ts.up.session()
		if err != nil {
			return fmt.Errorf("server %q: connect: %w", sc.Name, err)
		}
		n := 0
		for tool, err := range sess.Tools(ctx, nil) {
			if err != nil {
				return fmt.Errorf("server %q: list tools: %w", sc.Name, err)
			}
			name := sc.Name + "_" + tool.Name
			if taken[name] {
				return fmt.Errorf("server %q: tool name %q is already taken", sc.Name, name)
			}
			taken[name] = true
			g.extraTools[name] = true
			exposed := *tool
			exposed.Name = name
			kind := gateKindOf(tool, sc.Allow)
			server.AddTool(&exposed, g.gatedHandler(ts, tool.Name, name, kind))
			g.audit.Printf("tools.registered server=%q tool=%q gated=%t taints=%t", sc.Name, name, !kind.safe, kind.taints)
			n++
		}
		g.toolServers = append(g.toolServers, ts)
		g.audit.Printf("tools.server.synced server=%q count=%d", sc.Name, n)
	}
	return nil
}

// ── Classification ────────────────────────────────────────────────────────────

// gateKind is what the gate needs to know about one tool.
type gateKind struct {
	// safe tools run without asking even in a tainted conversation.
	safe bool
	// taints: the tool's results may carry outside content.
	taints bool
}

// gateKindOf classifies a tool from its annotations and the allow-list. A
// missing annotation reads as the MCP default: not read-only, open-world.
func gateKindOf(t *mcp.Tool, allow []string) gateKind {
	readOnly, openWorld := false, true
	if a := t.Annotations; a != nil {
		readOnly = a.ReadOnlyHint
		if a.OpenWorldHint != nil {
			openWorld = *a.OpenWorldHint
		}
	}
	k := gateKind{safe: readOnly && !openWorld, taints: openWorld}
	for _, p := range allow {
		if ok, _ := path.Match(p, t.Name); ok {
			k.safe = true
		}
	}
	return k
}

// ── Taint ─────────────────────────────────────────────────────────────────────

// toolGate tracks which conversations have read outside content, and which
// tools the user allowed for the rest of one.
type toolGate struct {
	mode  string
	audit *log.Logger

	// confirms signs the state of a question to the user (confirm.go).
	confirms confirmations

	mu    sync.Mutex
	convs map[string]*gateState
}

type gateState struct {
	allowed map[string]bool
	used    time.Time
}

// gateKey identifies a conversation: the caller and the conversation ID. With
// no conversation ID (stdio, or a client that sends none) it is the caller,
// so taint then lasts for every conversation of that caller.
func gateKey(identity, conversation string) string {
	return identity + "\x00" + conversation
}

// taint marks a conversation as having read outside content.
func (tg *toolGate) taint(key, identity, tool string) {
	if tg == nil {
		return
	}
	tg.mu.Lock()
	defer tg.mu.Unlock()
	now := time.Now()
	if st, ok := tg.convs[key]; ok {
		st.used = now
		return
	}
	tg.evictLocked(now)
	if tg.convs == nil {
		tg.convs = make(map[string]*gateState)
	}
	tg.convs[key] = &gateState{used: now}
	tg.audit.Printf("gate.tainted identity=%q tool=%q", identity, tool)
}

// gated reports whether a call to tool needs confirmation in this
// conversation: it is tainted and the user has not allowed the tool for it.
func (tg *toolGate) gated(key, tool string) bool {
	if tg == nil || tg.mode == gateOff {
		return false
	}
	tg.mu.Lock()
	defer tg.mu.Unlock()
	st, ok := tg.convs[key]
	if !ok || time.Since(st.used) > gateIdle {
		return false
	}
	return !st.allowed[tool]
}

// allowForConversation lets tool run unasked for the rest of the conversation.
func (tg *toolGate) allowForConversation(key, tool string) {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	if st, ok := tg.convs[key]; ok {
		if st.allowed == nil {
			st.allowed = make(map[string]bool)
		}
		st.allowed[tool] = true
	}
}

// evictLocked drops idle conversations, then the least recently used until
// there is room for one more.
func (tg *toolGate) evictLocked(now time.Time) {
	for k, st := range tg.convs {
		if now.Sub(st.used) > gateIdle {
			delete(tg.convs, k)
		}
	}
	for len(tg.convs) >= maxGatedConversations {
		oldest := ""
		for k, st := range tg.convs {
			if oldest == "" || st.used.Before(tg.convs[oldest].used) {
				oldest = k
			}
		}
		delete(tg.convs, oldest)
	}
}

// ── The gated call ────────────────────────────────────────────────────────────

// errToolServerCall is what the client sees when a proxied server fails. The
// detail goes to the audit log.
var errToolServerCall = errors.New("the fence gateway could not complete the call to the tool's server; see the gateway audit log")

// gatedHandler forwards a call to a proxied server's tool, asking the user
// first when the gate says so.
func (g *gateway) gatedHandler(ts *toolServer, upstreamName, name string, kind gateKind) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var authz string
		if req.Extra != nil {
			authz = req.Extra.Header.Get("Authorization")
		}
		identity := g.hc.identityFor(ctx, authz)
		key := gateKey(identity, conversationID(req))

		if !kind.safe && g.gate.gated(key, name) {
			if res, ok := g.confirmTool(req, key, identity, name); !ok {
				if res.IsError {
					g.hc.metrics.recordCall(outcomeBlocked, 0)
				}
				return res, nil
			}
		} else {
			g.hc.metrics.gateDecision(gateAllowed)
		}

		start := time.Now()
		res, err := ts.up.CallTool(ctx, &mcp.CallToolParams{Name: upstreamName, Arguments: req.Params.Arguments})
		g.hc.metrics.observeUpstream(time.Since(start))
		if err != nil {
			g.audit.Printf("tools.server.error server=%q tool=%q identity=%q err=%q", ts.cfg.Name, name, identity, err)
			g.hc.metrics.recordCall(outcomeUpstreamError, 0)
			return nil, errToolServerCall
		}
		if kind.taints {
			g.gate.taint(key, identity, name)
		}
		g.hc.metrics.recordCall(outcomeForwarded, 0)
		return res, nil
	}
}

// confirmTool decides a gated call. It returns (nil, true) to run it, or a
// result to return instead: the question to the user, or a refusal.
//
// The question travels as a multi round-trip request (SEP-2322): an
// input-required result carrying the elicitation and a signed state, which
// the client echoes back with the user's answer when it retries the call. On
// protocol versions before 2026-07-28 the SDK makes the same round trip
// itself. The state is bound to the conversation, the tool and the exact
// arguments, and is single-use, so a "yes" covers only the call the user saw.
func (g *gateway) confirmTool(req *mcp.CallToolRequest, key, identity, name string) (*mcp.CallToolResult, bool) {
	refuse := func(why string) (*mcp.CallToolResult, bool) {
		return blocked("this conversation has read outside content, which can carry instructions " +
			"planted by someone else, and " + name + " can change things or send data out. " + why), false
	}
	if g.gate.mode == gateBlock || !canElicit(req) {
		g.audit.Printf("gate.blocked identity=%q tool=%q mode=%s", identity, name, g.gate.mode)
		g.hc.metrics.gateDecision(gateBlocked)
		return refuse("The user could not be asked to confirm the call")
	}
	args := sha256.Sum256(req.Params.Arguments)
	binding := key + "\x00" + name + "\x00" + string(args[:])

	if req.Params.RequestState == "" && req.Params.InputResponses == nil {
		shown := string(req.Params.Arguments)
		if len(shown) > maxShownArgs {
			shown = shown[:maxShownArgs] + "…"
		}
		return &mcp.CallToolResult{
			InputRequests: mcp.InputRequestMap{gateConfirmID: &mcp.ElicitParams{
				Mode: "form",
				Message: "This conversation has read content from the web or another outside source, which can " +
					"carry instructions planted by someone else. The AI now wants to run " + name + " with:\n\n" +
					shown + "\n\nIt can change things or send data out. Allow it?",
				RequestedSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"remember": map[string]any{
							"type":    "boolean",
							"title":   "Allow " + name + " for the rest of this conversation",
							"default": false,
						},
					},
				},
			}},
			RequestState: g.gate.confirms.issue(binding),
		}, false
	}

	if !g.gate.confirms.redeem(req.Params.RequestState, binding) {
		g.audit.Printf("gate.confirmation_mismatch identity=%q tool=%q", identity, name)
		g.hc.metrics.gateDecision(gateBlocked)
		return refuse("The confirmation did not match this call")
	}
	answer, _ := req.Params.InputResponses[gateConfirmID].(*mcp.ElicitResult)
	if answer == nil || answer.Action != "accept" {
		action := "none"
		if answer != nil {
			action = answer.Action
		}
		g.audit.Printf("gate.declined identity=%q tool=%q action=%s", identity, name, action)
		g.hc.metrics.gateDecision(gateDeclined)
		return refuse("The user did not confirm the call")
	}
	remember, _ := answer.Content["remember"].(bool)
	if remember {
		g.gate.allowForConversation(key, name)
	}
	g.audit.Printf("gate.confirmed identity=%q tool=%q remember=%t", identity, name, remember)
	g.hc.metrics.gateDecision(gateConfirmed)
	return nil, true
}

// canElicit reports whether the client behind req declared elicitation
// support.
func canElicit(req *mcp.CallToolRequest) bool {
	if req == nil || req.Session == nil {
		return false
	}
	p := req.Session.InitializeParams()
	return p != nil && p.Capabilities != nil && p.Capabilities.Elicitation != nil
}
