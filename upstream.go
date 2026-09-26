package main

import (
	"context"
	"errors"
	"log"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// upstreamSession is the gateway's MCP session to the relay, replaced when
// the relay has dropped it.
//
// A stateful relay forgets its sessions when it restarts, and its janitor
// closes each one after MCP_SESSION_MAX_AGE (seven days by default). Either
// way it answers the old session ID with 404, which the SDK treats as final:
// the session is dead and every later call fails with ErrConnectionClosed.
// With one session opened at startup and never replaced, the gateway then
// failed every tool call until someone restarted it. A relay restart is also
// when its key rotates, so the key-rotation recovery in verify could never
// run against a stateful relay.
//
// So a call that finds the session gone discards it, opens a new one, and is
// retried once. The retry is safe: a 404 means the relay never ran the call,
// and a closed connection means it was never sent.
type upstreamSession struct {
	connect func(context.Context) (*mcp.ClientSession, error)
	audit   *log.Logger

	// mu is held while connecting, so concurrent calls that find the session
	// gone share one reconnect rather than each opening their own.
	mu   sync.Mutex
	sess *mcp.ClientSession
}

// session returns the current session, opening one if there is none.
//
// The connection is opened under context.Background, not the caller's
// context. The SDK keeps the context values it was connected with for the
// session's whole life, and a tool call's context carries that caller's own
// credential in passthrough mode: connecting under it would send every later
// housekeeping request — and the session itself — under one caller's identity.
func (u *upstreamSession) session() (*mcp.ClientSession, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.sess != nil {
		return u.sess, nil
	}
	s, err := u.connect(context.Background())
	if err != nil {
		return nil, err
	}
	u.sess = s
	return s, nil
}

// discard drops s if it is still the current session, and closes it. A
// session another call has already replaced is left alone.
func (u *upstreamSession) discard(s *mcp.ClientSession) {
	u.mu.Lock()
	if u.sess == s {
		u.sess = nil
	}
	u.mu.Unlock()
	_ = s.Close()
}

// CallTool calls a tool on the relay, reconnecting and retrying once if the
// session turns out to be gone.
func (u *upstreamSession) CallTool(ctx context.Context, p *mcp.CallToolParams) (*mcp.CallToolResult, error) {
	s, err := u.session()
	if err != nil {
		return nil, err
	}
	res, err := s.CallTool(ctx, p)
	if err == nil || !sessionGone(err) {
		return res, err
	}
	u.audit.Printf("upstream.session.lost tool=%q err=%q", p.Name, err)
	u.discard(s)
	if s, err = u.session(); err != nil {
		return nil, err
	}
	return s.CallTool(ctx, p)
}

// Close closes the current session, if any.
func (u *upstreamSession) Close() error {
	u.mu.Lock()
	s := u.sess
	u.sess = nil
	u.mu.Unlock()
	if s == nil {
		return nil
	}
	return s.Close()
}

// sessionGone reports whether err means the session can no longer be used:
// the relay no longer knows it (404), or the connection has been closed.
func sessionGone(err error) bool {
	return errors.Is(err, mcp.ErrSessionMissing) || errors.Is(err, mcp.ErrConnectionClosed)
}

// ── Conversations ────────────────────────────────────────────────────────────
//
// The relay files each caller's fetch history under identity and session, and
// searxng_session_sources promises "current session only". A stateless relay
// issues no sessions; it reads the conversation ID from the Mcp-Session-Id
// request header instead. Through a gateway that header was never set, so all
// conversations of one caller shared one history: the tool listed pages read
// in the caller's other chats. authTransport now sets it from the conversation
// the call belongs to.

// maxConversationIDLen and the character check in conversationID match what
// the relay accepts as a client-asserted session ID.
const maxConversationIDLen = 128

// conversationID identifies the downstream conversation a tool call belongs
// to: the gateway's own session ID when it issues them, otherwise the
// Mcp-Session-Id header the client sent (stateless gateway), if it is safe to
// carry. "" when there is none — stdio, or a client that sends no ID.
func conversationID(req *mcp.CallToolRequest) string {
	if req.Session != nil {
		if id := req.Session.ID(); id != "" {
			return id
		}
	}
	if req.Extra == nil {
		return ""
	}
	id := req.Extra.Header.Get("Mcp-Session-Id")
	if id == "" || len(id) > maxConversationIDLen {
		return ""
	}
	for i := 0; i < len(id); i++ {
		if id[i] < '!' || id[i] > '~' {
			return ""
		}
	}
	return id
}

// conversationKey types the context value carrying the conversation ID through
// to the upstream request.
type conversationKey struct{}

func withConversation(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, conversationKey{}, id)
}

func conversationFrom(ctx context.Context) string {
	v, _ := ctx.Value(conversationKey{}).(string)
	return v
}
