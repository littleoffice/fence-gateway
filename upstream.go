package main

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

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
	metrics *metrics // counts sessions found gone; may be nil
	// onReconnect, when set, runs in its own goroutine with each session
	// opened to replace a lost one — not with the first. A relay that
	// restarts may come back with different tools, and the gateway's tool
	// list was built from the old ones.
	onReconnect func(*mcp.ClientSession)

	// mu is held while connecting, so concurrent calls that find the session
	// gone share one reconnect rather than each opening their own.
	mu        sync.Mutex
	sess      *mcp.ClientSession
	connected bool // a session has been opened before
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
	if u.connected && u.onReconnect != nil {
		go u.onReconnect(s)
	}
	u.connected = true
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
	u.metrics.sessionLost()
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

// ── One relay session per conversation ───────────────────────────────────────
//
// The relay files each caller's fetch history under identity and session, and
// searxng_session_sources promises "current session only". Through a gateway
// holding one upstream session for everyone, every conversation of one caller
// shared a single history: the tool listed pages read in the caller's other
// chats, and a model could cite them as read in this one.
//
// So against a stateful relay each downstream conversation gets a relay
// session of its own. A stateless relay issues no sessions to split; it reads
// the conversation ID from the Mcp-Session-Id request header instead, which
// authTransport sets from the conversation the call belongs to.

const (
	// maxPooledSessions bounds the relay sessions held at once. The relay
	// refuses new sessions past its own cap (1000), and every one held here
	// counts against it.
	maxPooledSessions = 256
	// pooledSessionIdle closes a conversation's relay session after this long
	// unused. A later call from that conversation opens a new one, starting a
	// fresh history on the relay.
	pooledSessionIdle = 30 * time.Minute
	// maxConversationIDLen and the character check below match what the
	// relay accepts as a client-asserted session ID.
	maxConversationIDLen = 128
)

// sessionPool hands out the relay session for a conversation.
type sessionPool struct {
	shared  *upstreamSession // stdio, calls with no conversation, stateless relays
	connect func(context.Context) (*mcp.ClientSession, error)
	audit   *log.Logger
	metrics *metrics

	mu     sync.Mutex
	byConv map[string]*pooledSession
}

type pooledSession struct {
	up   *upstreamSession
	used time.Time
}

// forConversation returns the relay session for the conversation identified
// by key (the caller's identity and the conversation ID), opening one if
// needed. ended, when not nil, is the downstream session: its relay session is
// closed when it ends.
func (p *sessionPool) forConversation(key string, ended *mcp.ServerSession) *upstreamSession {
	if key == "" {
		return p.shared
	}
	// A relay that issued the shared session no ID is stateless: there are
	// no sessions to keep apart, and the conversation travels as a header.
	if s, err := p.shared.session(); err != nil || s.ID() == "" {
		return p.shared
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	p.evictLocked(now)
	if e, ok := p.byConv[key]; ok {
		e.used = now
		return e.up
	}
	up := &upstreamSession{connect: p.connect, audit: p.audit, metrics: p.metrics}
	if p.byConv == nil {
		p.byConv = make(map[string]*pooledSession)
	}
	p.byConv[key] = &pooledSession{up: up, used: now}
	if ended != nil {
		go func() {
			_ = ended.Wait()
			p.release(key, up)
		}()
	}
	return up
}

// release closes the relay session held for key, if it is still up.
func (p *sessionPool) release(key string, up *upstreamSession) {
	p.mu.Lock()
	e, ok := p.byConv[key]
	if ok && e.up == up {
		delete(p.byConv, key)
	}
	p.mu.Unlock()
	if ok && e.up == up {
		_ = up.Close()
	}
}

// evictLocked closes sessions idle past pooledSessionIdle, then the least
// recently used until there is room for one more.
func (p *sessionPool) evictLocked(now time.Time) {
	for key, e := range p.byConv {
		if now.Sub(e.used) > pooledSessionIdle {
			delete(p.byConv, key)
			go closeSession(e.up)
		}
	}
	for len(p.byConv) >= maxPooledSessions {
		oldest := ""
		for key, e := range p.byConv {
			if oldest == "" || e.used.Before(p.byConv[oldest].used) {
				oldest = key
			}
		}
		e := p.byConv[oldest]
		delete(p.byConv, oldest)
		go closeSession(e.up)
	}
}

// closeSession closes up, for use in a goroutine: a pooled session is closed
// off the pool's lock, and a failure to close one the relay may already have
// forgotten changes nothing.
func closeSession(up *upstreamSession) { _ = up.Close() }

// Close closes every pooled session and the shared one.
func (p *sessionPool) Close() error {
	p.mu.Lock()
	pooled := p.byConv
	p.byConv = nil
	p.mu.Unlock()
	for _, e := range pooled {
		_ = e.up.Close()
	}
	return p.shared.Close()
}

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
