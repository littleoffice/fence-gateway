package main

import (
	"slices"
	"testing"
	"time"
)

// A stateful relay issues sessions, and files fetch history under them. Each
// downstream conversation now gets a relay session of its own.
func TestStatefulRelayGetsOneSessionPerConversation(t *testing.T) {
	rig := startConversationRig(t, false, true)
	a, b := rig.client(t), rig.client(t)
	defer func() { _ = b.Close() }()
	call(t, a)
	call(t, b)
	call(t, a)
	call(t, b)
	got := rig.toolCallSessions()
	assertOneRelaySessionPerConversation(t, got)

	// When a conversation ends, its relay session is closed with it.
	aRelay := got[0]
	_ = a.Close()
	deadline := time.Now().Add(3 * time.Second)
	for !slices.Contains(rig.deletedSessions(), aRelay) {
		if time.Now().After(deadline) {
			t.Fatalf("relay session %q was not closed after its conversation ended; deleted: %q",
				aRelay, rig.deletedSessions())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Without the pool (the old behaviour) every conversation shared one relay
// session: this pins what the pool fixes.
func TestSharedRelaySessionWithoutPool(t *testing.T) {
	rig := startConversationRig(t, false, false)
	a, b := rig.client(t), rig.client(t)
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	call(t, a)
	call(t, b)
	if got := rig.toolCallSessions(); got[0] != got[1] {
		t.Fatalf("expected one shared relay session without the pool, got %q", got)
	}
}

// Idle conversations give their relay session back; the pool never holds more
// than maxPooledSessions.
func TestSessionPoolEviction(t *testing.T) {
	p := &sessionPool{shared: &upstreamSession{}}
	p.byConv = map[string]*pooledSession{}
	now := time.Now()
	p.byConv["idle"] = &pooledSession{up: &upstreamSession{}, used: now.Add(-pooledSessionIdle - time.Minute)}
	p.byConv["fresh"] = &pooledSession{up: &upstreamSession{}, used: now}
	p.mu.Lock()
	p.evictLocked(now)
	p.mu.Unlock()
	if _, ok := p.byConv["idle"]; ok {
		t.Error("an idle conversation kept its relay session")
	}
	if _, ok := p.byConv["fresh"]; !ok {
		t.Error("an active conversation lost its relay session")
	}

	for i := 0; i < maxPooledSessions+10; i++ {
		p.byConv[string(rune('a'+i%26))+time.Duration(i).String()] = &pooledSession{
			up: &upstreamSession{}, used: now.Add(time.Duration(i) * time.Millisecond)}
	}
	p.mu.Lock()
	p.evictLocked(now)
	p.mu.Unlock()
	if len(p.byConv) >= maxPooledSessions {
		t.Errorf("pool holds %d sessions, want fewer than %d", len(p.byConv), maxPooledSessions)
	}
}
