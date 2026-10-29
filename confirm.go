package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"sync"
	"time"
)

// confirmTTL is how long a question to the user stays answerable.
const confirmTTL = 10 * time.Minute

// confirmations issues and redeems the state the gateway hands a client with
// a question to the user (toolgate.go). The client only carries it, so it is
// authenticated: an HMAC under a per-process key over a nonce, an expiry and
// what was asked about. A state redeems once, before it expires, and only for
// the binding it was issued for. The zero value is ready to use.
type confirmations struct {
	once sync.Once
	key  []byte

	mu   sync.Mutex
	used map[string]time.Time // nonce -> expiry, for single use
}

func (c *confirmations) init() {
	c.once.Do(func() {
		c.key = make([]byte, 32)
		if _, err := rand.Read(c.key); err != nil {
			panic("confirmation key: " + err.Error())
		}
	})
}

func (c *confirmations) mac(nonceExp []byte, binding string) []byte {
	m := hmac.New(sha256.New, c.key)
	m.Write([]byte("fence-gateway confirm v1\x00"))
	m.Write(nonceExp)
	m.Write([]byte(binding))
	return m.Sum(nil)
}

// issue returns a state for a question about binding.
func (c *confirmations) issue(binding string) string {
	c.init()
	nonceExp := make([]byte, 24)
	_, _ = rand.Read(nonceExp[:16])
	binary.BigEndian.PutUint64(nonceExp[16:], uint64(time.Now().Add(confirmTTL).Unix()))
	return base64.RawURLEncoding.EncodeToString(nonceExp) + "." +
		base64.RawURLEncoding.EncodeToString(c.mac(nonceExp, binding))
}

// redeem reports whether state was issued for binding, is unexpired, and has
// not been redeemed before.
func (c *confirmations) redeem(state, binding string) bool {
	c.init()
	a, b, ok := strings.Cut(state, ".")
	if !ok {
		return false
	}
	nonceExp, err1 := base64.RawURLEncoding.DecodeString(a)
	sig, err2 := base64.RawURLEncoding.DecodeString(b)
	if err1 != nil || err2 != nil || len(nonceExp) != 24 || !hmac.Equal(sig, c.mac(nonceExp, binding)) {
		return false
	}
	now := time.Now()
	exp := time.Unix(int64(binary.BigEndian.Uint64(nonceExp[16:])), 0)
	if now.After(exp) {
		return false
	}
	nonce := string(nonceExp[:16])
	c.mu.Lock()
	defer c.mu.Unlock()
	for n, e := range c.used {
		if now.After(e) {
			delete(c.used, n)
		}
	}
	if _, seen := c.used[nonce]; seen {
		return false
	}
	if c.used == nil {
		c.used = make(map[string]time.Time)
	}
	c.used[nonce] = exp
	return true
}
