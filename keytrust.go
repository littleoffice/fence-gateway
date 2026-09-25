package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// fingerprintLen is the length of a relay key fingerprint: the first 8 bytes
// of SHA-256 over the public key, hex-encoded — what the relay prints in its
// startup banner, serves at /fence/public-key and puts in every fence's kid.
const fingerprintLen = 16

// normalizePin checks a -pin value and returns it in lower case.
//
// A malformed pin used to be accepted and compared as-is, so a typo — or an
// upper-case copy from somewhere that shows hex that way — matched no key:
// every result was then blocked, with the reason only in the audit log.
func normalizePin(pin string) (string, error) {
	pin = strings.ToLower(strings.TrimSpace(pin))
	if pin == "" {
		return "", nil
	}
	if len(pin) != fingerprintLen {
		return "", fmt.Errorf("-pin %q is %d characters; a relay key fingerprint is %d hex characters "+
			"(the relay's startup banner and /fence/public-key show it)", pin, len(pin), fingerprintLen)
	}
	if _, err := hex.DecodeString(pin); err != nil {
		return "", fmt.Errorf("-pin %q is not hex; a relay key fingerprint is %d hex characters", pin, fingerprintLen)
	}
	return pin, nil
}

// checkKeyTrust decides whether the way the gateway learns the relay's public
// key is safe to start with. It returns an error for a setup that is not, and
// otherwise a warning to log when the setup is weaker than a pin ("" when
// pinned).
//
// What a fence signature proves is only as good as the key it is checked
// against. With -pin the key must match a fingerprint the operator supplied,
// so it does not matter how the key travels. Without one the gateway believes
// whatever /fence/public-key serves, and fetches it again after any failed
// check. Over plain HTTP to another machine, anyone on the network path can
// serve their own key there and then sign anything they like. That setup is
// refused: pin the key (give the relay a persistent key with
// FENCE_SIGNING_KEY_FILE so the pin survives its restarts), or fetch it over
// HTTPS. -tofu does not count as a pin: its first fetch has the same problem.
func checkKeyTrust(keyURL, pin string, tofu bool) (warning string, err error) {
	if pin != "" {
		return "", nil
	}
	u, err := url.Parse(keyURL)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("fence key URL %q is not an absolute URL", keyURL)
	}
	switch {
	case u.Scheme == "https", u.Scheme == "http" && isLoopback(u.Hostname()):
	case u.Scheme == "http":
		return "", fmt.Errorf("the fence key is fetched over plain HTTP from %q with no -pin: anyone on "+
			"the network path could serve their own key and sign whatever they like. Pin the relay's "+
			"key with -pin <fingerprint> (give the relay a persistent key with FENCE_SIGNING_KEY_FILE so "+
			"the pin survives its restarts), or fetch the key over HTTPS with -key-url https://…", u.Host)
	default:
		return "", fmt.Errorf("fence key URL %q: scheme %q is not http or https", keyURL, u.Scheme)
	}
	if tofu {
		return "the fence key is trusted on first use and remembered only until the gateway restarts; " +
			"pin it with -pin <fingerprint> to catch a substituted relay from the first request", nil
	}
	return "the fence key is not pinned: the gateway trusts whatever key the relay's endpoint serves. " +
		"Pin it with -pin <fingerprint>, and give the relay a persistent key with FENCE_SIGNING_KEY_FILE " +
		"so the pin survives its restarts", nil
}

// isLoopback reports whether host names this machine.
func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
