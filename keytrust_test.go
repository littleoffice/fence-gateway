package main

import (
	"strings"
	"testing"
)

func TestNormalizePin(t *testing.T) {
	cases := []struct {
		in, want string
		wantErr  bool
	}{
		{"", "", false},
		{"5fb07c6222c503de", "5fb07c6222c503de", false},
		// Upper case used to match no key, so every result was blocked.
		{"5FB07C6222C503DE", "5fb07c6222c503de", false},
		{" 5fb07c6222c503de\n", "5fb07c6222c503de", false},
		{"5fb07c6222c503d", "", true},   // one short
		{"5fb07c6222c503dee", "", true}, // one long
		{"5fb07c6222c503dg", "", true},  // not hex
		{"sha256:5fb07c6222c503de", "", true},
	}
	for _, c := range cases {
		got, err := normalizePin(c.in)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("normalizePin(%q) = %q, %v; want %q, error %v", c.in, got, err, c.want, c.wantErr)
		}
	}
}

// Without a pin the gateway believes whatever key the endpoint serves. Over
// plain HTTP to another machine anyone on the path could serve their own, so
// that is refused; a pin makes the transport irrelevant.
func TestCheckKeyTrust(t *testing.T) {
	const pin = "5fb07c6222c503de"
	cases := []struct {
		name     string
		url, pin string
		tofu     bool
		wantErr  bool
		wantWarn bool
	}{
		{"pinned, plain HTTP to another host", "http://relay.internal:8080/fence/public-key", pin, false, false, false},
		{"pinned, HTTPS", "https://relay.example/fence/public-key", pin, false, false, false},
		{"unpinned, plain HTTP to another host", "http://relay.internal:8080/fence/public-key", "", false, true, false},
		{"unpinned, plain HTTP to a cluster IP", "http://10.0.0.7:8080/fence/public-key", "", false, true, false},
		{"TOFU is not a pin", "http://relay.internal:8080/fence/public-key", "", true, true, false},
		{"unpinned, HTTPS", "https://relay.example/fence/public-key", "", false, false, true},
		{"unpinned, localhost", "http://localhost:8080/fence/public-key", "", false, false, true},
		{"unpinned, 127.0.0.1 (the default upstream)", "http://127.0.0.1:8080/fence/public-key", "", false, false, true},
		{"unpinned, ::1", "http://[::1]:8080/fence/public-key", "", false, false, true},
		{"TOFU over HTTPS", "https://relay.example/fence/public-key", "", true, false, true},
		{"not a URL", "relay.internal/fence/public-key", "", false, true, false},
		{"unknown scheme", "ftp://relay.example/fence/public-key", "", false, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			warn, err := checkKeyTrust(c.url, c.pin, c.tofu)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, c.wantErr)
			}
			if (warn != "") != c.wantWarn {
				t.Errorf("warning = %q, wantWarn %v", warn, c.wantWarn)
			}
			if err != nil && strings.Contains(c.url, "http://") && !strings.Contains(err.Error(), "-pin") {
				t.Errorf("error does not say how to fix it: %v", err)
			}
		})
	}
}
