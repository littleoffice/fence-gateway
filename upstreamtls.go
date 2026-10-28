package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// checkUpstreamTransport decides whether the hop to the relay is safe to start
// with. It returns an error for one that is not, and otherwise a warning to log
// when plain HTTP was allowed on purpose ("" otherwise).
//
// Every upstream request carries a bearer credential, and every tool result
// comes back over this hop. Over plain HTTP to another machine anyone on the
// network path reads the credential and can rewrite what the relay sent, so
// that is refused unless -insecure-upstream says the network is trusted (a
// service mesh that adds mTLS, say). In passthrough mode the credential is the
// caller's own, which also works at the gateway, so plain HTTP is refused even
// then. Loopback never leaves the machine and is always allowed.
func checkUpstreamTransport(upstream string, insecure bool, ua upstreamAuth) (warning string, err error) {
	u, err := url.Parse(upstream)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("-upstream %q is not an absolute URL", upstream)
	}
	switch {
	case u.Scheme == "https", u.Scheme == "http" && isLoopback(u.Hostname()):
		return "", nil
	case u.Scheme != "http":
		return "", fmt.Errorf("-upstream %q: scheme %q is not http or https", upstream, u.Scheme)
	case ua.passthrough():
		return "", fmt.Errorf("-upstream %q is plain HTTP to another host, and UPSTREAM_MCP_AUTH_MODE=passthrough "+
			"sends callers' own tokens over it: serve the relay over HTTPS (MCP_TLS_CERT/MCP_TLS_KEY or "+
			"MCP_TLS_ACME_DOMAINS on the relay) and use -upstream https://…; -insecure-upstream does not "+
			"apply in passthrough mode", upstream)
	case !insecure:
		return "", fmt.Errorf("-upstream %q is plain HTTP to another host: the relay credential and every "+
			"tool result would cross the network in cleartext. Serve the relay over HTTPS and use "+
			"-upstream https://… (add -upstream-ca for a private CA), or set -insecure-upstream when "+
			"the network itself is protected (a service mesh with mTLS)", upstream)
	}
	return "the relay is reached over plain HTTP (-insecure-upstream): its credential and every tool " +
		"result cross the network in cleartext, so this is safe only on a network that is protected " +
		"some other way", nil
}

// newUpstreamCA builds the transport for the relay when -upstream-ca is set:
// it trusts only the CAs in the PEM bundle at path, in place of the system
// roots. The bundle may hold several CAs, for a rotation overlap. It is read
// once, at startup, so a missing or empty bundle fails startup rather than the
// first request; a rotated CA takes effect on the next restart.
func newUpstreamCA(path string) (*http.Transport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("no PEM certificates found in file")
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return t, nil
}

// upstreamRoundTripper is the base transport for requests to the relay:
// the -upstream-ca transport when one is set, otherwise the system roots.
func upstreamRoundTripper(ca *http.Transport) http.RoundTripper {
	if ca == nil {
		return http.DefaultTransport
	}
	return ca
}

// relayTransport is the base transport for a request to target, one of the
// relay's other endpoints (the fence key, metrics): the -upstream-ca bundle
// when target is on the upstream's host, and the system roots otherwise, since
// -key-url or UPSTREAM_METRICS_URL may name a host the bundle does not cover.
func relayTransport(ca *http.Transport, upstream, target string) http.RoundTripper {
	if ca == nil || !sameHost(upstream, target) {
		return http.DefaultTransport
	}
	return ca
}

func sameHost(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	return errA == nil && errB == nil && ua.Host != "" && strings.EqualFold(ua.Host, ub.Host)
}
