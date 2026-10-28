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
// that is refused unless -insecure-upstream says the network is protected some
// other way: a service mesh whose sidecars add mTLS, where the gateway itself
// must speak plain HTTP. In passthrough mode the credential is the caller's
// own, which also works at the gateway, and the warning says so. Loopback
// never leaves the machine and is always allowed.
func checkUpstreamTransport(upstream string, insecure bool, ua upstreamAuth) (warning string, err error) {
	plain, err := plainRemote("-upstream", upstream)
	if err != nil || !plain {
		return "", err
	}
	if !insecure {
		return "", fmt.Errorf("-upstream %q is plain HTTP to another host: the relay credential and every "+
			"tool result would cross the network in cleartext. Serve the relay over HTTPS and use "+
			"-upstream https://… (add -upstream-ca for a private CA), or set -insecure-upstream when "+
			"the network itself is protected (a service mesh with mTLS)", upstream)
	}
	warning = "the relay is reached over plain HTTP (-insecure-upstream): its credential and every tool " +
		"result cross the network in cleartext, so this is safe only on a network that is protected " +
		"some other way"
	if ua.passthrough() {
		warning += ". In passthrough mode that credential is each caller's own token, which also " +
			"works at the gateway"
	}
	return warning, nil
}

// checkMetricsTransport applies the same rule to an explicit
// UPSTREAM_METRICS_URL, which carries the relay's metrics token. The default
// is derived from -upstream and was checked with it.
func checkMetricsTransport(metricsURL string, insecure bool) error {
	plain, err := plainRemote("UPSTREAM_METRICS_URL", metricsURL)
	if err != nil || !plain || insecure {
		return err
	}
	return fmt.Errorf("UPSTREAM_METRICS_URL %q is plain HTTP to another host: the relay's metrics token "+
		"would cross the network in cleartext. Use https://, or set -insecure-upstream when the "+
		"network itself is protected", metricsURL)
}

// plainRemote reports whether raw is plain HTTP to a host other than this
// machine. HTTPS and loopback are not; any other scheme is an error.
func plainRemote(name, raw string) (bool, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false, fmt.Errorf("%s %q is not an absolute URL", name, raw)
	}
	switch {
	case u.Scheme == "https", u.Scheme == "http" && isLoopback(u.Hostname()):
		return false, nil
	case u.Scheme != "http":
		return false, fmt.Errorf("%s %q: scheme %q is not http or https", name, raw, u.Scheme)
	}
	return true, nil
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
