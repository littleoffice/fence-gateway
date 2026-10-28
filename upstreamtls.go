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
	"sync"
	"time"
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

// upstreamCA is the -upstream-ca bundle: the CAs trusted for the relay's
// certificate, in place of the system roots. The file is re-read when its
// modification time moves, so a CA rotated in place — a cert-manager CA
// Issuer's Secret mounted into the pod, say — is picked up without a restart.
// Put the old and the new CA in the file together while certificates issued by
// both are in use.
type upstreamCA struct {
	path string

	mu   sync.Mutex
	mod  time.Time
	cur  *http.Transport
	base *http.Transport // template for each rebuilt transport
}

// newUpstreamCA loads path once, so a missing or empty bundle fails startup
// rather than the first request.
func newUpstreamCA(path string) (*upstreamCA, error) {
	c := &upstreamCA{path: path, base: http.DefaultTransport.(*http.Transport).Clone()}
	if _, err := c.load(); err != nil {
		return nil, err
	}
	return c, nil
}

// load reads the bundle and builds a transport that trusts only it.
func (c *upstreamCA) load() (*http.Transport, error) {
	fi, err := os.Stat(c.path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(c.path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("no PEM certificates found in file")
	}
	t := c.base.Clone()
	t.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}

	c.mu.Lock()
	old := c.cur
	c.cur, c.mod = t, fi.ModTime()
	c.mu.Unlock()
	if old != nil {
		// Connections already open were verified against the old bundle and
		// stay valid; idle ones are dropped so the next request dials anew.
		old.CloseIdleConnections()
	}
	return t, nil
}

// transport returns the transport for the current bundle, reloading it first
// when the file has changed. A reload that fails (the file caught mid-write)
// keeps the last good bundle rather than failing requests.
func (c *upstreamCA) transport() *http.Transport {
	fi, err := os.Stat(c.path)
	c.mu.Lock()
	cur, fresh := c.cur, err != nil || fi.ModTime().Equal(c.mod)
	c.mu.Unlock()
	if fresh {
		return cur
	}
	if t, err := c.load(); err == nil {
		return t
	}
	return cur
}

// RoundTrip makes upstreamCA the base http.RoundTripper for every request to
// the relay: MCP, the fence key and its metrics.
func (c *upstreamCA) RoundTrip(r *http.Request) (*http.Response, error) {
	return c.transport().RoundTrip(r)
}

// upstreamRoundTripper is the base transport for requests to the relay:
// the -upstream-ca bundle when one is set, otherwise the system roots.
func upstreamRoundTripper(ca *upstreamCA) http.RoundTripper {
	if ca == nil {
		return http.DefaultTransport
	}
	return ca
}

// certReloader serves MCP_TLS_CERT/MCP_TLS_KEY through a GetCertificate hook,
// re-reading the pair when either file's modification time moves. A
// certificate renewed in place — cert-manager updating its Secret, or an
// operator replacing the files — is served without a restart. A reload that
// fails mid-rotation (cert rewritten, key not yet, so the pair does not match)
// keeps serving the last good certificate rather than failing handshakes.
// mcp-searxng-relay serves its manual certificate the same way.
type certReloader struct {
	certFile, keyFile string

	mu      sync.RWMutex
	cached  *tls.Certificate
	modCert time.Time
	modKey  time.Time
}

// newCertReloader loads the pair once, so a bad pair fails startup.
func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile}
	if _, err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *certReloader) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c := r.currentIfFresh(); c != nil {
		return c, nil
	}
	c, err := r.load()
	if err != nil {
		if cached := r.current(); cached != nil {
			return cached, nil
		}
		return nil, err
	}
	return c, nil
}

func (r *certReloader) current() *tls.Certificate {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cached
}

// currentIfFresh returns the cached certificate while both files carry the
// modification times it was loaded from, and nil when a reload is due. A stat
// error keeps the cached certificate, so a transient filesystem error does not
// drop a working one.
func (r *certReloader) currentIfFresh() *tls.Certificate {
	ci, errC := os.Stat(r.certFile)
	ki, errK := os.Stat(r.keyFile)
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.cached == nil {
		return nil
	}
	if errC != nil || errK != nil {
		return r.cached
	}
	if ci.ModTime().Equal(r.modCert) && ki.ModTime().Equal(r.modKey) {
		return r.cached
	}
	return nil
}

func (r *certReloader) load() (*tls.Certificate, error) {
	ci, err := os.Stat(r.certFile)
	if err != nil {
		return nil, err
	}
	ki, err := os.Stat(r.keyFile)
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.cached = &cert
	r.modCert = ci.ModTime()
	r.modKey = ki.ModTime()
	r.mu.Unlock()
	return &cert, nil
}

// relayTransport is the base transport for a request to target, one of the
// relay's other endpoints (the fence key, metrics): the -upstream-ca bundle
// when target is on the upstream's host, and the system roots otherwise, since
// -key-url or UPSTREAM_METRICS_URL may name a host the bundle does not cover.
func relayTransport(ca *upstreamCA, upstream, target string) http.RoundTripper {
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
