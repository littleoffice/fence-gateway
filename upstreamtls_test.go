package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Plain HTTP to another host carries the relay credential and every tool
// result in cleartext, so it needs -insecure-upstream, and is refused outright
// when the credential is the caller's own.
func TestCheckUpstreamTransport(t *testing.T) {
	static := upstreamAuth{mode: upstreamAuthStatic}
	pass := upstreamAuth{mode: upstreamAuthPassthrough}
	exch := upstreamAuth{mode: upstreamAuthExchange}
	cases := []struct {
		name     string
		upstream string
		insecure bool
		ua       upstreamAuth
		wantErr  string
		wantWarn bool
	}{
		{"HTTPS", "https://relay.internal:8080/mcp", false, static, "", false},
		{"HTTPS, passthrough", "https://relay.internal:8080/mcp", false, pass, "", false},
		{"loopback (the default upstream)", "http://127.0.0.1:8080/mcp", false, static, "", false},
		{"localhost, passthrough", "http://localhost:8080/mcp", false, pass, "", false},
		{"IPv6 loopback", "http://[::1]:8080/mcp", false, static, "", false},
		{"plain HTTP to another host", "http://relay.internal:8080/mcp", false, static, "plain HTTP to another host", false},
		{"plain HTTP to a cluster IP", "http://10.0.0.7:8080/mcp", false, static, "plain HTTP to another host", false},
		{"plain HTTP, allowed on purpose", "http://relay.internal:8080/mcp", true, static, "", true},
		{"plain HTTP, exchange, allowed on purpose", "http://relay.internal:8080/mcp", true, exch, "", true},
		{"plain HTTP, passthrough", "http://relay.internal:8080/mcp", false, pass, "passthrough", false},
		{"plain HTTP, passthrough, flag does not apply", "http://relay.internal:8080/mcp", true, pass, "passthrough", false},
		{"not a URL", "relay.internal:8080", false, static, "", false},
		{"other scheme", "ftp://relay.internal/mcp", false, static, "scheme", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			warn, err := checkUpstreamTransport(c.upstream, c.insecure, c.ua)
			if c.name == "not a URL" {
				if err == nil {
					t.Fatalf("want an error for %q", c.upstream)
				}
				return
			}
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want one mentioning %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if (warn != "") != c.wantWarn {
				t.Errorf("warning = %q, want warning %v", warn, c.wantWarn)
			}
		})
	}
}

// testCA is a throwaway certificate authority.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// leaf issues a server certificate for 127.0.0.1, returned as PEM cert and key.
func (ca *testCA) leaf(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "relay"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
}

// tlsServer starts an HTTPS server presenting a certificate from ca.
func tlsServer(t *testing.T, ca *testCA) *httptest.Server {
	t.Helper()
	c, k := ca.leaf(t)
	pair, err := tls.X509KeyPair(c, k)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// writeFile writes data and moves the modification time forward, so a
// rewrite within the filesystem's timestamp resolution still reads as a change.
func writeFile(t *testing.T, path string, data []byte, mod time.Time) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mod, mod); err != nil {
		t.Fatal(err)
	}
}

func getVia(rt http.RoundTripper, url string) error {
	resp, err := (&http.Client{Transport: rt, Timeout: 5 * time.Second}).Get(url)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

// -upstream-ca trusts its bundle instead of the system roots, and picks up a
// CA rotated in place without a restart, as a cert-manager CA Issuer's Secret
// is updated in the pod.
func TestUpstreamCAReload(t *testing.T) {
	oldCA, newCA := newTestCA(t, "old"), newTestCA(t, "new")
	oldSrv, newSrv := tlsServer(t, oldCA), tlsServer(t, newCA)

	path := filepath.Join(t.TempDir(), "ca.crt")
	start := time.Now().Add(-time.Minute)
	writeFile(t, path, oldCA.pem, start)
	ca, err := newUpstreamCA(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := getVia(ca, oldSrv.URL); err != nil {
		t.Fatalf("relay signed by the bundle's CA: %v", err)
	}
	if err := getVia(ca, newSrv.URL); err == nil {
		t.Fatal("relay signed by a CA outside the bundle was accepted")
	}

	// Rotation overlap: both CAs in the bundle.
	writeFile(t, path, append(append([]byte{}, oldCA.pem...), newCA.pem...), start.Add(time.Second))
	if err := getVia(ca, oldSrv.URL); err != nil {
		t.Fatalf("old CA during overlap: %v", err)
	}
	if err := getVia(ca, newSrv.URL); err != nil {
		t.Fatalf("new CA during overlap: %v", err)
	}

	// A bundle caught mid-write keeps the last good one.
	writeFile(t, path, []byte("-----BEGIN CERT"), start.Add(2*time.Second))
	if err := getVia(ca, newSrv.URL); err != nil {
		t.Fatalf("a broken bundle dropped the last good one: %v", err)
	}

	// Old CA retired.
	writeFile(t, path, newCA.pem, start.Add(3*time.Second))
	ca.transport().CloseIdleConnections()
	if err := getVia(ca, oldSrv.URL); err == nil {
		t.Fatal("relay signed by the retired CA was still accepted")
	}
}

func TestNewUpstreamCARejectsBadBundle(t *testing.T) {
	dir := t.TempDir()
	if _, err := newUpstreamCA(filepath.Join(dir, "missing.crt")); err == nil {
		t.Error("a missing bundle was accepted")
	}
	empty := filepath.Join(dir, "empty.crt")
	writeFile(t, empty, []byte("not a certificate\n"), time.Now())
	if _, err := newUpstreamCA(empty); err == nil || !strings.Contains(err.Error(), "no PEM certificates") {
		t.Errorf("err = %v, want a no-certificates error", err)
	}
}

// The bundle applies to the relay's own endpoints only: an explicit -key-url
// or UPSTREAM_METRICS_URL on another host keeps the system roots.
func TestRelayTransport(t *testing.T) {
	ca := &upstreamCA{}
	const up = "https://relay.internal:8443/mcp"
	if relayTransport(ca, up, "https://relay.internal:8443/fence/public-key") != http.RoundTripper(ca) {
		t.Error("the relay's key endpoint does not use the bundle")
	}
	if relayTransport(ca, up, "https://keys.example/fence/public-key") != http.DefaultTransport {
		t.Error("another host's key endpoint uses the bundle")
	}
	if relayTransport(nil, up, "https://relay.internal:8443/metrics") != http.DefaultTransport {
		t.Error("no bundle should mean the system roots")
	}
}

// MCP_TLS_CERT/MCP_TLS_KEY are served through a reloader: a certificate
// renewed in place is served on the next handshake, and a half-written pair
// keeps the last good one.
func TestCertReloader(t *testing.T) {
	ca := newTestCA(t, "issuer")
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	start := time.Now().Add(-time.Minute)

	c1, k1 := ca.leaf(t)
	writeFile(t, certFile, c1, start)
	writeFile(t, keyFile, k1, start)
	r, err := newCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	first, err := r.getCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Renewed: new cert and key.
	c2, k2 := ca.leaf(t)
	writeFile(t, certFile, c2, start.Add(time.Second))
	writeFile(t, keyFile, k2, start.Add(time.Second))
	second, err := r.getCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(second.Certificate[0]) == string(first.Certificate[0]) {
		t.Fatal("the renewed certificate was not picked up")
	}

	// Mid-rotation: the cert is rewritten, the key is not yet.
	c3, _ := ca.leaf(t)
	writeFile(t, certFile, c3, start.Add(2*time.Second))
	third, err := r.getCertificate(nil)
	if err != nil {
		t.Fatalf("a mismatched pair failed the handshake: %v", err)
	}
	if string(third.Certificate[0]) != string(second.Certificate[0]) {
		t.Error("a mismatched pair replaced the last good certificate")
	}

	if _, err := newCertReloader(filepath.Join(dir, "missing.crt"), keyFile); err == nil {
		t.Error("a missing certificate was accepted at startup")
	}
}
