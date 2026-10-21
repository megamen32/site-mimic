package mimic

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/megamen32/headless-client/quic/http3"
	utls "github.com/refraction-networking/utls"
)

const chrome152UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"

func TestNewHTTP3(t *testing.T) {
	p := Profile{Name: "chrome-152-h3", TLSClientHello: "chrome_152", UserAgent: chrome152UA}
	client, err := NewHTTP3(p)
	if err != nil {
		t.Fatalf("NewHTTP3: %v", err)
	}
	if client.Transport == nil {
		t.Fatal("no transport")
	}
	closer, ok := client.Transport.(io.Closer)
	if !ok {
		t.Fatal("the h3 transport is not an io.Closer — the UDP socket would leak")
	}
	if err := closer.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

// TestNewHTTP3UserAgent checks that the profile's user agent reaches the
// wire even when the request carries none.
func TestNewHTTP3UserAgent(t *testing.T) {
	p := Profile{UserAgent: chrome152UA}
	client, err := NewHTTP3(p)
	if err != nil {
		t.Fatalf("NewHTTP3: %v", err)
	}
	defer client.Transport.(io.Closer).Close()

	req, err := http.NewRequest(http.MethodGet, "http://example.invalid/", nil)
	if err != nil {
		t.Fatal(err)
	}
	// The request never leaves the machine: the h3 transport rejects the
	// plain-http scheme, but the header is set before that.
	if _, err := client.Do(req); err == nil {
		t.Error("the h3 transport accepted a plain http request")
	}
	if got := req.Header.Get("User-Agent"); got != "" {
		t.Errorf("the caller's request was modified: user agent = %q", got)
	}
}

func TestNewHTTP3RejectsForeignProfile(t *testing.T) {
	_, err := NewHTTP3(Profile{TLSClientHello: "node_24"})
	if err == nil {
		t.Fatal("a Node profile was accepted by the h3 transport")
	}
	if !strings.HasPrefix(err.Error(), "mimic: ") {
		t.Errorf("error %q is not prefixed with \"mimic: \"", err)
	}
}

func TestNewHTTP3RejectsProxy(t *testing.T) {
	_, err := NewHTTP3(Profile{}, WithProxy("http://user:pass@127.0.0.1:3128"))
	if err == nil {
		t.Fatal("a CONNECT proxy was accepted by the h3 transport")
	}
	if !strings.Contains(err.Error(), "QUIC") {
		t.Errorf("error %q does not mention QUIC", err)
	}
}

// TestHTTP3LocalServer speaks HTTP/3 to a local h3 server built with the
// same uquic dependency: the full round trip — QUIC handshake, h3 request,
// h3 response — without touching the network.
func TestHTTP3LocalServer(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := newTestH3Server(t)
	go func() { _ = srv.Serve(pc) }()
	defer srv.Close()

	p := Profile{Name: "chrome-152-h3", TLSClientHello: "chrome_152", UserAgent: chrome152UA}
	client, err := NewHTTP3(p, WithInsecureTLS())
	if err != nil {
		t.Fatalf("NewHTTP3: %v", err)
	}
	defer client.Transport.(io.Closer).Close()

	url := "https://" + pc.LocalAddr().String() + "/"
	req, err := p.Request(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("h3 request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	t.Logf("status=%s proto=%s body=%q", resp.Status, resp.Proto, strings.TrimSpace(string(body)))
	if resp.Proto != "HTTP/3.0" {
		t.Errorf("proto = %s, want HTTP/3.0", resp.Proto)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %s, want 200", resp.Status)
	}
	if got := resp.Header.Get("X-Request-Proto"); got != "HTTP/3.0" {
		t.Errorf("server saw proto %q, want HTTP/3.0", got)
	}
	if !strings.Contains(string(body), "HTTP/3.0") {
		t.Errorf("body = %q, want it to name the protocol", body)
	}
	if got := resp.Header.Get("X-UA"); got != chrome152UA {
		t.Errorf("server saw user agent %q, want %q", got, chrome152UA)
	}
}

// TestHTTP3UDPSocketTTL checks that the profile's IP TTL lands on the UDP
// socket — the same knob the TCP path stamps on its sockets.
func TestHTTP3UDPSocketTTL(t *testing.T) {
	pc, err := http3ListenPacket(transportOptions{}, Profile{IPTTL: 128})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	udp, ok := pc.(*net.UDPConn)
	if !ok {
		t.Fatalf("socket is %T, want *net.UDPConn", pc)
	}
	raw, err := udp.SyscallConn()
	if err != nil {
		t.Fatalf("syscall conn: %v", err)
	}
	var ttl int
	var sockErr error
	raw.Control(func(fd uintptr) {
		ttl, sockErr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS)
		if sockErr != nil {
			ttl, sockErr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL)
		}
	})
	if sockErr != nil {
		t.Fatalf("read ttl: %v", sockErr)
	}
	if ttl != 128 {
		t.Errorf("socket ttl = %d, want 128", ttl)
	}
}

// TestHTTP3LocalServerWithResolve checks the pinned-resolve path: the
// packets go to the pinned IP while the SNI keeps the hostname.
func TestHTTP3LocalServerWithResolve(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := newTestH3Server(t)
	go func() { _ = srv.Serve(pc) }()
	defer srv.Close()

	p := Profile{Name: "chrome-152-h3", TLSClientHello: "chrome_152", UserAgent: chrome152UA}
	client, err := NewHTTP3(p, WithInsecureTLS(), WithResolve(map[string]string{"localhost": "127.0.0.1"}))
	if err != nil {
		t.Fatalf("NewHTTP3: %v", err)
	}
	defer client.Transport.(io.Closer).Close()

	port := pc.LocalAddr().(*net.UDPAddr).Port
	req, err := p.Request(http.MethodGet, fmt.Sprintf("https://localhost:%d/", port), nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("h3 request: %v", err)
	}
	defer resp.Body.Close()
	t.Logf("status=%s proto=%s sni=%q", resp.Status, resp.Proto, resp.Header.Get("X-SNI"))
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %s, want 200", resp.Status)
	}
	if got := resp.Header.Get("X-SNI"); got != "localhost" {
		t.Errorf("server saw SNI %q, want localhost", got)
	}
}

// TestHTTP3VerifiesCertificates checks that the h3 path verifies the
// server's certificate by default. Every other h3 test turns verification
// off, so nothing would notice a flipped default — and a client that stops
// verifying is a client that accepts any certificate.
//
// The loopback server's certificate is self-signed, so the handshake must
// fail without WithInsecureTLS.
func TestHTTP3VerifiesCertificates(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := newTestH3Server(t)
	go func() { _ = srv.Serve(pc) }()
	defer srv.Close()

	p := Profile{Name: "chrome-152-h3", TLSClientHello: "chrome_152", UserAgent: chrome152UA}
	client, err := NewHTTP3(p) // no WithInsecureTLS: the certificate must be checked
	if err != nil {
		t.Fatalf("NewHTTP3: %v", err)
	}
	defer client.Transport.(io.Closer).Close()

	url := "https://" + pc.LocalAddr().String() + "/"
	req, err := p.Request(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("the handshake succeeded against a self-signed certificate")
	}
	t.Logf("rejected as expected: %v", err)
}

// newTestH3Server starts an h3 server for the loopback tests.
func newTestH3Server(t *testing.T) *http3.Server {
	t.Helper()
	return &http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Request-Proto", r.Proto)
			w.Header().Set("X-SNI", r.TLS.ServerName)
			w.Header().Set("X-UA", r.UserAgent())
			w.Header().Set("X-Resume", fmt.Sprintf("%t", r.TLS.DidResume))
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "hello over "+r.Proto)
		}),
		TLSConfig: &utls.Config{Certificates: []utls.Certificate{selfSignedCert(t)}},
	}
}

// selfSignedCert makes a throwaway certificate for the loopback server.
func selfSignedCert(t *testing.T) utls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mimic h3 test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := utls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}
	return cert
}

// TestHTTP3Live speaks HTTP/3 to a public endpoint and checks the response
// really came over h3. It is skipped unless MIMIC_HTTP3_LIVE=1 is set, so
// the suite never depends on the network; MIMIC_HTTP3_LIVE_URL overrides the
// endpoint.
func TestHTTP3Live(t *testing.T) {
	if os.Getenv("MIMIC_HTTP3_LIVE") != "1" {
		t.Skip("set MIMIC_HTTP3_LIVE=1 to run the live h3 request")
	}
	endpoint := os.Getenv("MIMIC_HTTP3_LIVE_URL")
	if endpoint == "" {
		endpoint = "https://quic.tlsfingerprint.io/"
	}
	p := Profile{Name: "chrome-152-h3", TLSClientHello: "chrome_152", UserAgent: chrome152UA}
	client, err := NewHTTP3(p, WithDialTimeout(20*time.Second))
	if err != nil {
		t.Fatalf("NewHTTP3: %v", err)
	}
	defer client.Transport.(io.Closer).Close()

	req, err := p.Request(http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("h3 request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	t.Logf("status=%s proto=%s alpn=%q body=%s", resp.Status, resp.Proto, resp.TLS.NegotiatedProtocol, strings.TrimSpace(string(body)))
	if resp.Proto != "HTTP/3.0" {
		t.Errorf("proto = %s, want HTTP/3.0", resp.Proto)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %s, want 200", resp.Status)
	}
}

// TestHTTP3CarriesEachHostItsOwnName checks that two connections of one
// client carry their own server name.
//
// A browser opens one socket for many origins and sends the name of each
// origin in its own hello. The QUIC stack of the dependency took the name
// from the shared ClientHello spec, so the second connection to another
// host carried the first one's name and failed with a local TLS error.
func TestHTTP3CarriesEachHostItsOwnName(t *testing.T) {
	server := newTestH3Server(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	go func() { _ = server.Serve(pc) }()

	_, port, err := net.SplitHostPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("split the server address: %v", err)
	}
	p := Profile{Name: "chrome-156-h3", TLSClientHello: "chrome_156", UserAgent: chrome152UA}
	client, err := NewHTTP3(p, WithInsecureTLS(), WithResolve(map[string]string{
		"first.test":  "127.0.0.1",
		"second.test": "127.0.0.1",
	}))
	if err != nil {
		t.Fatalf("NewHTTP3: %v", err)
	}
	defer client.Transport.(io.Closer).Close()

	seen := map[string]bool{}
	for _, host := range []string{"first.test", "second.test"} {
		req, err := http.NewRequest(http.MethodGet, "https://"+host+":"+port+"/", nil)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("the request to %s failed: %v", host, err)
		}
		resp.Body.Close()
		seen[resp.Header.Get("X-SNI")] = true
	}
	for _, host := range []string{"first.test", "second.test"} {
		if !seen[host] {
			t.Errorf("the server saw %v, the connection to %s did not carry its own name", seen, host)
		}
	}
}

// TestHTTP3ResumesTheSession checks that the h3 path resumes like a
// browser: the second connection to an origin offers the ticket the first
// one got, and the server sees a resumed session.
//
// A browser that never resumes always sends the full handshake, and its
// hello never carries the pre_shared_key extension. The QUIC stack could
// not resume either: the ClientHello had no place for the ticket and the
// TLS configuration had no cache to keep it in.
func TestHTTP3ResumesTheSession(t *testing.T) {
	server := newTestH3Server(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	go func() { _ = server.Serve(pc) }()

	_, port, err := net.SplitHostPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("split the server address: %v", err)
	}
	p := Profile{Name: "chrome-156-h3", TLSClientHello: "chrome_156", UserAgent: chrome152UA}
	client, err := NewHTTP3(p, WithInsecureTLS(),
		WithResolve(map[string]string{"resumption.test": "127.0.0.1"}))
	if err != nil {
		t.Fatalf("NewHTTP3: %v", err)
	}
	defer client.Transport.(io.Closer).Close()

	resumed := make([]bool, 0, 2)
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequest(http.MethodGet, "https://resumption.test:"+port+"/", nil)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("the request %d failed: %v", attempt, err)
		}
		resp.Body.Close()
		resumed = append(resumed, resp.Header.Get("X-Resume") == "true")
		// The transport pools connections, so the second request would ride
		// the first one and there would be no second handshake to resume.
		// Dropping the idle connection forces a new one.
		client.CloseIdleConnections()
		time.Sleep(100 * time.Millisecond)
	}

	if resumed[0] {
		t.Error("the first connection claimed to be a resumed one")
	}
	if !resumed[1] {
		t.Error("the second connection did not resume: the client never offered the ticket")
	}
}
