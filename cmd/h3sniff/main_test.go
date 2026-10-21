package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/megamen32/site-mimic/mimic"
)

// TestTheStandReportsTheClientsFingerprint drives the stand the way the
// canary does and checks what it reports.
//
// The report is the whole point of the tool: a server that reads the
// client's QUIC ClientHello, its transport parameters and its HTTP/3
// settings. The test pins the fingerprint of our own h3 client, which is
// the Chrome QUIC hello minus the server name (the client here talks to an
// address, so it sends no SNI).
func TestTheStandReportsTheClientsFingerprint(t *testing.T) {
	cert := selfSignedCert(t)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	var sink safeBuffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		if err := serve(ctx, pc, cert, &sink); err != nil {
			t.Logf("the stand stopped: %v", err)
		}
	}()

	profile := mimic.Profile{
		Name:           "chrome-152-h3",
		TLSClientHello: "chrome_152",
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
	}
	client, err := mimic.NewHTTP3(profile, mimic.WithInsecureTLS())
	if err != nil {
		t.Fatalf("NewHTTP3: %v", err)
	}
	defer client.Transport.(io.Closer).Close()

	port := pc.LocalAddr().(*net.UDPAddr).Port
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d/", port), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("the request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if resp.Proto != "HTTP/3.0" {
		t.Errorf("proto = %q, want HTTP/3.0", resp.Proto)
	}
	if string(body) != "ok\n" {
		t.Errorf("body = %q, want %q", body, "ok\n")
	}

	// The stand reports the connection.
	var rep report
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		line := strings.TrimSpace(sink.String())
		if line != "" {
			if err := json.Unmarshal([]byte(line), &rep); err != nil {
				t.Fatalf("the report is not JSON: %v (%q)", err, line)
			}
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if rep.JA4 == "" {
		t.Fatalf("the stand reported no fingerprint: %q", sink.String())
	}

	// The Chrome QUIC hello, without the server name: the client talked to
	// an address.
	if got, want := rep.JA4, "q13i0312h3_55b375c5d22e_eb028bd37c08"; got != want {
		t.Errorf("JA4 = %s, want %s", got, want)
	}
	if got, want := rep.Extensions, 12; got != want {
		t.Errorf("%d extensions, want %d", got, want)
	}
	if len(rep.ALPN) != 1 || rep.ALPN[0] != "h3" {
		t.Errorf("ALPN = %v, want [h3]", rep.ALPN)
	}
	if got, want := rep.TransportParameters["12584"], "4f5249474e4f4950"; got != want {
		t.Errorf("google_connection_options = %s, want %s", got, want)
	}
	// The settings the client sends on its control stream.
	for id, want := range map[string]uint64{"1": 65536, "6": 262144, "7": 100, "51": 1} {
		if got := rep.Settings[id]; got != want {
			t.Errorf("setting %s = %d, want %d", id, got, want)
		}
	}
	if got, want := rep.UserAgent, profile.UserAgent; got != want {
		t.Errorf("user agent = %q, want %q", got, want)
	}
}

// safeBuffer is a bytes.Buffer the stand and the test can both touch: the
// stand writes the report from its own goroutine.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// selfSignedCert makes the certificate the stand serves: a throwaway one
// for 127.0.0.1, made on the spot.
func selfSignedCert(t *testing.T) *utls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("the key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "site-mimic h3sniff test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("the certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("the key: %v", err)
	}
	cert, err := utls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatalf("the key pair: %v", err)
	}
	return &utls.Config{
		Certificates: []utls.Certificate{cert},
		NextProtos:   []string{"h3"},
	}
}
