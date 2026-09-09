package mimic

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// ClientHelloCapture performs a real uTLS handshake against host
// ("host" or "host:port", port defaults to 443) and returns the raw
// ClientHello TLS record bytes exactly as they hit the wire:
//
//	record: type 0x16 + version(2) + length(2)
//	handshake: type 0x01 + 3-byte length + ClientHello body
//
// Write the result with WriteClientHelloJSON and feed it to
// tools/parse_clienthello.py to obtain JA3/JA4 — the same artifact a packet
// capture of a real browser produces.
func ClientHelloCapture(ctx context.Context, host, helloIDName string) ([]byte, error) {
	if _, err := ParseClientHelloID(helloIDName); err != nil {
		return nil, err
	}
	if !strings.Contains(host, ":") {
		host = net.JoinHostPort(host, "443")
	}
	serverName, _, err := net.SplitHostPort(host)
	if err != nil {
		return nil, err
	}
	conn, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("mimic: dial %s: %w", host, err)
	}
	capturer := &clientHelloCapturer{Conn: conn}
	uConn, err := newUConn(capturer, &utls.Config{ServerName: serverName}, helloIDName)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("mimic: utls client %s: %w", helloIDName, err)
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := uConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("mimic: utls handshake to %s: %w", host, err)
	}
	_ = conn.Close()
	return capturer.firstWrite, nil
}

// WriteClientHelloJSON persists a captured record as
// {"target": ..., "client_hello_b64": ...} — the envelope
// tools/parse_clienthello.py consumes.
func WriteClientHelloJSON(path, target string, record []byte) error {
	envelope := map[string]string{
		"target":           target,
		"client_hello_b64": base64.StdEncoding.EncodeToString(record),
	}
	raw, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

// clientHelloCapturer stashes the first write on the connection — the
// ClientHello record the handshake emits.
type clientHelloCapturer struct {
	net.Conn
	once       sync.Once
	firstWrite []byte
}

func (c *clientHelloCapturer) Write(b []byte) (int, error) {
	c.once.Do(func() {
		if len(b) > 0 {
			c.firstWrite = append([]byte(nil), b...)
		}
	})
	return c.Conn.Write(b)
}
