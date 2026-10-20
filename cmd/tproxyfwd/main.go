// Command tproxyfwd is the transparent TCP forwarder that a rooted Android
// phone needs for a site-mimic capture.
//
// Why it exists
// -------------
// A rooted phone lets you redirect an app's TCP traffic with iptables:
//
//	iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner <uid> \
//	    ! -d 127.0.0.0/8 -j REDIRECT --to-ports 30886
//
// REDIRECT hands the connection to a local listener, but the listener no
// longer knows the original destination — the kernel already rewrote the
// address. The original destination is still recoverable: the kernel keeps
// it per socket and hands it over with getsockopt(SO_ORIGINAL_DST). This
// command does exactly that, then relays the connection through a SOCKS5
// proxy to a machine that terminates TLS (mitmproxy in --mode socks5):
//
//	app TCP -> REDIRECT :30886 -> tproxyfwd -> SOCKS5 -> mitmdump
//
// The forwarder never decrypts anything: it only moves bytes. The ClientHello
// is plaintext on the wire, so the capture side can read the fingerprint
// without any CA on the phone at all (see cmd/hello-tap for that path).
//
// The forwarder is self-contained: it speaks SOCKS5 itself (no proxy
// library), and the platform-specific getsockopt(SO_ORIGINAL_DST) call
// lives in dst_linux.go so the command still builds on a macOS
// workstation. Validated on a rooted Android phone against ru.oneme.app on
// 2026-10-20: the capture reproduced the committed fingerprint (JA3 md5
// fb1972c15d60b7be0427edfbd00affde) byte for byte.
//
// Usage on the phone (root shell):
//
//	TPROXYFWD_LISTEN=127.0.0.1:30886 \
//	TPROXYFWD_SOCKS5=10.0.0.5:31896 \
//	    setsid tproxyfwd >>/data/local/tmp/tproxyfwd.log 2>&1 &
//
// Environment:
//
//	TPROXYFWD_LISTEN  local listen address (default 127.0.0.1:30886)
//	TPROXYFWD_SOCKS5  SOCKS5 upstream, host:port (default 127.0.0.1:1080)
//	TPROXYFWD_LOG     "1" to log every relayed connection to stderr
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"time"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	listen := envOr("TPROXYFWD_LISTEN", "127.0.0.1:30886")
	upstream := envOr("TPROXYFWD_SOCKS5", "127.0.0.1:1080")
	verbose := os.Getenv("TPROXYFWD_LOG") == "1"

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatalf("tproxyfwd: listen %s: %v", listen, err)
	}
	log.Printf("tproxyfwd: listening on %s, socks5 upstream %s", listen, upstream)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("tproxyfwd: accept: %v", err)
			continue
		}
		go func() {
			if err := handle(conn, upstream, verbose); err != nil {
				log.Printf("tproxyfwd: %v", err)
			}
		}()
	}
}

// handle resolves the original destination of an accepted connection and
// relays it through the SOCKS5 upstream.
func handle(conn net.Conn, upstream string, verbose bool) error {
	defer conn.Close()

	dst, err := originalDst(conn)
	if err != nil {
		return fmt.Errorf("original destination: %w", err)
	}
	if verbose {
		log.Printf("tproxyfwd: %s -> %s", conn.RemoteAddr(), dst)
	}

	up, err := net.DialTimeout("tcp", upstream, 15*time.Second)
	if err != nil {
		return fmt.Errorf("dial socks5 %s: %w", upstream, err)
	}
	defer up.Close()

	if err := socks5Connect(up, dst); err != nil {
		return fmt.Errorf("socks5 connect %s: %w", dst, err)
	}

	// Relay in both directions; the first error wins, the rest are normal
	// ("connection reset by peer" after the peer closed).
	errc := make(chan error, 2)
	go func() { errc <- copyConn(up, conn) }()
	go func() { errc <- copyConn(conn, up) }()
	<-errc
	return nil
}

// copyConn copies src into dst and half-closes dst when the source ends.
func copyConn(dst, src net.Conn) error {
	_, err := io.Copy(dst, src)
	if tcp, ok := dst.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

// buildConnectRequest builds the SOCKS5 CONNECT request for a domain target
// (RFC 1928 section 3).
//
// The domain length is ONE byte. A two-byte length silently breaks every
// connection: the proxy reads the high byte (0x00) as the length, so the
// host looks empty and the port is stitched together from the leftover
// length byte and the first character of the host — mitmdump then reports
// "Name or service not known" for a destination that looks like ":3889".
// This exact bug shipped once here and was caught by a live run against a
// real phone; socks5_test.go locks the wire format.
func buildConnectRequest(host string, port int) ([]byte, error) {
	if len(host) == 0 {
		return nil, fmt.Errorf("socks5: empty host")
	}
	if len(host) > 255 {
		return nil, fmt.Errorf("socks5: host too long (%d bytes)", len(host))
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("socks5: bad port %d", port)
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	return req, nil
}

// socks5Connect performs a no-auth SOCKS5 CONNECT to target.
func socks5Connect(conn net.Conn, target string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}

	// greeting: version 5, one method, "no authentication"
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		return fmt.Errorf("socks5: unsupported auth method 0x%02x", reply[1])
	}

	// request: VER CMD RSV ATYP=3 (domain) | LEN(1 byte) | HOST | PORT(2 bytes)
	//
	// RFC 1928 encodes the length of a domain-name in ONE byte, not two.
	// With a 2-byte length the proxy reads the high byte (0x00) as the
	// length, so it sees an empty host and a port made of the remaining
	// length byte plus the first host character — every CONNECT is
	// rejected with "Name or service not known".
	req, err := buildConnectRequest(host, port)
	if err != nil {
		return err
	}
	if _, err := conn.Write(req); err != nil {
		return err
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[1] != 0x00 {
		return fmt.Errorf("socks5: connect failed, code %d", head[1])
	}
	// Drain the bound address, whatever its form.
	switch head[3] {
	case 0x01:
		_, err = io.ReadFull(conn, make([]byte, 4+2))
	case 0x04:
		_, err = io.ReadFull(conn, make([]byte, 16+2))
	case 0x03:
		l := make([]byte, 1)
		if _, err = io.ReadFull(conn, l); err == nil {
			_, err = io.ReadFull(conn, make([]byte, int(l[0])+2))
		}
	default:
		err = fmt.Errorf("socks5: unknown address type %d", head[3])
	}
	return err
}
