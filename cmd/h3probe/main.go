// Command h3probe reads the HTTP/3 control stream a client sends.
//
// It listens for QUIC connections, accepts the first unidirectional stream —
// the control stream — and prints the frames it carries: the SETTINGS frame
// with its identifier/value pairs, and the GREASE frames around it. That is
// the part of an HTTP/3 client a server actually fingerprints, and the part
// a client library gets wrong most easily: a client that sends an empty
// SETTINGS frame announces a different client than one that sends Chrome's.
//
// The tool also serves an HTTPS origin that advertises the listener in its
// Alt-Svc header, so a browser can be pointed at it and the same run shows
// what a real browser sends:
//
//	h3probe -serve          # HTTPS on :8443, Alt-Svc points at the h3 port
//	open https://localhost:8443/ in a browser
//
// With -serve the origin answers every request with the Alt-Svc header, and
// the browser upgrades to HTTP/3 on the next request.
//
// Without a browser the tool is still useful: -wait prints the frames of
// whatever client connects first, for example a client built with this
// repository's mimic package.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/megamen32/headless-client/quic"
	h3http3 "github.com/megamen32/headless-client/quic/http3"
	utls "github.com/refraction-networking/utls"
)

func main() {
	var (
		addr      = flag.String("addr", "127.0.0.1:0", "the UDP address the HTTP/3 listener binds")
		serveAddr = flag.String("serve", "", "also serve an HTTPS origin on this address, advertising the listener in Alt-Svc")
		wait      = flag.Duration("wait", 30*time.Second, "how long to wait for a client")
		quiet     = flag.Bool("quiet", false, "print the raw control stream bytes only")
	)
	flag.Parse()

	if err := run(*addr, *serveAddr, *wait, *quiet); err != nil {
		fmt.Fprintf(os.Stderr, "h3probe: %v\n", err)
		os.Exit(1)
	}
}

func run(addr, serveAddr string, wait time.Duration, quiet bool) error {
	sock, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("udp socket: %w", err)
	}
	defer sock.Close()
	pc := &countingConn{PacketConn: sock}

	cert, err := selfSignedCert()
	if err != nil {
		return err
	}
	tlsConf := h3http3.ConfigureTLSConfig(&utls.Config{
		Certificates: []utls.Certificate{cert.utls},
		NextProtos:   []string{"h3"},
	})
	ln, err := quic.Listen(pc, tlsConf, &quic.Config{
		Allow0RTT: true,
	})
	if err != nil {
		return fmt.Errorf("quic listener: %w", err)
	}
	defer ln.Close()

	quicPort := pc.LocalAddr().(*net.UDPAddr).Port
	fmt.Printf("h3 listening on udp/%s (port %d)\n", pc.LocalAddr(), quicPort)

	if serveAddr != "" {
		if err := serveOrigin(serveAddr, quicPort, cert.std); err != nil {
			return err
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	conn, err := ln.Accept(ctx)
	if err != nil {
		return fmt.Errorf("accept: %w", err)
	}
	fmt.Printf("client connected from %s\n", conn.RemoteAddr())

	str, err := conn.AcceptUniStream(ctx)
	if err != nil {
		return fmt.Errorf("control stream: %w", err)
	}
	// The control stream stays open for the life of the connection, so it
	// is read until the SETTINGS frame is complete — reading it to the end
	// would wait for a connection close that never comes.
	buf := make([]byte, 4096)
	var raw []byte
	for {
		n, err := str.Read(buf)
		if n > 0 {
			raw = append(raw, buf[:n]...)
			if _, complete := settingsFrom(raw); complete {
				break
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return fmt.Errorf("read control stream: %w", err)
			}
			break
		}
	}
	if !quiet {
		printControlStream(raw)
	}
	fmt.Printf("raw control stream (%d bytes): %s\n", len(raw), hex.EncodeToString(raw))
	return nil
}

// countingConn logs the first packets that reach the socket, so a run that
// never completes says whether the client sent anything at all.
type countingConn struct {
	net.PacketConn
	mu    sync.Mutex
	count int
}

func (c *countingConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err == nil {
		c.mu.Lock()
		c.count++
		if c.count <= 5 {
			fmt.Printf("packet %d from %s: %d bytes\n", c.count, addr, n)
		}
		c.mu.Unlock()
	}
	return n, addr, err
}

// serveOrigin runs an HTTPS origin that advertises the HTTP/3 listener in its
// Alt-Svc header, so a browser that visits it upgrades to HTTP/3.
func serveOrigin(addr string, quicPort int, cert tls.Certificate) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", fmt.Sprintf("h3=\":%d\"", quicPort))
		w.Header().Set("X-Request-Proto", r.Proto)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "hello over "+r.Proto+"\n")
	})
	srv := &http.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("tcp socket: %w", err)
	}
	fmt.Printf("https origin on %s (Alt-Svc: h3=\":%d\")\n", ln.Addr(), quicPort)
	go func() {
		if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "h3probe: origin: %v\n", err)
		}
	}()
	return nil
}

// settingsFrom decodes the SETTINGS frame at the head of a control stream
// and reports whether the frame is complete.
func settingsFrom(raw []byte) (map[uint64]uint64, bool) {
	settings := map[uint64]uint64{}
	if len(raw) == 0 {
		return settings, false
	}
	streamType, pos, ok := readVarint(raw)
	if !ok || streamType != 0x00 {
		return settings, false
	}
	if pos >= len(raw) {
		return settings, false
	}
	frameType, n, ok := readVarint(raw[pos:])
	if !ok || frameType != 0x04 {
		return settings, false
	}
	pos += n
	length, n, ok := readVarint(raw[pos:])
	if !ok {
		return settings, false
	}
	pos += n
	if pos+int(length) > len(raw) {
		return settings, false
	}
	payload := raw[pos : pos+int(length)]
	for len(payload) > 0 {
		id, n, ok := readVarint(payload)
		if !ok {
			return settings, false
		}
		payload = payload[n:]
		value, n, ok := readVarint(payload)
		if !ok {
			return settings, false
		}
		payload = payload[n:]
		settings[id] = value
	}
	return settings, true
}

// printControlStream decodes the control stream: the stream type and then
// every frame, with the SETTINGS frame broken into its identifier/value
// pairs.
func printControlStream(raw []byte) {
	pos := 0
	streamType, n, ok := readVarint(raw[pos:])
	if !ok {
		fmt.Println("control stream: truncated stream type")
		return
	}
	pos += n
	fmt.Printf("control stream: type 0x%x\n", streamType)

	for pos < len(raw) {
		frameType, n, ok := readVarint(raw[pos:])
		if !ok {
			fmt.Println("control stream: truncated frame type")
			return
		}
		pos += n
		length, n, ok := readVarint(raw[pos:])
		if !ok {
			fmt.Println("control stream: truncated frame length")
			return
		}
		pos += n
		if pos+int(length) > len(raw) {
			fmt.Printf("control stream: frame 0x%x claims %d bytes, %d left\n", frameType, length, len(raw)-pos)
			return
		}
		payload := raw[pos : pos+int(length)]
		pos += int(length)

		switch frameType {
		case 0x4:
			fmt.Printf("frame SETTINGS (%d bytes):\n", len(payload))
			printSettings(payload)
		case 0xd:
			fmt.Printf("frame GREASE 0x%x (%d bytes): %s\n", frameType, len(payload), hex.EncodeToString(payload))
		default:
			fmt.Printf("frame 0x%x (%d bytes): %s\n", frameType, len(payload), hex.EncodeToString(payload))
		}
	}
}

// printSettings decodes a SETTINGS payload into identifier/value pairs.
func printSettings(payload []byte) {
	for pos := 0; pos < len(payload); {
		id, n, ok := readVarint(payload[pos:])
		if !ok {
			fmt.Println("  truncated setting identifier")
			return
		}
		pos += n
		value, n, ok := readVarint(payload[pos:])
		if !ok {
			fmt.Println("  truncated setting value")
			return
		}
		pos += n
		name := settingName(id)
		if name != "" {
			fmt.Printf("  0x%02x %-28s = %d\n", id, name, value)
			continue
		}
		fmt.Printf("  0x%02x %-28s = %d\n", id, "unknown", value)
	}
}

// settingName names the setting identifiers RFC 9114 and RFC 9297 define, so
// a captured frame reads like a specification instead of a number list.
func settingName(id uint64) string {
	switch id {
	case 0x1:
		return "QPACK_MAX_TABLE_CAPACITY"
	case 0x6:
		return "MAX_FIELD_SECTION_SIZE"
	case 0x7:
		return "QPACK_BLOCKED_STREAMS"
	case 0x8:
		return "ENABLE_CONNECT_PROTOCOL"
	case 0x33:
		return "H3_DATAGRAM"
	}
	return ""
}

// readVarint reads a QUIC variable-length integer.
func readVarint(b []byte) (uint64, int, bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	switch b[0] >> 6 {
	case 0:
		return uint64(b[0]), 1, true
	case 1:
		if len(b) < 2 {
			return 0, 0, false
		}
		return uint64(b[0]&0x3f)<<8 | uint64(b[1]), 2, true
	case 2:
		if len(b) < 4 {
			return 0, 0, false
		}
		return uint64(b[0]&0x3f)<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3]), 4, true
	default:
		if len(b) < 8 {
			return 0, 0, false
		}
		var v uint64
		for i := 0; i < 8; i++ {
			v = v<<8 | uint64(b[i])
		}
		return v & 0x3fffffffffffffff, 8, true
	}
}

// selfSignedCert makes a throwaway certificate for the local listeners. The
// QUIC listener takes a uTLS certificate and the HTTPS origin a standard one,
// so both are built from the same key pair.
func selfSignedCert() (certPair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return certPair{}, fmt.Errorf("key: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "h3probe"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return certPair{}, fmt.Errorf("certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return certPair{}, fmt.Errorf("marshal key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	utlsCert, err := utls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return certPair{}, fmt.Errorf("utls key pair: %w", err)
	}
	stdCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return certPair{}, fmt.Errorf("key pair: %w", err)
	}
	return certPair{utls: utlsCert, std: stdCert}, nil
}

// certPair carries one certificate in the two forms the listeners need.
type certPair struct {
	utls utls.Certificate
	std  tls.Certificate
}
