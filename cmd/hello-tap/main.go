// Command hello-tap is a forward proxy that records the TLS ClientHello of
// every tunnelled connection and then forwards the traffic untouched.
//
// Why a TCP-level tap and not a MITM: the ClientHello is plaintext on the
// wire, so JA3/JA4 can be read without decrypting anything — no CA on the
// device, no certificate pinning problems, and the app keeps working
// exactly as before. Only the handshake is looked at; the payload is
// relayed byte for byte.
//
// Use it to learn what a native client looks like on the wire (a rooted
// Android phone pointed at this proxy, a desktop app, anything):
//
//	go run ./cmd/hello-tap -listen 0.0.0.0:8888
//	# device: HTTP proxy = <host running the tap>:8888
//
// Output is JSONL, one record per TLS connection:
//
//	{"host":"ru.oneme.ru:443","sni":"ru.oneme.ru","ja3":"…","ja4":"…",
//	 "alpn":["h2"],"cipher_count":16,"extension_count":18,"session_id_len":32}
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/megamen32/site-mimic/mimic"
)

type record struct {
	Time           string   `json:"time"`
	Host           string   `json:"host"`
	SNI            string   `json:"sni"`
	JA3            string   `json:"ja3"`
	JA3MD5         string   `json:"ja3_md5"`
	JA4            string   `json:"ja4"`
	JA4R           string   `json:"ja4_r"`
	ALPN           []string `json:"alpn"`
	CipherCount    int      `json:"cipher_count"`
	ExtensionCount int      `json:"extension_count"`
	SessionIDLen   int      `json:"session_id_len"`
	Groups         []uint16 `json:"supported_groups"`
	SigAlgs        []uint16 `json:"signature_algorithms"`
	Error          string   `json:"error,omitempty"`
}

func main() {
	listen := flag.String("listen", "0.0.0.0:8888", "listen address")
	out := flag.String("out", "", "JSONL output file (default stdout)")
	flag.Parse()

	var sink io.Writer = os.Stdout
	if *out != "" {
		f, err := os.OpenFile(*out, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		sink = f
	}
	enc := json.NewEncoder(sink)

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("hello-tap listening on %s", *listen)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handle(conn, enc)
	}
}

func handle(conn net.Conn, enc *json.Encoder) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))

	br := bufio.NewReader(conn)
	// A TLS handshake starts with the record type 0x16. Peeking keeps the
	// bytes in the buffer: a proxy request is read line by line, and a
	// client that sends a hello and closes would otherwise lose the hello
	// in the line buffer.
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	if first[0] == 0x16 {
		// Not a proxy request: the peer sent a TLS handshake straight to
		// us (a DNAT/REDIRECT on the device side).
		relayTransparent(conn, br, enc)
		return
	}
	target, err := readConnect(br)
	if err != nil {
		// Transparent mode: not a proxy request. The peer sent a TLS
		// handshake straight to us (a DNAT/REDIRECT on the device side).
		// The SNI in the hello tells us where the traffic was going.
		relayTransparent(conn, br, enc)
		return
	}
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})

	upstream, err := net.DialTimeout("tcp", target, 15*time.Second)
	if err != nil {
		_ = enc.Encode(record{Time: time.Now().UTC().Format(time.RFC3339), Host: target, Error: err.Error()})
		return
	}
	defer upstream.Close()

	// The client's first flight is the TLS handshake: read it whole, parse
	// the ClientHello, then relay the bytes we already consumed.
	hello, err := readClientHello(br)
	if err == nil {
		rec := record{
			Time: time.Now().UTC().Format(time.RFC3339),
			Host: target,
		}
		if parsed, perr := mimic.ParseClientHello(hello); perr == nil {
			ja3, md5sum := parsed.JA3()
			rec.SNI = parsed.SNI
			rec.JA3 = ja3
			rec.JA3MD5 = md5sum
			rec.JA4 = parsed.JA4()
			rec.JA4R = parsed.JA4R()
			rec.ALPN = parsed.ALPN
			rec.CipherCount = len(parsed.CipherSuites)
			rec.ExtensionCount = len(parsed.Extensions)
			rec.SessionIDLen = len(parsed.SessionID)
			rec.Groups = parsed.Groups
			rec.SigAlgs = parsed.SigAlgs
		} else {
			rec.Error = perr.Error()
		}
		_ = enc.Encode(rec)
	}

	if len(hello) > 0 {
		if _, err := upstream.Write(hello); err != nil {
			return
		}
	}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, br)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, upstream)
		done <- struct{}{}
	}()
	<-done
}

// relayTransparent handles a directly-forwarded TLS connection: it peeks the
// ClientHello, learns the target host from the SNI, and relays the traffic
// to that host:443.
func relayTransparent(conn net.Conn, br *bufio.Reader, enc *json.Encoder) {
	log.Printf("transparent connection from %s", conn.RemoteAddr())
	hello, err := readClientHello(br)
	if err != nil {
		log.Printf("  no TLS hello from %s: %v", conn.RemoteAddr(), err)
		return
	}
	rec := record{Time: time.Now().UTC().Format(time.RFC3339)}
	parsed, perr := mimic.ParseClientHello(hello)
	if perr != nil {
		rec.Error = perr.Error()
		_ = enc.Encode(rec)
		return
	}
	ja3, md5sum := parsed.JA3()
	rec.SNI = parsed.SNI
	rec.Host = parsed.SNI + ":443"
	rec.JA3 = ja3
	rec.JA3MD5 = md5sum
	rec.JA4 = parsed.JA4()
	rec.JA4R = parsed.JA4R()
	rec.ALPN = parsed.ALPN
	rec.CipherCount = len(parsed.CipherSuites)
	rec.ExtensionCount = len(parsed.Extensions)
	rec.SessionIDLen = len(parsed.SessionID)
	rec.Groups = parsed.Groups
	rec.SigAlgs = parsed.SigAlgs
	_ = enc.Encode(rec)

	if parsed.SNI == "" {
		return
	}
	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(parsed.SNI, "443"), 15*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()
	if _, err := upstream.Write(hello); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, br)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, upstream)
		done <- struct{}{}
	}()
	<-done
}

// readConnect parses a CONNECT request and returns the requested target.
func readConnect(br *bufio.Reader) (string, error) {
	var head []string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return "", err
		}
		head = append(head, line)
		if strings.TrimSpace(line) == "" {
			break
		}
		if len(head) > 64 {
			return "", fmt.Errorf("proxy: request header block too long")
		}
	}
	parts := strings.Fields(strings.TrimSpace(head[0]))
	if len(parts) != 3 || !strings.EqualFold(parts[0], "CONNECT") {
		return "", fmt.Errorf("proxy: not a CONNECT request")
	}
	return parts[1], nil
}

// readClientHello reads the first TLS handshake record from the connection
// and returns its bytes.
func readClientHello(br *bufio.Reader) ([]byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(br, header); err != nil {
		return nil, err
	}
	if header[0] != 0x16 {
		return nil, fmt.Errorf("proxy: not a TLS handshake record")
	}
	length := int(header[3])<<8 | int(header[4])
	if length <= 0 || length > 1<<14 {
		return nil, fmt.Errorf("proxy: implausible handshake length %d", length)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(br, body); err != nil {
		return nil, err
	}
	return append(header, body...), nil
}

var _ = http.StatusOK
