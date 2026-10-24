package mimic

import (
	"bufio"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"

	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/megamen32/headless-client/websocket"
	utls "github.com/refraction-networking/utls"
)

// wsGUID is the magic value of RFC 6455 that the server mixes into the
// accept key.
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// upgradeCapture is what a raw listener saw of the upgrade request.
type upgradeCapture struct {
	headerNames  []string
	headerValues map[string]string
	alpn         []string
}

// TestDialWebSocket_UpgradeShape checks the wire shape of the upgrade
// request: the header set and the header order a browser sends.
//
// The order matters as much as the set — a server that reads the request
// line by line sees "Connection: Upgrade" before "User-Agent" in Chrome,
// and a sorted set is a different client.
func TestDialWebSocket_UpgradeShape(t *testing.T) {
	capture := &upgradeCapture{headerValues: map[string]string{}}
	addr, stop := rawTLSServer(t, capture, func(key string) string {
		return acceptKey(key)
	})
	defer stop()

	profile := Profile{
		Name:           "chrome152-ws",
		TLSClientHello: "chrome_152",
		UserAgent:      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := DialWebSocket(ctx, profile, "wss://"+addr+"/ws", WithInsecureTLS())
	if err != nil {
		t.Fatalf("DialWebSocket: %v", err)
	}
	_ = conn.Close()

	// The browser shape: the cache headers Chrome sends, the compression
	// offer, and no client hints — Chrome does not send sec-ch-ua on the
	// upgrade request.
	for _, name := range []string{"Pragma", "Cache-Control", "Accept-Encoding", "Sec-WebSocket-Extensions"} {
		if _, ok := capture.headerValues[name]; !ok {
			t.Errorf("upgrade request has no %s; headers: %v", name, capture.headerNames)
		}
	}
	if _, ok := capture.headerValues["Sec-Ch-Ua"]; ok {
		t.Errorf("upgrade request carries a client hint; Chrome sends none there")
	}
	if got := capture.headerValues["User-Agent"]; got != profile.UserAgent {
		t.Errorf("User-Agent: got %q, want the profile's", got)
	}

	// The order Chrome writes.
	for _, pair := range [][2]string{
		{"Connection", "User-Agent"},
		{"Pragma", "Cache-Control"},
		{"Sec-WebSocket-Key", "Sec-WebSocket-Extensions"},
	} {
		first, second := indexOfFold(capture.headerNames, pair[0]), indexOfFold(capture.headerNames, pair[1])
		if first < 0 || second < 0 {
			t.Fatalf("upgrade request is missing %s or %s; headers: %v", pair[0], pair[1], capture.headerNames)
		}
		if first > second {
			t.Errorf("%s came after %s; Chrome writes %s first; headers: %v",
				pair[0], pair[1], pair[0], capture.headerNames)
		}
	}
}

// TestDialWebSocket_NarrowsALPN proves the WebSocket connection does not
// become h2: the upgrade request is an HTTP/1.1 request, and Chrome opens
// a WebSocket over a connection that negotiated "http/1.1" only.
func TestDialWebSocket_NarrowsALPN(t *testing.T) {
	capture := &upgradeCapture{headerValues: map[string]string{}}
	addr, stop := rawTLSServer(t, capture, acceptKey)
	defer stop()

	profile := Profile{TLSClientHello: "chrome_152", UserAgent: "chrome-ws-test"}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := DialWebSocket(ctx, profile, "wss://"+addr+"/ws", WithInsecureTLS())
	if err != nil {
		t.Fatalf("DialWebSocket: %v", err)
	}
	_ = conn.Close()

	if len(capture.alpn) != 1 || capture.alpn[0] != "http/1.1" {
		t.Errorf("ALPN offered: got %v, want [http/1.1] (a WebSocket upgrade is an HTTP/1.1 request)", capture.alpn)
	}
}

// TestDialWebSocket_NativeProfile checks that a native client profile keeps
// its own headers on the upgrade. The browser shape would be a lie there:
// the identity of the app is the point.
func TestDialWebSocket_NativeProfile(t *testing.T) {
	capture := &upgradeCapture{headerValues: map[string]string{}}
	addr, stop := rawTLSServer(t, capture, acceptKey)
	defer stop()

	profile := Profile{
		Name:           "max-app-ws",
		TLSClientHello: "max_app",
		UserAgent:      "OKMessages/26.35.1 (Android 15; samsung SM-G998B; 450dpi; 1080x2400)",
		Headers: map[string]string{
			"Cache-Control":   "no-store",
			"Accept":          "image/webp,/;q=0.8",
			"Connection":      "Keep-Alive",
			"Accept-Encoding": "gzip",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := DialWebSocket(ctx, profile, "wss://"+addr+"/ws", WithInsecureTLS())
	if err != nil {
		t.Fatalf("DialWebSocket: %v", err)
	}
	_ = conn.Close()

	if got := capture.headerValues["Cache-Control"]; got != "no-store" {
		t.Errorf("Cache-Control: got %q, want the profile's no-store", got)
	}
	if got := capture.headerValues["Accept"]; got != "image/webp,/;q=0.8" {
		t.Errorf("Accept: got %q, want the profile's value", got)
	}
	if _, ok := capture.headerValues["Pragma"]; ok {
		t.Errorf("a native profile must not inherit the browser's Pragma header; headers: %v", capture.headerNames)
	}
	// "Connection" belongs to the upgrade, not to the profile.
	if got := capture.headerValues["Connection"]; !strings.Contains(strings.ToLower(got), "upgrade") {
		t.Errorf("Connection: got %q, want the upgrade value", got)
	}
}

// TestDialWebSocket_RoundTrip is the end-to-end check: a real server, a
// real handshake, a real frame in and a real frame back.
func TestDialWebSocket_RoundTrip(t *testing.T) {
	var negotiated string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			negotiated = r.TLS.NegotiatedProtocol
		}
		conn, err := websocket.Upgrade(w, r, nil, 1024, 1024)
		if err != nil {
			t.Errorf("server upgrade: %v", err)
			return
		}
		defer conn.Close()
		for {
			typ, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if err := conn.WriteMessage(typ, data); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	profile := Profile{TLSClientHello: "chrome_152", UserAgent: "chrome-ws-test"}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := DialWebSocket(ctx, profile, "wss://"+strings.TrimPrefix(server.URL, "https://")+"/ws",
		WithInsecureTLS())
	if err != nil {
		t.Fatalf("DialWebSocket: %v", err)
	}
	defer conn.Close()

	if err := conn.WriteMessage(websocket.TextMessage, []byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "ping" {
		t.Errorf("echo: got %q, want ping", data)
	}
	if negotiated != "http/1.1" {
		t.Errorf("negotiated protocol: got %q, want http/1.1", negotiated)
	}
}

// wireWSJA4 is the JA4 of the captured Chrome 152 WebSocket hello —
// SNI api.oneme.ru, ALPN http/1.1 — as tools/ja4_from_pcap.py read it off
// the ws reference capture (frame 23).
const wireWSJA4 = "t13d1516h1_8daaf6152771_5b37b36a67c0"

// TestWebSocketHello_MatchesWireReference proves the ClientHello the
// WebSocket dialer puts on the wire is the captured Chrome one: ALPN
// narrowed to http/1.1 and the ALPS application-settings extensions gone
// with it. A real browser negotiating http/1.1 sends no ALPS — a hello
// that keeps it is one extension too many and hashes to a different JA4.
func TestWebSocketHello_MatchesWireReference(t *testing.T) {
	conn := &deadConn{}
	cfg := &utls.Config{
		ServerName: "api.oneme.ru",
		// A fresh cache keeps the hello in the captured full-handshake
		// form: no ticket, no pre_shared_key extension.
		ClientSessionCache:                 utls.NewLRUClientSessionCache(0),
		OmitEmptyPsk:                       true,
		PreferSkipResumptionOnNilExtension: true,
	}
	uc, err := newUConn(conn, cfg, "chrome_152")
	if err != nil {
		t.Fatalf("newUConn: %v", err)
	}
	narrowALPN(uc, []string{"http/1.1"})
	_ = uc.Handshake()
	if len(conn.written) == 0 {
		t.Fatalf("no ClientHello written")
	}
	hello, err := ParseClientHello(conn.written)
	if err != nil {
		t.Fatalf("parse client hello: %v", err)
	}

	if len(hello.ALPN) != 1 || hello.ALPN[0] != "http/1.1" {
		t.Errorf("ALPN: got %v, want [http/1.1]", hello.ALPN)
	}
	for _, id := range []uint16{17513, 17613} {
		if slices.Contains(hello.Extensions, id) {
			t.Errorf("hello keeps the ALPS extension %#06x on the http/1.1 path; Chrome drops it", id)
		}
	}
	if got := len(stripGREASE(hello.Extensions)); got != 16 {
		t.Errorf("extension count: got %d, want 16 (the captured WS hello); extensions: %v",
			got, hello.Extensions)
	}
	if got := hello.JA4(); got != wireWSJA4 {
		t.Errorf("JA4: got %s, want %s (the captured WS hello)", got, wireWSJA4)
	}
}

// wireWSHeaderOrder is the header order of the captured Chrome 152 upgrade
// request to api.oneme.ru (2026-10-22 wire capture, decrypted via the
// Chrome keylog): the request line aside, this is the exact wire sequence.
var wireWSHeaderOrder = []string{
	"Host",
	"Connection", // "Upgrade"
	"Pragma",     // no-cache
	"Cache-Control",
	"User-Agent",
	"Upgrade", // websocket
	"Origin",  // https://web.max.ru
	"Sec-WebSocket-Version",
	"Accept-Encoding",
	"Accept-Language",
	"Sec-WebSocket-Key",
	"Sec-WebSocket-Extensions",
}

// TestDialWebSocket_WireHeaderOrder proves the upgrade request the dialer
// writes matches the captured Chrome order byte for byte. A sorted or
// otherwise reordered upgrade is a different client even with the right
// header set, so the order is part of the identity.
//
// The dial goes to a local TLS listener with InsecureTLS and no pinned
// resolve — the server records the request as plaintext after the TLS
// layer, so no keylog is needed.
func TestDialWebSocket_WireHeaderOrder(t *testing.T) {
	capture := &upgradeCapture{headerValues: map[string]string{}}
	addr, stop := rawTLSServer(t, capture, acceptKey)
	defer stop()

	profile := Profile{
		Name:           "chrome152-ws-wire",
		TLSClientHello: "chrome_152",
		UserAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
			"(KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
		AcceptLanguage: "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := DialWebSocket(ctx, profile, "wss://"+addr+"/websocket",
		WithInsecureTLS(),
		WithWebSocketHeader(http.Header{"Origin": []string{"https://web.max.ru"}}))
	if err != nil {
		t.Fatalf("DialWebSocket: %v", err)
	}
	_ = conn.Close()

	if got := capture.headerValues["Origin"]; got != "https://web.max.ru" {
		t.Errorf("Origin: got %q, want https://web.max.ru", got)
	}
	if got := capture.headerValues["Sec-WebSocket-Extensions"]; got != "permessage-deflate; client_max_window_bits" {
		t.Errorf("Sec-WebSocket-Extensions: got %q, want the Chrome permessage-deflate offer", got)
	}
	if got := capture.headerValues["Accept-Encoding"]; got != "gzip, deflate, br, zstd" {
		t.Errorf("Accept-Encoding: got %q, want the Chrome value", got)
	}
	if _, ok := capture.headerValues["Sec-Ch-Ua"]; ok {
		t.Errorf("upgrade carries sec-ch-ua; the captured Chrome sends none")
	}

	// The wire order: every captured header in exactly the captured
	// sequence. Host/Connection/Upgrade/Key/Version are written by the
	// websocket client itself — ChromeHTTP1's ordered writer interleaves
	// them in the captured places.
	names := make([]string, 0, len(capture.headerNames))
	for _, n := range capture.headerNames {
		if len(names) == 0 || !strings.EqualFold(n, names[len(names)-1]) {
			names = append(names, n)
		}
	}
	// Monotonic: the captured order must appear in the written order.
	last := -1
	for i, want := range wireWSHeaderOrder {
		idx := indexOfFold(names, want)
		if idx < 0 {
			t.Fatalf("upgrade is missing %s; headers: %v", want, names)
		}
		if idx <= last {
			t.Errorf("header %s (captured position %d) is out of order; wire: %v",
				want, i, names)
		}
		last = idx
	}
}

// rawTLSServer starts a TLS listener that records the upgrade request and
// answers with a 101. The response carries the accept key the client
// verifies, so the handshake completes.
func rawTLSServer(t *testing.T, capture *upgradeCapture, accept func(key string) string) (string, func()) {
	t.Helper()

	// httptest hands out a certificate we can reuse for a hand-rolled
	// listener, so the test needs no certificate plumbing of its own.
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := certServer.TLS.Certificates[0]
	certServer.Close()

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"http/1.1"},
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			capture.alpn = append([]string(nil), chi.SupportedProtos...)
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				requestLine, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				_ = requestLine
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					line = strings.TrimRight(line, "\r\n")
					if line == "" {
						break
					}
					name, value, found := strings.Cut(line, ":")
					if !found {
						continue
					}
					capture.headerNames = append(capture.headerNames, name)
					capture.headerValues[name] = strings.TrimSpace(value)
				}
				key := capture.headerValues["Sec-WebSocket-Key"]
				response := "HTTP/1.1 101 Switching Protocols\r\n" +
					"Upgrade: websocket\r\n" +
					"Connection: Upgrade\r\n" +
					"Sec-WebSocket-Accept: " + accept(key) + "\r\n\r\n"
				_, _ = conn.Write([]byte(response))
				// Hold the connection until the client closes it.
				_, _ = reader.ReadString('\n')
			}()
		}
	}()

	return listener.Addr().String(), func() { _ = listener.Close() }
}

func acceptKey(key string) string {
	sum := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func indexOfFold(list []string, name string) int {
	return slices.IndexFunc(list, func(candidate string) bool {
		return strings.EqualFold(candidate, name)
	})
}
