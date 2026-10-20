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
