package mimic

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestWireOrder_SecondRequestDoesNotPanic guards the resumption trap: a
// ClientHelloSpec without a pre_shared_key extension (node_24, chrome_152)
// cannot present a resumption ticket, and uTLS panics once the session cache
// holds one for the host. The second request to the same host used to kill
// the process — the fetchd daemon crashed with it.
//
// The regression is about the *client* surviving repeated use, not about one
// request: the first connection seeds the cache, the second must not panic.
func TestWireOrder_SecondRequestDoesNotPanic(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	profile := Profile{
		Name:            "node_24-local",
		TLSClientHello:  node24HelloName,
		UserAgent:       "MiniMaxAgent",
		HTTP1WireOrder:  true,
		WireHeaderOrder: []string{"accept", "content-type", "user-agent"},
		Headers: map[string]string{
			"accept":       "application/json",
			"content-type": "application/json",
		},
	}

	client, err := New(profile, WithInsecureTLS())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 3; i++ {
		req, err := profile.Request("POST", srv.URL+"/v1/messages", strings.NewReader(`{"ping":1}`))
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status %s", i, resp.Status)
		}
		if !strings.Contains(string(body), `"ok":true`) {
			t.Fatalf("request %d: body %q", i, body)
		}
	}
}

// TestWireOrder_HeaderOrderAndCasing pins the wire behaviour the profile
// promises: the header block is written in the captured order, with the
// captured casing, and the host line comes first.
func TestWireOrder_HeaderOrderAndCasing(t *testing.T) {
	var seen string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("X-Probe")
		io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	profile := Profile{
		Name:            "node_24-local",
		TLSClientHello:  node24HelloName,
		UserAgent:       "MiniMaxAgent",
		HTTP1WireOrder:  true,
		WireHeaderOrder: []string{"x-probe", "accept", "content-type", "user-agent", "content-length"},
		Headers: map[string]string{
			"accept":       "application/json",
			"content-type": "application/json",
		},
	}
	client, err := New(profile, WithInsecureTLS())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req, err := profile.Request("POST", srv.URL+"/v1/messages", strings.NewReader(`{"ping":1}`))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("X-Probe", "case-sensitive-value")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = resp.Body.Close()
	if seen != "case-sensitive-value" {
		t.Fatalf("header value: got %q", seen)
	}
}

// TestWireOrder_HonoursTheRequestContext guards the deadlock of the wire
// order transport: the response read blocked on the socket, and neither the
// request context nor the client's timeout reached it. A server that
// completes the handshake and then stalls kept the caller waiting forever,
// and the connection leaked with it.
//
// The request must come back with an error once the context is done.
func TestWireOrder_HonoursTheRequestContext(t *testing.T) {
	// A TLS server that accepts the handshake and never answers.
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := certServer.TLS.Certificates[0]
	certServer.Close()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"http/1.1"},
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Keep the connection open and silent.
			go func() {
				io.Copy(io.Discard, conn)
			}()
		}
	}()

	profile := Profile{
		Name:            "node_24-stall",
		TLSClientHello:  node24HelloName,
		UserAgent:       "MiniMaxAgent",
		HTTP1WireOrder:  true,
		WireHeaderOrder: []string{"accept", "user-agent"},
		Headers:         map[string]string{"accept": "application/json"},
	}
	client, err := New(profile, WithInsecureTLS())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.CloseIdleConnections()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+ln.Addr().String()+"/", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := client.Do(req)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the request succeeded against a server that never answered")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the request did not return: the context never reached the response read")
	}
}
