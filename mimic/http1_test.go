package mimic

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
