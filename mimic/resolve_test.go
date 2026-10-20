package mimic

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestResolveAppliesToTheExactPath guards a silent no-op: the pinned resolve
// was consulted in exactly one place, the uTLS profile dialer, so the exact
// path — the recommended profile, the one the header-order fidelity lives on
// — dialed by name and ignored the table. A site whose edge host is hidden
// from public DNS could not be reached at all.
//
// The host here does not resolve; the pinned address points it at the local
// server. The SNI stays the hostname.
func TestResolveAppliesToTheExactPath(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split the server address: %v", err)
	}

	profile := Profile{
		Name:           "chrome-exact-resolve",
		TLSClientHello: "chrome_exact",
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/152.0.0.0",
	}
	client, err := New(profile,
		WithInsecureTLS(),
		WithResolve(map[string]string{"nowhere.invalid": "127.0.0.1"}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.CloseIdleConnections()

	url := fmt.Sprintf("https://nowhere.invalid:%s/", port)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("the pinned resolve was ignored: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "ok") {
		t.Errorf("body = %q, want the server's answer", body)
	}
}
