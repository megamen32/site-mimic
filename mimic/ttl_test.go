package mimic

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Control presence proves the TTL hook is wired; the on-the-wire TTL value
// itself is verified externally (tcpdump, see docs/phone-reference.md).
func TestApplyTTLInstallsControl(t *testing.T) {
	if d := applyTTL(&net.Dialer{}, 0); d.Control != nil {
		t.Fatal("ttl 0 must keep the kernel default (no Control hook)")
	}
	if d := applyTTL(&net.Dialer{}, 128); d.Control == nil {
		t.Fatal("ttl 128 must install the Control hook")
	}
}

func TestEffectiveTTLPrecedence(t *testing.T) {
	o := transportOptions{ttl: 128}
	if got := effectiveTTL(o, Profile{IPTTL: 255}); got != 128 {
		t.Fatalf("option must win over profile: got %d", got)
	}
	if got := effectiveTTL(transportOptions{}, Profile{IPTTL: 128}); got != 128 {
		t.Fatalf("profile field must apply: got %d", got)
	}
	if got := effectiveTTL(transportOptions{}, Profile{}); got != 0 {
		t.Fatalf("no override must yield 0: got %d", got)
	}
}

// The hook must not break dialing: a real request through a TTL-stamped
// dialer still round-trips.
func TestWithTTLDialsAndReceives(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client, err := New(Profile{}, WithTTL(128), WithInsecureTLS())
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}
