package mimic

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The resumption guard: the library must speak the browser's A/B on the
// wire — a full handshake without pre_shared_key until the server has issued
// a ticket, then a real PSK offer with a binder computed over that ticket —
// and a ticket must never cross from one profile to another.
//
// Every assertion here is made on the bytes the server read off the socket,
// not on the library's internals.

// resumptionHostPrefix starts the SNI the test client presents. The ticket
// store is keyed by the server name, so every test server gets a name of its
// own: that keeps the tests apart from each other and from the tickets of
// the other specs (web.max.ru, api2.oneme.ru) that the fixture guards rely
// on.
const resumptionHostPrefix = "resumption-"

// resumptionSeq numbers the names the tests use, so that every one of them
// starts with an empty ticket store.
var resumptionSeq atomic.Int64

// resumptionRecorder keeps what every connection to the test server put on
// the wire: the ClientHello the server read, and whether the server resumed
// the session (an abbreviated handshake).
type resumptionRecorder struct {
	net.Listener
	host  string
	mu    sync.Mutex
	conns []*recordingConn
}

// Accept wraps the accepted connection so the first TLS record off the
// socket — the ClientHello — can be kept.
func (l *resumptionRecorder) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	rec := &recordingConn{Conn: c, rec: l}
	l.conns = append(l.conns, rec)
	return rec, nil
}

// hellos returns the ClientHello of every connection, in the order the
// server accepted them.
func (l *resumptionRecorder) hellos(t *testing.T) []*ClientHello {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]*ClientHello, 0, len(l.conns))
	for i, c := range l.conns {
		if len(c.hello) == 0 {
			t.Fatalf("connection %d: no ClientHello was read", i)
		}
		hello, err := ParseClientHello(c.hello)
		if err != nil {
			t.Fatalf("connection %d: parse the ClientHello: %v", i, err)
		}
		out = append(out, hello)
	}
	return out
}

// didResume reports whether the server abbreviated the handshake of the
// n-th connection.
//
// The flag is read per connection and not per callback: the HTTP/2 server
// reports the active state twice for a connection that carried one request.
func (l *resumptionRecorder) didResume(t *testing.T, n int) bool {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if n >= len(l.conns) {
		t.Fatalf("the server saw %d connections, want at least %d", len(l.conns), n+1)
	}
	return l.conns[n].resumed
}

// recordingConn keeps the first TLS record it reads, and whether the
// handshake that followed was abbreviated.
type recordingConn struct {
	net.Conn
	rec     *resumptionRecorder
	acc     []byte
	hello   []byte
	done    bool
	resumed bool
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && !c.done {
		c.acc = append(c.acc, p[:n]...)
		if raw, ok := completeTLSRecord(c.acc); ok {
			c.hello = raw
			c.done = true
			c.acc = nil
		}
	}
	return n, err
}

// setResumed records the outcome of the handshake of this connection.
func (c *recordingConn) setResumed(resumed bool) {
	c.rec.mu.Lock()
	defer c.rec.mu.Unlock()
	c.resumed = resumed
}

// completeTLSRecord returns the first complete TLS record in b.
func completeTLSRecord(b []byte) ([]byte, bool) {
	if len(b) < 5 {
		return nil, false
	}
	size := int(b[3])<<8 | int(b[4])
	if len(b) < 5+size {
		return nil, false
	}
	return b[:5+size], true
}

// newResumptionServer starts a TLS server that issues session tickets and
// accepts resumption, and that records the ClientHello of every connection.
//
// The server speaks HTTP/1.1, so a raw request can be written over the
// connection the dialer returns.
func newResumptionServer(t *testing.T) *resumptionRecorder {
	t.Helper()
	return startResumptionServer(t, false)
}

// newResumptionServerHTTP2 starts the same server with HTTP/2, for the tests
// that go through the public client.
func newResumptionServerHTTP2(t *testing.T) *resumptionRecorder {
	t.Helper()
	return startResumptionServer(t, true)
}

func startResumptionServer(t *testing.T, http2 bool) *resumptionRecorder {
	t.Helper()
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	// A server-side ticket cache is what makes the server issue tickets and
	// accept a resumption.
	ts.TLS = &tls.Config{ClientSessionCache: tls.NewLRUClientSessionCache(8)}
	ts.EnableHTTP2 = http2
	rec := &resumptionRecorder{
		Listener: ts.Listener,
		host:     fmt.Sprintf("%s%d.test", resumptionHostPrefix, resumptionSeq.Add(1)),
	}
	ts.Config.ConnState = func(c net.Conn, state http.ConnState) {
		if state != http.StateActive {
			return
		}
		tc, ok := c.(*tls.Conn)
		if !ok {
			return
		}
		conn, ok := tc.NetConn().(*recordingConn)
		if !ok {
			return
		}
		conn.setResumed(tc.ConnectionState().DidResume)
	}
	ts.Listener = rec
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return rec
}

// dialResumption opens one TLS connection with the given profile and runs one
// HTTP request over it.
//
// Reading the response is what makes the client process the NewSessionTicket
// the server sent right after the handshake: without that read the client
// never learns the ticket and never resumes.
func dialResumption(t *testing.T, rec *resumptionRecorder, helloName string) {
	t.Helper()
	addr := rec.Addr().String()
	opts := transportOptions{
		dialTimeout: 10 * time.Second,
		insecureTLS: true, // the test server's certificate is self-signed
		serverName:  rec.host,
	}
	conn, err := dialProfileTLS(t.Context(), opts, Profile{TLSClientHello: helloName}, "tcp", addr, false, nil)
	if err != nil {
		t.Fatalf("dial %s: %v", helloName, err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+rec.host+"\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write the request: %v", err)
	}
	br := bufio.NewReader(conn)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			break
		}
		if line == "\r\n" {
			break
		}
	}
}

// TestResumptionSecondHelloCarriesPSK is the wire-level proof that the
// library resumes like a browser: the first contact with a host is a full
// handshake whose hello carries no pre_shared_key, the second one offers the
// ticket the server issued — last extension, binder computed over that very
// hello — and the server answers with an abbreviated handshake.
func TestResumptionSecondHelloCarriesPSK(t *testing.T) {
	rec := newResumptionServer(t)

	dialResumption(t, rec, "chrome_152")
	dialResumption(t, rec, "chrome_152")

	hellos := rec.hellos(t)
	if len(hellos) != 2 {
		t.Fatalf("the server saw %d connections, want 2", len(hellos))
	}
	if hasExtension(hellos[0], 0x0029) {
		t.Errorf("the first hello must not carry pre_shared_key: %v", hellos[0].Extensions)
	}
	if !hasExtension(hellos[1], 0x0029) {
		t.Fatalf("the second hello must carry pre_shared_key: %v", hellos[1].Extensions)
	}
	if last := hellos[1].Extensions[len(hellos[1].Extensions)-1]; last != 0x0029 {
		t.Errorf("pre_shared_key must be the last extension, got %#06x", last)
	}
	if rec.didResume(t, 0) {
		t.Error("the first connection must have been a full handshake")
	}
	if !rec.didResume(t, 1) {
		t.Error("the server must have resumed the second connection")
	}
}

// TestResumptionFreshHelloMatchesCapture pins the fresh handshake to the
// capture of a real Chrome: the JA4 must not move, the extension set must be
// the captured one, and the hello must carry no pre_shared_key.
//
// The comparison reuses the mechanism of exact_capture_test.go — the same
// fixture and the same parsing — instead of a second, weaker one.
func TestResumptionFreshHelloMatchesCapture(t *testing.T) {
	reference := loadFixture(t, "max_web_clienthello_chrome155.json")

	// The spec path, exactly as the capture guard does it.
	spec, err := chrome152Spec()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := handshakeClientHello(t, spec, "web.max.ru").JA4(), reference.JA4(); got != want {
		t.Errorf("spec hello JA4: got %s, want %s", got, want)
	}

	// The runtime path: a real handshake against a server, with no ticket
	// for that host yet.
	rec := newResumptionServer(t)
	dialResumption(t, rec, "chrome_152")
	hello := rec.hellos(t)[0]

	if got, want := hello.JA4(), reference.JA4(); got != want {
		t.Errorf("fresh hello JA4: got %s, want %s", got, want)
	}
	if hasExtension(hello, 0x0029) {
		t.Errorf("the fresh hello must not carry pre_shared_key: %v", hello.Extensions)
	}
	oursSet := nonGREASEExtensions(hello.Extensions)
	refSet := nonGREASEExtensions(reference.Extensions)
	for id := range refSet {
		if !oursSet[id] {
			t.Errorf("extension %#06x is missing from the fresh hello", id)
		}
	}
	for id := range oursSet {
		if !refSet[id] {
			t.Errorf("extension %#06x is in the fresh hello but not in the capture", id)
		}
	}
}

// TestResumptionTicketDoesNotCrossProfiles is the isolation guard: a ticket
// negotiated under one profile must never be offered under another one.
//
// The server would accept such an offer — the binder is computed over the
// hello that carries it, so it is valid for any shape — which is exactly why
// the library, not the server, has to keep the tickets apart.
func TestResumptionTicketDoesNotCrossProfiles(t *testing.T) {
	for _, pair := range [][2]string{
		{"chrome_152", "chrome_auto"},
		{"chrome_auto", "chrome_152"},
		{"chrome_152", "max_app"},
	} {
		t.Run(pair[0]+"_to_"+pair[1], func(t *testing.T) {
			rec := newResumptionServer(t)
			dialResumption(t, rec, pair[0]) // collects a ticket
			dialResumption(t, rec, pair[1]) // a different identity: no ticket

			hellos := rec.hellos(t)
			if len(hellos) != 2 {
				t.Fatalf("the server saw %d connections, want 2", len(hellos))
			}
			if hasExtension(hellos[1], 0x0029) {
				t.Errorf("%s must not offer the ticket of %s: %v", pair[1], pair[0], hellos[1].Extensions)
			}
			if rec.didResume(t, 1) {
				t.Errorf("the %s connection must not have resumed on a %s ticket", pair[1], pair[0])
			}
		})
	}
}

// TestResumptionSameProfileResumes is the counterpart of the isolation
// guard: two connections of the same profile do share the ticket, so the
// isolation is per profile and not a resumption that was switched off.
//
// It also covers the default profile (chrome_auto), whose uTLS preset ships
// without a pre_shared_key extension and would otherwise never resume.
func TestResumptionSameProfileResumes(t *testing.T) {
	for _, helloName := range []string{"chrome_152", "chrome_auto", "max_app"} {
		t.Run(helloName, func(t *testing.T) {
			rec := newResumptionServer(t)
			dialResumption(t, rec, helloName)
			dialResumption(t, rec, helloName)

			hellos := rec.hellos(t)
			if len(hellos) != 2 {
				t.Fatalf("the server saw %d connections, want 2", len(hellos))
			}
			if hasExtension(hellos[0], 0x0029) {
				t.Errorf("the first hello must not carry pre_shared_key: %v", hellos[0].Extensions)
			}
			if !hasExtension(hellos[1], 0x0029) {
				t.Fatalf("the second hello must carry pre_shared_key: %v", hellos[1].Extensions)
			}
			if last := hellos[1].Extensions[len(hellos[1].Extensions)-1]; last != 0x0029 {
				t.Errorf("pre_shared_key must be the last extension, got %#06x", last)
			}
			if !rec.didResume(t, 1) {
				t.Error("the server must have resumed the second connection")
			}
		})
	}
}

// TestResumptionAcrossClientInstances is the "a browser keeps its tickets"
// guard: the ticket store is shared by every client of a profile, so a
// client built later — a different object, its own connection pool — resumes
// on the ticket the first one collected.
func TestResumptionAcrossClientInstances(t *testing.T) {
	rec := newResumptionServerHTTP2(t)
	url := "https://" + rec.Addr().String() + "/"

	for i := 0; i < 2; i++ {
		client, err := New(Profile{TLSClientHello: "chrome_152"}, WithInsecureTLS(), WithServerName(rec.host))
		if err != nil {
			t.Fatalf("client %d: %v", i, err)
		}
		resp, err := client.Get(url)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	hellos := rec.hellos(t)
	if len(hellos) != 2 {
		t.Fatalf("the server saw %d connections, want 2", len(hellos))
	}
	if hasExtension(hellos[0], 0x0029) {
		t.Errorf("the first hello must not carry pre_shared_key: %v", hellos[0].Extensions)
	}
	if !hasExtension(hellos[1], 0x0029) {
		t.Errorf("the second client must resume on the ticket of the first: %v", hellos[1].Extensions)
	}
	if !rec.didResume(t, 1) {
		t.Error("the server must have resumed the second connection")
	}
}

// TestResumptionHelloFingerprints pins both sides of the A/B: the fresh
// hello must keep the captured fingerprint of the client it imitates, and
// the resuming hello must carry the captured PSK shape.
//
// The chrome_152 and max_app resuming fingerprints are the ones of the real
// captures (the chrome_152_psk variant and the MAX app's own resuming
// hello), so a resumption that drifts from the browser shows up here.
func TestResumptionHelloFingerprints(t *testing.T) {
	for _, tc := range []struct {
		helloName string
		freshJA4  string
		resumeJA4 string
	}{
		{
			helloName: "chrome_152",
			freshJA4:  chrome155CaptureJA4,
			resumeJA4: "t13d1518h2_8daaf6152771_e2d80978ab2e",
		},
		{
			helloName: "chrome_auto",
			freshJA4:  "t13d1516h2_8daaf6152771_d8a2da3f94cd",
			resumeJA4: "t13d1517h2_8daaf6152771_b6f405a00624",
		},
		{
			helloName: "max_app",
			freshJA4:  maxAppJA4,
			resumeJA4: maxAppPSKJA4,
		},
	} {
		t.Run(tc.helloName, func(t *testing.T) {
			rec := newResumptionServer(t)
			dialResumption(t, rec, tc.helloName)
			dialResumption(t, rec, tc.helloName)

			hellos := rec.hellos(t)
			if len(hellos) != 2 {
				t.Fatalf("the server saw %d connections, want 2", len(hellos))
			}
			if got := hellos[0].JA4(); got != tc.freshJA4 {
				t.Errorf("fresh hello JA4: got %s, want %s", got, tc.freshJA4)
			}
			if got := hellos[1].JA4(); got != tc.resumeJA4 {
				t.Errorf("resuming hello JA4: got %s, want %s", got, tc.resumeJA4)
			}
		})
	}
}

// TestResumptionScopeKeepsProfilesApart pins the keying of the shared ticket
// store: one scope per ClientHello identity, shared only by the names that
// resolve to the same preset.
func TestResumptionScopeKeepsProfilesApart(t *testing.T) {
	same := [][2]string{
		{"", "chrome_auto"},
		{"", "android_149"},
		{"chrome_auto", "android_149"},
	}
	for _, pair := range same {
		if resumptionScope(pair[0]) != resumptionScope(pair[1]) {
			t.Errorf("%q and %q resolve to the same preset and must share the ticket store", pair[0], pair[1])
		}
	}
	apart := [][2]string{
		{"chrome_152", "chrome_auto"},
		{"chrome_152", "chrome_152_psk"},
		{"max_app", "max_app_psk"},
		{"node_24", "chrome_152"},
	}
	for _, pair := range apart {
		if resumptionScope(pair[0]) == resumptionScope(pair[1]) {
			t.Errorf("%q and %q are different identities and must not share the ticket store", pair[0], pair[1])
		}
	}
}

// TestResumptionScopeCacheIsolatesEntries checks the keying of the scoped
// store: the entry of one scope must live under a different key than the
// entry of another scope, so the shared store cannot mix them up.
func TestResumptionScopeCacheIsolatesEntries(t *testing.T) {
	// A server name of its own: the store is global and shared with the
	// other tests of this package.
	key := fmt.Sprintf("scope-unit-%d.test", resumptionSeq.Add(1))

	a := &scopedSessionCache{scope: "chrome_152"}
	b := &scopedSessionCache{scope: "chrome_auto"}

	a.Put(key, nil)
	if _, ok := clientSessionCache.Get("chrome_152" + sessionScopeSeparator + key); !ok {
		t.Error("the scoped store must keep the entry under the scoped key")
	}
	if _, ok := clientSessionCache.Get("chrome_auto" + sessionScopeSeparator + key); ok {
		t.Error("the other scope must not have an entry")
	}
	if _, ok := clientSessionCache.Get(key); ok {
		t.Error("the raw server name must not be a key of the shared store")
	}
	if _, ok := b.Get(key); ok {
		t.Error("the other scope must not see the entry either")
	}
}
