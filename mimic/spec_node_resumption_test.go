package mimic

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// The Node 24 resumption guard.
//
// The resumed hello was measured on 2026-10-20 from a live Node 24.18.0
// (Electron 42.8.0, BoringSSL) client that resumed against a loopback server
// issuing TLS 1.3 tickets. The capture of that hello is
// testdata/node24_clienthello_resumed.json.
//
// What the measurement pinned:
//
//   - pre_shared_key (0x0029) is the LAST extension of the hello, after the
//     padding — RFC 8446 puts it last, and BoringSSL does not reorder it.
//   - the hello stays 512 bytes long: the padding gives way to the PSK. The
//     padding payload shrinks by exactly the size of the pre_shared_key
//     extension, so the total does not move.
//   - everything else is unchanged: the same 12 extensions in the same order,
//     the same ciphers, the same 32-byte session id.
//
// The test server and its helpers come from resumption_test.go.

const (
	// node24ResumedJA4 is the JA4 of the resumed Node 24 hello, as measured.
	node24ResumedJA4 = "t13d1813h1_5d04281c6031_02c8e53ee398"

	// node24FreshPadding is the length of the padding payload the full
	// handshake carries. The hello without the padding and without the PSK is
	// 512 - (4 + 242) = 266 bytes.
	node24FreshPadding = 242
)

// loadFixtureRecord reads the raw ClientHello record of a fixture — the bytes
// as they hit the wire. The parsed form does not keep the record's length, and
// the length is part of the measurement: the hello is padded to 512 bytes.
func loadFixtureRecord(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var envelope struct {
		Target         string `json:"target"`
		ClientHelloB64 string `json:"client_hello_b64"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	record, err := base64.StdEncoding.DecodeString(envelope.ClientHelloB64)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return record
}

// extensionIndex returns the wire position of an extension, or -1.
func extensionIndex(exts []uint16, id uint16) int {
	for i, e := range exts {
		if e == id {
			return i
		}
	}
	return -1
}

// TestNode24ResumedFixture_MatchesMeasurement pins the captured resumed hello
// to the numbers the measurement produced: the extension order, the padding
// that gives way to the pre_shared_key, the 512-byte hello and the JA4.
//
// The fixture is the ground truth — every other assertion in this file is
// compared against it.
func TestNode24ResumedFixture_MatchesMeasurement(t *testing.T) {
	record := loadFixtureRecord(t, "node24_clienthello_resumed.json")
	hello, err := ParseClientHello(record)
	if err != nil {
		t.Fatalf("parse the resumed hello: %v", err)
	}

	// The same 12 extensions as the full handshake, in the same order, plus
	// the pre_shared_key — last.
	wantExts := []uint16{
		0x0000, // server_name
		0x0017, // extended_master_secret
		0xff01, // renegotiation_info
		0x000a, // supported_groups
		0x000b, // ec_point_formats
		0x0023, // session_ticket
		0x0010, // ALPN
		0x000d, // signature_algorithms
		0x0033, // key_share
		0x002d, // psk_key_exchange_modes
		0x002b, // supported_versions
		0x0015, // padding
		0x0029, // pre_shared_key
	}
	if len(hello.Extensions) != len(wantExts) {
		t.Fatalf("extension count: got %d, want %d (%v)", len(hello.Extensions), len(wantExts), hello.Extensions)
	}
	for i, want := range wantExts {
		if hello.Extensions[i] != want {
			t.Errorf("extension[%d]: got %#06x, want %#06x", i, hello.Extensions[i], want)
		}
	}

	// The padding gives way to the pre_shared_key: the hello keeps its 512
	// bytes, so the padding payload is the full handshake's minus the size of
	// the pre_shared_key extension (its 4-byte header plus its payload).
	psk := hello.ExtensionData[0x0029]
	if len(psk) == 0 {
		t.Fatal("the captured hello carries no pre_shared_key payload")
	}
	wantPadding := node24FreshPadding - (4 + len(psk))
	if got := len(hello.ExtensionData[0x0015]); got != wantPadding {
		t.Errorf("padding payload: got %d, want %d (the full handshake's %d minus the %d-byte pre_shared_key extension)",
			got, wantPadding, node24FreshPadding, 4+len(psk))
	}

	// The hello is 512 bytes: a 5-byte record header and a 512-byte handshake
	// message.
	if got, want := len(record), 517; got != want {
		t.Errorf("record length: got %d, want %d", got, want)
	}

	if got := hello.JA4(); got != node24ResumedJA4 {
		t.Errorf("resumed JA4: got %s, want %s", got, node24ResumedJA4)
	}
	if len(hello.ALPN) != 1 || hello.ALPN[0] != "http/1.1" {
		t.Errorf("ALPN: got %v, want [http/1.1]", hello.ALPN)
	}
	if len(hello.SessionID) != 32 {
		t.Errorf("session id: got %d bytes, want 32", len(hello.SessionID))
	}
}

// TestNode24ResumptionSpec_FreshHelloUnchanged proves the placeholder does
// not move the full-handshake form: without a ticket the managed
// pre_shared_key extension is concealed, and the hello on the wire stays the
// captured one, byte for byte in everything a server fingerprints.
func TestNode24ResumptionSpec_FreshHelloUnchanged(t *testing.T) {
	spec, err := node24ResumptionSpec()
	if err != nil {
		t.Fatalf("node24ResumptionSpec: %v", err)
	}
	reference := loadFixture(t, "node24_clienthello_1.json")
	ours := handshakeClientHello(t, spec, "test.auto-gram.ru")

	if hasExtension(ours, 0x0029) {
		t.Errorf("the fresh hello must not carry pre_shared_key: %v", ours.Extensions)
	}
	compareHello(t, "node_24 fresh", ours, reference)

	ja3, _ := ours.JA3()
	if ja3 != node24JA3 {
		t.Errorf("our JA3:\n got %s\nwant %s", ja3, node24JA3)
	}
	if got := ours.JA4(); got != node24JA4 {
		t.Errorf("our JA4: got %s, want %s", got, node24JA4)
	}
}

// TestNode24ResumptionSpec_ResumedHello is the wire-level proof that the
// spec resumes the way the real Node client does: the first contact is a full
// handshake whose hello carries no pre_shared_key, the second one offers the
// ticket — last extension, after the padding — with a binder computed over
// that very hello, and the server answers with an abbreviated handshake.
func TestNode24ResumptionSpec_ResumedHello(t *testing.T) {
	rec := newResumptionServer(t)
	// A cache of its own: the ticket must not leak into another test.
	cache := utls.NewLRUClientSessionCache(4)

	dialNode24Resumption(t, rec, cache) // collects a ticket
	dialNode24Resumption(t, rec, cache) // offers it

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
	// The padding stays in front of it — that is the order BoringSSL uses.
	if i := extensionIndex(hellos[1].Extensions, 0x0015); i != len(hellos[1].Extensions)-2 {
		t.Errorf("padding must be the extension right before pre_shared_key, got index %d of %v", i, hellos[1].Extensions)
	}

	// The padding gives way to the pre_shared_key, so the hello keeps its
	// 512 bytes. The baseline is the padding of the first connection of
	// this same test, not a constant: both connections carry the same
	// server name, so the only difference between them is the
	// pre_shared_key extension, and the padding must give way to exactly
	// that.
	psk := hellos[1].ExtensionData[0x0029]
	freshPadding := len(hellos[0].ExtensionData[0x0015])
	wantPadding := freshPadding - (4 + len(psk))
	if got := len(hellos[1].ExtensionData[0x0015]); got != wantPadding {
		t.Errorf("padding payload: got %d, want %d (the first connection's %d minus the %d-byte pre_shared_key extension)",
			got, wantPadding, freshPadding, 4+len(psk))
	}

	// The hello itself does not move: the record is the same length as
	// the first connection's, so the total is still 512 bytes of message.
	records := rec.rawHellos(t)
	if len(records[0]) != len(records[1]) {
		t.Errorf("record length: the resumed hello is %d bytes, the first one %d — the padding should have given way to the pre_shared_key",
			len(records[1]), len(records[0]))
	}

	// The fingerprint of the resumed hello is the measured one.
	if got := hellos[1].JA4(); got != node24ResumedJA4 {
		t.Errorf("resumed JA4: got %s, want %s", got, node24ResumedJA4)
	}

	if rec.didResume(t, 0) {
		t.Error("the first connection must have been a full handshake")
	}
	if !rec.didResume(t, 1) {
		t.Error("the server must have resumed the second connection")
	}
}

// dialNode24Resumption opens one TLS connection with the node_24 resumption
// spec and runs one HTTP request over it.
//
// The spec is built per connection, exactly as newUConn does: uTLS's managed
// pre_shared_key extension carries the session it was filled with, so a spec
// shared between two connections would offer the first connection's ticket
// with the second connection's binder — a hello the server rejects.
//
// Reading the response is what makes the client process the NewSessionTicket
// the server sent right after the handshake: without that read the client
// never learns the ticket and never resumes.
func dialNode24Resumption(t *testing.T, rec *resumptionRecorder, cache utls.ClientSessionCache) {
	t.Helper()
	spec, err := node24ResumptionSpec()
	if err != nil {
		t.Fatalf("node24ResumptionSpec: %v", err)
	}
	raw, err := net.Dial("tcp", rec.Addr().String())
	if err != nil {
		t.Fatalf("dial %s: %v", rec.Addr(), err)
	}
	cfg := &utls.Config{
		ServerName:         rec.host,
		InsecureSkipVerify: true, // the test server's certificate is self-signed
		ClientSessionCache: cache,
		// Conceal the pre_shared_key extension while there is no ticket: the
		// hello on the wire stays the captured full-handshake form.
		OmitEmptyPsk: true,
		// The same guard the library's own client sets.
		PreferSkipResumptionOnNilExtension: true,
	}
	uc := utls.UClient(raw, cfg, utls.HelloCustom)
	if err := uc.ApplyPreset(spec); err != nil {
		t.Fatalf("apply preset: %v", err)
	}
	if err := uc.HandshakeContext(t.Context()); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer uc.Close()
	if _, err := io.WriteString(uc, "GET / HTTP/1.1\r\nHost: "+rec.host+"\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write the request: %v", err)
	}
	br := bufio.NewReader(uc)
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
