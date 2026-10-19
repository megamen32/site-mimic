package mimic

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Reference fingerprints of the MAX messenger app (ru.oneme.app 26.35.1,
// Conscrypt/OkHttp on Android 15), captured 2026-10-19 from the app's own
// connection to api2.oneme.ru.
const (
	maxAppJA3 = "771-4865,4866,4867,49195,49196,52393,49199,49200,52392,49161,49162," +
		"49171,49172,156,157,47,53-0,23,65281,10,11,35,5,13,51,45,43-29,23,24-0"
	maxAppJA3MD5 = "fb1972c15d60b7be0427edfbd00affde"
	maxAppJA4    = "t13d171100_5b57614c22b0_40271e0a5736"

	// The resumption variant: the same hello plus pre_shared_key (0x0029).
	maxAppPSKJA3 = "771-4865,4866,4867,49195,49196,52393,49199,49200,52392,49161,49162," +
		"49171,49172,156,157,47,53-0,23,65281,10,11,35,5,13,51,45,43,41-29,23,24-0"
	maxAppPSKJA4 = "t13d171200_5b57614c22b0_352634941f3a"
)

// TestMaxAppFixture_Fingerprint pins the captured hellos of the real app.
func TestMaxAppFixture_Fingerprint(t *testing.T) {
	full := loadFixture(t, "max_app_clienthello_full.json")
	psk := loadFixture(t, "max_app_clienthello_psk.json")

	ja3, ja3md5 := full.JA3()
	if ja3 != maxAppJA3 {
		t.Errorf("full JA3:\n got %s\nwant %s", ja3, maxAppJA3)
	}
	if ja3md5 != maxAppJA3MD5 {
		t.Errorf("full JA3 md5: got %s, want %s", ja3md5, maxAppJA3MD5)
	}
	if got := full.JA4(); got != maxAppJA4 {
		t.Errorf("full JA4: got %s, want %s", got, maxAppJA4)
	}

	ja3psk, _ := psk.JA3()
	if ja3psk != maxAppPSKJA3 {
		t.Errorf("psk JA3:\n got %s\nwant %s", ja3psk, maxAppPSKJA3)
	}
	if got := psk.JA4(); got != maxAppPSKJA4 {
		t.Errorf("psk JA4: got %s, want %s", got, maxAppPSKJA4)
	}

	for name, hello := range map[string]*ClientHello{"full": full, "psk": psk} {
		if hello.SNI != "api2.oneme.ru" {
			t.Errorf("%s SNI: got %q, want api2.oneme.ru", name, hello.SNI)
		}
		// The app sends no ALPN at all — the extension is absent, not empty.
		if len(hello.ALPN) != 0 {
			t.Errorf("%s ALPN: got %v, want none", name, hello.ALPN)
		}
		if len(hello.CipherSuites) != 17 {
			t.Errorf("%s cipher count: got %d, want 17", name, len(hello.CipherSuites))
		}
		if len(hello.SessionID) != 32 {
			t.Errorf("%s session id: got %d bytes, want 32", name, len(hello.SessionID))
		}
		if len(hello.SigAlgs) != 9 {
			t.Errorf("%s sig alg count: got %d, want 9", name, len(hello.SigAlgs))
		}
		if len(hello.Groups) != 3 {
			t.Errorf("%s group count: got %d, want 3", name, len(hello.Groups))
		}
	}
	if got := len(full.Extensions); got != 11 {
		t.Errorf("full extension count: got %d, want 11", got)
	}
	if got := len(psk.Extensions); got != 12 {
		t.Errorf("psk extension count: got %d, want 12", got)
	}
}

// TestMaxAppSpec_MatchesReference is the 1:1 guard: the ClientHello our
// "max_app" spec puts on the wire must fingerprint exactly like the real
// app's — same JA3, same JA4, same ciphers, extension order, groups, point
// formats, signature algorithms and session id length. The reference is a
// real capture; ours is produced by a real uTLS handshake, so a spec that
// only "looks right" in a struct literal still fails here.
func TestMaxAppSpec_MatchesReference(t *testing.T) {
	spec, err := maxAppSpec()
	if err != nil {
		t.Fatalf("maxAppSpec: %v", err)
	}
	reference := loadFixture(t, "max_app_clienthello_full.json")
	ours := handshakeClientHello(t, spec, "api2.oneme.ru")

	compareHello(t, "max_app", ours, reference)

	ja3, ja3md5 := ours.JA3()
	if ja3 != maxAppJA3 {
		t.Errorf("our JA3:\n got %s\nwant %s", ja3, maxAppJA3)
	}
	if ja3md5 != maxAppJA3MD5 {
		t.Errorf("our JA3 md5: got %s, want %s", ja3md5, maxAppJA3MD5)
	}
	if got := ours.JA4(); got != maxAppJA4 {
		t.Errorf("our JA4: got %s, want %s", got, maxAppJA4)
	}
	if len(ours.ALPN) != 0 {
		t.Errorf("our ALPN: got %v, want none (the app sends no ALPN extension)", ours.ALPN)
	}
}

// TestMaxAppPSKSpec_MatchesReference is the same guard for the resumption
// variant: the pre_shared_key extension must be present, must be last, and
// must carry the captured payload byte for byte.
func TestMaxAppPSKSpec_MatchesReference(t *testing.T) {
	spec, err := maxAppPSKSpec()
	if err != nil {
		t.Fatalf("maxAppPSKSpec: %v", err)
	}
	reference := loadFixture(t, "max_app_clienthello_psk.json")
	ours := handshakeClientHello(t, spec, "api2.oneme.ru")

	compareHello(t, "max_app_psk", ours, reference)

	ja3, _ := ours.JA3()
	if ja3 != maxAppPSKJA3 {
		t.Errorf("our JA3:\n got %s\nwant %s", ja3, maxAppPSKJA3)
	}
	if got := ours.JA4(); got != maxAppPSKJA4 {
		t.Errorf("our JA4: got %s, want %s", got, maxAppPSKJA4)
	}
	if len(ours.Extensions) == 0 || ours.Extensions[len(ours.Extensions)-1] != 0x0029 {
		t.Errorf("pre_shared_key must be the last extension, got %v", ours.Extensions)
	}
	want := reference.ExtensionData[0x0029]
	got := ours.ExtensionData[0x0029]
	if !bytes.Equal(got, want) {
		t.Errorf("psk payload: got %d bytes, want the captured %d bytes (identical: %v)",
			len(got), len(want), bytes.Equal(got, want))
	}
}

// TestMaxWebFixture_Chrome155 pins the web.max.ru capture: the mobile
// Chrome 155 that renders the web version produces exactly the JA4 the
// repo's "chrome_152" profile is built for, so the web profile needs no new
// TLS spec — only the captured headers.
func TestMaxWebFixture_Chrome155(t *testing.T) {
	hello := loadFixture(t, "max_web_clienthello_chrome155.json")
	ja3, _ := hello.JA3()
	if got := hello.JA4(); got != "t13d1517h2_8daaf6152771_cb7bf5808d99" {
		t.Errorf("web.max.ru JA4: got %s, want t13d1517h2_8daaf6152771_cb7bf5808d99", got)
	}
	if len(hello.ALPN) != 2 || hello.ALPN[0] != "h2" || hello.ALPN[1] != "http/1.1" {
		t.Errorf("web.max.ru ALPN: got %v, want [h2 http/1.1]", hello.ALPN)
	}
	if hello.SNI != "web.max.ru" {
		t.Errorf("web.max.ru SNI: got %q", hello.SNI)
	}
	// Chrome shuffles its extension order per connection: 19 extensions in
	// this sample, 17 of them non-GREASE.
	if len(hello.Extensions) != 19 {
		t.Errorf("web.max.ru extension count: got %d, want 19", len(hello.Extensions))
	}
	t.Logf("web.max.ru Chrome 155 JA3: %s", ja3)
}

// compareHello asserts that two hellos agree on everything a server can
// fingerprint: ciphers, extension order, groups, point formats, signature
// algorithms, supported versions and the legacy session id length.
func compareHello(t *testing.T, name string, ours, reference *ClientHello) {
	t.Helper()
	if len(ours.CipherSuites) != len(reference.CipherSuites) {
		t.Fatalf("%s cipher count: ours %d, reference %d", name, len(ours.CipherSuites), len(reference.CipherSuites))
	}
	for i := range ours.CipherSuites {
		if ours.CipherSuites[i] != reference.CipherSuites[i] {
			t.Errorf("%s cipher[%d]: ours %#06x, reference %#06x", name, i, ours.CipherSuites[i], reference.CipherSuites[i])
		}
	}
	if len(ours.Extensions) != len(reference.Extensions) {
		t.Fatalf("%s extension count: ours %d, reference %d", name, len(ours.Extensions), len(reference.Extensions))
	}
	for i := range ours.Extensions {
		if ours.Extensions[i] != reference.Extensions[i] {
			t.Errorf("%s extension[%d]: ours %#06x, reference %#06x", name, i, ours.Extensions[i], reference.Extensions[i])
		}
	}
	if len(ours.SigAlgs) != len(reference.SigAlgs) {
		t.Fatalf("%s sig alg count: ours %d, reference %d", name, len(ours.SigAlgs), len(reference.SigAlgs))
	}
	for i := range ours.SigAlgs {
		if ours.SigAlgs[i] != reference.SigAlgs[i] {
			t.Errorf("%s sig alg[%d]: ours %#06x, reference %#06x", name, i, ours.SigAlgs[i], reference.SigAlgs[i])
		}
	}
	if len(ours.Groups) != len(reference.Groups) {
		t.Fatalf("%s group count: ours %d, reference %d", name, len(ours.Groups), len(reference.Groups))
	}
	for i := range ours.Groups {
		if ours.Groups[i] != reference.Groups[i] {
			t.Errorf("%s group[%d]: ours %#06x, reference %#06x", name, i, ours.Groups[i], reference.Groups[i])
		}
	}
	if len(ours.PointFormats) != len(reference.PointFormats) {
		t.Fatalf("%s point format count: ours %d, reference %d", name, len(ours.PointFormats), len(reference.PointFormats))
	}
	for i := range ours.PointFormats {
		if ours.PointFormats[i] != reference.PointFormats[i] {
			t.Errorf("%s point format[%d]: ours %d, reference %d", name, i, ours.PointFormats[i], reference.PointFormats[i])
		}
	}
	if len(ours.SupportedVersions) != len(reference.SupportedVersions) {
		t.Fatalf("%s supported version count: ours %d, reference %d", name, len(ours.SupportedVersions), len(reference.SupportedVersions))
	}
	for i := range ours.SupportedVersions {
		if ours.SupportedVersions[i] != reference.SupportedVersions[i] {
			t.Errorf("%s supported version[%d]: ours %#06x, reference %#06x", name, i, ours.SupportedVersions[i], reference.SupportedVersions[i])
		}
	}
	if len(ours.SessionID) != len(reference.SessionID) {
		t.Errorf("%s session id: ours %d bytes, reference %d bytes", name, len(ours.SessionID), len(reference.SessionID))
	}
	if ours.Version != reference.Version {
		t.Errorf("%s legacy version: ours %#06x, reference %#06x", name, ours.Version, reference.Version)
	}
	// Deterministic extension payloads must match byte for byte. The random
	// ones are excluded: the session id, the key share and the PSK binder.
	for _, id := range []uint16{0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0005, 0x000d, 0x002d, 0x002b} {
		got, want := ours.ExtensionData[id], reference.ExtensionData[id]
		if !bytes.Equal(got, want) {
			t.Errorf("%s extension %#06x payload: got %x, want %x", name, id, got, want)
		}
	}
}

// handshakeClientHello runs a real uTLS handshake against a dead socket and
// returns the ClientHello the spec put on the wire — the same bytes a server
// would fingerprint.
func handshakeClientHello(t *testing.T, spec *utls.ClientHelloSpec, sni string) *ClientHello {
	t.Helper()
	conn := &deadConn{}
	cfg := &utls.Config{
		ServerName:                         sni,
		ClientSessionCache:                 clientSessionCache,
		OmitEmptyPsk:                       true,
		PreferSkipResumptionOnNilExtension: true,
	}
	uc := utls.UClient(conn, cfg, utls.HelloCustom)
	if err := uc.ApplyPreset(spec); err != nil {
		t.Fatalf("apply preset: %v", err)
	}
	// The handshake fails right after the hello is written — that is all we
	// need.
	_ = uc.Handshake()
	if len(conn.written) == 0 {
		t.Fatalf("no ClientHello written")
	}
	hello, err := ParseClientHello(conn.written)
	if err != nil {
		t.Fatalf("parse our client hello: %v", err)
	}
	return hello
}

// deadConn accepts writes and fails every read: enough for uTLS to emit its
// ClientHello and stop.
type deadConn struct {
	written []byte
}

func (c *deadConn) Write(p []byte) (int, error) {
	c.written = append(c.written, p...)
	return len(p), nil
}

func (c *deadConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *deadConn) Close() error                     { return nil }
func (c *deadConn) LocalAddr() net.Addr              { return deadAddr{} }
func (c *deadConn) RemoteAddr() net.Addr             { return deadAddr{} }
func (c *deadConn) SetDeadline(time.Time) error      { return nil }
func (c *deadConn) SetReadDeadline(time.Time) error  { return nil }
func (c *deadConn) SetWriteDeadline(time.Time) error { return nil }

type deadAddr struct{}

func (deadAddr) Network() string { return "dead" }
func (deadAddr) String() string  { return "dead" }
