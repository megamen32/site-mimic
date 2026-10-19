package mimic

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// Reference fingerprint of the real MiniMax Code client (Node 24.18.0 /
// Electron 42.8.0, BoringSSL), captured three times on 2026-10-19 through
// the site-mimic verification stand (test.auto-gram.ru).
const (
	node24JA3 = "771-4865,4866,4867,49199,49195,49200,49196,49191,52393,52392,49161,49171,49162,49172,156,157,47,53-0,23,65281,10,11,35,16,13,51,45,43,21-29,23,24-0"
	node24JA4 = "t13d1812h1_5d04281c6031_ef7df7f74e48"
)

// loadFixture reads a captured ClientHello envelope
// ({"target":…, "client_hello_b64":…}) from testdata.
func loadFixture(t *testing.T, name string) *ClientHello {
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
	hello, err := ParseClientHello(record)
	if err != nil {
		t.Fatalf("parse client hello: %v", err)
	}
	return hello
}

// TestNode24Fixture_Fingerprint checks the captured hellos of the real client
// and pins the reference JA3/JA4. Three independent connections are stored:
// the Node/BoringSSL stack does not shuffle extensions per connection, so
// all three must produce the same fingerprint.
func TestNode24Fixture_Fingerprint(t *testing.T) {
	fixtures := []string{
		"node24_clienthello_1.json",
		"node24_clienthello_2.json",
		"node24_clienthello_3.json",
	}
	for _, name := range fixtures {
		hello := loadFixture(t, name)
		ja3, ja3md5 := hello.JA3()
		if ja3 != node24JA3 {
			t.Errorf("%s JA3:\n got %s\nwant %s", name, ja3, node24JA3)
		}
		if len(ja3md5) != 32 {
			t.Errorf("%s JA3 md5: got %q", name, ja3md5)
		}
		if got := hello.JA4(); got != node24JA4 {
			t.Errorf("%s JA4: got %s, want %s", name, got, node24JA4)
		}
		if got := hello.SNI; got != "test.auto-gram.ru" {
			t.Errorf("%s SNI: got %q", name, got)
		}
		if len(hello.ALPN) != 1 || hello.ALPN[0] != "http/1.1" {
			t.Errorf("%s ALPN: got %v, want [http/1.1]", name, hello.ALPN)
		}
		if len(hello.CipherSuites) != 18 {
			t.Errorf("%s cipher count: got %d, want 18", name, len(hello.CipherSuites))
		}
		if len(hello.Extensions) != 12 {
			t.Errorf("%s extension count: got %d, want 12", name, len(hello.Extensions))
		}
		if len(hello.SessionID) != 32 {
			t.Errorf("%s session id: got %d bytes, want 32", name, len(hello.SessionID))
		}
	}
}

// TestNode24Spec_MatchesReference is the 1:1 guard: the ClientHello our
// "node_24" spec produces must fingerprint exactly like the real client's —
// same JA3 string, same JA4, same ciphers, extensions, groups, point
// formats and signature algorithms. Change the spec and this fails.
func TestNode24Spec_MatchesReference(t *testing.T) {
	spec, err := node24Spec()
	if err != nil {
		t.Fatalf("node24Spec: %v", err)
	}
	reference := loadFixture(t, "node24_clienthello_1.json")

	ours := clientHelloFromSpec(spec, "test.auto-gram.ru")

	ja3, _ := ours.JA3()
	if ja3 != node24JA3 {
		t.Errorf("our JA3:\n got %s\nwant %s", ja3, node24JA3)
	}
	if got := ours.JA4(); got != node24JA4 {
		t.Errorf("our JA4: got %s, want %s", got, node24JA4)
	}
	if got := reference.JA4(); got != ours.JA4() {
		t.Errorf("JA4 drift against the captured client: ours %s, reference %s", ours.JA4(), got)
	}

	if len(ours.CipherSuites) != len(reference.CipherSuites) {
		t.Fatalf("cipher count: ours %d, reference %d", len(ours.CipherSuites), len(reference.CipherSuites))
	}
	for i := range ours.CipherSuites {
		if ours.CipherSuites[i] != reference.CipherSuites[i] {
			t.Errorf("cipher[%d]: ours %#06x, reference %#06x", i, ours.CipherSuites[i], reference.CipherSuites[i])
		}
	}
	if len(ours.Extensions) != len(reference.Extensions) {
		t.Fatalf("extension count: ours %d, reference %d", len(ours.Extensions), len(reference.Extensions))
	}
	for i := range ours.Extensions {
		if ours.Extensions[i] != reference.Extensions[i] {
			t.Errorf("extension[%d]: ours %#06x, reference %#06x", i, ours.Extensions[i], reference.Extensions[i])
		}
	}
	if len(ours.SigAlgs) != len(reference.SigAlgs) {
		t.Fatalf("sig alg count: ours %d, reference %d", len(ours.SigAlgs), len(reference.SigAlgs))
	}
	for i := range ours.SigAlgs {
		if ours.SigAlgs[i] != reference.SigAlgs[i] {
			t.Errorf("sig alg[%d]: ours %#06x, reference %#06x", i, ours.SigAlgs[i], reference.SigAlgs[i])
		}
	}
	if len(ours.Groups) != len(reference.Groups) {
		t.Fatalf("group count: ours %d, reference %d", len(ours.Groups), len(reference.Groups))
	}
	for i := range ours.Groups {
		if ours.Groups[i] != reference.Groups[i] {
			t.Errorf("group[%d]: ours %#06x, reference %#06x", i, ours.Groups[i], reference.Groups[i])
		}
	}
	if len(ours.PointFormats) != len(reference.PointFormats) {
		t.Fatalf("point format count: ours %d, reference %d", len(ours.PointFormats), len(reference.PointFormats))
	}
	if len(ours.SupportedVersions) != len(reference.SupportedVersions) {
		t.Fatalf("supported version count: ours %d, reference %d", len(ours.SupportedVersions), len(reference.SupportedVersions))
	}
}

// clientHelloFromSpec renders the fingerprint-relevant parts of a uTLS spec
// as a ClientHello, so the spec can be compared with a captured hello
// without a network handshake.
func clientHelloFromSpec(spec *utls.ClientHelloSpec, sni string) *ClientHello {
	hello := &ClientHello{
		Version:       spec.TLSVersMin, // legacy_version
		SNI:           sni,
		ExtensionData: map[uint16][]byte{},
	}
	hello.CipherSuites = append(hello.CipherSuites, spec.CipherSuites...)
	hello.CompressionMethods = append(hello.CompressionMethods, spec.CompressionMethods...)
	for _, ext := range spec.Extensions {
		id, ok := extensionID(ext)
		if !ok {
			continue
		}
		hello.Extensions = append(hello.Extensions, id)
		switch e := ext.(type) {
		case *utls.SupportedCurvesExtension:
			for _, c := range e.Curves {
				hello.Groups = append(hello.Groups, uint16(c))
			}
		case *utls.SupportedPointsExtension:
			hello.PointFormats = append(hello.PointFormats, e.SupportedPoints...)
		case *utls.SignatureAlgorithmsExtension:
			for _, s := range e.SupportedSignatureAlgorithms {
				hello.SigAlgs = append(hello.SigAlgs, uint16(s))
			}
		case *utls.ALPNExtension:
			hello.ALPN = append(hello.ALPN, e.AlpnProtocols...)
		case *utls.SupportedVersionsExtension:
			for _, v := range e.Versions {
				hello.SupportedVersions = append(hello.SupportedVersions, v)
			}
		}
	}
	return hello
}
