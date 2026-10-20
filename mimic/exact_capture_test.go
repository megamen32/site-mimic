package mimic

import (
	"context"
	"net"
	"net/http"
	"testing"

	headless "github.com/megamen32/headless-client"
)

// The byte-exact path must speak the same fingerprint as the capture we took
// ourselves, and the Chrome 152 spec must match that capture as closely as a
// live handshake allows.
//
// "As closely as a live handshake allows" is the important part: a
// ClientHello cannot be byte-identical to a capture. The 32 random bytes are
// fresh, the key share must be fresh (a replayed public key would leave the
// client unable to decrypt the server's Finished, so the handshake would
// fail), the ALPS payload and the 0xCA34 payload are randomised by Chrome
// per build, and the GREASE values are random by design. The extension
// order is shuffled per connection too.
//
// What has to match is everything a server can fingerprint: the JA4, the
// extension set, and the deterministic extension payloads. Everything else
// is Chrome's own randomness, reproduced as randomness.

// chrome155CaptureJA4 is the fingerprint of the Chrome 155 capture we took
// ourselves (mimic/testdata/max_web_clienthello_chrome155.json).
const chrome155CaptureJA4 = "t13d1517h2_8daaf6152771_cb7bf5808d99"

// TestExactPathMatchesOurOwnCapture pins the byte-exact path to the same
// fingerprint as our own capture.
//
// Without this guard a bump of the headless-client fork changes the
// ClientHello silently: the profile still loads, the requests still work,
// and the only sign is a server that starts treating us as a different
// browser. The fork's 0xCA34 patch is what keeps the extension count at 19
// (17 non-GREASE), so this test also guards that patch.
func TestExactPathMatchesOurOwnCapture(t *testing.T) {
	ours := exactPathClientHello(t)
	if got := ours.JA4(); got != chrome155CaptureJA4 {
		t.Errorf("chrome_exact JA4: got %s, want %s (the capture of our own Chrome)", got, chrome155CaptureJA4)
	}
	if len(ours.Extensions) != 19 {
		t.Errorf("chrome_exact extension count: got %d, want 19 (17 non-GREASE plus the 0xCA34 pair)", len(ours.Extensions))
	}
	if !hasExtension(ours, 0xca34) {
		t.Errorf("chrome_exact has no 0xCA34; the fork patch that adds it is the one that matches the capture")
	}
}

// TestChrome152SpecMatchesOurOwnCapture checks the reconstructed spec
// against the same capture: same fingerprint, same extension set, and the
// same bytes in every extension Chrome does not randomise.
func TestChrome152SpecMatchesOurOwnCapture(t *testing.T) {
	spec, err := chrome152Spec()
	if err != nil {
		t.Fatal(err)
	}
	ours := handshakeClientHello(t, spec, "web.max.ru")
	reference := loadFixture(t, "max_web_clienthello_chrome155.json")

	if got, want := ours.JA4(), reference.JA4(); got != want {
		t.Errorf("JA4: ours %s, capture %s", got, want)
	}

	// The extension set, without the GREASE values, which are random.
	oursSet := nonGREASEExtensions(ours.Extensions)
	refSet := nonGREASEExtensions(reference.Extensions)
	if len(oursSet) != len(refSet) {
		t.Fatalf("extension count: ours %d, capture %d", len(oursSet), len(refSet))
	}
	for id := range refSet {
		if !oursSet[id] {
			t.Errorf("extension %#06x is missing from the spec", id)
		}
	}
	for id := range oursSet {
		if !refSet[id] {
			t.Errorf("extension %#06x is in the spec but not in the capture", id)
		}
	}

	// The deterministic payloads. The excluded ones are the ones Chrome
	// randomises per connection, and the reason is written next to each.
	for id := range refSet {
		switch id {
		case 0x000a: // supported_groups: carries a GREASE value
			continue
		case 0x000d: // signature_algorithms: carries a GREASE value
			continue
		case 0x002b: // supported_versions: carries a GREASE value
			continue
		case 0x0033: // key_share: a fresh key every connection
			continue
		case 0xfe0d: // ALPS settings: randomised by Chrome
			continue
		case 0xca34: // unregistered extension: randomised per build
			continue
		}
		got, want := ours.ExtensionData[id], reference.ExtensionData[id]
		if string(got) != string(want) {
			t.Errorf("extension %#06x payload: ours %x, capture %x", id, got, want)
		}
	}
}

// exactPathClientHello runs the byte-exact transport against a socket that
// records what is written, and returns the ClientHello it produced.
func exactPathClientHello(t *testing.T) *ClientHello {
	t.Helper()

	captured := &deadConn{}
	tlsRT := headless.ChromeWindows.Transport(headless.TLSOptions{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return captured, nil
		},
	})
	req, err := http.NewRequest("GET", "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	// The handshake fails right after the hello is written; the bytes are
	// what the server would have seen.
	_, _ = tlsRT.RoundTrip(req)

	if len(captured.written) == 0 {
		t.Fatal("no ClientHello written")
	}
	hello, err := ParseClientHello(captured.written)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return hello
}

func hasExtension(hello *ClientHello, id uint16) bool {
	for _, ext := range hello.Extensions {
		if ext == id {
			return true
		}
	}
	return false
}

// nonGREASEExtensions returns the extension ids of a hello without the
// GREASE placeholders, whose values are random per connection.
func nonGREASEExtensions(ids []uint16) map[uint16]bool {
	out := map[uint16]bool{}
	for _, id := range ids {
		if isGREASE(id) {
			continue
		}
		out[id] = true
	}
	return out
}
