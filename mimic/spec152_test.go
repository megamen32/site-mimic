package mimic

import (
	"fmt"
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// TestChrome152ShufflesExtensionOrder pins the browser behaviour the JA4
// cannot see.
//
// Chrome randomises the extension order on every connection, so a fixed
// order is a tell on its own. The JA4 reads the same either way — it hashes
// the extension list sorted — so only this test can tell the difference.
//
// A few extensions do not move: the GREASE pair, the padding and
// pre_shared_key. In the real Chrome capture
// (mimic/testdata/max_web_clienthello_chrome155.json) the GREASE extension
// is the first one and the second GREASE the last, while 0xCA34 sits in the
// middle — a GREASE floating in the middle of the list is a tell.
//
// The GREASE *value* is randomised per connection too, so the comparison
// normalises it: otherwise every order would look different and the test
// would pass even if nothing moved.
func TestChrome152ShufflesExtensionOrder(t *testing.T) {
	orders := map[string]bool{}
	ca34Positions := map[int]bool{}
	const runs = 40
	for i := 0; i < runs; i++ {
		conn := &deadConn{}
		cfg := &utls.Config{
			ServerName:                         "example.com",
			ClientSessionCache:                 clientSessionCache,
			OmitEmptyPsk:                       true,
			PreferSkipResumptionOnNilExtension: true,
		}
		uc, err := newUConn(conn, cfg, "chrome_152")
		if err != nil {
			t.Fatalf("newUConn: %v", err)
		}
		// The handshake fails right after the hello is written — that is all
		// we need.
		_ = uc.Handshake()
		if len(conn.written) == 0 {
			t.Fatal("no ClientHello written")
		}
		hello, err := ParseClientHello(conn.written)
		if err != nil {
			t.Fatalf("parse our client hello: %v", err)
		}
		if len(hello.Extensions) == 0 {
			t.Fatal("the hello carries no extensions")
		}
		// The GREASE pair keeps its place: the first extension, as in the
		// real capture.
		if !isGREASE(hello.Extensions[0]) {
			t.Errorf("the first extension is 0x%04x, want the GREASE extension", hello.Extensions[0])
		}
		ids := make([]string, 0, len(hello.Extensions))
		for _, id := range hello.Extensions {
			if isGREASE(id) {
				ids = append(ids, "g")
				continue
			}
			ids = append(ids, fmt.Sprintf("%04x", id))
		}
		orders[strings.Join(ids, ",")] = true

		// 0xCA34 must not be pinned to the end: in the real capture it sits
		// in the middle of the list, and a Chrome that always puts an
		// extension last is not a Chrome.
		for pos, id := range hello.Extensions {
			if id == chrome152CA34ExtID {
				ca34Positions[pos] = true
				break
			}
		}
	}
	if len(orders) < 2 {
		t.Errorf("%d distinct extension order(s) in %d connections — Chrome randomises the order per connection", len(orders), runs)
	}
	if len(ca34Positions) < 2 {
		t.Errorf("0xCA34 sat at %d position(s) in %d connections — Chrome shuffles the whole list", len(ca34Positions), runs)
	}
}

// TestChrome152PSKStaysLast checks the one extension that must never move:
// pre_shared_key has to be the last one in the hello (RFC 8446), and uTLS
// refuses a hello where it is not.
//
// The two variants differ in what the wire carries: chrome_152 is the
// full-handshake form and has no pre_shared_key at all (utls conceals the
// placeholder while there is no ticket), while chrome_152_psk carries the
// captured one — and it must be the last extension.
func TestChrome152PSKStaysLast(t *testing.T) {
	helloFor := func(t *testing.T, helloName string) *ClientHello {
		t.Helper()
		conn := &deadConn{}
		cfg := &utls.Config{
			ServerName:                         "example.com",
			ClientSessionCache:                 clientSessionCache,
			OmitEmptyPsk:                       true,
			PreferSkipResumptionOnNilExtension: true,
		}
		uc, err := newUConn(conn, cfg, helloName)
		if err != nil {
			t.Fatalf("%s: newUConn: %v", helloName, err)
		}
		_ = uc.Handshake()
		if len(conn.written) == 0 {
			t.Fatalf("%s: no ClientHello written", helloName)
		}
		hello, err := ParseClientHello(conn.written)
		if err != nil {
			t.Fatalf("%s: parse our client hello: %v", helloName, err)
		}
		return hello
	}

	// The full-handshake form carries no pre_shared_key.
	fresh := helloFor(t, "chrome_152")
	for _, id := range fresh.Extensions {
		if id == 0x0029 {
			t.Errorf("chrome_152 carries pre_shared_key without a ticket")
		}
	}

	// The psk variant carries it, and it is the last extension.
	psk := helloFor(t, "chrome_152_psk")
	last := psk.Extensions[len(psk.Extensions)-1]
	if last != 0x0029 {
		t.Errorf("chrome_152_psk: the last extension is 0x%04x, want pre_shared_key (0x0029)", last)
	}
}

// The chrome_152 spec must carry the two 152-line novelties over the 149
// layout — post-quantum signature algorithms (with a leading GREASE value)
// and the 0xCA34 extension — and, as of 2026-09-02, NO pre_shared_key on
// the dominant full-handshake shape (Google A/Bs the PSK experiment).
func TestChrome152Spec(t *testing.T) {
	spec, err := chrome152Spec()
	if err != nil {
		t.Fatal(err)
	}
	hasCA34, hasPSK := false, false
	for _, ext := range spec.Extensions {
		if e, ok := ext.(*utls.GenericExtension); ok && e.Id == 0xCA34 {
			hasCA34 = true
			if len(e.Data) == 0 {
				t.Fatal("0xCA34 extension must carry the captured payload")
			}
		}
		if e, ok := ext.(*utls.GenericExtension); ok && e.Id == 0x0029 {
			hasPSK = true
		}
	}
	if !hasCA34 {
		t.Fatal("chrome_152 spec must contain 0xCA34")
	}
	if hasPSK {
		t.Fatal("chrome_152 (dominant variant) must not carry pre_shared_key; use chrome_152_psk")
	}
	assertPQSigAlgs(t, spec)
}

// chrome_152_psk keeps the 18-extension variant with pre_shared_key last.
func TestChrome152PSKSpec(t *testing.T) {
	spec, err := chrome152PSKSpec()
	if err != nil {
		t.Fatal(err)
	}
	hasCA34, hasPSK := false, false
	last := spec.Extensions[len(spec.Extensions)-1]
	for _, ext := range spec.Extensions {
		if e, ok := ext.(*utls.GenericExtension); ok && e.Id == 0xCA34 {
			hasCA34 = true
		}
		if e, ok := ext.(*utls.GenericExtension); ok && e.Id == 0x0029 {
			hasPSK = true
		}
	}
	if !hasCA34 || !hasPSK {
		t.Fatalf("chrome_152_psk must contain 0xCA34 and 0x0029 (hasCA34=%v hasPSK=%v)", hasCA34, hasPSK)
	}
	if e, ok := last.(*utls.GenericExtension); !ok || e.Id != 0x0029 {
		t.Fatal("pre_shared_key must stay last (RFC 8446)")
	}
	assertPQSigAlgs(t, spec)
}

func assertPQSigAlgs(t *testing.T, spec *utls.ClientHelloSpec) {
	t.Helper()
	for _, ext := range spec.Extensions {
		if sa, ok := ext.(*utls.SignatureAlgorithmsExtension); ok {
			algs := sa.SupportedSignatureAlgorithms
			if len(algs) < 4 {
				t.Fatalf("signature algorithms too short: %d", len(algs))
			}
			want := []utls.SignatureScheme{0x6a6a, 0x0904, 0x0905, 0x0906}
			for i, w := range want {
				if algs[i] != w {
					t.Fatalf("sig algs[%d] = %#x, want %#x", i, algs[i], w)
				}
			}
			return
		}
	}
	t.Fatal("spec must contain a SignatureAlgorithmsExtension")
}

// chrome_152 and chrome_152_psk must be recognised profile names.
func TestChrome152NameAccepted(t *testing.T) {
	for _, name := range []string{"chrome_152", "chrome_152_psk"} {
		if _, err := ParseClientHelloID(name); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
