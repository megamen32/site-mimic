package mimic

import (
	"testing"

	utls "github.com/refraction-networking/utls"
)

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
