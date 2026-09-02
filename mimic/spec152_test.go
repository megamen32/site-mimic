package mimic

import (
	"testing"

	utls "github.com/refraction-networking/utls"
)

// The chrome_152 spec must carry the two 152-line novelties over the 149
// layout: post-quantum signature algorithms (with a leading GREASE value)
// and the pre_shared_key + 0xCA34 extension pair (Android/Windows 152 set).
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
	if !hasCA34 || !hasPSK {
		t.Fatalf("chrome_152 spec must contain 0xCA34 and 0x0029 (hasCA34=%v hasPSK=%v)", hasCA34, hasPSK)
	}
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
	t.Fatal("chrome_152 spec must contain a SignatureAlgorithmsExtension")
}

// chrome_152 must be a recognised profile name.
func TestChrome152NameAccepted(t *testing.T) {
	if _, err := ParseClientHelloID("chrome_152"); err != nil {
		t.Fatal(err)
	}
}
