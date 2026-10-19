package mimic

import (
	"testing"

	utls "github.com/refraction-networking/utls"
)

// TestNode24Spec_Shape locks the Node 24 (Electron 42 / BoringSSL)
// ClientHello shape. Every value here was captured from a live Node 24.18.0
// process on 2026-10-19; together they determine the JA3/JA4 the server
// sees:
//
//	JA3 771-4865,4866,4867,49199,49195,49200,49196,49191,52393,52392,49161,
//	    49171,49162,49172,156,157,47,53-0,23,65281,10,11,35,16,13,51,45,43,
//	    21-29,23,24-0
//	JA4 t13d1812h1_5d04281c6031_ef7df7f74e48
func TestNode24Spec_Shape(t *testing.T) {
	spec, err := node24Spec()
	if err != nil {
		t.Fatalf("node24Spec: %v", err)
	}

	wantCiphers := []uint16{
		0x1301, 0x1302, 0x1303,
		0xc02f, 0xc02b, 0xc030, 0xc02c, 0xc027,
		0xcca9, 0xcca8,
		0xc009, 0xc013, 0xc00a, 0xc014,
		0x009c, 0x009d, 0x002f, 0x0035,
	}
	if len(spec.CipherSuites) != len(wantCiphers) {
		t.Fatalf("cipher count: got %d, want %d", len(spec.CipherSuites), len(wantCiphers))
	}
	for i, want := range wantCiphers {
		if spec.CipherSuites[i] != want {
			t.Errorf("cipher[%d]: got %#06x, want %#06x", i, spec.CipherSuites[i], want)
		}
	}

	// Extension order is part of the fingerprint: JA3 hashes it, JA4 hashes
	// it too. BoringSSL does not shuffle.
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
	}
	if len(spec.Extensions) != len(wantExts) {
		t.Fatalf("extension count: got %d, want %d", len(spec.Extensions), len(wantExts))
	}
	for i, want := range wantExts {
		got, ok := extensionID(spec.Extensions[i])
		if !ok {
			t.Fatalf("extension[%d]: unsupported type %T", i, spec.Extensions[i])
		}
		if got != want {
			t.Errorf("extension[%d]: got %#06x, want %#06x", i, got, want)
		}
	}

	// ALPN: the Node stack offers http/1.1 only.
	alpn, ok := spec.Extensions[6].(*utls.ALPNExtension)
	if !ok {
		t.Fatalf("extension[6] is %T, want ALPNExtension", spec.Extensions[6])
	}
	if len(alpn.AlpnProtocols) != 1 || alpn.AlpnProtocols[0] != "http/1.1" {
		t.Errorf("ALPN: got %v, want [http/1.1]", alpn.AlpnProtocols)
	}

	// Signature algorithms: nine schemes, in the captured order.
	sigAlgs, ok := spec.Extensions[7].(*utls.SignatureAlgorithmsExtension)
	if !ok {
		t.Fatalf("extension[7] is %T, want SignatureAlgorithmsExtension", spec.Extensions[7])
	}
	wantSigs := []utls.SignatureScheme{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201}
	if len(sigAlgs.SupportedSignatureAlgorithms) != len(wantSigs) {
		t.Fatalf("sig alg count: got %d, want %d", len(sigAlgs.SupportedSignatureAlgorithms), len(wantSigs))
	}
	for i, want := range wantSigs {
		if sigAlgs.SupportedSignatureAlgorithms[i] != want {
			t.Errorf("sig alg[%d]: got %#06x, want %#06x", i, sigAlgs.SupportedSignatureAlgorithms[i], want)
		}
	}

	// Key share: x25519 only.
	ks, ok := spec.Extensions[8].(*utls.KeyShareExtension)
	if !ok {
		t.Fatalf("extension[8] is %T, want KeyShareExtension", spec.Extensions[8])
	}
	if len(ks.KeyShares) != 1 || ks.KeyShares[0].Group != utls.X25519 {
		t.Errorf("key share: got %+v, want one x25519 entry", ks.KeyShares)
	}

	// Supported versions: TLS 1.3 and 1.2.
	vers, ok := spec.Extensions[10].(*utls.SupportedVersionsExtension)
	if !ok {
		t.Fatalf("extension[10] is %T, want SupportedVersionsExtension", spec.Extensions[10])
	}
	if len(vers.Versions) != 2 || vers.Versions[0] != utls.VersionTLS13 || vers.Versions[1] != utls.VersionTLS12 {
		t.Errorf("supported versions: got %v, want [0x0304 0x0303]", vers.Versions)
	}

	// The Node client speaks HTTP/1.1 only — the transport must not probe h2.
	if !clientHelloIsHTTP1Only(node24HelloName) {
		t.Errorf("%s must be recognised as HTTP/1.1-only", node24HelloName)
	}
	if clientHelloIsHTTP1Only("chrome_auto") {
		t.Errorf("chrome_auto must not be treated as HTTP/1.1-only")
	}
}

// TestNode24Spec_RealHandshake_MatchesReference is the wire-level guard: a
// real uTLS handshake with the node_24 spec must produce a ClientHello that
// fingerprints exactly like the captured Node client — same JA3, same JA4,
// same ciphers in the same order, same extension order and payloads.
//
// The struct-level assertions above cannot catch a wrong uTLS constant (two
// cipher constants swapped in the literal still "look right"), so this test
// runs the handshake and parses the bytes that hit the wire.
func TestNode24Spec_RealHandshake_MatchesReference(t *testing.T) {
	spec, err := node24Spec()
	if err != nil {
		t.Fatalf("node24Spec: %v", err)
	}
	reference := loadFixture(t, "node24_clienthello_1.json")
	ours := handshakeClientHello(t, spec, "test.auto-gram.ru")

	compareHello(t, "node_24", ours, reference)

	ja3, _ := ours.JA3()
	if ja3 != node24JA3 {
		t.Errorf("our JA3:\n got %s\nwant %s", ja3, node24JA3)
	}
	if got := ours.JA4(); got != node24JA4 {
		t.Errorf("our JA4: got %s, want %s", got, node24JA4)
	}
	if len(ours.ALPN) != 1 || ours.ALPN[0] != "http/1.1" {
		t.Errorf("our ALPN: got %v, want [http/1.1]", ours.ALPN)
	}
}

// extensionID returns the wire id of a uTLS extension.
func extensionID(ext utls.TLSExtension) (uint16, bool) {
	switch ext.(type) {
	case *utls.SNIExtension:
		return 0x0000, true
	case *utls.ExtendedMasterSecretExtension:
		return 0x0017, true
	case *utls.RenegotiationInfoExtension:
		return 0xff01, true
	case *utls.SupportedCurvesExtension:
		return 0x000a, true
	case *utls.SupportedPointsExtension:
		return 0x000b, true
	case *utls.SessionTicketExtension:
		return 0x0023, true
	case *utls.ALPNExtension:
		return 0x0010, true
	case *utls.SignatureAlgorithmsExtension:
		return 0x000d, true
	case *utls.KeyShareExtension:
		return 0x0033, true
	case *utls.PSKKeyExchangeModesExtension:
		return 0x002d, true
	case *utls.SupportedVersionsExtension:
		return 0x002b, true
	case *utls.UtlsPaddingExtension:
		return 0x0015, true
	default:
		return 0, false
	}
}
