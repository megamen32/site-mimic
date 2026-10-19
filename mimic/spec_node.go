package mimic

import (
	"crypto/rand"
	"fmt"

	utls "github.com/refraction-networking/utls"
)

// node24Spec builds the ClientHello of Node.js 24 / Electron 42 (BoringSSL).
//
// Why this exists: a server that fingerprints clients sees two very different
// shapes behind the same API. A browser (Chrome/Firefox/Safari) and a Node
// process (Electron app, CLI agent, SDK) present different ClientHellos, and
// an edge that whitelists one rejects the other. site-mimic fits the browser
// shapes; this spec fits the Node one, so a Go client can present the exact
// identity of a Node-based client.
//
// Wire reference — Node 24.18.0 (Electron 42.8.0), captured 2026-10-19 on
// macOS arm64 against the site-mimic verification stand:
//
//	JA3  771-4865,4866,4867,49199,49195,49200,49196,49191,52393,52392,49161,
//	     49171,49162,49172,156,157,47,53-0,23,65281,10,11,35,16,13,51,45,43,
//	     21-29,23,24-0
//	JA4  t13d1812h1_5d04281c6031_ef7df7f74e48
//	ALPN http/1.1 only — undici speaks HTTP/1.1; no "h2" in the offer.
//
// Shape notes (all observed, not guessed):
//   - 14 cipher suites, no GREASE anywhere in the hello.
//   - 12 extensions in a fixed order; BoringSSL does not shuffle them.
//   - 32-byte legacy session id (BoringSSL sends one, Go's crypto/tls does not).
//   - padding (0x0015) is BoringSSL's: the hello is padded to 512 bytes
//     total, so the padding length follows from the rest of the hello.
//   - x25519 is the only key share; supported_groups advertises three groups.
//
// The Node stack speaks HTTP/1.1, so a profile using this spec must not be
// sent over the HTTP/2 transport — see clientHelloIsHTTP1Only.
func node24Spec() (*utls.ClientHelloSpec, error) {
	return &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			utls.TLS_AES_128_GCM_SHA256,                        // 0x1301
			utls.TLS_AES_256_GCM_SHA384,                        // 0x1302
			utls.TLS_CHACHA20_POLY1305_SHA256,                  // 0x1303
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,         // 0xc02f
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,       // 0xc02b
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,         // 0xc030
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,       // 0xc02c
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,         // 0xc027
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, // 0xcca9
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,   // 0xcca8
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,          // 0xc009
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,            // 0xc013
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,          // 0xc00a
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,            // 0xc014
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,               // 0x009c
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,               // 0x009d
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,                  // 0x002f
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,                  // 0x0035
		},
		CompressionMethods: []uint8{0},
		GetSessionID: func(ticket []byte) [32]byte {
			var id [32]byte
			if _, err := rand.Read(id[:]); err != nil {
				// A zero session id is still a legal hello; keep the shape.
				return id
			}
			return id
		},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519, utls.CurveP256, utls.CurveP384,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				0x0403, // ecdsa_secp256r1_sha256
				0x0804, // rsa_pss_rsae_sha256
				0x0401, // rsa_pkcs1_sha256
				0x0503, // ecdsa_secp384r1_sha384
				0x0805, // rsa_pss_rsae_sha384
				0x0501, // rsa_pkcs1_sha384
				0x0806, // rsa_pss_rsae_sha512
				0x0601, // rsa_pkcs1_sha512
				0x0201, // rsa_pkcs1_sha1
			}},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519},
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.VersionTLS13, utls.VersionTLS12,
			}},
			&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
		},
	}, nil
}

// node24HelloName is the profile value that selects the Node 24 ClientHello.
const node24HelloName = "node_24"

// clientHelloIsHTTP1Only reports whether the named ClientHello cannot
// negotiate HTTP/2 over ALPN. Such a client never negotiates h2, so the
// transport must speak HTTP/1.1 from the first connection instead of probing
// h2 and falling back — the probe would double the handshakes and put a
// second ClientHello on the wire.
//
// Two shapes qualify: the Node stack offers "http/1.1" only, and the MAX app
// stack offers no ALPN extension at all (Conscrypt/OkHttp never sends one) —
// both end up on HTTP/1.1.
func clientHelloIsHTTP1Only(name string) bool {
	return name == node24HelloName || name == maxAppHelloName || name == maxAppPSKHelloName
}

// node24HelloID is the uTLS ID used for validity checks. The concrete spec
// is resolved in newUConn (HelloCustom), like the chrome_152 profiles.
func node24HelloID() utls.ClientHelloID {
	return utls.HelloCustom
}

var _ = fmt.Sprintf // keep fmt import for future spec errors
