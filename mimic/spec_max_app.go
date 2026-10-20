package mimic

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	utls "github.com/refraction-networking/utls"
)

// maxAppPSKPayloadHex is the pre_shared_key extension (0x0029) exactly as the
// MAX app sent it on 2026-10-19 (267 bytes: one 208-byte resumption identity
// + obfuscated age + one SHA-256 binder). It is a stale ticket from a
// finished session: the server treats it as an unknown ticket and answers
// with a full handshake, exactly like a browser offering yesterday's ticket.
//
// The value is kept verbatim so the wire bytes match the capture byte for
// byte — the payload is not part of any fingerprint (JA3/JA4 hash extension
// ids, not payloads).
const maxAppPSKPayloadHex = "00d600d0a2c812bea6d88883a169d1d0dba074f0a57f7a5b6f838855b5518c2005e81fec95bb94ee262c58eb123920d1" +
	"f7a9ee82bfd7b0e619d63cfb2351a28a950f844bc9b3636ec95034cde137ae98f8a8068274103e7061a9df2e420badd4" +
	"434da528d31b4503fa0ee94c6a523c579cb0167d554d472c46af56834f9609d7b67b614515d5a1700ec8c1338cb26b49" +
	"9d756b36a4d5d5935fcca15e50fff87e8fe6e86d94cc28c0c2fcfd27177f6fa48fd2813f290e4c88baf38509537cc2dd" +
	"3d8cc8e599c20a87c38701ab70f3bf04e81e7d3bf9742dd6003130bde39265b30aadb81bc521d8714ede7ccc761d2905" +
	"c72c94b887f3891ac8dcd5f5b2e4df39921601d16371a9339df016"

// maxAppSpec builds the ClientHello of the MAX messenger app (ru.oneme.app,
// build 26.35.1) as it talks to the ru.oneme.ru API.
//
// Why this exists: the MAX app does not use a browser TLS stack. Its API
// connections come from the Android system TLS provider (Conscrypt) through
// OkHttp, and that stack has a shape no browser produces:
//
//   - NO ALPN extension at all. The app negotiates no application protocol
//     over TLS, so the connection stays on whatever the server speaks by
//     default. A browser always offers "h2"; a Node client offers
//     "http/1.1"; the MAX app offers nothing.
//   - 17 cipher suites, TLS 1.3 first, then ECDHE, then the plain RSA
//     suites, and CBC-SHA1 ECDHE suites (0xc009/0xc00a/0xc013/0xc014).
//     Conscrypt keeps the legacy RSA list; Chrome dropped it.
//   - 11 extensions in a fixed order, including status_request (0x0005),
//     which no browser sends.
//   - a 32-byte legacy session id (Conscrypt sends one; Go does not).
//   - signature algorithms in Conscrypt order: ECDSA P-256, then RSA-PSS
//     RSAE, then RSA PKCS#1, then SHA-384/SHA-512 variants, and rsa_pkcs1_sha1
//     last. The rsa_pss_pss_* family (Chrome's post-quantum-capable set) is
//     absent.
//
// Wire reference — MAX 26.35.1 on an Android 15 phone, captured
// 2026-10-19 from the app's own connection to api2.oneme.ru:
//
//	JA3  771-4865,4866,4867,49195,49196,52393,49199,49200,52392,49161,49162,
//	     49171,49172,156,157,47,53-0,23,65281,10,11,35,5,13,51,45,43-29,23,24-0
//	JA3 md5 fb1972c15d60b7be0427edfbd00affde
//	JA4  t13d171100_5b57614c22b0_40271e0a5736
//	ALPN (none) — the extension is absent, not empty.
//
// The same stack reaches the CDN host i.oneme.ru with a slightly different
// extension list (no session_ticket) and HTTP/1.1 request headers:
//
//	Cache-Control: no-store
//	Accept: image/webp,/;q=0.8
//	User-Agent: OKMessages/26.35.1 (Android 15; samsung SM-G998B; 450dpi; ...)
//	Connection: Keep-Alive
//	Accept-Encoding: gzip
//
// The app resumes aggressively: 113 of 116 captured connections to
// api2.oneme.ru carried a pre_shared_key extension (0x0029, last), the
// remaining 3 were fresh full handshakes. max_app is the fresh shape,
// max_app_psk the dominant resumption shape.
func maxAppSpec() (*utls.ClientHelloSpec, error) {
	return &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			utls.TLS_AES_128_GCM_SHA256,                        // 0x1301
			utls.TLS_AES_256_GCM_SHA384,                        // 0x1302
			utls.TLS_CHACHA20_POLY1305_SHA256,                  // 0x1303
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,       // 0xc02b
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,       // 0xc02c
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, // 0xcca9
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,         // 0xc02f
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,         // 0xc030
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,   // 0xcca8
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,          // 0xc009
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,          // 0xc00a
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,            // 0xc013
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
			&utls.SNIExtension{},                  // 0x0000
			&utls.ExtendedMasterSecretExtension{}, // 0x0017
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient}, // 0xff01
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{ // 0x000a
				utls.X25519, utls.CurveP256, utls.CurveP384,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0}}, // 0x000b
			&utls.SessionTicketExtension{},                             // 0x0023
			&utls.StatusRequestExtension{},                             // 0x0005
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{ // 0x000d
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
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{ // 0x0033
				{Group: utls.X25519},
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}}, // 0x002d
			&utls.SupportedVersionsExtension{Versions: []uint16{ // 0x002b
				utls.VersionTLS13, utls.VersionTLS12,
			}},
		},
	}, nil
}

// maxAppPSKSpec is the resumption variant of the MAX app hello: the same
// shape plus a pre_shared_key extension (0x0029) sent last, exactly like the
// app does on reconnect. The ticket payload is a captured one, so the server
// treats it as an unknown ticket and answers with a full handshake.
func maxAppPSKSpec() (*utls.ClientHelloSpec, error) {
	spec, err := maxAppSpec()
	if err != nil {
		return nil, err
	}
	psk, err := hex.DecodeString(maxAppPSKPayloadHex)
	if err != nil {
		return nil, fmt.Errorf("mimic: max_app psk payload: %w", err)
	}
	// Must stay last AND must be the only PSK-class extension: utls asserts
	// the pre_shared_key extension is the final extension of the hello.
	spec.Extensions = append(spec.Extensions, &utls.GenericExtension{Id: 0x0029, Data: psk})
	return spec, nil
}

// maxAppHelloName is the profile value that selects the MAX app ClientHello.
const maxAppHelloName = "max_app"

// maxAppPSKHelloName selects the resumption variant.
const maxAppPSKHelloName = "max_app_psk"

// maxAppHelloID is the uTLS ID used for validity checks. The concrete spec
// is resolved in newUConn (HelloCustom), like the node_24 and chrome_152
// profiles.
func maxAppHelloID() utls.ClientHelloID {
	return utls.HelloCustom
}

var _ = fmt.Sprintf // keep fmt import for future spec errors
