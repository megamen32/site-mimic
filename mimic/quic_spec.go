package mimic

import (
	"encoding/hex"
	"fmt"

	quic "github.com/refraction-networking/uquic"
	utls "github.com/refraction-networking/utls"
)

// The QUIC ClientHello is the Chrome QUIC shape, not the Chrome TCP one.
// Chrome's QUIC hello carries 11 extensions and 3 cipher suites where its TCP
// hello carries 20 and 16 — two different fingerprint classes — and so does
// ours. The base is uquic's Chrome 115 QUIC preset; on top of it go the
// Chrome 152 novelties the TCP path applies too (mimic/spec152.go): the
// post-quantum signature algorithms behind a GREASE value and the
// unregistered 0xCA34 extension. The values are the captured ones — the same
// literals spec152.go puts on the wire — not invented here.
//
// Measured on the wire (2026-10-20, hostname target): JA4
// q13d0311h3_55b375c5d22e_8dd94ab2d40e. The real phone's Chrome QUIC
// fingerprint is q13d0311h3_55b375c5d22e_653d80c3fe9d
// (docs/phone-reference.md): the JA4_a and JA4_b parts are equal, the JA4_c
// part is not — the repo keeps no raw QUIC capture fixture, so the reason is
// not decomposed here and is not claimed.
//
// The SNI rides along when the target is a hostname. Against an IP address
// RFC 6066 forbids an SNI, the extension leaves the hello and the
// fingerprint becomes q13i0310h3_… — a different, equally correct form.
const (
	// chrome152GREASESigAlg is the GREASE value Chrome puts in front of the
	// post-quantum signature algorithms.
	chrome152GREASESigAlg utls.SignatureScheme = 0x6a6a
	// chrome152PQSigAlgMLDSA44/65/87 are the ML-DSA signature schemes
	// Chrome 152 offers (the same codes mimic/spec152.go sends).
	chrome152PQSigAlgMLDSA44 utls.SignatureScheme = 0x0904
	chrome152PQSigAlgMLDSA65 utls.SignatureScheme = 0x0905
	chrome152PQSigAlgMLDSA87 utls.SignatureScheme = 0x0906
)

// chrome152CA34ExtID is the unregistered extension Chrome 152 sends next to
// the ECH GREASE pair (mimic/spec152.go carries its captured payload).
const chrome152CA34ExtID = 0xCA34

// The QUIC transport parameters of a real Android Chrome 152, decoded from the
// raw bytes of extension 0x0039 in a phone capture (full handshake, 2026-08-30)
// and mapped onto uquic's typed transport-parameter classes by
// examples/uquic-probe. The same values keep the hello in the 11-extension
// QUIC form recorded in docs/RESEARCH-STATUS.ru.md.
//
// What is captured: the parameter values below. What is not: the total length
// on the wire — the GREASE parameter's id is randomised per connection, and it
// is the id that decides how many bytes the parameter list takes. So the list
// is as long as the capture's, but not necessarily the same number of bytes.
const (
	// quicChromeMaxUDPPayloadSize is max_udp_payload_size (0x03): the IPv4
	// MTU-sized payload Chrome asks for.
	quicChromeMaxUDPPayloadSize = 1472
	// quicChromeMaxIdleTimeoutMS is max_idle_timeout (0x01), in ms.
	quicChromeMaxIdleTimeoutMS = 30000
	// quicChromeInitialMaxData is initial_max_data (0x04): 15 MiB.
	quicChromeInitialMaxData = 15728640
	// quicChromeStreamWindow is the per-stream window (0x05/0x06/0x07):
	// 6 MiB.
	quicChromeStreamWindow = 6291456
	// quicChromeMaxStreamsBidi is initial_max_streams_bidi (0x08).
	quicChromeMaxStreamsBidi = 100
	// quicChromeMaxStreamsUni is initial_max_streams_uni (0x09).
	quicChromeMaxStreamsUni = 103
	// quicChromeMaxDatagramFrameSize is max_datagram_frame_size (0x20),
	// RFC 9221.
	quicChromeMaxDatagramFrameSize = 65536
	// quicChromeGoogleConnOptionsID is google_connection_options; Chrome
	// sends the ASCII token "ORIGECCPIW2X" in it.
	quicChromeGoogleConnOptionsID = 0x3128
)

// quicChromeGoogleConnOptions is the captured google_connection_options
// value: the ASCII token Chrome puts in that transport parameter.
var quicChromeGoogleConnOptions = []byte("ORIGECCPIW2X")

// quicChromeGREASEValue is the captured value of the GREASE transport
// parameter (random id, fixed 6-byte payload — the browser randomises the id
// per connection, utls does that for us).
var quicChromeGREASEValue = []byte{0x70, 0x63, 0x53, 0x4d, 0xa9, 0x42}

// quicChromeVersionInformation is the captured version_information parameter
// (0x11, RFC 9368): the chosen version 1 plus the GREASE version the phone
// offered.
func quicChromeVersionInformation() *utls.VersionInformation {
	return &utls.VersionInformation{
		ChoosenVersion:    1,
		AvailableVersions: []uint32{1, 0xdada2a0a},
	}
}

// chrome152QUICSpec builds the QUIC/TLS spec of a Chrome 152 h3 client.
//
// uquic has no 152 preset, so the Chrome 115 preset is the base: it carries
// the Initial-packet form (connection-id lengths, the first packet number and
// the random padding frames Chrome puts in its first flight) and the ALPN
// "h3". On top of it go the two 152 TLS novelties and the transport
// parameters captured from a real phone.
func chrome152QUICSpec() (*quic.QUICSpec, error) {
	spec, err := quic.QUICID2Spec(quic.QUICChrome_115)
	if err != nil {
		return nil, fmt.Errorf("mimic: quic chrome spec: %w", err)
	}
	if spec.ClientHelloSpec == nil {
		return nil, fmt.Errorf("mimic: quic chrome spec has no client hello")
	}
	patchChrome152Hello(spec.ClientHelloSpec)
	patchChromeTransportParams(spec.ClientHelloSpec)
	return &spec, nil
}

// patchChrome152Hello adds the Chrome 152 novelties to a QUIC hello: the
// post-quantum signature algorithms in front of the GREASE value and the
// unregistered 0xCA34 extension with the payload spec152.go already ships.
func patchChrome152Hello(spec *utls.ClientHelloSpec) {
	for i, ext := range spec.Extensions {
		sa, ok := ext.(*utls.SignatureAlgorithmsExtension)
		if !ok {
			continue
		}
		merged := []utls.SignatureScheme{
			chrome152GREASESigAlg,
			chrome152PQSigAlgMLDSA44,
			chrome152PQSigAlgMLDSA65,
			chrome152PQSigAlgMLDSA87,
		}
		for _, alg := range sa.SupportedSignatureAlgorithms {
			switch alg {
			case chrome152GREASESigAlg, chrome152PQSigAlgMLDSA44, chrome152PQSigAlgMLDSA65, chrome152PQSigAlgMLDSA87:
				continue // already in front
			}
			merged = append(merged, alg)
		}
		sa.SupportedSignatureAlgorithms = merged
		spec.Extensions[i] = sa
		break
	}
	// The payload is the one the TCP path sends — the hex string is the
	// single source of truth for it (mimic/spec152.go).
	ca34, err := hex.DecodeString(chrome152CA34PayloadHex)
	if err != nil {
		// The constant is a literal in this package; a decode error would
		// mean the source was edited into something invalid.
		panic("mimic: chrome_152 0xCA34 payload: " + err.Error())
	}
	spec.Extensions = append(spec.Extensions, &utls.GenericExtension{Id: chrome152CA34ExtID, Data: ca34})
}

// patchChromeTransportParams replaces the preset's transport parameters with
// the ones a real Chrome 152 sends. uquic writes the list verbatim
// (ClientOverride), so the wire bytes are exactly the captured ones.
//
// The order is shuffled, like the preset's own list: Chrome randomises the
// order of the transport parameters, and a fixed order is a tell. uquic
// shuffles when it builds the spec, not per connection, so the order is
// stable for the lifetime of one client — a known deviation, not a secret.
//
// The source connection id stays empty, and that is what Chrome sends. In
// the captured phone hellos the transport parameter
// initial_source_connection_id (0x0f) is empty in every one of them, and
// the Initial packet carries a zero-length source connection id. uquic's
// Chrome preset sets SrcConnIDLength to 0, so the id it generates is empty
// as well, and the parameter stays equal to the packet — RFC 9000 section
// 7.2 wants the two to match, and a server rejects the connection when they
// differ.
//
// The transport parameters as a whole are byte-identical to the capture:
// 94 bytes, every parameter the same value, the same set, and the same
// GREASE parameter (its id is random per connection on both sides).
//
// The ClientHello is where this path still differs from the real browser.
// The captured hello has the ALPS extension (0x44cd), Chrome's ECH GREASE
// id (0xfe0d) instead of the preset's, no 0xCA34, the nine classic
// signature algorithms instead of thirteen, and four supported groups
// (X25519MLKEM768 first) instead of three. That is the JA4_c difference,
// and it is not claimed away.
func patchChromeTransportParams(spec *utls.ClientHelloSpec) {
	for i, ext := range spec.Extensions {
		qtp, ok := ext.(*utls.QUICTransportParametersExtension)
		if !ok {
			continue
		}
		qtp.TransportParameters = utls.TransportParameters{
			utls.MaxUDPPayloadSize(quicChromeMaxUDPPayloadSize),
			utls.InitialSourceConnectionID{}, // empty, like Chrome's: see the comment above
			utls.InitialMaxStreamsUni(quicChromeMaxStreamsUni),
			utls.InitialMaxStreamDataUni(quicChromeStreamWindow),
			utls.InitialMaxStreamDataBidiLocal(quicChromeStreamWindow),
			utls.MaxIdleTimeout(quicChromeMaxIdleTimeoutMS),
			&utls.GREASETransportParameter{ValueOverride: quicChromeGREASEValue},
			utls.MaxDatagramFrameSize(quicChromeMaxDatagramFrameSize),
			utls.InitialMaxStreamsBidi(quicChromeMaxStreamsBidi),
			utls.InitialMaxStreamDataBidiRemote(quicChromeStreamWindow),
			utls.InitialMaxData(quicChromeInitialMaxData),
			quicChromeVersionInformation(),
			&utls.FakeQUICTransportParameter{Id: quicChromeGoogleConnOptionsID, Val: quicChromeGoogleConnOptions},
		}
		spec.Extensions[i] = quic.ShuffleQUICTransportParameters(qtp)
		return
	}
}
