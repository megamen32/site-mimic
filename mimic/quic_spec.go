package mimic

import (
	"fmt"
	"time"

	headless "github.com/megamen32/headless-client"
	h3quic "github.com/megamen32/headless-client/quic"
	utls "github.com/refraction-networking/utls"
)

// The QUIC fingerprint of this package is the one a real Chrome puts on the
// wire, taken from the headless-client QUIC stack
// (github.com/megamen32/headless-client).
//
// The stack's ClientHello is the Chrome QUIC shape byte for byte: twelve
// extensions (thirteen by name), three cipher suites, the post-quantum key
// share, ALPS, the ECH GREASE pair and the two unregistered extensions
// Chrome sends next to it, 0xCA34 and 0x12E0. Its QUIC transport
// parameters are Chrome's as well, the google_connection_options token
// included: the stack sends "ORIGNOIP", the token Chrome 156 sends.
//
// Measured on the wire (2026-10-21, Google Chrome 156.0.8078.47 on macOS,
// against a local HTTP/3 stand that prints the client's hello, transport
// parameters and control stream): the browser's QUIC JA4 is
// q13i0312h3_55b375c5d22e_eb028bd37c08, and the hello this package sends
// now fingerprints the same.
//
// The transport parameters as a whole are the captured ones: the same
// thirteen parameters, each with the same value — 96 bytes in total, the
// GREASE parameter included. Three of them differ per connection, in Chrome
// too: the GREASE parameter's id and payload, the GREASE version inside
// version_information (Chrome draws it at either end of the available
// versions list), and the order of the parameters themselves (Chrome
// shuffles them).
//
// The source connection id stays empty, and that is what Chrome sends. In the
// captured phone hellos the transport parameter
// initial_source_connection_id (0x0f) is empty in every one of them, and the
// Initial packet carries a zero-length source connection id.
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
	// sends an ASCII token in it.
	quicChromeGoogleConnOptionsID = 0x3128
	// quicChromeVersionInformationID is version_information (0x11), RFC 9368.
	quicChromeVersionInformationID = 0x11
)

// quicChromeGoogleConnOptions is the captured google_connection_options
// value: the ASCII token Chrome puts in that transport parameter.
//
// The token is Chrome's own and changes with the release. Chrome 152 on
// Android sent "ORIGECCPIW2X", Chrome 155 on macOS sent "ORIG", and Chrome
// 156 on macOS sends "ORIGNOIP" (measured 2026-10-21). This is the newest
// one measured.
var quicChromeGoogleConnOptions = []byte("ORIGNOIP")

// quicChromeVersionInformation is the captured version_information parameter
// (0x11, RFC 9368): the chosen version 1 plus the GREASE version the phone
// offered.
//
// The GREASE version is drawn per connection by a real Chrome, and the QUIC
// stack draws one the same way — every byte of it ends in 0x0a, which is
// Chrome's scheme. The captured value is one sample of that scheme, and the
// stack's own value is what goes on the wire.
var quicChromeVersionInformation = []byte{
	0x00, 0x00, 0x00, 0x01, // the chosen version: QUIC v1
	0x00, 0x00, 0x00, 0x01, // the versions the client supports
	0xda, 0xda, 0x2a, 0x0a, // the GREASE version
}

// The HTTP/3 settings of this package are Chrome's, measured on the wire.
//
// The measurement (2026-10-21, Google Chrome 155 on macOS, HTTP/3 against a
// local server that printed the client's control stream) gave this SETTINGS
// frame:
//
//	0x01 QPACK_MAX_TABLE_CAPACITY = 65536
//	0x06 MAX_FIELD_SECTION_SIZE   = 262144
//	0x07 QPACK_BLOCKED_STREAMS    = 100
//	0x33 H3_DATAGRAM              = 1
//
// plus a GREASE setting with a random id and a random value. The control
// stream carried a GREASE frame and a PRIORITY_UPDATE frame
// ("u=0, i") after the settings, both of which the QUIC stack sends when it
// is told to send GREASE frames.
//
// The old h3 path sent an empty SETTINGS frame: no QPACK capacity, no
// datagram support, no GREASE — a client that announces a different HTTP/3
// than every browser does.
const (
	// quicChromeQPACKMaxTableCapacity is SETTINGS_QPACK_MAX_TABLE_CAPACITY
	// (0x01).
	quicChromeQPACKMaxTableCapacity = 65536
	// quicChromeMaxFieldSectionSize is SETTINGS_MAX_FIELD_SECTION_SIZE
	// (0x06).
	quicChromeMaxFieldSectionSize = 262144
	// quicChromeQPACKBlockedStreams is SETTINGS_QPACK_BLOCKED_STREAMS
	// (0x07).
	quicChromeQPACKBlockedStreams = 100
	// quicChromeH3Datagram is SETTINGS_H3_DATAGRAM (0x33), RFC 9297.
	quicChromeH3Datagram = 1
)

// The setting identifiers of RFC 9114 and RFC 9297.
const (
	h3SettingQPACKMaxTableCapacity = 0x01
	h3SettingMaxFieldSectionSize   = 0x06
	h3SettingQPACKBlockedStreams   = 0x07
	h3SettingH3Datagram            = 0x33
)

// chromeH3Settings is the SETTINGS frame this package sends: the measured
// Chrome values, and nothing else.
func chromeH3Settings() map[uint64]uint64 {
	return map[uint64]uint64{
		h3SettingQPACKMaxTableCapacity: quicChromeQPACKMaxTableCapacity,
		h3SettingMaxFieldSectionSize:   quicChromeMaxFieldSectionSize,
		h3SettingQPACKBlockedStreams:   quicChromeQPACKBlockedStreams,
		h3SettingH3Datagram:            quicChromeH3Datagram,
	}
}

// chromeQUICConfig builds the TLS and QUIC configuration of the h3 path.
//
// The QUIC stack's own defaults carry the Chrome QUIC shape: the Chrome
// ClientHello, Chrome's transport parameter order, the empty source
// connection id, the 1250-byte Initial packet, the 6 MiB stream windows and
// the 15 MiB connection window. The values the stack gets wrong are
// replaced here — google_connection_options is the captured token, not the
// stack's "ORIG" — and the parameters the stack would otherwise leave out
// are set to the captured values.
//
// The helloName is the profile's TLS identity: it decides the QUIC shape
// (mimic/quic_shape.go). A profile whose identity was measured — Chrome 155,
// Chrome 156, Yandex.Browser — gets exactly the hello that browser sends;
// the others keep the stack's newest shape.
func chromeQUICConfig(o transportOptions, helloName string) (*utls.Config, *h3quic.Config) {
	tlsConfig, quicConfig := headless.ChromeWindows.QUICConfig(headless.QUICOptions{
		Transport:          headless.QUICHTTP3,
		ServerName:         o.serverName,
		InsecureSkipVerify: o.insecureTLS,
		KeepAlivePeriod:    0,
		MaxIdleTimeout:     quicChromeMaxIdleTimeoutMS * time.Millisecond,
	})

	// The captured google_connection_options replaces the stack's own token.
	// The map is the stack's; it is filled in before the first connection.
	if quicConfig.AdditionalTransportParameters == nil {
		quicConfig.AdditionalTransportParameters = map[uint64][]byte{}
	}
	token := quicChromeGoogleConnOptions
	if shape, ok := quicShapeFor(helloName); ok {
		// The shape the profile was measured with: the unregistered
		// extensions it does send, and the token it sends them with.
		applyQUICShape(quicConfig.CachedClientHelloSpec, shape)
		if len(shape.googleConnOptions) > 0 {
			token = shape.googleConnOptions
		}
	}
	quicConfig.AdditionalTransportParameters[quicChromeGoogleConnOptionsID] = token

	// The parameters the stack derives from its configuration are the
	// captured ones already; they are spelled out here so a change in the
	// stack's defaults cannot silently move them.
	quicConfig.InitialPacketSize = quicChromeInitialPacketSize
	quicConfig.InitialStreamReceiveWindow = quicChromeStreamWindow
	quicConfig.InitialConnectionReceiveWindow = quicChromeInitialMaxData
	quicConfig.MaxIncomingStreams = quicChromeMaxStreamsBidi
	quicConfig.MaxIncomingUniStreams = quicChromeMaxStreamsUni
	quicConfig.EnableDatagrams = true
	quicConfig.MaxDatagramFrameSize = quicChromeMaxDatagramFrameSize

	// The handshake window, like the TCP path's handshake timeout.
	quicConfig.HandshakeIdleTimeout = o.dialTimeout

	// QUIC v1: the version the capture was taken on.
	quicConfig.Versions = []h3quic.Version{h3quic.Version1}

	return tlsConfig, quicConfig
}

// quicChromeInitialPacketSize is the size of the first QUIC packet Chrome
// sends: 1250 bytes, the minimum a QUIC Initial may have after the
// amplification limit.
const quicChromeInitialPacketSize = 1250

// checkHTTP3Profile rejects profiles whose ClientHello has no Chrome-shaped
// QUIC counterpart: the QUIC hello is the Chrome one, so a profile of
// another browser would be mimicked over QUIC by something else entirely.
//
// chrome_exact is refused on purpose: it is a byte-exact Chrome *TCP* TLS
// layer, and over QUIC that layer is not applied — accepting it silently
// would promise bytes the wire never carries.
func checkHTTP3Profile(p Profile) error {
	switch p.TLSClientHello {
	case "", "chrome_auto", "android_149", "chrome_152", "chrome_152_psk", "chrome_155", "chrome_156", "yandex_browser":
		return nil
	}
	return fmt.Errorf("mimic: http3: profile tls_client_hello %q has no Chrome QUIC fingerprint (want chrome_auto, android_149, chrome_152, chrome_152_psk, chrome_155, chrome_156 or yandex_browser; the QUIC wire always carries a measured Chrome QUIC hello)", p.TLSClientHello)
}
