package mimic

import (
	utls "github.com/refraction-networking/utls"
)

// The QUIC shape of a profile: the unregistered extensions its QUIC hello
// carries, and the token it puts in the google_connection_options transport
// parameter.
//
// The QUIC stack builds one hello — the Chrome shape of the newest release
// it knows — so a profile that imitates an older or a different browser has
// to take the newer parts away again. Which extensions and which token
// belong together is a measured fact: every row of the table below is a
// capture, not a preference.
//
// The token in particular follows the Chrome release, not the platform: the
// phone's Chrome 152 sent "ORIGECCPIW2X", the phone's Chrome 155 and
// Yandex.Browser send "ORIG", desktop Chrome 156 sends "ORIGNOIP".
type quicShape struct {
	// unregisteredExtensions are the unregistered extensions the profile's
	// QUIC hello carries. The stack offers 0xCA34 and 0x12E0; a profile
	// measured without them keeps an empty list.
	unregisteredExtensions []uint16
	// googleConnOptions is the ASCII token in the google_connection_options
	// transport parameter (0x3128).
	googleConnOptions []byte
}

// The identifiers of the two unregistered extensions Chrome sends next to
// the ECH GREASE pair.
const (
	quicUnregisteredCA34ID uint16 = 0xCA34
	quicUnregistered12E0ID uint16 = 0x12E0
)

// quicShapes maps a profile's TLS identity to the QUIC shape that identity
// was measured with.
//
// The profiles that are not in the table keep the stack's own shape: the
// newest Chrome the stack knows. That is the right answer for chrome_auto
// ("tracks the latest Chrome") and for android_149, whose QUIC shape was
// not measured.
var quicShapes = map[string]quicShape{
	// Chrome 156 (2026-10-21, Chrome 156.0.8078.47 on macOS): both
	// unregistered extensions, token "ORIGNOIP".
	"chrome_156": {
		unregisteredExtensions: []uint16{quicUnregisteredCA34ID, quicUnregistered12E0ID},
		googleConnOptions:      []byte("ORIGNOIP"),
	},
	// Chrome 155 (2026-10-21, the same release on a phone and on macOS):
	// 0xCA34 and no 0x12E0, token "ORIG".
	"chrome_155": {
		unregisteredExtensions: []uint16{quicUnregisteredCA34ID},
		googleConnOptions:      []byte("ORIG"),
	},
	// Chrome 152 (2026-08-30, a phone): no unregistered extension at all —
	// Chrome sent 0xCA34 over TCP but not over QUIC — and the token
	// "ORIGECCPIW2X". The chrome_152 spec carries the Chrome 152/155 TCP
	// hello, and this is the QUIC half of the Chrome 152 pair.
	"chrome_152": {
		unregisteredExtensions: nil,
		googleConnOptions:      []byte("ORIGECCPIW2X"),
	},
	// Yandex.Browser 26.8.7.49 (2026-10-21, a phone): its Chromium fork
	// lags the upstream patch level, so it sends neither extension, token
	// "ORIG".
	"yandex_browser": {
		unregisteredExtensions: nil,
		googleConnOptions:      []byte("ORIG"),
	},
}

// quicShapeFor returns the QUIC shape a profile's TLS identity carries, and
// whether one was measured for it. A profile without a measured shape keeps
// the stack's own hello and the stack's own token.
func quicShapeFor(helloName string) (quicShape, bool) {
	shape, ok := quicShapes[helloName]
	return shape, ok
}

// applyQUICShape rewrites the QUIC ClientHello the stack built into the
// shape the profile was measured with: the unregistered extensions the
// profile does not send are taken away, and the ones it does send are put
// back with the stack's own payload (Chrome sends the same bytes in both
// hellos — measured on Chrome 156, 2026-10-21).
func applyQUICShape(spec *utls.ClientHelloSpec, shape quicShape) {
	if spec == nil {
		return
	}
	// A fresh slice: filtering in place would overwrite the elements the
	// loop is still reading.
	kept := make([]utls.TLSExtension, 0, len(spec.Extensions))
	unregistered := map[uint16]utls.TLSExtension{}
	for _, ext := range spec.Extensions {
		generic, ok := ext.(*utls.GenericExtension)
		if !ok {
			kept = append(kept, ext)
			continue
		}
		switch generic.Id {
		case quicUnregisteredCA34ID, quicUnregistered12E0ID:
			unregistered[generic.Id] = ext
			continue
		}
		kept = append(kept, ext)
	}
	spec.Extensions = kept
	for _, id := range shape.unregisteredExtensions {
		ext, ok := unregistered[id]
		if !ok {
			continue
		}
		spec.Extensions = append(spec.Extensions, ext)
	}
}
