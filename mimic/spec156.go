package mimic

import (
	utls "github.com/refraction-networking/utls"
)

// chrome156Ext12E0ID is the identifier of the unregistered extension Chrome
// 156 sends next to 0xCA34 (measured on the wire 2026-10-21, Chrome
// 156.0.8078.47 on macOS).
//
// Chrome 155 did not send it: the hello carried 17 extensions and
// fingerprinted as t13d1517h2_8daaf6152771_cb7bf5808d99, Chrome 156 carries
// 18 and fingerprints as t13d1518h2_8daaf6152771_4980c97edce0. JA4 hashes
// the extension IDs, not the payloads.
const chrome156Ext12E0ID = 0x12E0

// chrome156Ext12E0Payload is the payload Chrome 156 sends in 0x12E0: two
// zero bytes in every capture, in the TCP hello as well as in the QUIC one.
var chrome156Ext12E0Payload = []byte{0x00, 0x00}

// chrome156CA34PayloadHex is the 0xCA34 payload of the Chrome 156 capture
// committed as mimic/testdata/chrome156_clienthello.json (Chrome 156.0.8078.47
// on macOS, 2026-10-21).
//
// Chrome rotates the bytes of this extension per build, so the payload is one
// sample of a scheme, not a constant: the extension carries a list of
// (identifier, value) pairs.
const chrome156CA34PayloadHex = "00b80582df1302010582df1302060582df13020d0582df13020e0582df13020f0582df1302120582df1302130582df13021408839a648c9b2d010708839a648c9b2d010808839a648c9b2d010908839a648c9b2d010a08839a648c9b2d010b08839a648c9b2d010c08839a648c9b2d010d08839a648c9b2d011208839a648c9b2d011304d679090104d679090404d679090504d679090604d679090704d679090804d679090a04d679090b04d679090c04d679090d04d679090f"

// chrome156Spec builds the ClientHello of the current stable Chrome 156.
//
// The shape is the Chrome 152 one — the uTLS Chrome preset, the
// post-quantum signature algorithms, the unregistered 0xCA34 extension — plus
// the 0x12E0 extension Chrome 156 added. The wire reference is
// t13d1518h2_8daaf6152771_4980c97edce0, measured on a real Chrome
// 156.0.8078.47 (macOS, 2026-10-21) and committed as
// mimic/testdata/chrome156_clienthello.json.
//
// The resumption placeholder is the same one chrome_152 uses: utls fills it
// from the session cache when the client holds a ticket for the host and
// conceals it (OmitEmptyPsk) when it does not.
func chrome156Spec() (*utls.ClientHelloSpec, error) {
	spec, err := chromeBaseSpec(chrome156CA34PayloadHex, true, &utls.GenericExtension{
		Id:   chrome156Ext12E0ID,
		Data: chrome156Ext12E0Payload,
	})
	if err != nil {
		return nil, err
	}
	return &spec, nil
}
