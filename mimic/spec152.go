package mimic

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"

	utls "github.com/refraction-networking/utls"
)

// chrome152CA34Payload is the opaque data current stable Chrome 152 sends in
// its unregistered extension 0xCA34 on Android/Windows (captured from a real
// Android Chrome 152.0.7977.64 on a Samsung S21 Ultra, m.vk.ru navigation,
// 2026-09-01). The Linux desktop build of the same version sends a similar
// payload in extension 0xCA24 instead.
const chrome152CA34PayloadHex = "00b804d679090104d679090704d679090a08839a648c9b2d010804d679090804d679090d0582df1302010582df13020d0582df13021308839a648c9b2d011308839a648c9b2d010704d679090508839a648c9b2d010c08839a648c9b2d01090582df13020604d679090b08839a648c9b2d010b0582df13020f04d679090c04d679090608839a648c9b2d010d0582df13021208839a648c9b2d010a08839a648c9b2d01120582df13020e04d679090f0582df13021404d6790904"

// chrome152PSKPayload is the pre_shared_key extension (0x0029) captured from
// the same hello: a resumption ticket offer. The server treats an unknown
// ticket as a full handshake, exactly like a browser with a stale ticket.
const chrome152PSKPayloadHex = "00260020469f3e3d562016e08e28c5c53829047bf8871baf925754a18663113017c6488c8ced32b900212029f2d98f7dd041ab488aafccff1a40a827afbfd1ef5d9c34987f6447d4225c56"

// chrome152Spec builds a uTLS ClientHelloSpec matching current stable
// Chrome 152 as captured on Android/Windows (wire reference
// t13d1518h2_8daaf6152771_e2d80978ab2e): the HelloChrome_Auto layout plus
// the two 152-line novelties over 149 — post-quantum signature algorithms
// (ML-DSA-44/65/87, preceded by a signature-algorithms GREASE value) and
// the pre_shared_key + 0xCA34 extension pair. pre_shared_key stays last
// (RFC 8446 requirement); the rest is shuffled per connection.
func chrome152Spec() (*utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		return nil, fmt.Errorf("mimic: chrome_152 base spec: %w", err)
	}
	patched := false
	for i, ext := range spec.Extensions {
		if sa, ok := ext.(*utls.SignatureAlgorithmsExtension); ok {
			merged := make([]utls.SignatureScheme, 0, len(sa.SupportedSignatureAlgorithms)+4)
			merged = append(merged,
				utls.SignatureScheme(0x6a6a), // GREASE
				0x0904, 0x0905, 0x0906,       // ML-DSA-44/65/87
			)
			merged = append(merged, sa.SupportedSignatureAlgorithms...)
			sa.SupportedSignatureAlgorithms = merged
			spec.Extensions[i] = sa
			patched = true
			break
		}
	}
	if !patched {
		return nil, fmt.Errorf("mimic: chrome_152 base spec has no signature_algorithms extension")
	}
	ca34, err := hex.DecodeString(chrome152CA34PayloadHex)
	if err != nil {
		return nil, fmt.Errorf("mimic: chrome_152 0xCA34 payload: %w", err)
	}
	psk, err := hex.DecodeString(chrome152PSKPayloadHex)
	if err != nil {
		return nil, fmt.Errorf("mimic: chrome_152 psk payload: %w", err)
	}
	spec.Extensions = append(spec.Extensions,
		&utls.GenericExtension{Id: 0xCA34, Data: ca34},
		&utls.GenericExtension{Id: 0x0029, Data: psk}, // must stay last
	)
	return &spec, nil
}

// shuffleExtensions randomises the extension order per connection, keeping
// pre_shared_key (0x0029) last as RFC 8446 requires. uTLS only shuffles its
// built-in Chrome presets; a HelloCustom preset is written in spec order.
func shuffleExtensions(exts []utls.TLSExtension) []utls.TLSExtension {
	pskIdx := -1
	for i, ext := range exts {
		if e, ok := ext.(*utls.GenericExtension); ok && e.Id == 0x0029 {
			pskIdx = i
			break
		}
	}
	var psk utls.TLSExtension
	if pskIdx >= 0 {
		psk = exts[pskIdx]
		exts = append(exts[:pskIdx], exts[pskIdx+1:]...)
	}
	rand.Shuffle(len(exts), func(i, j int) { exts[i], exts[j] = exts[j], exts[i] })
	if pskIdx >= 0 {
		exts = append(exts, psk)
	}
	return exts
}

// newUConn builds a uTLS connection for the given profile hello name.
// "chrome_152" uses the custom spec; every other name resolves through
// ParseClientHelloID.
func newUConn(rawConn net.Conn, cfg *utls.Config, helloName string) (*utls.UConn, error) {
	if helloName == "chrome_152" {
		uc := utls.UClient(rawConn, cfg, utls.HelloCustom)
		spec, err := chrome152Spec()
		if err != nil {
			return nil, err
		}
		if err := uc.ApplyPreset(spec); err != nil {
			return nil, fmt.Errorf("mimic: chrome_152 apply preset: %w", err)
		}
		uc.Extensions = shuffleExtensions(uc.Extensions)
		return uc, nil
	}
	helloID, err := ParseClientHelloID(helloName)
	if err != nil {
		return nil, err
	}
	return utls.UClient(rawConn, cfg, helloID), nil
}
