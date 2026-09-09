package mimic

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"

	utls "github.com/refraction-networking/utls"
)

// chrome152CA34PayloadHex is the opaque data Chrome 152 sends in its
// unregistered extension 0xCA34 next to the ECH GREASE pair (recaptured from
// a real headed Windows Chrome 152.0.7977.64 via the verification stand,
// 2026-09-02; superseded the 2026-09-01 Android capture). JA4 hashes
// extension IDs, not payloads.
const chrome152CA34PayloadHex = "00b808839a648c9b2d01080582df1302130582df13020608839a648c9b2d010908839a648c9b2d010704d679090b04d67909050582df1302120582df13020f08839a648c9b2d010c0582df13021404d679090708839a648c9b2d010a08839a648c9b2d010b0582df13020e0582df13020104d679090104d679090408839a648c9b2d010d04d679090808839a648c9b2d011204d679090f04d67909060582df13020d04d679090a04d679090d04d679090c08839a648c9b2d0113"

// chrome152PSKPayload is the pre_shared_key extension (0x0029) captured from
// the same hello: a resumption ticket offer. The server treats an unknown
// ticket as a full handshake, exactly like a browser with a stale ticket.
const chrome152PSKPayloadHex = "00260020469f3e3d562016e08e28c5c53829047bf8871baf925754a18663113017c6488c8ced32b900212029f2d98f7dd041ab488aafccff1a40a827afbfd1ef5d9c34987f6447d4225c56"

// chrome152Spec builds a uTLS ClientHelloSpec matching current stable
// Chrome 152 (wire reference t13d1517h2_8daaf6152771_cb7bf5808d99,
// re-verified on the live stand 2026-09-02): the HelloChrome_Auto layout
// plus post-quantum signature algorithms (ML-DSA-44/65/87 behind a GREASE
// value) and the 0xCA34 extension. Chrome A/Bs the pre_shared_key part of
// yesterday's experiment on and off per connection; the dominant public
// shape today carries no PSK on a fresh full handshake — chrome_152_psk
// keeps the 18-extension variant for when it returns.
func chrome152Spec() (*utls.ClientHelloSpec, error) {
	spec, err := chrome152BaseSpec(true)
	if err != nil {
		return nil, err
	}
	return &spec, nil
}

// chrome152PSKSpec is the 18-extension variant with pre_shared_key last
// (t13d1518h2_8daaf6152771_e2d80978ab2e) observed 2026-09-01 and still
// served to some connections on 2026-09-02.
func chrome152PSKSpec() (*utls.ClientHelloSpec, error) {
	spec, err := chrome152BaseSpec(false)
	if err != nil {
		return nil, err
	}
	psk, err := hex.DecodeString(chrome152PSKPayloadHex)
	if err != nil {
		return nil, fmt.Errorf("mimic: chrome_152 psk payload: %w", err)
	}
	// Must stay last AND must be the only PSK-class extension: utls asserts
	// PreSharedKeyExtension is the final extension of the hello.
	spec.Extensions = append(spec.Extensions, &utls.GenericExtension{Id: 0x0029, Data: psk})
	return &spec, nil
}

// chrome152BaseSpec builds the common 17-extension layout; withFakePSK adds
// the utls-managed resumption placeholder (used by the fresh-handshake
// variant, where real sessions make utls fill it).
func chrome152BaseSpec(withFakePSK bool) (utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		return spec, fmt.Errorf("mimic: chrome_152 base spec: %w", err)
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
		return spec, fmt.Errorf("mimic: chrome_152 base spec has no signature_algorithms extension")
	}
	ca34, err := hex.DecodeString(chrome152CA34PayloadHex)
	if err != nil {
		return spec, fmt.Errorf("mimic: chrome_152 0xCA34 payload: %w", err)
	}
	spec.Extensions = append(spec.Extensions, &utls.GenericExtension{Id: 0xCA34, Data: ca34})
	if withFakePSK {
		// Resumption placeholder: utls fills it from the session cache when
		// one exists; OmitEmptyPsk conceals it on full handshakes. Must be
		// the only PSK-class extension and stay last (utls asserts both).
		spec.Extensions = append(spec.Extensions, &utls.UtlsPreSharedKeyExtension{})
	}
	return spec, nil
}

// shuffleExtensions randomises the extension order per connection, keeping
// pre_shared_key (0x0029) last as RFC 8446 requires. uTLS only shuffles its
// built-in Chrome presets; a HelloCustom preset is written in spec order.
func shuffleExtensions(exts []utls.TLSExtension) []utls.TLSExtension {
	pskIdx := -1
	for i, ext := range exts {
		if _, ok := ext.(utls.PreSharedKeyExtension); ok {
			pskIdx = i // FakePreSharedKeyExtension or an explicit PSK: stays last
			break
		}
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
	if helloName == "chrome_152" || helloName == "chrome_152_psk" {
		uc := utls.UClient(rawConn, cfg, utls.HelloCustom)
		var spec *utls.ClientHelloSpec
		var err error
		if helloName == "chrome_152" {
			spec, err = chrome152Spec()
		} else {
			spec, err = chrome152PSKSpec()
		}
		if err != nil {
			return nil, err
		}
		if err := uc.ApplyPreset(spec); err != nil {
			return nil, fmt.Errorf("mimic: %s apply preset: %w", helloName, err)
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
