package mimic

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"

	utls "github.com/refraction-networking/utls"
)

// chrome152CA34ExtID is the identifier of the unregistered extension Chrome
// 152 sends next to the ECH GREASE pair. The QUIC hello does not carry it:
// Chrome's QUIC hello and Chrome's TCP hello are two different shapes, and
// only the TCP one has 0xCA34 (see mimic/quic_spec.go).
const chrome152CA34ExtID = 0xCA34

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
// value) and the 0xCA34 extension.
//
// The pre_shared_key part is not hard-coded here: the spec carries uTLS's
// managed placeholder, which is filled from the session cache when the
// client holds a ticket for the host and concealed (OmitEmptyPsk) when it
// does not. That is the browser's A/B: the dominant public shape today
// carries no PSK on a fresh full handshake, and a resuming hello carries
// 0x0029 last with a binder computed over that hello.
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
//
// The payload is the captured one, so it is a ticket the server does not
// know: the server answers with a full handshake, exactly like a browser
// offering yesterday's ticket. For a real resumption use chrome_152 — its
// binder is computed from the ticket the server actually issued.
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

// chrome152BaseSpec builds the common 17-extension layout; withResumption
// adds the utls-managed resumption placeholder (used by the fresh-handshake
// variant, where real sessions make utls fill it).
func chrome152BaseSpec(withResumption bool) (utls.ClientHelloSpec, error) {
	return chromeBaseSpec(chrome152CA34PayloadHex, withResumption)
}

// chromeBaseSpec builds the layout the chrome_152 and chrome_156 specs
// share: the uTLS Chrome preset, the post-quantum signature algorithms and
// the unregistered 0xCA34 extension with the given payload. The extra
// extensions are added before the resumption placeholder, which has to stay
// last.
func chromeBaseSpec(ca34PayloadHex string, withResumption bool, extra ...utls.TLSExtension) (utls.ClientHelloSpec, error) {
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
	ca34, err := hex.DecodeString(ca34PayloadHex)
	if err != nil {
		return spec, fmt.Errorf("mimic: chrome 0xCA34 payload: %w", err)
	}
	spec.Extensions = append(spec.Extensions, &utls.GenericExtension{Id: 0xCA34, Data: ca34})
	spec.Extensions = append(spec.Extensions, extra...)
	if withResumption {
		// Resumption placeholder: utls fills it from the session cache when
		// one exists; OmitEmptyPsk conceals it on full handshakes. Must be
		// the only PSK-class extension and stay last (utls asserts both).
		withResumptionPSK(&spec)
	}
	return spec, nil
}

// shuffleExtensions randomises the extension order per connection, the way
// Chrome does — but not every extension moves. Chrome keeps a few of them
// positionally invariant: the GREASE pair, the padding and pre_shared_key.
// uTLS applies the same rule to its own Chrome presets
// (utls.ShuffleChromeTLSExtensions); a HelloCustom preset is written in spec
// order, so the rule has to be applied here.
//
// The rule comes from the wire, not from taste: in the real Chrome capture
// (mimic/testdata/max_web_clienthello_chrome155.json) the GREASE extension
// is the first one and the second GREASE the last, while 0xCA34 sits in the
// middle — a GREASE floating in the middle of the list is a tell.
//
// uTLS only shuffles its built-in Chrome presets, so this function exists.
func shuffleExtensions(exts []utls.TLSExtension) []utls.TLSExtension {
	// The pre_shared_key extension has to stay last (RFC 8446 and uTLS's
	// own assertion), so it is pulled out before the shuffle and put back
	// at the end.
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

	// Everything that must not move keeps its slot; the rest is permuted
	// among the remaining slots.
	movable := make([]utls.TLSExtension, 0, len(exts))
	slots := make([]int, 0, len(exts))
	for i, ext := range exts {
		if positionallyInvariant(ext) {
			continue
		}
		movable = append(movable, ext)
		slots = append(slots, i)
	}
	rand.Shuffle(len(movable), func(i, j int) { movable[i], movable[j] = movable[j], movable[i] })
	for k, slot := range slots {
		exts[slot] = movable[k]
	}

	if pskIdx >= 0 {
		exts = append(exts, psk)
	}
	return exts
}

// positionallyInvariant reports whether an extension must keep its place in
// the hello, the way Chrome keeps it: the GREASE pair, the padding and
// pre_shared_key.
func positionallyInvariant(ext utls.TLSExtension) bool {
	switch ext.(type) {
	case *utls.UtlsGREASEExtension, *utls.UtlsPaddingExtension:
		return true
	}
	return false
}

// newUConn builds a uTLS connection for the given profile hello name.
// "chrome_152" uses the custom spec; every other name resolves through
// ParseClientHelloID.
func newUConn(rawConn net.Conn, cfg *utls.Config, helloName string) (*utls.UConn, error) {
	if helloName == node24HelloName {
		// The resumption form, not the plain one: it carries uTLS's
		// managed pre_shared_key placeholder, which is concealed while
		// there is no ticket (the hello then stays the captured
		// full-handshake form) and carries a proper PSK offer from the
		// second connection on. The spec is built per connection, so the
		// binder is computed over the hello it is sent with.
		spec, err := node24ResumptionSpec()
		if err != nil {
			return nil, err
		}
		uc := utls.UClient(rawConn, cfg, utls.HelloCustom)
		if err := uc.ApplyPreset(spec); err != nil {
			return nil, fmt.Errorf("mimic: %s apply preset: %w", helloName, err)
		}
		// BoringSSL emits a fixed extension order — do not shuffle it.
		return uc, nil
	}
	if helloName == maxAppHelloName || helloName == maxAppPSKHelloName {
		var spec *utls.ClientHelloSpec
		var err error
		if helloName == maxAppHelloName {
			spec, err = maxAppSpec()
		} else {
			spec, err = maxAppPSKSpec()
		}
		if err != nil {
			return nil, err
		}
		uc := utls.UClient(rawConn, cfg, utls.HelloCustom)
		if err := uc.ApplyPreset(spec); err != nil {
			return nil, fmt.Errorf("mimic: %s apply preset: %w", helloName, err)
		}
		// Conscrypt emits a fixed extension order — do not shuffle it.
		return uc, nil
	}
	if helloName == "chrome_152" || helloName == "chrome_152_psk" || helloName == "chrome_156" {
		uc := utls.UClient(rawConn, cfg, utls.HelloCustom)
		var spec *utls.ClientHelloSpec
		var err error
		switch helloName {
		case "chrome_152":
			spec, err = chrome152Spec()
		case "chrome_152_psk":
			spec, err = chrome152PSKSpec()
		default:
			spec, err = chrome156Spec()
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
	if helloID == utls.HelloChrome_Auto {
		// The Chrome preset uTLS ships carries no pre_shared_key extension,
		// so a client that speaks it never resumes: every connection is a
		// full handshake, while a real Chrome resumes from the second one
		// on. The managed placeholder restores the browser's A/B — no
		// ticket yet means the extension is concealed and the hello stays
		// the captured one, a ticket means a proper PSK offer with a
		// binder computed over that hello.
		spec, err := utls.UTLSIdToSpec(helloID)
		if err != nil {
			return nil, fmt.Errorf("mimic: %s base spec: %w", helloName, err)
		}
		withResumptionPSK(&spec)
		uc := utls.UClient(rawConn, cfg, utls.HelloCustom)
		if err := uc.ApplyPreset(&spec); err != nil {
			return nil, fmt.Errorf("mimic: %s apply preset: %w", helloName, err)
		}
		return uc, nil
	}
	return utls.UClient(rawConn, cfg, helloID), nil
}
