package mimic

import "testing"

// The two mobile references, captured on a real phone (2026-10-21, S21,
// Android 15, rooted, USB) with the capture chain of tools/phone:
//
//   - Chrome 155.0.8059.81, the browser's own ClientHello to m.vk.ru;
//   - Yandex.Browser 26.8.7.49, its ClientHello to api.browser.yandex.net.
//
// The captures are committed so the numbers can be checked without the
// phone, and the tests below pin what each of them says.

// TestPhoneChrome155Capture pins the mobile Chrome hello.
//
// The fingerprint is the same one desktop Chrome 155 produces
// (t13d1517h2_8daaf6152771_cb7bf5808d99): the mobile set of extensions is
// the desktop one, seventeen of them, 0xCA34 included, with the
// post-quantum signature algorithms. 0x12E0 is not there — that extension
// arrived with Chrome 156.
func TestPhoneChrome155Capture(t *testing.T) {
	hello := loadFixture(t, "phone_chrome155_clienthello.json")

	if got, want := hello.JA4(), "t13d1517h2_8daaf6152771_cb7bf5808d99"; got != want {
		t.Errorf("phone Chrome 155 JA4: got %s, want %s", got, want)
	}
	if !hasExtension(hello, 0xca34) {
		t.Error("the phone's Chrome 155 hello carries no 0xCA34; the capture is not the one it was taken from")
	}
	if hasExtension(hello, 0x12e0) {
		t.Error("the phone's Chrome 155 hello carries 0x12E0; that extension belongs to Chrome 156")
	}
	if got, want := len(hello.SigAlgs), 12; got != want {
		t.Errorf("the hello carries %d signature algorithms, want %d (the post-quantum three plus the classic nine)", got, want)
	}
}

// TestYandexBrowserCapture pins the Yandex.Browser hello.
//
// Yandex's browser is a Chromium fork that lags the upstream patch level:
// its hello carries sixteen extensions and no 0xCA34, which is the shape of
// Chrome 151. A client that answers to Yandex's own browser must not carry
// the extension a current Chrome carries.
func TestYandexBrowserCapture(t *testing.T) {
	hello := loadFixture(t, "yandex_browser_clienthello.json")

	if got, want := hello.JA4(), "t13d1516h2_8daaf6152771_806a8c22fdea"; got != want {
		t.Errorf("Yandex.Browser JA4: got %s, want %s", got, want)
	}
	if hasExtension(hello, 0xca34) {
		t.Error("the Yandex.Browser hello carries 0xCA34; its Chromium fork does not send it")
	}
	if got, want := len(hello.Groups), 5; got != want {
		t.Errorf("the hello offers %d groups, want %d (the greased one, the post-quantum one and three classic)", got, want)
	}
	if !hasGroup(hello, 0x11ec) {
		t.Error("the Yandex.Browser hello offers no X25519MLKEM768; the capture is not the one it was taken from")
	}
}

// hasGroup reports whether the hello offers the given curve.
func hasGroup(hello *ClientHello, id uint16) bool {
	for _, group := range hello.Groups {
		if group == id {
			return true
		}
	}
	return false
}

// TestYandexBrowserSpecMatchesTheCapture checks the reconstructed spec
// against the Yandex.Browser capture: the same fingerprint, the same
// extension set, and the same bytes in every extension the browser does not
// randomise.
//
// The spec is the chrome_152 layout without the 0xCA34 extension — the
// extension a current Chrome sends and Yandex's fork does not.
func TestYandexBrowserSpecMatchesTheCapture(t *testing.T) {
	spec, err := yandexBrowserSpec()
	if err != nil {
		t.Fatal(err)
	}
	ours := handshakeClientHello(t, spec, "api.browser.yandex.net")
	reference := loadFixture(t, "yandex_browser_clienthello.json")

	if got, want := ours.JA4(), reference.JA4(); got != want {
		t.Errorf("JA4: ours %s, capture %s", got, want)
	}

	oursSet := nonGREASEExtensions(ours.Extensions)
	refSet := nonGREASEExtensions(reference.Extensions)
	if len(oursSet) != len(refSet) {
		t.Fatalf("extension count: ours %d, capture %d", len(oursSet), len(refSet))
	}
	for id := range refSet {
		if !oursSet[id] {
			t.Errorf("extension %#06x is missing from the spec", id)
		}
	}
	for id := range oursSet {
		if !refSet[id] {
			t.Errorf("extension %#06x is in the spec but not in the capture", id)
		}
	}

	for id := range refSet {
		switch id {
		case 0x000a, 0x000d, 0x002b: // carry a GREASE value
			continue
		case 0x0033: // key_share: a fresh key every connection
			continue
		case 0xfe0d: // ALPS settings: randomised by Chrome
			continue
		}
		got, want := ours.ExtensionData[id], reference.ExtensionData[id]
		if string(got) != string(want) {
			t.Errorf("extension %#06x payload: ours %x, capture %x", id, got, want)
		}
	}
}

// TestChrome155SpecMatchesThePhoneCapture checks that the chrome_155
// profile — the same spec as chrome_152 under the name of the release it
// reproduces — is the shape the phone's Chrome 155 sends.
func TestChrome155SpecMatchesThePhoneCapture(t *testing.T) {
	spec, err := chrome152Spec()
	if err != nil {
		t.Fatal(err)
	}
	ours := handshakeClientHello(t, spec, "m.vk.ru")
	reference := loadFixture(t, "phone_chrome155_clienthello.json")

	if got, want := ours.JA4(), reference.JA4(); got != want {
		t.Errorf("JA4: ours %s, capture %s", got, want)
	}
	if !hasExtension(ours, 0xca34) {
		t.Error("the spec carries no 0xCA34; the phone's Chrome 155 sends it")
	}
}

// TestPhoneChrome155ResumedQUICHello pins the shape of a resuming Chrome:
// the fresh hello plus the pre_shared_key (0x0029) and the
// signed_certificate_timestamp (0x002a).
//
// This is the gap, stated as a measurement. A real Chrome offers a ticket
// on its second connection to an origin — the phone's Chrome 155 does
// (captured 2026-10-21, q13d0314h3_55b375c5d22e_79cc91d6b50c) — while our
// h3 client never resumes: the QUIC stack of the dependency has no session
// store, and a session state cannot be rebuilt outside it. A server that
// counts resumptions sees a browser on the first connection and something
// else on the second.
func TestPhoneChrome155ResumedQUICHello(t *testing.T) {
	hello := loadFixture(t, "phone_chrome155_quic_resumed_hello.json")

	if got, want := hello.JA4QUIC(), "q13d0314h3_55b375c5d22e_79cc91d6b50c"; got != want {
		t.Errorf("the resumed QUIC JA4: got %s, want %s", got, want)
	}
	if !hasExtension(hello, 0x0029) {
		t.Error("the resumed hello carries no pre_shared_key; a resuming browser offers its ticket")
	}
	if !hasExtension(hello, 0x002a) {
		t.Error("the resumed hello carries no signed_certificate_timestamp")
	}
	if hasExtension(hello, 0x12e0) {
		t.Error("the resumed hello carries 0x12E0; that extension belongs to Chrome 156")
	}
}
