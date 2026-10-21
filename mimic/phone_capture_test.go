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
