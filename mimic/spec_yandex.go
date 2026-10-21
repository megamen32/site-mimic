package mimic

import (
	utls "github.com/refraction-networking/utls"
)

// yandexBrowserSpec builds the ClientHello of Yandex.Browser.
//
// Yandex's browser is a Chromium fork that lags the upstream patch level:
// its hello carries sixteen extensions and no 0xCA34, which is the shape of
// Chrome 151. The post-quantum signature algorithms and the ML-KEM768 group
// are there, so the fork is recent — but it does not send the unregistered
// extension a current Chrome sends.
//
// Measured on a phone (2026-10-21, Yandex.Browser 26.8.7.49, Android 15),
// the capture is committed as mimic/testdata/yandex_browser_clienthello.json
// and the fingerprint is t13d1516h2_8daaf6152771_806a8c22fdea.
//
// A client that has to look like Yandex's own browser must not carry
// 0xCA34: on the Yandex ecosystem that extension is a tell, because the
// browser there does not send it.
func yandexBrowserSpec() (*utls.ClientHelloSpec, error) {
	// The same layout as chrome_152 — the uTLS Chrome preset plus the
	// post-quantum signature algorithms — without the 0xCA34 extension.
	spec, err := chromeBaseSpec("", true)
	if err != nil {
		return nil, err
	}
	return &spec, nil
}
