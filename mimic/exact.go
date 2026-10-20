package mimic

import (
	"context"
	"net"
	"net/http"
	"time"

	headless "github.com/megamen32/headless-client"
)

// newExactRoundTripper builds the round tripper for profiles with
// tls_client_hello: "chrome_exact". The TLS, HTTP/2 and header-order layers
// are delegated to github.com/megamen32/headless-client, whose ClientHello is
// measured against the current stable Chrome (JA4-verified with its capture
// stand); proxy support comes from our CONNECT dialer passed as DialContext.
func newExactRoundTripper(o transportOptions, p Profile) (http.RoundTripper, error) {
	dialer := applyTTL(chromeDialer(o.dialTimeout), effectiveTTL(o, p))
	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		// The pinned resolve applies here too: the exact path is the one
		// most often used, and a site whose edge host is hidden from public
		// DNS must not be dialed by name. The SNI stays the hostname — the
		// headless transport derives it from the address it was given, not
		// from the address the connection actually went to.
		return dialUnderProxy(ctx, dialer, o.proxyURL, network, o.resolveAddr(addr))
	}
	tlsRT := headless.ChromeWindows.Transport(headless.TLSOptions{
		DialContext:        dialContext,
		InsecureSkipVerify: o.insecureTLS,
		ServerName:         o.serverName,
	})
	h1 := &http.Transport{
		DialContext:         dialContext,
		TLSHandshakeTimeout: 15 * time.Second,
		IdleConnTimeout:     90 * time.Second,
	}
	return &schemeRoundTripper{https: tlsRT, plain: h1}, nil
}

// schemeRoundTripper routes https to the exact-fingerprint round tripper and
// plain http to the stdlib transport (the exact one is TLS-specific).
type schemeRoundTripper struct {
	https http.RoundTripper
	plain http.RoundTripper
}

func (rt *schemeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" && rt.https != nil {
		return rt.https.RoundTrip(req)
	}
	return rt.plain.RoundTrip(req)
}
