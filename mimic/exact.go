package mimic

import (
	"context"
	"net"
	"net/http"
	"time"

	headless "github.com/kulikov0/headless-client"
)

// newExactRoundTripper builds the round tripper for profiles with
// tls_client_hello: "chrome_exact". The TLS, HTTP/2 and header-order layers
// are delegated to github.com/kulikov0/headless-client, whose ClientHello is
// measured against the current stable Chrome (JA4-verified with its capture
// stand); proxy support comes from our CONNECT dialer passed as DialContext.
func newExactRoundTripper(o transportOptions, p Profile) (http.RoundTripper, error) {
	dialer := &net.Dialer{Timeout: o.dialTimeout, KeepAlive: 30 * time.Second}
	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialUnderProxy(ctx, dialer, o.proxyURL, network, addr)
	}
	tlsRT := headless.ChromeWindows.Transport(headless.TLSOptions{
		DialContext:        dialContext,
		InsecureSkipVerify: o.insecureTLS,
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
