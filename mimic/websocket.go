package mimic

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	headless "github.com/megamen32/headless-client"
	"github.com/megamen32/headless-client/websocket"
	utls "github.com/refraction-networking/utls"
)

// DialWebSocket opens a WebSocket connection that carries the profile's
// identity: the same TLS ClientHello as the HTTP client from the same
// profile, and an upgrade request that looks like the one the profile's
// client would send.
//
// Chrome opens a WebSocket over a connection that negotiates ALPN
// "http/1.1": the upgrade request is an HTTP/1.1 request, and a connection
// that became h2 could not carry it. The uTLS path therefore narrows the
// profile's ALPN list to http/1.1 for this connection only — the rest of
// the ClientHello stays exactly the captured one.
//
// "ws://" is a plain TCP connection, "wss://" the TLS one. The returned
// connection speaks the usual WebSocket frames; the handshake is done.
//
// The permessage-deflate offer follows Chrome. The vendored client refuses
// a server that answers with a compression extension that lacks both
// no-context-takeover flags, where Chrome would accept it — drop
// "Sec-WebSocket-Extensions" from the header to opt out of compression.
func DialWebSocket(ctx context.Context, p Profile, rawURL string, opts ...Option) (*websocket.Conn, error) {
	o := transportOptions{dialTimeout: 30 * time.Second}
	for _, opt := range opts {
		opt(&o)
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("mimic: websocket url: %w", err)
	}
	switch u.Scheme {
	case "ws", "wss":
	default:
		return nil, fmt.Errorf("mimic: unsupported websocket scheme %q (want ws or wss)", u.Scheme)
	}

	header := webSocketHeader(p, o)

	dialer := *websocket.DefaultDialer
	dialer.Proxy = nil
	dialer.HandshakeTimeout = o.dialTimeout

	tcpDialer := applyTTL(chromeDialer(o.dialTimeout), effectiveTTL(o, p))
	dialer.NetDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialUnderProxy(ctx, tcpDialer, o.proxyURL, network, addr)
	}

	if p.TLSClientHello == "chrome_exact" {
		// The exact path delegates the TLS handshake to the headless client,
		// whose ClientHello is measured against the current stable Chrome
		// and matches it byte for byte. The upgrade request is written by
		// the same Chrome handshake writer.
		exact := headless.ChromeWindows.WebSocketDialer(headless.TLSOptions{
			DialContext:        dialer.NetDialContext,
			InsecureSkipVerify: o.insecureTLS,
			ServerName:         o.serverName,
		})
		exact.NetDialContext = dialer.NetDialContext
		conn, _, err := exact.DialContext(ctx, rawURL, header)
		if err != nil {
			return nil, fmt.Errorf("mimic: websocket dial %s: %w", rawURL, err)
		}
		return conn, nil
	}

	dialer.NetDialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialProfileTLS(ctx, o, p, network, addr, false, []string{"http/1.1"})
	}
	conn, _, err := dialer.DialContext(ctx, rawURL, header)
	if err != nil {
		return nil, fmt.Errorf("mimic: websocket dial %s: %w", rawURL, err)
	}
	return conn, nil
}

// webSocketHeader builds the headers of the upgrade request.
//
// A browser opens a WebSocket with a smaller header set than its HTTP
// requests: Chrome sends no client hints on the upgrade (no sec-ch-ua
// there), sends the cache headers it does send, and offers
// permessage-deflate. The measured shape comes from the Chrome table in the
// headless client.
//
// A native client profile (an app with its own protocol) keeps its own
// headers: the identity is the whole point there, and the browser shape
// would be a lie. Only the headers the WebSocket client owns are dropped.
func webSocketHeader(p Profile, o transportOptions) http.Header {
	header := http.Header{}

	if isBrowserHello(p.TLSClientHello) {
		header = headless.ChromeWindows.Headers(headless.DestWebSocket)
		if p.UserAgent != "" {
			header.Set("User-Agent", p.UserAgent)
		}
		if lang := profileAcceptLanguage(p); lang != "" {
			header.Set("Accept-Language", lang)
		}
	} else {
		for name, value := range p.Headers {
			header.Set(name, value)
		}
		if p.UserAgent != "" {
			header.Set("User-Agent", p.UserAgent)
		}
	}

	// The client owns the hop-by-hop headers of the upgrade: "Host" is
	// written from the URL, the rest from the handshake itself.
	for _, name := range websocketOwnedHeaders {
		header.Del(name)
	}
	for name, values := range o.wsHeader {
		if isWebSocketOwnedHeader(name) {
			continue
		}
		header[http.CanonicalHeaderKey(name)] = values
	}
	return header
}

// websocketOwnedHeaders are the headers the WebSocket client sets itself;
// a profile or a caller header cannot override them.
var websocketOwnedHeaders = []string{
	"Upgrade", "Connection", "Sec-Websocket-Key", "Sec-Websocket-Version",
	"Sec-Websocket-Protocol",
}

func isWebSocketOwnedHeader(name string) bool {
	canonical := http.CanonicalHeaderKey(name)
	for _, owned := range websocketOwnedHeaders {
		if canonical == owned {
			return true
		}
	}
	return false
}

// isBrowserHello reports whether the ClientHello belongs to a browser. A
// browser and a native client send different headers on the upgrade, and
// the profile says which one it is.
func isBrowserHello(helloName string) bool {
	return strings.HasPrefix(helloName, "chrome")
}

// profileAcceptLanguage returns the accept-language of the profile, whether
// it came from the dedicated field or from the header table.
func profileAcceptLanguage(p Profile) string {
	if p.AcceptLanguage != "" {
		return p.AcceptLanguage
	}
	return p.Headers["Accept-Language"]
}

// narrowALPN replaces the ALPN list of the ClientHello.
//
// The extension object is replaced, never mutated: the spec objects are
// shared with the next connection, and a mutated ALPN list would silently
// change the fingerprint of every later handshake.
func narrowALPN(uc *utls.UConn, protos []string) {
	exts := make([]utls.TLSExtension, len(uc.Extensions))
	copy(exts, uc.Extensions)
	for i, ext := range exts {
		if _, ok := ext.(*utls.ALPNExtension); ok {
			exts[i] = &utls.ALPNExtension{AlpnProtocols: protos}
			uc.Extensions = exts
			return
		}
	}
	// A spec without an ALPN extension (the Conscrypt shape of the native
	// app) offers nothing: the server then assumes HTTP/1.1, which is what
	// the upgrade request needs.
}
