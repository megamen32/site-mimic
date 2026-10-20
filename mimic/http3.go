package mimic

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	quic "github.com/refraction-networking/uquic"
	"github.com/refraction-networking/uquic/http3"
	utls "github.com/refraction-networking/utls"
)

// NewHTTP3 builds an *http.Client that speaks HTTP/3 over QUIC with a
// browser-shaped QUIC fingerprint. It takes the same profile and the same
// options as New, so the caller code stays the same — only the wire changes:
// instead of TCP + TLS + ALPN "h2" the client sends a QUIC Initial packet
// carrying the Chrome 152 ClientHello (post-quantum signature algorithms and
// the 0xCA34 extension) and the transport parameters a real Android Chrome
// sends. See mimic/quic_spec.go.
//
// The profile's headers are applied the same way as with New: build the
// request with Profile.Request (or set the User-Agent yourself) and hand it
// to the client. The client sets the profile's user agent when the request
// carries none.
//
// The returned client's Transport is an io.Closer — close it to release the
// UDP socket and the QUIC connections it holds.
//
// QUIC does not travel through an HTTP CONNECT tunnel, so a proxied request
// is an error rather than a silent direct connection.
func NewHTTP3(p Profile, opts ...Option) (*http.Client, error) {
	o := transportOptions{dialTimeout: 30 * time.Second}
	for _, opt := range opts {
		opt(&o)
	}
	if o.proxyURL != "" {
		return nil, fmt.Errorf("mimic: http3: a CONNECT proxy cannot carry QUIC (proxy %s)", o.proxyURL)
	}
	if err := checkHTTP3Profile(p); err != nil {
		return nil, err
	}
	spec, err := chrome152QUICSpec()
	if err != nil {
		return nil, err
	}
	pc, err := http3ListenPacket(o, p)
	if err != nil {
		return nil, err
	}
	uTransport := &quic.UTransport{
		Transport: &quic.Transport{Conn: pc},
		QUICSpec:  spec,
	}
	rt := &http3.RoundTripper{
		TLSClientConfig: &utls.Config{
			// An empty ServerName makes uquic use the request's host; the
			// option overrides it for every host.
			ServerName:         o.serverName,
			InsecureSkipVerify: o.insecureTLS,
		},
		QuicConfig: &quic.Config{
			// The handshake window, like the TCP path's handshake timeout.
			HandshakeIdleTimeout: o.dialTimeout,
			// Matches the max_idle_timeout we advertise in the transport
			// parameters, so the peer and we agree on the connection life.
			MaxIdleTimeout: quicChromeMaxIdleTimeoutMS * time.Millisecond,
		},
	}
	urt := http3.GetURoundTripper(rt, spec, uTransport)
	urt.Dial = http3Dialer(o, uTransport)
	return &http.Client{
		Transport: &http3Transport{rt: urt, ua: p.UserAgent},
		Jar:       p.CookieJar,
	}, nil
}

// checkHTTP3Profile rejects profiles whose ClientHello has no Chrome-shaped
// QUIC counterpart: the QUIC hello is the Chrome 152 one, so a profile of
// another browser would be mimicked over QUIC by something else entirely.
func checkHTTP3Profile(p Profile) error {
	switch p.TLSClientHello {
	case "", "chrome_auto", "android_149", "chrome_152", "chrome_152_psk", "chrome_exact":
		return nil
	}
	return fmt.Errorf("mimic: http3: profile tls_client_hello %q has no Chrome QUIC fingerprint (want chrome_auto, chrome_152 or chrome_exact)", p.TLSClientHello)
}

// http3ListenPacket opens the UDP socket the QUIC connections run over. One
// socket serves the whole client, like a browser's socket pool, and carries
// the profile's IP TTL — the same knob the TCP path stamps on its sockets.
func http3ListenPacket(o transportOptions, p Profile) (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: applyTTL(chromeDialer(o.dialTimeout), effectiveTTL(o, p)).Control,
	}
	pc, err := lc.ListenPacket(context.Background(), "udp", ":0")
	if err != nil {
		return nil, fmt.Errorf("mimic: http3: udp socket: %w", err)
	}
	return pc, nil
}

// http3Dialer resolves the address of a QUIC connection. A pinned resolve
// (WithResolve) swaps the address but not the SNI: the certificate and the
// routing stay the hostname's, only the packet goes to the pinned IP.
func http3Dialer(o transportOptions, uTransport *quic.UTransport) func(context.Context, string, *utls.Config, *quic.Config) (quic.EarlyConnection, error) {
	return func(ctx context.Context, addr string, tlsCfg *utls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("mimic: http3: address %q: %w", addr, err)
		}
		if ip, ok := o.resolve[host]; ok {
			host = ip
		}
		udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
		if err != nil {
			return nil, fmt.Errorf("mimic: http3: resolve %s: %w", host, err)
		}
		return uTransport.DialEarly(ctx, udpAddr, tlsCfg, cfg)
	}
}

// http3Transport is the round tripper behind NewHTTP3's client.
type http3Transport struct {
	rt *http3.URoundTripper
	ua string
}

func (t *http3Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.ua != "" && req.Header != nil && req.Header.Get("User-Agent") == "" {
		// A round tripper must not touch the caller's request, so the
		// header goes onto a copy.
		req = req.Clone(req.Context())
		req.Header.Set("User-Agent", t.ua)
	}
	if u, err := http.ProxyFromEnvironment(req); err == nil && u != nil {
		return nil, fmt.Errorf("mimic: http3: proxy %s cannot carry QUIC", u.Host)
	}
	return t.rt.RoundTrip(req)
}

// Close releases the QUIC connections and the UDP socket behind them.
func (t *http3Transport) Close() error { return t.rt.Close() }
