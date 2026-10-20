package mimic

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	h3quic "github.com/megamen32/headless-client/quic"
	h3 "github.com/megamen32/headless-client/quic/http3"
	utls "github.com/refraction-networking/utls"
)

// NewHTTP3 builds an *http.Client that speaks HTTP/3 over QUIC with a
// browser-shaped QUIC fingerprint. It takes the same profile and the same
// options as New, so the caller code stays the same — only the wire changes:
// instead of TCP + TLS + ALPN "h2" the client sends a QUIC Initial packet
// carrying the Chrome QUIC ClientHello (the eleven-extension shape a real
// Android Chrome sends, with the post-quantum key share, ALPS and the ECH
// GREASE pair) and the transport parameters captured from that browser.
// See mimic/quic_spec.go.
//
// The QUIC wire always carries that one QUIC fingerprint: a QUIC hello is a
// different shape from a TCP hello, and the QUIC stack has no per-profile
// presets. The profile's tls_client_hello names the TCP identity, so it is
// accepted only when it is a Chrome one — the profile must not claim a
// browser the QUIC fingerprint does not match.
//
// The profile's headers are applied the same way as with New: build the
// request with Profile.Request (or set the User-Agent yourself) and hand it
// to the client. The client sets the profile's user agent and accept-language
// when the request carries neither.
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
	tlsConfig, quicConfig := chromeQUICConfig(o)
	pc, err := http3ListenPacket(o, p)
	if err != nil {
		return nil, err
	}
	transport := &h3quic.Transport{
		Conn: pc,
		// Chrome sends an empty source connection id, and the transport
		// parameter initial_source_connection_id says so too. The default
		// would be four bytes, and RFC 9000 wants the parameter and the
		// packet to agree.
		ConnectionIDLength:           0,
		AllowZeroLengthConnectionIDs: true,
	}
	rt := &h3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig:      quicConfig,
		// The datagram support Chrome announces in its SETTINGS frame, and
		// the GREASE setting and frame around it.
		EnableDatagrams:    true,
		SendGreaseFrames:   true,
		AdditionalSettings: chromeH3Settings(),
		Dial:               http3Dialer(o, transport),
	}
	return &http.Client{
		Transport: &http3Transport{rt: rt, ua: p.UserAgent, acceptLanguage: p.AcceptLanguage},
		Jar:       p.CookieJar,
	}, nil
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
func http3Dialer(o transportOptions, transport *h3quic.Transport) func(context.Context, string, *utls.Config, *h3quic.Config) (*h3quic.Conn, error) {
	return func(ctx context.Context, addr string, tlsCfg *utls.Config, cfg *h3quic.Config) (*h3quic.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("mimic: http3: address %q: %w", addr, err)
		}
		if ip, ok := o.resolve[host]; ok {
			host = ip
		}
		udpAddr, err := resolveUDPAddr(ctx, host, port)
		if err != nil {
			return nil, fmt.Errorf("mimic: http3: resolve %s: %w", host, err)
		}
		return transport.DialEarly(ctx, udpAddr, tlsCfg, cfg)
	}
}

// resolveUDPAddr resolves the host with the caller's context, so a slow or
// hung resolver cannot outlive the request. net.ResolveUDPAddr takes no
// context and would block past the deadline.
func resolveUDPAddr(ctx context.Context, host, port string) (*net.UDPAddr, error) {
	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("port %q: %w", port, err)
	}
	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: p}, nil
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no address for %s", host)
	}
	return &net.UDPAddr{IP: ips[0].IP, Port: p}, nil
}

// http3Transport is the round tripper behind NewHTTP3's client.
type http3Transport struct {
	rt *h3.Transport
	ua string
	// acceptLanguage is the profile's accept-language value, applied only
	// when the request carries none.
	acceptLanguage string
}

func (t *http3Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header != nil {
		needUA := t.ua != "" && req.Header.Get("User-Agent") == ""
		needLang := t.acceptLanguage != "" && req.Header.Get("Accept-Language") == ""
		if needUA || needLang {
			// A round tripper must not touch the caller's request, so the
			// headers go onto a copy.
			req = req.Clone(req.Context())
			if needUA {
				req.Header.Set("User-Agent", t.ua)
			}
			if needLang {
				req.Header.Set("Accept-Language", t.acceptLang())
			}
		}
	}
	u, err := http.ProxyFromEnvironment(req)
	if err != nil {
		// A malformed proxy setting is a configuration error, not a
		// reason to connect directly behind the user's back.
		return nil, fmt.Errorf("mimic: http3: proxy setting: %w", err)
	}
	if u != nil {
		return nil, fmt.Errorf("mimic: http3: proxy %s cannot carry QUIC", u.Host)
	}
	return t.rt.RoundTrip(req)
}

// acceptLang returns the profile's accept-language value.
func (t *http3Transport) acceptLang() string { return t.acceptLanguage }

// Close releases the QUIC connections and the UDP socket behind them.
func (t *http3Transport) Close() error { return t.rt.Close() }
