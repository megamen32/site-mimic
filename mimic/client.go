// Package mimic provides an HTTP client whose transport-level fingerprint —
// TLS ClientHello (JA3/JA4), ALPN, HTTP/2 — follows a site profile captured
// from a real browser, so a Go program presents the same wire-level identity
// the site expects.
//
// The stock Go crypto/tls ClientHello is trivially distinguishable: fixed
// cipher order, no ALPN by default, missing Chrome extensions (padding
// 0x0015, session ticket 0x0023, compressed certificates 0x001b, delegated
// credentials 0x0017, application-settings 0x4469/0x44cd). site-mimic
// replaces the handshake with uTLS and speaks HTTP/2 over ALPN.
package mimic

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// errNoH2 is returned by the dialer when the server did not negotiate h2 via
// ALPN; the round tripper then retries the request over HTTP/1.1.
var errNoH2 = errors.New("mimic: server did not negotiate h2 via ALPN")

// ParseClientHelloID maps a profile name to a uTLS ClientHelloID.
//
// Recognized names: "" / "chrome_auto" (default — tracks the latest Chrome
// spec bundled with uTLS and is the right choice for most sites), "firefox_auto",
// "ios_auto", "random", "random_alpn".
func ParseClientHelloID(name string) (utls.ClientHelloID, error) {
	switch name {
	case "", "chrome_auto":
		return utls.HelloChrome_Auto, nil
	case "firefox_auto":
		return utls.HelloFirefox_Auto, nil
	case "ios_auto":
		return utls.HelloIOS_Auto, nil
	case "random":
		return utls.HelloRandomized, nil
	case "random_alpn":
		return utls.HelloRandomizedALPN, nil
	default:
		return utls.ClientHelloID{}, fmt.Errorf("mimic: unknown tls_client_hello %q (want chrome_auto, firefox_auto, ios_auto, random, random_alpn)", name)
	}
}

// Option adjusts transport construction.
type Option func(*transportOptions)

type transportOptions struct {
	proxyURL    string
	insecureTLS bool
	dialTimeout time.Duration
}

// WithProxy routes traffic through an HTTP CONNECT proxy
// (e.g. "http://user:pass@host:port"). Without it the client honours the
// standard HTTPS_PROXY / HTTP_PROXY environment variables.
func WithProxy(proxyURL string) Option {
	return func(o *transportOptions) { o.proxyURL = proxyURL }
}

// WithInsecureTLS disables certificate verification. Debugging only.
func WithInsecureTLS() Option {
	return func(o *transportOptions) { o.insecureTLS = true }
}

// WithDialTimeout bounds the TCP dial + CONNECT + TLS handshake window.
func WithDialTimeout(d time.Duration) Option {
	return func(o *transportOptions) { o.dialTimeout = d }
}

// New builds an *http.Client whose TLS handshakes are performed by uTLS with
// the profile's ClientHelloID. HTTPS requests negotiate HTTP/2 via ALPN and
// fall back to HTTP/1.1 per host when a server does not offer h2. Pass a
// profile with CookieJar set to keep site cookies across requests.
func New(p Profile, opts ...Option) (*http.Client, error) {
	o := transportOptions{dialTimeout: 30 * time.Second}
	for _, opt := range opts {
		opt(&o)
	}
	helloID, err := ParseClientHelloID(p.TLSClientHello)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Timeout: o.dialTimeout, KeepAlive: 30 * time.Second}
	dial := func(ctx context.Context, network, addr string, requireH2 bool) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		rawConn, err := dialUnderProxy(ctx, dialer, o.proxyURL, network, addr)
		if err != nil {
			return nil, err
		}
		cfg := &utls.Config{ServerName: host, InsecureSkipVerify: o.insecureTLS}
		uConn := utls.UClient(rawConn, cfg, helloID)
		_ = rawConn.SetDeadline(time.Now().Add(o.dialTimeout))
		if err := uConn.HandshakeContext(ctx); err != nil {
			_ = rawConn.Close()
			return nil, fmt.Errorf("mimic: utls handshake to %s: %w", addr, err)
		}
		_ = rawConn.SetDeadline(time.Time{})
		if requireH2 && uConn.ConnectionState().NegotiatedProtocol != "h2" {
			_ = uConn.Close()
			return nil, errNoH2
		}
		return uConn, nil
	}

	dialTLSH2 := func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		return dial(ctx, network, addr, true)
	}
	h2 := &http2.Transport{DialTLSContext: dialTLSH2}

	h1 := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dial(ctx, network, addr, false)
		},
		TLSHandshakeTimeout: 15 * time.Second,
		IdleConnTimeout:     90 * time.Second,
	}

	rt := &roundTripper{h2: h2, h1: h1, h1Only: map[string]bool{}}
	return &http.Client{Transport: rt, Jar: p.CookieJar}, nil
}

// roundTripper routes https requests through the uTLS+h2 transport and falls
// back to HTTP/1.1 for plain http URLs and for hosts that have ever refused
// the h2 ALPN.
type roundTripper struct {
	h2     *http2.Transport
	h1     *http.Transport
	mu     sync.Mutex
	h1Only map[string]bool
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return rt.h1.RoundTrip(req)
	}
	if rt.isH1Only(req.URL.Host) {
		return rt.h1.RoundTrip(req)
	}
	resp, err := rt.h2.RoundTrip(req)
	if errors.Is(err, errNoH2) {
		rt.markH1Only(req.URL.Host)
		return rt.h1.RoundTrip(req)
	}
	return resp, err
}

func (rt *roundTripper) isH1Only(host string) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.h1Only[host]
}

func (rt *roundTripper) markH1Only(host string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.h1Only[host] = true
}

// dialUnderProxy dials addr, tunnelling through the configured CONNECT proxy
// first. proxyURL empty means: resolve from HTTPS_PROXY/HTTP_PROXY env as a
// plain Go transport would.
func dialUnderProxy(ctx context.Context, dialer *net.Dialer, proxyURL, network, addr string) (net.Conn, error) {
	proxy, err := resolveProxy(proxyURL, addr)
	if err != nil {
		return nil, err
	}
	if proxy == nil {
		return dialer.DialContext(ctx, network, addr)
	}
	host, port, _ := net.SplitHostPort(addr)
	return proxyConnect(ctx, dialer, proxy, host, port)
}

func resolveProxy(proxyURL, addr string) (*url.URL, error) {
	if proxyURL != "" {
		return url.Parse(proxyURL)
	}
	req := &http.Request{URL: &url.URL{Scheme: "https", Host: addr}}
	return http.ProxyFromEnvironment(req)
}

// proxyConnect opens the TCP connection to the proxy and issues HTTP CONNECT
// to host:port. uTLS's DialTLSContext replaces Go's stdlib proxy handling, so
// the tunnel must be established by hand before the TLS handshake.
func proxyConnect(ctx context.Context, dialer *net.Dialer, proxy *url.URL, host, port string) (net.Conn, error) {
	conn, err := dialer.DialContext(ctx, "tcp", proxy.Host)
	if err != nil {
		return nil, fmt.Errorf("mimic: proxy dial %s: %w", proxy.Host, err)
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	target := net.JoinHostPort(host, port)
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if proxy.User != nil {
		if pass, ok := proxy.User.Password(); ok {
			req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(proxy.User.Username()+":"+pass)) + "\r\n"
		}
	}
	req += "\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("mimic: proxy CONNECT write: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("mimic: proxy CONNECT read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("mimic: proxy CONNECT %s: %s", resp.Status, target)
	}
	_ = conn.SetDeadline(time.Time{})
	return &tunnelConn{Conn: conn, Reader: br}, nil
}

// tunnelConn keeps bytes already buffered while reading the CONNECT response
// available to the TLS handshake that follows on the same socket.
type tunnelConn struct {
	net.Conn
	*bufio.Reader
}

func (c *tunnelConn) Read(b []byte) (int, error)  { return c.Reader.Read(b) }
func (c *tunnelConn) Write(b []byte) (int, error) { return c.Conn.Write(b) }
