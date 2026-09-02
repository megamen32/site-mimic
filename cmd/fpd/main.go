// Command fpd is the live full-fingerprint display for the site-mimic
// verification stand (test.auto-gram.ru).
//
// haproxy routes SNI test.auto-gram.ru here with send-proxy-v2, so fpd
// learns the real client IP:port from the PPv2 header. It peeks the raw
// ClientHello bytes before handing the connection to crypto/tls (JA3/JA4
// per the FoxIO spec, ported from tools/ja3_ja4.py), and keeps an
// AF_PACKET sniffer on the WAN interface for the client's IP TTL and SYN
// TCP options — the layers a userspace TLS server cannot see.
//
// GET / and /fp serve the report (HTML for browsers, JSON otherwise);
// every other path is reverse-proxied untouched to the JSONL receiver, so
// the stand keeps logging as before. When -keylog is set, TLS session
// keys are appended there for post-hoc h2 frame decryption with tshark.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"sync"
)

type connMeta struct {
	hello *clientHello
	addr  clientAddr
}

// metaKey carries per-connection capture data into request contexts.
type metaKey struct{}

func metaFrom(r *http.Request) connMeta {
	m, _ := r.Context().Value(metaKey{}).(connMeta)
	return m
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8478", "listen address")
	certFile := flag.String("cert", "/etc/letsencrypt/live/test.auto-gram.ru/fullchain.pem", "TLS certificate")
	keyFile := flag.String("key", "/etc/letsencrypt/live/test.auto-gram.ru/privkey.pem", "TLS key")
	upstream := flag.String("upstream", "http://127.0.0.1:8477", "receiver base URL for pass-through paths")
	iface := flag.String("iface", "enp28s0f2np2", "WAN interface for the TTL/SYN sniffer")
	selftest := flag.Bool("selftest", false, "run a local PPv2+TLS probe against -listen and print /fp")
	flag.Parse()

	if *selftest {
		runSelftest(*listen)
		return
	}

	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("fpd: load cert: %v", err)
	}
	connCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	if kl := os.Getenv("FPD_KEYLOG"); kl != "" {
		f, err := os.OpenFile(kl, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			log.Fatalf("fpd: open keylog: %v", err)
		}
		connCfg.KeyLogWriter = f
		log.Printf("fpd: TLS keys -> %s", kl)
	}

	sn := newSniffer(*iface, 443)
	go sn.run()

	upURL, err := url.Parse(*upstream)
	if err != nil {
		log.Fatalf("fpd: upstream: %v", err)
	}
	rep := newReportBuilder(upURL.Host)
	proxy := httputil.NewSingleHostReverseProxy(upURL)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/fp" || r.URL.Path == "/fp/recent" {
			rep.serve(w, r, sn)
			return
		}
		proxy.ServeHTTP(w, r)
	})

	srv := &http.Server{
		Handler: mux,
		// Non-nil TLSConfig with h2 makes net/http's bundled http2 server
		// take over conns whose ALPN negotiated "h2". Certificates live on
		// the per-connection config below.
		TLSConfig: &tls.Config{NextProtos: []string{"h2", "http/1.1"}},
	}

	log.Printf("fpd: listening on %s (cert %s, upstream %s, iface %s)",
		*listen, path.Dir(*certFile), *upstream, *iface)
	log.Fatal(serveTLS(srv, *listen, connCfg))
}

// serveTLS accepts PPv2-prefixed connections, peeks the raw ClientHello,
// upgrades to TLS and feeds the connections to srv through a channel
// listener. Ownership of each accepted conn transfers to srv on send.
func serveTLS(srv *http.Server, addr string, cfg *tls.Config) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s := &metaStore{m: map[net.Conn]connMeta{}}
	srv.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		if meta, ok := s.get(c); ok {
			ctx = context.WithValue(ctx, metaKey{}, meta)
		}
		return ctx
	}
	ch := make(chan net.Conn)
	go func() { _ = srv.Serve(&channelListener{ch: ch, addr: ln.Addr()}) }()

	for {
		raw, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(raw net.Conn) {
			meta, hello, prefix, err := handshakeFront(raw)
			if err != nil {
				if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
					log.Printf("fpd: front from %s: %v", raw.RemoteAddr(), err)
				}
				raw.Close()
				return
			}
			rc := &replayConn{Conn: raw, prefix: prefix}
			tlsConn := tls.Server(rc, cfg)
			s.put(tlsConn, connMeta{hello: hello, addr: meta})
			rc.onClose = func() { s.del(tlsConn) }
			ch <- tlsConn
		}(raw)
	}
}

// metaStore tracks per-conn capture data without leaking closed conns.
type metaStore struct {
	mu sync.Mutex
	m  map[net.Conn]connMeta
}

func (s *metaStore) put(c net.Conn, meta connMeta) {
	s.mu.Lock()
	s.m[c] = meta
	s.mu.Unlock()
}

func (s *metaStore) get(c net.Conn) (connMeta, bool) {
	s.mu.Lock()
	meta, ok := s.m[c]
	s.mu.Unlock()
	return meta, ok
}

func (s *metaStore) del(c net.Conn) {
	s.mu.Lock()
	delete(s.m, c)
	s.mu.Unlock()
}

// handshakeFront reads the proxy-v2 header and the ClientHello record(s)
// and returns the bytes to replay into the TLS server.
func handshakeFront(raw net.Conn) (clientAddr, *clientHello, []byte, error) {
	br := newBufioReader(raw)
	addr, err := readProxyV2Header(br)
	if err != nil {
		return addr, nil, nil, fmt.Errorf("proxy-v2: %w", err)
	}
	rec, err := readHelloRecords(br)
	if err != nil {
		return addr, nil, nil, fmt.Errorf("client-hello: %w", err)
	}
	hello, err := parseClientHelloRecord(rec)
	if err != nil {
		return addr, nil, nil, fmt.Errorf("parse: %w", err)
	}
	// Drain anything still buffered beyond the hello (normally nothing:
	// the client waits for ServerHello before sending more).
	rest := make([]byte, br.Buffered())
	if _, err := io.ReadFull(br, rest); err != nil {
		return addr, nil, nil, fmt.Errorf("drain: %w", err)
	}
	var replay []byte
	replay = append(replay, rec...)
	replay = append(replay, rest...)
	return addr, hello, replay, nil
}

// replayConn feeds the already-consumed bytes back before the raw conn
// and removes the conn's meta entry when net/http closes it.
type replayConn struct {
	net.Conn
	prefix  []byte
	pos     int
	onClose func()
}

func (c *replayConn) Read(b []byte) (int, error) {
	if c.pos < len(c.prefix) {
		n := copy(b, c.prefix[c.pos:])
		c.pos += n
		return n, nil
	}
	return c.Conn.Read(b)
}

func (c *replayConn) Close() error {
	if c.onClose != nil {
		c.onClose()
	}
	return c.Conn.Close()
}

type channelListener struct {
	ch        chan net.Conn
	addr      net.Addr
	closed    chan struct{}
	closeOnce sync.Once
}

func (l *channelListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *channelListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *channelListener) Addr() net.Addr { return l.addr }

// runSelftest dials the local listener with a synthetic proxy-v2 header,
// performs a TLS handshake and prints the /fp report — lets the display
// be exercised end-to-end without touching haproxy.
func runSelftest(addr string) {
	clientIP, clientPort := "192.168.2.100", 61234
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		log.Fatalf("selftest: dial: %v", err)
	}
	defer raw.Close()
	src := net.ParseIP(clientIP).To4()
	dst := net.ParseIP("95.165.165.65").To4()
	hdr := make([]byte, 16+12)
	copy(hdr, "\r\n\r\n\x00\r\nQUIT\n")
	hdr[12] = 0x21           // version 2, PROXY command
	hdr[13] = 0x11           // AF_INET, STREAM
	hdr[14], hdr[15] = 0, 12 // payload length
	copy(hdr[16:20], src)    // src addr
	copy(hdr[20:24], dst)    // dst addr
	hdr[24], hdr[25] = byte(clientPort>>8), byte(clientPort)
	hdr[26], hdr[27] = 0x01, 0xbb // 443
	if _, err := raw.Write(hdr); err != nil {
		log.Fatalf("selftest: ppv2 write: %v", err)
	}
	tlsConn := tls.Client(raw, &tls.Config{
		ServerName:         "test.auto-gram.ru",
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"}, // http.Transport with custom DialTLSContext does not speak h2
	})
	if err := tlsConn.Handshake(); err != nil {
		log.Fatalf("selftest: tls: %v", err)
	}
	req, _ := http.NewRequest("GET", "https://test.auto-gram.ru/fp?format=json", nil)
	req.Header.Set("User-Agent", "fpd-selftest")
	client := &http.Client{
		Transport: &http.Transport{DialTLSContext: func(ctx context.Context, network, a string) (net.Conn, error) {
			return tlsConn, nil
		}},
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("selftest: request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
}
