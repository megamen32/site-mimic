// Command h3sniff is an HTTP/3 server that reports the fingerprint of
// every client that connects.
//
// It is the QUIC counterpart of cmd/fpd: the same three things the TCP
// stand reports — the ClientHello, the transport parameters and the HTTP/3
// settings — read from the QUIC Initial packet and the control stream
// instead of from a TLS record.
//
// One JSON line per connection:
//
//	{"client":"192.0.2.10:54321","ja4":"q13d0311h3_...","ja3":"...",
//	 "sni":"www.google.com","alpn":["h3"],"extensions":11,
//	 "transport_parameters":{"1":"80007530"},"settings":{"1":65536},
//	 "user_agent":"Mozilla/5.0 ..."}
//
// The ClientHello comes out of the Initial packet: RFC 9001 derives the
// Initial keys from the connection id, so a listener reads a client's hello
// without any secret material.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	h3quic "github.com/megamen32/headless-client/quic"
	h3http3 "github.com/megamen32/headless-client/quic/http3"
	"github.com/megamen32/headless-client/quic/qpack"
	utls "github.com/refraction-networking/utls"

	"github.com/megamen32/site-mimic/internal/quicwire"
	"github.com/megamen32/site-mimic/mimic"
)

// report is what the server prints for one connection.
type report struct {
	Client              string            `json:"client"`
	JA4                 string            `json:"ja4,omitempty"`
	JA3                 string            `json:"ja3,omitempty"`
	SNI                 string            `json:"sni,omitempty"`
	ALPN                []string          `json:"alpn,omitempty"`
	Extensions          int               `json:"extensions,omitempty"`
	CipherSuites        int               `json:"cipher_suites,omitempty"`
	ExtensionIDs        []string          `json:"extension_ids,omitempty"`
	ExtensionData       map[string]string `json:"extension_data,omitempty"`
	SigAlgs             []string          `json:"sig_algs,omitempty"`
	Groups              []string          `json:"supported_groups,omitempty"`
	TransportParameters map[string]string `json:"transport_parameters,omitempty"`
	TransportParamsRaw  string            `json:"transport_parameters_raw,omitempty"`
	Settings            map[string]uint64 `json:"settings,omitempty"`
	UserAgent           string            `json:"user_agent,omitempty"`
	Error               string            `json:"error,omitempty"`
}

// verbose makes the server log what happens on every connection.
var verbose bool

// browserMode makes the stand drive a real browser through a resumption.
//
// A browser that loads one page opens one connection and keeps it, so
// there is no second hello to look at — and a second hello is the whole
// point: the one that carries the ticket. The stand answers the page with
// a document that asks for a subresource a second and a half later, and
// closes every connection once its response is out. The browser has to
// open a new connection for the subresource, and this time it offers the
// ticket the first handshake left it.
var browserMode bool

// browserCloseDelay is how long the stand waits before closing a
// connection in the browser mode: the response has to reach the browser
// first, and the page has to start running before the connection goes
// away.
const browserCloseDelay = 500 * time.Millisecond

func main() {
	addr := flag.String("addr", "127.0.0.1:8443", "UDP address to listen on")
	certFile := flag.String("cert", "", "TLS certificate (PEM)")
	keyFile := flag.String("key", "", "TLS key (PEM)")
	out := flag.String("out", "-", "where the reports go (- is stdout)")
	wait := flag.Duration("wait", 0, "stop after this long (0 = until interrupted)")
	flag.BoolVar(&verbose, "v", false, "log what happens on every connection")
	flag.BoolVar(&browserMode, "browser", false, "drive a real browser through a resumption")
	flag.Parse()

	cert, err := utls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("load the certificate: %v", err)
	}
	tlsConf := h3http3.ConfigureTLSConfig(&utls.Config{
		Certificates: []utls.Certificate{cert},
		NextProtos:   []string{"h3"},
	})

	sink := os.Stdout
	if *out != "-" {
		f, err := os.Create(*out)
		if err != nil {
			log.Fatalf("open the report file: %v", err)
		}
		defer f.Close()
		sink = f
	}

	pc, err := net.ListenPacket("udp", *addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if *wait > 0 {
		go func() {
			time.Sleep(*wait)
			cancel()
		}()
	}

	log.Printf("h3sniff listening on %s", pc.LocalAddr())
	if err := serve(ctx, pc, tlsConf, sink); err != nil && ctx.Err() == nil {
		log.Fatalf("serve: %v", err)
	}
}

// serve runs the stand until the context is cancelled.
func serve(ctx context.Context, pc net.PacketConn, tlsConf *utls.Config, sink io.Writer) error {
	return serveSniffer(ctx, pc, tlsConf, newSniffer(sink))
}

// serveSniffer runs the stand on a sniffer the caller keeps: a test needs
// to see what the stand did, not only what it reported.
func serveSniffer(ctx context.Context, pc net.PacketConn, tlsConf *utls.Config, sniffer *sniffer) error {
	ln, err := h3quic.Listen(&sniffConn{PacketConn: pc, sniffer: sniffer}, tlsConf, &h3quic.Config{})
	if err != nil {
		return err
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go handle(conn, sniffer)
	}
}

// handle serves one connection: the client's control stream (its SETTINGS),
// its requests (their headers), and the responses that keep the browser
// happy.
func handle(conn *h3quic.Conn, sniffer *sniffer) {
	// The context of the connection: it lives as long as the connection
	// does. The loop that accepts the streams has to outlive the first
	// request — a stand that stops there answers one request per
	// connection, and the second request of a client waits for the idle
	// timeout.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-conn.Context().Done()
		cancel()
	}()

	// The server's own control stream: the SETTINGS frame has to be the
	// first frame of it.
	ctrl, err := conn.OpenUniStreamSync(ctx)
	if err != nil {
		logf("control stream: %v", err)
		return
	}
	if _, err := ctrl.Write(serverControlStream()); err != nil {
		logf("write the control stream: %v", err)
		return
	}
	logf("connection from %s", conn.RemoteAddr())

	var settingsMu sync.Mutex
	settings := map[string]uint64{}
	settingsDone := make(chan struct{})
	var settingsOnce sync.Once

	go func() {
		for {
			str, err := conn.AcceptUniStream(ctx)
			if err != nil {
				return
			}
			go readControlStream(str, func(parsed map[uint64]uint64) {
				settingsOnce.Do(func() {
					settingsMu.Lock()
					for id, value := range parsed {
						settings[fmt.Sprintf("%d", id)] = value
					}
					settingsMu.Unlock()
					close(settingsDone)
				})
			})
		}
	}()

	headers := make(chan map[string]string, 1)
	go func() {
		for {
			str, err := conn.AcceptStream(ctx)
			if err != nil {
				return
			}
			go func() {
				defer str.Close()
				got := readRequestHeaders(str)
				logf("request headers: %v", got)
				select {
				case headers <- got:
				default:
				}
				writeResponse(str, responseBody(got))
				if browserMode {
					// The connection goes away once the response is out,
					// so the next request of the browser opens a new one.
					// The graceful code is the one a browser reconnects
					// from without a backoff.
					time.AfterFunc(browserCloseDelay, func() {
						_ = conn.CloseWithError(h3quic.ApplicationErrorCode(0), "canary")
						sniffer.noteClosed()
					})
				}
			}()
		}
	}()

	// The report is about the first request, and it must not wait for
	// ever: a client that opens a connection and says nothing gets no
	// report.
	first, cancelFirst := context.WithTimeout(ctx, 60*time.Second)
	defer cancelFirst()

	var gotHeaders map[string]string
	select {
	case gotHeaders = <-headers:
	case <-settingsDone:
		select {
		case gotHeaders = <-headers:
		case <-time.After(5 * time.Second):
		}
	case <-first.Done():
		return
	}

	// The settings live on the control stream, which the client opens next
	// to its request: a report without them would be half a fingerprint.
	select {
	case <-settingsDone:
	case <-time.After(3 * time.Second):
		logf("the client sent no settings")
	case <-first.Done():
		return
	}

	rep := sniffer.report(conn.RemoteAddr().String())
	if gotHeaders != nil {
		rep.UserAgent = gotHeaders["user-agent"]
	}
	settingsMu.Lock()
	rep.Settings = settings
	settingsMu.Unlock()
	sniffer.publish(rep)

	// The connection stays served until it is closed: a client may send
	// more requests over it, and the stand has to answer them.
	<-ctx.Done()
}

// readControlStream reads the client's control stream and hands the
// SETTINGS frame to the callback.
func readControlStream(str *h3quic.ReceiveStream, onSettings func(map[uint64]uint64)) {
	// The first byte of the stream is its type; the SETTINGS frame follows.
	var head [1]byte
	if _, err := str.Read(head[:]); err != nil {
		return
	}
	if head[0] != 0x00 {
		// A QPACK encoder or decoder stream: this server uses only the
		// static table, so there is nothing to do with them.
		return
	}
	data := []byte{head[0]}
	buf := make([]byte, 4096)
	for {
		n, err := str.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
			if parsed, complete := quicwire.H3Settings(data); complete {
				onSettings(parsed)
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// readRequestHeaders reads the request's HEADERS frame and decodes it.
func readRequestHeaders(str *h3quic.Stream) map[string]string {
	out := map[string]string{}
	decoder := qpack.NewDecoder()
	buf := make([]byte, 4096)
	var data []byte
	for {
		n, err := str.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
			if fields, ok := decodeHeaders(decoder, data); ok {
				for _, hf := range fields {
					out[strings.ToLower(hf.Name)] = hf.Value
				}
				return out
			}
		}
		if err != nil {
			return out
		}
	}
}

// decodeHeaders decodes a header block: the frame type and the length come
// first, then the QPACK block.
func decodeHeaders(decoder *qpack.Decoder, data []byte) ([]qpack.HeaderField, bool) {
	pos := 0
	frameType, n, ok := quicwire.ReadVarint(data[pos:])
	if !ok {
		return nil, false
	}
	pos += n
	length, n, ok := quicwire.ReadVarint(data[pos:])
	if !ok {
		return nil, false
	}
	pos += n
	if pos+int(length) > len(data) {
		return nil, false
	}
	if frameType != 0x01 { // HEADERS
		return nil, true
	}
	// The decoder keeps its place inside the block: one call decodes one
	// field, until it says there is nothing left.
	var fields []qpack.HeaderField
	next := decoder.Decode(data[pos : pos+int(length)])
	for {
		field, err := next()
		if err != nil {
			break
		}
		fields = append(fields, field)
	}
	return fields, true
}

// serverControlStream is the head of the server's control stream: the
// stream type and the SETTINGS frame.
func serverControlStream() []byte {
	// SETTINGS_MAX_FIELD_SECTION_SIZE = 262144, QPACK_BLOCKED_STREAMS = 100.
	payload := []byte{0x06, 0x80, 0x04, 0x00, 0x00, 0x07, 0x40, 0x64}
	out := []byte{0x00, 0x04}
	out = append(out, byte(len(payload)))
	return append(out, payload...)
}

// browserPage is the document the stand serves to a real browser. It asks
// for a subresource twice, and the stand closes the connection between the
// requests, so each of them is a connection of its own — the second and
// the third with the ticket of the first.
//
// The response names itself: the stand sends the content type
// "text/html; charset=utf-8" with the page, so the browser runs the
// script and asks for the subresources.
const browserPage = `<!DOCTYPE html><title>site-mimic canary</title>
<script>
setTimeout(function(){var i=new Image();i.src="/canary-1.png"},1500);
setTimeout(function(){var i=new Image();i.src="/canary-2.png"},3000);
</script>
`

// responseBody is what the stand answers with: the driving page for the
// root, a short answer for everything else. The subresources of the page
// must not get the page back, or the browser would keep asking for more
// of them.
func responseBody(headers map[string]string) string {
	if !browserMode {
		return "ok\n"
	}
	if path := headers[":path"]; path != "" && path != "/" {
		return "ok\n"
	}
	return browserPage
}

// The HEADERS frames of the stand's answer.
//
// The payload of a frame is the header block prefix (the required insert
// count and the delta base, both zero — the static table is enough) and
// then the indexed field lines: the static table entry 25, which is
// ":status: 200", and, in the browser mode, the entry 52, which is
// "content-type: text/html; charset=utf-8".
var (
	responseHeaders        = []byte{0x01, 0x03, 0x00, 0x00, 0xd9}
	browserResponseHeaders = []byte{0x01, 0x04, 0x00, 0x00, 0xd9, 0xf4}
)

// writeResponse answers the request with a static-table :status 200 and the
// given body.
func writeResponse(str *h3quic.Stream, body string) {
	headers := responseHeaders
	if browserMode {
		headers = browserResponseHeaders
	}
	if _, err := str.Write(headers); err != nil {
		return
	}
	frame := []byte{0x00, byte(len(body))}
	frame = append(frame, body...)
	str.Write(frame)
	str.Close()
}

// sniffConn is the socket the QUIC stack reads from. Every datagram that
// passes through it is offered to the sniffer first.
type sniffConn struct {
	net.PacketConn
	sniffer *sniffer
}

func (c *sniffConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err == nil {
		c.sniffer.observe(addr, p[:n])
	}
	return n, addr, err
}

// sniffer keeps one QUIC connection per client address and remembers what
// each of them sent.
type sniffer struct {
	mu sync.Mutex
	// conns is keyed by the client's address and the connection's first
	// destination connection id: a client that opens one socket for many
	// origins runs several connections over it, and they must not be mixed
	// up.
	conns map[string]*quicwire.Connection
	// hellos holds the hellos of one address in the order they arrived.
	hellos map[string][]*mimic.ClientHello
	// closed counts the connections the stand closed on its own.
	closed int
	sink   io.Writer
}

func newSniffer(sink io.Writer) *sniffer {
	return &sniffer{
		conns:  map[string]*quicwire.Connection{},
		hellos: map[string][]*mimic.ClientHello{},
		sink:   sink,
	}
}

// observe offers one datagram to the connection it belongs to.
//
// The connection is keyed by the client's address. A browser opens one
// socket for many origins, so two of its connections share the key and the
// newer hello replaces the older one in the report. The hello of the
// connection that is reported is the one seen last for that address; a
// client that opens a socket per connection (or a test) sees one report per
// connection.
func (s *sniffer) observe(addr net.Addr, datagram []byte) {
	address := addr.String()
	// The connection's identity is the client's address and the
	// destination connection id of its first Initial packet.
	dcid, ok := quicwire.DestinationConnectionID(datagram)
	if !ok {
		return
	}
	key := address + "\x00" + string(dcid)
	s.mu.Lock()
	conn := s.conns[key]
	if conn == nil {
		conn = quicwire.NewConnection()
		s.conns[key] = conn
	}
	s.mu.Unlock()

	if !conn.AddInitial(datagram) {
		return
	}
	msg, ok := conn.ClientHello()
	if !ok {
		return
	}
	hello, err := mimic.ParseClientHello(helloRecord(msg))
	if err != nil {
		return
	}
	s.mu.Lock()
	s.hellos[address] = append(s.hellos[address], hello)
	s.mu.Unlock()
}

// report builds the report of one connection.
func (s *sniffer) report(client string) report {
	s.mu.Lock()
	var hello *mimic.ClientHello
	if seen := s.hellos[client]; len(seen) > 0 {
		// The newest hello of that address: a client that opened several
		// connections over one socket is reported on its last one.
		hello = seen[len(seen)-1]
	}
	s.mu.Unlock()
	rep := report{Client: client}
	if hello == nil {
		rep.Error = "no ClientHello"
		return rep
	}
	rep.JA4 = hello.JA4QUIC()
	rep.JA3, _ = hello.JA3()
	rep.SNI = hello.SNI
	rep.ALPN = hello.ALPN
	rep.Extensions = len(hello.Extensions)
	rep.CipherSuites = len(hello.CipherSuites)
	for _, id := range hello.Extensions {
		rep.ExtensionIDs = append(rep.ExtensionIDs, fmt.Sprintf("%#04x", id))
	}
	// The payload of every extension, in hex. The identifiers say which
	// extensions a client sends; the payload says what it puts in them, and
	// that is the part a captured fingerprint cannot be reconstructed from.
	rep.ExtensionData = map[string]string{}
	for id, data := range hello.ExtensionData {
		rep.ExtensionData[fmt.Sprintf("%#04x", id)] = hex.EncodeToString(data)
	}
	for _, id := range hello.SigAlgs {
		rep.SigAlgs = append(rep.SigAlgs, fmt.Sprintf("%#04x", id))
	}
	for _, id := range hello.Groups {
		rep.Groups = append(rep.Groups, fmt.Sprintf("%#04x", id))
	}
	rep.TransportParameters = map[string]string{}
	raw, ok := hello.ExtensionData[0x39]
	if !ok {
		return rep
	}
	// The transport parameters as they went on the wire: the ids in Chrome's
	// order, with the GREASE ones included. The map above loses the order.
	rep.TransportParamsRaw = hex.EncodeToString(raw)
	params, err := quicwire.TransportParameters(raw)
	if err != nil {
		rep.Error = err.Error()
		return rep
	}
	for id, value := range params {
		rep.TransportParameters[fmt.Sprintf("%d", id)] = hex.EncodeToString(value)
	}
	return rep
}

// noteClosed counts a connection the stand closed on its own.
func (s *sniffer) noteClosed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed++
}

// closedCount is how many connections the stand closed on its own.
func (s *sniffer) closedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// publish prints one report.
func (s *sniffer) publish(rep report) {
	line, err := json.Marshal(rep)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Fprintln(s.sink, string(line))
}

// logf prints a line when the server runs with -v.
func logf(format string, args ...any) {
	if verbose {
		log.Printf(format, args...)
	}
}

// helloRecord wraps a TLS handshake message in a record header, so the
// library's ClientHello parser can read it — QUIC carries handshake
// messages without records, but the bytes inside are the same.
func helloRecord(msg []byte) []byte {
	rec := []byte{0x16, 0x03, 0x01, byte(len(msg) >> 8), byte(len(msg))}
	return append(rec, msg...)
}
