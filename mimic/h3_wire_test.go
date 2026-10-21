package mimic

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	h3quic "github.com/megamen32/headless-client/quic"
	h3http3 "github.com/megamen32/headless-client/quic/http3"
	utls "github.com/refraction-networking/utls"

	"github.com/megamen32/site-mimic/internal/quicwire"
)

// quicVersion1 is QUIC v1, the version Chrome chooses.
const quicVersion1 = uint32(1)

// versionInformationKey reduces the version_information transport parameter
// to the parts that do not change per connection: the chosen version and the
// version the client supports.
//
// The greased version is drawn per connection, and Chrome draws it at either
// end of the available versions list — six captures of Chrome 156 showed
// three of each — so the list is compared as a set, not as a sequence.
func versionInformationKey(value []byte) string {
	if len(value) != 12 {
		return hex.EncodeToString(value)
	}
	chosen := binary.BigEndian.Uint32(value[:4])
	plain := uint32(0)
	for _, v := range []uint32{
		binary.BigEndian.Uint32(value[4:8]),
		binary.BigEndian.Uint32(value[8:12]),
	} {
		if v == quicVersion1 {
			plain = v
		}
	}
	return fmt.Sprintf("%08x:%08x", chosen, plain)
}

// The tests in this file read what the h3 path puts on the wire. They do not
// trust the configuration objects: the control stream is taken from a live
// connection, and the ClientHello is taken from the QUIC Initial packet the
// client sends — decrypted with the Initial keys, which RFC 9001 derives
// from the client's destination connection id, so no secret material is
// needed.

// TestChromeH3SettingsOnTheWire reads the HTTP/3 control stream a real
// connection produces.
//
// The old h3 path sent an empty SETTINGS frame, so this test would have
// found nothing. The values are the ones Chrome sends, measured on the wire
// against a local server (docs/methodology.md).
func TestChromeH3SettingsOnTheWire(t *testing.T) {
	control := make(chan h3Control, 1)
	addr := startH3ControlServer(t, control)

	p := Profile{Name: "chrome-152-h3", TLSClientHello: "chrome_152", UserAgent: chrome152UA}
	client, err := NewHTTP3(p, WithInsecureTLS(),
		WithResolve(map[string]string{"localhost": "127.0.0.1"}))
	if err != nil {
		t.Fatalf("NewHTTP3: %v", err)
	}
	defer client.Transport.(io.Closer).Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://localhost:"+addr+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	clientErr := make(chan error, 1)
	go func() {
		// The server answers nothing; the request is only the vehicle for
		// the connection.
		_, err := client.Do(req)
		clientErr <- err
	}()

	var got h3Control
	select {
	case got = <-control:
	case <-time.After(10 * time.Second):
		t.Fatal("the client sent no control stream")
	}
	if got.err != nil {
		t.Fatalf("the server reported: %v", got.err)
	}
	select {
	case err := <-clientErr:
		t.Logf("the client gave up: %v", err)
	default:
	}
	raw := got.data

	settings := decodeH3ControlStream(t, raw)
	t.Logf("control stream: %s", hex.EncodeToString(raw))

	want := map[uint64]uint64{
		h3SettingQPACKMaxTableCapacity: quicChromeQPACKMaxTableCapacity,
		h3SettingMaxFieldSectionSize:   quicChromeMaxFieldSectionSize,
		h3SettingQPACKBlockedStreams:   quicChromeQPACKBlockedStreams,
		h3SettingH3Datagram:            quicChromeH3Datagram,
	}
	for id, value := range want {
		got, ok := settings[id]
		if !ok {
			t.Errorf("the SETTINGS frame has no 0x%02x setting", id)
			continue
		}
		if got != value {
			t.Errorf("setting 0x%02x = %d, want %d", id, got, value)
		}
	}
	// The GREASE setting Chrome adds: a random id with a random value.
	var grease int
	for id := range settings {
		if isGREASEH3SettingID(id) {
			grease++
		}
	}
	if grease == 0 {
		t.Error("the SETTINGS frame carries no GREASE setting")
	}
}

// TestChromeH3ControlStreamIsNotEmpty pins the regression: an empty SETTINGS
// frame is what the previous h3 path sent, and a server sees it as a
// different client from every browser.
func TestChromeH3ControlStreamIsNotEmpty(t *testing.T) {
	control := make(chan h3Control, 1)
	addr := startH3ControlServer(t, control)

	p := Profile{Name: "chrome-156-h3", TLSClientHello: "chrome_156"}
	client, err := NewHTTP3(p, WithInsecureTLS(),
		WithResolve(map[string]string{"localhost": "127.0.0.1"}))
	if err != nil {
		t.Fatalf("NewHTTP3: %v", err)
	}
	defer client.Transport.(io.Closer).Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://localhost:"+addr+"/", nil)
	clientErr := make(chan error, 1)
	go func() {
		_, err := client.Do(req)
		clientErr <- err
	}()

	var got h3Control
	select {
	case got = <-control:
	case <-time.After(10 * time.Second):
		select {
		case err := <-clientErr:
			t.Fatalf("the client gave up before the control stream arrived: %v", err)
		default:
		}
		t.Fatal("the client sent no control stream")
	}
	if got.err != nil {
		t.Fatalf("the server reported: %v", got.err)
	}
	raw := got.data
	if len(raw) <= 1 {
		t.Fatalf("the control stream carries %d bytes: an empty SETTINGS frame", len(raw))
	}
	settings := decodeH3ControlStream(t, raw)
	if len(settings) == 0 {
		t.Error("the SETTINGS frame is empty")
	}
}

// startH3ControlServer runs a QUIC server that reads the first unidirectional
// stream of the first client and sends its bytes to the channel. It is the
// Go counterpart of the measurement harness in cmd/h3probe.
func startH3ControlServer(t *testing.T, control chan<- h3Control) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	serverTLS := h3http3.ConfigureTLSConfig(&utls.Config{
		Certificates: []utls.Certificate{selfSignedCert(t)},
		NextProtos:   []string{"h3"},
	})
	ln, err := h3quic.Listen(pc, serverTLS, &h3quic.Config{})
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := ln.Accept(ctx)
		if err != nil {
			control <- h3Control{err: err}
			return
		}
		defer conn.CloseWithError(0, "")
		str, err := conn.AcceptUniStream(ctx)
		if err != nil {
			control <- h3Control{err: err}
			return
		}
		// The control stream stays open for the life of the connection, so
		// it is read until the SETTINGS frame is complete — not until the
		// end of the stream.
		buf := make([]byte, 4096)
		var data []byte
		for {
			n, err := str.Read(buf)
			if n > 0 {
				data = append(data, buf[:n]...)
				if _, complete := quicwire.H3Settings(data); complete {
					control <- h3Control{data: data}
					return
				}
			}
			if err != nil {
				control <- h3Control{data: data, err: err}
				return
			}
		}
	}()

	_, port, err := net.SplitHostPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	return port
}

// decodeH3ControlStream decodes the control stream: the stream type, then
// every frame, and the SETTINGS frame as identifier/value pairs.
func decodeH3ControlStream(t *testing.T, raw []byte) map[uint64]uint64 {
	t.Helper()
	if len(raw) == 0 {
		t.Fatal("empty control stream")
	}
	streamType, pos, ok := quicwire.ReadVarint(raw)
	if !ok {
		t.Fatal("the control stream has no stream type")
	}
	if streamType != 0x00 {
		t.Fatalf("stream type 0x%x, want the control stream 0x00", streamType)
	}
	settings := map[uint64]uint64{}
	for pos < len(raw) {
		frameType, n, ok := quicwire.ReadVarint(raw[pos:])
		if !ok {
			t.Fatal("truncated frame type")
		}
		pos += n
		length, n, ok := quicwire.ReadVarint(raw[pos:])
		if !ok {
			t.Fatal("truncated frame length")
		}
		pos += n
		if pos+int(length) > len(raw) {
			t.Fatalf("frame 0x%x claims %d bytes, %d left", frameType, length, len(raw)-pos)
		}
		payload := raw[pos : pos+int(length)]
		pos += int(length)
		if frameType != 0x04 {
			continue
		}
		for len(payload) > 0 {
			id, n, ok := quicwire.ReadVarint(payload)
			if !ok {
				t.Fatal("truncated setting id")
			}
			payload = payload[n:]
			value, n, ok := quicwire.ReadVarint(payload)
			if !ok {
				t.Fatal("truncated setting value")
			}
			payload = payload[n:]
			settings[id] = value
		}
	}
	return settings
}

// isGREASEH3SettingID reports whether the setting id is a GREASE one. Chrome
// draws a random id for the GREASE setting, so the test only looks for the
// shape: a large, non-standard value.
func isGREASEH3SettingID(id uint64) bool {
	switch id {
	case h3SettingQPACKMaxTableCapacity, h3SettingMaxFieldSectionSize,
		h3SettingQPACKBlockedStreams, h3SettingH3Datagram:
		return false
	}
	return id > 0x1f
}

// quicProfileCases is what each profile's QUIC wire must look like: the
// fingerprint of the browser it imitates, the number of extensions, the
// google_connection_options token and the captured transport parameters it
// is checked against.
//
// Every row is a capture, not a design: Chrome 152 and Chrome 155 and
// Chrome 156 on a desktop, Yandex's own browser on a phone. The two
// extensions and the token move with the Chrome release, and the extension
// set moves with it too — Chrome 152 sent 0xCA34 over TCP but not over
// QUIC, Chrome 155 sent it over both.
var quicProfileCases = []struct {
	helloName string
	ja4       string
	exts      int
	gco       string
	tpFixture string
}{
	{
		helloName: "chrome_152",
		ja4:       "q13d0311h3_55b375c5d22e_653d80c3fe9d",
		exts:      11,
		gco:       "4f5249474543435049573258", // ORIGECCPIW2X
		tpFixture: "testdata/chrome_quic_transport_parameters.bin",
	},
	{
		helloName: "chrome_155",
		ja4:       "q13d0312h3_55b375c5d22e_178839b6cec1",
		exts:      12,
		gco:       "4f524947", // ORIG
		tpFixture: "testdata/chrome155_quic_transport_parameters.bin",
	},
	{
		helloName: "chrome_156",
		ja4:       "q13d0313h3_55b375c5d22e_eb028bd37c08",
		exts:      13,
		gco:       "4f5249474e4f4950", // ORIGNOIP
		tpFixture: "testdata/chrome156_quic_transport_parameters.bin",
	},
	{
		helloName: "yandex_browser",
		ja4:       "q13d0311h3_55b375c5d22e_653d80c3fe9d",
		exts:      11,
		gco:       "4f524947", // ORIG
		tpFixture: "testdata/yandex_browser_quic_transport_parameters.bin",
	},
}

// TestChromeQUICClientHelloOnTheWire reads the QUIC Initial the client sends,
// decrypts it and fingerprints the ClientHello inside.
//
// The reference is the capture of the browser the profile imitates: the
// hello this path sends has to fingerprint the same, or the h3 wire
// announces a different browser than the TCP one.
func TestChromeQUICClientHelloOnTheWire(t *testing.T) {
	for _, tc := range quicProfileCases {
		t.Run(tc.helloName, func(t *testing.T) {
			hello := captureQUICClientHello(t, tc.helloName)
			ja4 := hello.JA4QUIC()
			t.Logf("QUIC ClientHello JA4 on the wire: %s", ja4)
			if ja4 != tc.ja4 {
				t.Errorf("QUIC JA4 = %s, want %s", ja4, tc.ja4)
			}
			if got, want := len(hello.Extensions), tc.exts; got != want {
				t.Errorf("the hello carries %d extensions, want %d", got, want)
			}
			if got, want := len(hello.CipherSuites), 3; got != want {
				t.Errorf("the hello offers %d cipher suites, want %d", got, want)
			}
			if len(hello.ALPN) != 1 || hello.ALPN[0] != "h3" {
				t.Errorf("hello ALPN = %v, want [h3]", hello.ALPN)
			}
		})
	}
}

// TestChromeQUICTransportParametersOnTheWire compares the transport
// parameters the client puts on the wire with the bytes a real browser sent,
// committed as a fixture.
//
// The GREASE parameter's id and payload are random per connection on both
// sides, so the parameters are compared as id -> value pairs, with the
// GREASE one matched by its shape. The version_information parameter carries
// a GREASE version, which Chrome draws per connection: the captured value is
// one sample, and the value on the wire is checked against the same scheme.
//
// One parameter is left out on purpose: 0x310B, which Chrome sends only to
// Google's own servers (it is absent from every capture taken against a
// local stand, and present in the ones taken against Google).
func TestChromeQUICTransportParametersOnTheWire(t *testing.T) {
	for _, tc := range quicProfileCases {
		t.Run(tc.helloName, func(t *testing.T) {
			captured, err := os.ReadFile(tc.tpFixture)
			if err != nil {
				t.Fatalf("read the captured transport parameters: %v", err)
			}
			hello := captureQUICClientHello(t, tc.helloName)
			raw, ok := hello.ExtensionData[0x39]
			if !ok {
				t.Fatal("the hello has no quic transport parameters extension")
			}
			ours, err := quicwire.TransportParameters(raw)
			if err != nil {
				t.Fatalf("our transport parameters: %v", err)
			}
			theirs, err := quicwire.TransportParameters(captured)
			if err != nil {
				t.Fatalf("the captured transport parameters: %v", err)
			}

			nonGREASE := func(m map[uint64][]byte) map[uint64]string {
				out := map[uint64]string{}
				for id, value := range m {
					if quicwire.IsGREASEParamID(id) {
						continue
					}
					if id == 0x3127 {
						// Google's own parameter, right next to the
						// google_connection_options one: Chrome sends it
						// to Google's servers only (it is absent from every
						// capture taken against a local stand).
						continue
					}
					if id == quicChromeVersionInformationID {
						// The GREASE version inside version_information is
						// drawn per connection, on the browser's side as
						// well, so the captured value is one sample and not
						// a constant. The chosen version and the version
						// list are compared as a set: Chrome draws the
						// greased version at either end.
						out[id] = versionInformationKey(value)
						continue
					}
					out[id] = hex.EncodeToString(value)
				}
				return out
			}
			got, want := nonGREASE(ours), nonGREASE(theirs)
			if len(got) != len(want) {
				t.Errorf("%d transport parameters, want the captured %d (%v)", len(got), len(want), got)
			}
			for id, wantHex := range want {
				gotHex, ok := got[id]
				if !ok {
					t.Errorf("transport parameter 0x%02x missing", id)
					continue
				}
				if gotHex != wantHex {
					t.Errorf("transport parameter 0x%02x = %s, want the captured %s", id, gotHex, wantHex)
				}
			}

			// The GREASE parameter: a random id, a random payload.
			var greaseID uint64
			var greaseValue []byte
			for id, value := range ours {
				if quicwire.IsGREASEParamID(id) {
					greaseID, greaseValue = id, value
				}
			}
			if greaseID == 0 {
				t.Error("the transport parameters carry no GREASE parameter")
			}
			var capturedGREASE []byte
			for id, value := range theirs {
				if quicwire.IsGREASEParamID(id) {
					capturedGREASE = value
				}
			}
			if len(capturedGREASE) == 0 {
				t.Fatal("the captured transport parameters carry no GREASE parameter")
			}
			if len(greaseValue) > 15 {
				t.Errorf("the GREASE parameter carries %d bytes, want at most 15", len(greaseValue))
			}

			// The token of the release the profile imitates.
			if got, want := got[quicChromeGoogleConnOptionsID], tc.gco; got != want {
				t.Errorf("google_connection_options = %s, want %s", got, want)
			}

			// The GREASE version: the same scheme the capture shows — every
			// byte of it ends in 0x0a — but a different value, because
			// Chrome draws it per connection.
			version, ok := ours[quicChromeVersionInformationID]
			if !ok {
				t.Fatal("the transport parameters carry no version_information")
			}
			if len(version) != 12 {
				t.Fatalf("version_information is %d bytes, want 12", len(version))
			}
			if got, want := versionInformationKey(version), "00000001:00000001"; got != want {
				t.Errorf("version_information = %s, want the chosen version 1 and the version list", got)
			}
			greased := uint32(0)
			for _, v := range []uint32{
				binary.BigEndian.Uint32(version[4:8]),
				binary.BigEndian.Uint32(version[8:12]),
			} {
				if v != quicVersion1 {
					greased = v
				}
			}
			if greased == 0 {
				t.Fatalf("version_information = %s, carries no greased version", hex.EncodeToString(version))
			}
			for i := 0; i < 4; i++ {
				if b := byte(greased >> (24 - 8*i)); b&0x0f != 0x0a {
					t.Errorf("byte %d of the GREASE version is 0x%02x, want the low nibble 0x0a", i, b)
				}
			}
		})
	}
}

// captureQUICClientHello makes the h3 client send a QUIC Initial to a
// socket that answers nothing, and returns the ClientHello inside it.
func captureQUICClientHello(t *testing.T, helloName string) *ClientHello {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	port := pc.LocalAddr().(*net.UDPAddr).Port

	p := Profile{Name: helloName + "-h3", TLSClientHello: helloName}
	client, err := NewHTTP3(p, WithInsecureTLS(), WithDialTimeout(2*time.Second),
		WithResolve(map[string]string{"localhost": "127.0.0.1"}))
	if err != nil {
		t.Fatalf("NewHTTP3: %v", err)
	}
	defer client.Transport.(io.Closer).Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("https://localhost:%d/", port), nil)
	go func() { _, _ = client.Do(req) }()

	deadline := time.Now().Add(5 * time.Second)
	buf := make([]byte, 2048)
	conn := quicwire.NewConnection()
	for time.Now().Before(deadline) {
		pc.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			continue
		}
		datagram := append([]byte(nil), buf[:n]...)
		conn.AddInitial(datagram)
		if msg, ok := conn.ClientHello(); ok {
			hello, err := ParseClientHello(helloRecord(msg))
			if err != nil {
				t.Fatalf("parse client hello: %v", err)
			}
			return hello
		}
	}
	t.Fatal("the client sent no complete ClientHello")
	return nil
}

// h3Control is what the control-stream server reports: the bytes of the
// control stream, or the error that stopped it.
type h3Control struct {
	data []byte
	err  error
}
