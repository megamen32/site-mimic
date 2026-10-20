package mimic

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
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
)

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

	p := Profile{Name: "chrome-152-h3", TLSClientHello: "chrome_152"}
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
				if _, complete := h3SettingsFrom(data); complete {
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

// h3SettingsFrom decodes the SETTINGS frame at the head of a control stream
// and reports whether the frame is complete.
func h3SettingsFrom(raw []byte) (map[uint64]uint64, bool) {
	settings := map[uint64]uint64{}
	if len(raw) == 0 {
		return settings, false
	}
	streamType, pos, ok := readVarint(raw)
	if !ok || streamType != 0x00 {
		return settings, false
	}
	if pos >= len(raw) {
		return settings, false
	}
	frameType, n, ok := readVarint(raw[pos:])
	if !ok {
		return settings, false
	}
	pos += n
	if frameType != 0x04 {
		return settings, false
	}
	length, n, ok := readVarint(raw[pos:])
	if !ok {
		return settings, false
	}
	pos += n
	if pos+int(length) > len(raw) {
		return settings, false
	}
	payload := raw[pos : pos+int(length)]
	for len(payload) > 0 {
		id, n, ok := readVarint(payload)
		if !ok {
			return settings, false
		}
		payload = payload[n:]
		value, n, ok := readVarint(payload)
		if !ok {
			return settings, false
		}
		payload = payload[n:]
		settings[id] = value
	}
	return settings, true
}

// decodeH3ControlStream decodes the control stream: the stream type, then
// every frame, and the SETTINGS frame as identifier/value pairs.
func decodeH3ControlStream(t *testing.T, raw []byte) map[uint64]uint64 {
	t.Helper()
	if len(raw) == 0 {
		t.Fatal("empty control stream")
	}
	streamType, pos, ok := readVarint(raw)
	if !ok {
		t.Fatal("the control stream has no stream type")
	}
	if streamType != 0x00 {
		t.Fatalf("stream type 0x%x, want the control stream 0x00", streamType)
	}
	settings := map[uint64]uint64{}
	for pos < len(raw) {
		frameType, n, ok := readVarint(raw[pos:])
		if !ok {
			t.Fatal("truncated frame type")
		}
		pos += n
		length, n, ok := readVarint(raw[pos:])
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
			id, n, ok := readVarint(payload)
			if !ok {
				t.Fatal("truncated setting id")
			}
			payload = payload[n:]
			value, n, ok := readVarint(payload)
			if !ok {
				t.Fatal("truncated setting value")
			}
			payload = payload[n:]
			settings[id] = value
		}
	}
	return settings
}

// readVarint reads a QUIC variable-length integer and returns its value and
// the number of bytes it took.
func readVarint(b []byte) (uint64, int, bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	switch b[0] >> 6 {
	case 0:
		return uint64(b[0]), 1, true
	case 1:
		if len(b) < 2 {
			return 0, 0, false
		}
		return uint64(b[0]&0x3f)<<8 | uint64(b[1]), 2, true
	case 2:
		if len(b) < 4 {
			return 0, 0, false
		}
		return uint64(b[0]&0x3f)<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3]), 4, true
	default:
		if len(b) < 8 {
			return 0, 0, false
		}
		var v uint64
		for i := 0; i < 8; i++ {
			v = v<<8 | uint64(b[i])
		}
		return v & 0x3fffffffffffffff, 8, true
	}
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

// TestChromeQUICClientHelloOnTheWire reads the QUIC Initial the client sends,
// decrypts it and fingerprints the ClientHello inside.
//
// The reference is the phone capture: the real Chrome's QUIC JA4 is
// q13d0311h3_55b375c5d22e_653d80c3fe9d. The hello this path sends has to
// fingerprint the same, or the h3 wire announces a different browser than
// the TCP one.
func TestChromeQUICClientHelloOnTheWire(t *testing.T) {
	hello := captureQUICClientHello(t)
	ja4 := ja4QUIC(hello)
	t.Logf("QUIC ClientHello JA4 on the wire: %s", ja4)
	if got, want := ja4, "q13d0311h3_55b375c5d22e_653d80c3fe9d"; got != want {
		t.Errorf("QUIC JA4 = %s, want %s (the phone's real Chrome)", got, want)
	}
	if got, want := len(hello.Extensions), 11; got != want {
		t.Errorf("the hello carries %d extensions, want %d", got, want)
	}
	if got, want := len(hello.CipherSuites), 3; got != want {
		t.Errorf("the hello offers %d cipher suites, want %d", got, want)
	}
	if len(hello.ALPN) != 1 || hello.ALPN[0] != "h3" {
		t.Errorf("hello ALPN = %v, want [h3]", hello.ALPN)
	}
}

// TestChromeQUICTransportParametersOnTheWire compares the transport
// parameters the client puts on the wire with the bytes a real Chrome sent,
// committed as a fixture.
//
// The GREASE parameter's id and payload are random per connection on both
// sides, so the parameters are compared as id -> value pairs, with the
// GREASE one matched by its shape. The version_information parameter carries
// a GREASE version, which Chrome draws per connection: the captured value is
// one sample, and the value on the wire is checked against the same scheme.
func TestChromeQUICTransportParametersOnTheWire(t *testing.T) {
	captured, err := os.ReadFile("testdata/chrome_quic_transport_parameters.bin")
	if err != nil {
		t.Fatalf("read the captured transport parameters: %v", err)
	}
	hello := captureQUICClientHello(t)
	raw, ok := hello.ExtensionData[0x39]
	if !ok {
		t.Fatal("the hello has no quic transport parameters extension")
	}
	ours := decodeTransportParameters(t, raw)
	theirs := decodeTransportParameters(t, captured)

	nonGREASE := func(m map[uint64][]byte) map[uint64]string {
		out := map[uint64]string{}
		for id, value := range m {
			if isGREASETransportParamID(id) {
				continue
			}
			if id == quicChromeVersionInformationID {
				// The GREASE version inside version_information is drawn
				// per connection, on the browser's side as well, so the
				// captured value is one sample and not a constant. The
				// chosen version and the version list are compared
				// exactly; the GREASE version is compared by its scheme.
				if len(value) != 12 {
					out[id] = hex.EncodeToString(value)
					continue
				}
				out[id] = hex.EncodeToString(value[:8])
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

	// The GREASE version: the same scheme the capture shows — every byte
	// of it ends in 0x0a — but a different value, because Chrome draws it
	// per connection.
	version, ok := ours[quicChromeVersionInformationID]
	if !ok {
		t.Fatal("the transport parameters carry no version_information")
	}
	if len(version) != 12 {
		t.Fatalf("version_information is %d bytes, want 12", len(version))
	}
	if got, want := hex.EncodeToString(version[:8]), "0000000100000001"; got != want {
		t.Errorf("version_information = %s, want the chosen version 1 and the version list", got)
	}
	for i, b := range version[8:] {
		if b&0x0f != 0x0a {
			t.Errorf("byte %d of the GREASE version is 0x%02x, want the low nibble 0x0a", i, b)
		}
	}

	// The GREASE parameter: a random id, a random payload.
	var greaseID uint64
	var greaseValue []byte
	for id, value := range ours {
		if isGREASETransportParamID(id) {
			greaseID, greaseValue = id, value
		}
	}
	if greaseID == 0 {
		t.Error("the transport parameters carry no GREASE parameter")
	}
	var capturedGREASE []byte
	for id, value := range theirs {
		if isGREASETransportParamID(id) {
			capturedGREASE = value
		}
	}
	if len(capturedGREASE) == 0 {
		t.Fatal("the captured transport parameters carry no GREASE parameter")
	}
	if len(greaseValue) > 15 {
		t.Errorf("the GREASE parameter carries %d bytes, want at most 15", len(greaseValue))
	}
}

// captureQUICClientHello makes the h3 client send a QUIC Initial to a
// socket that answers nothing, and returns the ClientHello inside it.
func captureQUICClientHello(t *testing.T) *ClientHello {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	port := pc.LocalAddr().(*net.UDPAddr).Port

	p := Profile{Name: "chrome-152-h3", TLSClientHello: "chrome_152"}
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
	crypto := map[uint64][]byte{}
	for time.Now().Before(deadline) {
		pc.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			continue
		}
		datagram := append([]byte(nil), buf[:n]...)
		for _, frame := range quicInitialFrames(t, datagram) {
			crypto[frame.offset] = frame.data
		}
		if msg, ok := clientHelloFromCrypto(crypto); ok {
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

// quicInitialFrame is one CRYPTO frame of a QUIC Initial packet.
type quicInitialFrame struct {
	offset uint64
	data   []byte
}

// quicInitialFrames decrypts a QUIC Initial packet and returns its CRYPTO
// frames.
func quicInitialFrames(t *testing.T, datagram []byte) []quicInitialFrame {
	t.Helper()
	dcid, header, pnAndPayload, ok := parseLongHeader(datagram)
	if !ok {
		return nil
	}
	secret, err := hkdf.Extract(sha256.New, dcid, quicV1InitialSalt)
	if err != nil {
		t.Fatalf("hkdf extract: %v", err)
	}
	clientSecret, err := hkdf.Expand(sha256.New, secret, string(expandLabel("client in", 32)), 32)
	if err != nil {
		t.Fatalf("hkdf expand: %v", err)
	}
	key, err := hkdf.Expand(sha256.New, clientSecret, string(expandLabel("quic key", 16)), 16)
	if err != nil {
		t.Fatalf("hkdf expand key: %v", err)
	}
	iv, err := hkdf.Expand(sha256.New, clientSecret, string(expandLabel("quic iv", 12)), 12)
	if err != nil {
		t.Fatalf("hkdf expand iv: %v", err)
	}
	hp, err := hkdf.Expand(sha256.New, clientSecret, string(expandLabel("quic hp", 16)), 16)
	if err != nil {
		t.Fatalf("hkdf expand hp: %v", err)
	}
	payload, ok := decryptInitialPayload(t, header, pnAndPayload, key, iv, hp)
	if !ok {
		return nil
	}
	return cryptoFrames(payload)
}

// quicV1InitialSalt is the salt RFC 9001 defines for QUIC v1.
var quicV1InitialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

// expandLabel builds the HKDF-ExpandLabel info of TLS 1.3 (RFC 8446 §7.1).
func expandLabel(label string, length int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 2+1+len(full)+1)
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	return info
}

// parseLongHeader returns the destination connection id, the header bytes
// without the packet number, and the packet number with the payload.
func parseLongHeader(datagram []byte) ([]byte, []byte, []byte, bool) {
	if len(datagram) < 6 || datagram[0]&0x80 == 0 {
		return nil, nil, nil, false
	}
	if (datagram[0]&0x30)>>4 != 0 {
		return nil, nil, nil, false // not an Initial
	}
	pos := 5
	dcidLen := int(datagram[pos])
	pos++
	if pos+dcidLen > len(datagram) {
		return nil, nil, nil, false
	}
	dcid := datagram[pos : pos+dcidLen]
	pos += dcidLen
	scidLen := int(datagram[pos])
	pos++
	if pos+scidLen > len(datagram) {
		return nil, nil, nil, false
	}
	pos += scidLen
	tokenLen, n, ok := readVarint(datagram[pos:])
	if !ok {
		return nil, nil, nil, false
	}
	pos += n + int(tokenLen)
	length, n, ok := readVarint(datagram[pos:])
	if !ok {
		return nil, nil, nil, false
	}
	pos += n
	if pos+int(length) > len(datagram) {
		return nil, nil, nil, false
	}
	return dcid, datagram[:pos], datagram[pos : pos+int(length)], true
}

// decryptInitialPayload removes the header protection and decrypts the
// payload of a QUIC Initial packet.
func decryptInitialPayload(t *testing.T, header, pnAndPayload, key, iv, hp []byte) ([]byte, bool) {
	t.Helper()
	if len(pnAndPayload) < 4+16+16 {
		return nil, false
	}
	block, err := aes.NewCipher(hp)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	sample := pnAndPayload[4:20]
	mask := make([]byte, 16)
	block.Encrypt(mask, sample)

	first := header[0] ^ (mask[0] & 0x0f)
	if (first&0x30)>>4 != 0 {
		return nil, false
	}
	pnLen := int(first&0x03) + 1
	pnBytes := make([]byte, pnLen)
	for i := 0; i < pnLen; i++ {
		pnBytes[i] = pnAndPayload[i] ^ mask[1+i]
	}
	pn := uint64(0)
	for _, b := range pnBytes {
		pn = pn<<8 | uint64(b)
	}

	fullHeader := append([]byte{first}, header[1:]...)
	fullHeader = append(fullHeader, pnBytes...)

	gcm, err := cipher.NewGCM(blockForKey(t, key))
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	plain, err := gcm.Open(nil, nonce, pnAndPayload[pnLen:], fullHeader)
	if err != nil {
		return nil, false
	}
	return plain, true
}

// blockForKey returns an AES block cipher for the given key.
func blockForKey(t *testing.T, key []byte) cipher.Block {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	return block
}

// cryptoFrames returns the CRYPTO frames of a decrypted QUIC payload.
//
// A CRYPTO frame carries its offset before its length (RFC 9000 §19.6), and
// both are variable-length integers.
func cryptoFrames(payload []byte) []quicInitialFrame {
	var frames []quicInitialFrame
	pos := 0
	for pos < len(payload) {
		frameType, n, ok := readVarint(payload[pos:])
		if !ok {
			return frames
		}
		pos += n
		if frameType == 0x00 || frameType == 0x01 {
			// PADDING and PING carry no length and no payload.
			continue
		}
		if frameType == 0x06 {
			offset, offsetLen, ok := readVarint(payload[pos:])
			if !ok {
				return frames
			}
			pos += offsetLen
			length, lengthLen, ok := readVarint(payload[pos:])
			if !ok {
				return frames
			}
			pos += lengthLen
			if pos+int(length) > len(payload) {
				return frames
			}
			frames = append(frames, quicInitialFrame{
				offset: offset,
				data:   append([]byte(nil), payload[pos:pos+int(length)]...),
			})
			pos += int(length)
			continue
		}
		length, n, ok := readVarint(payload[pos:])
		if !ok {
			return frames
		}
		pos += n
		if pos+int(length) > len(payload) {
			return frames
		}
		pos += int(length)
	}
	return frames
}

// clientHelloFromCrypto assembles the CRYPTO frames into the TLS handshake
// stream and returns the ClientHello when it is complete.
func clientHelloFromCrypto(frames map[uint64][]byte) ([]byte, bool) {
	size := uint64(0)
	for offset, data := range frames {
		if offset+uint64(len(data)) > size {
			size = offset + uint64(len(data))
		}
	}
	if size < 4 {
		return nil, false
	}
	stream := make([]byte, size)
	for offset, data := range frames {
		copy(stream[offset:], data)
	}
	length := uint64(stream[1])<<16 | uint64(stream[2])<<8 | uint64(stream[3])
	if uint64(len(stream)) < 4+length {
		return nil, false
	}
	// The handshake message with its four-byte header: the type is 1
	// (ClientHello) and the three-byte length follows it.
	return stream[:4+length], true
}
