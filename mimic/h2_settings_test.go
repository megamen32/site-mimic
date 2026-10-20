package mimic

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// h2Frame is one HTTP/2 frame: a 9-byte header and its payload.
type h2Frame struct {
	length   uint32
	typ      uint8
	flags    uint8
	streamID uint32
	payload  []byte
}

// readH2Frames reads the frames the client sends after its preface.
//
// The exact path's HTTP/2 layer is the headless client's: its SETTINGS
// frame and the window it opens with are Chrome's, and a server can
// fingerprint them. The fork's own test suite asserts the values, but this
// repository's CI never runs that suite — so a fork bump could change the
// frame and nothing here would notice.
func readH2Frames(conn net.Conn, want int) ([]h2Frame, error) {
	preface := make([]byte, len(http2ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil {
		return nil, fmt.Errorf("read the preface: %w", err)
	}
	if string(preface) != http2ClientPreface {
		return nil, fmt.Errorf("preface = %q, want %q", preface, http2ClientPreface)
	}
	frames := make([]h2Frame, 0, want)
	header := make([]byte, 9)
	for len(frames) < want {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(conn, header); err != nil {
			break
		}
		length := uint32(header[0])<<16 | uint32(header[1])<<8 | uint32(header[2])
		f := h2Frame{
			length:   length,
			typ:      header[3],
			flags:    header[4],
			streamID: binary.BigEndian.Uint32(header[5:9]) & 0x7fffffff,
		}
		if length > 0 {
			f.payload = make([]byte, length)
			if _, err := io.ReadFull(conn, f.payload); err != nil {
				break
			}
		}
		frames = append(frames, f)
	}
	return frames, nil
}

// http2ClientPreface is the client connection preface of HTTP/2.
const http2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

const (
	h2FrameSettings     = 0x4
	h2FrameWindowUpdate = 0x8
)

// TestExactPathH2Settings pins the HTTP/2 fingerprint of the exact path: the
// SETTINGS the client sends and the connection window it opens with.
//
// The values are Chrome's. They are what a server can fingerprint, and the
// repository claimed them as a match without pinning them anywhere in this
// tree — the assertion lived in the dependency's own suite, which this
// repository's CI never runs.
func TestExactPathH2Settings(t *testing.T) {
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := certServer.TLS.Certificates[0]
	certServer.Close()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type frameResult struct {
		frames []h2Frame
		err    error
	}
	frames := make(chan frameResult, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			frames <- frameResult{err: err}
			return
		}
		defer conn.Close()
		f, err := readH2Frames(conn, 2)
		frames <- frameResult{frames: f, err: err}
	}()

	profile := Profile{
		Name:           "chrome-exact-h2",
		TLSClientHello: "chrome_exact",
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/152.0.0.0",
	}
	client, err := New(profile, WithInsecureTLS())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.CloseIdleConnections()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split the server address: %v", err)
	}
	url := fmt.Sprintf("https://127.0.0.1:%s/", port)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	go func() {
		// The request never completes — the server speaks no h2 — but the
		// frames the client sends first are what this test reads.
		_, _ = client.Do(req)
	}()

	var got []h2Frame
	select {
	case res := <-frames:
		if res.err != nil {
			t.Fatalf("read the client's frames: %v", res.err)
		}
		got = res.frames
	case <-time.After(10 * time.Second):
		t.Fatal("the client sent no frames")
	}
	if len(got) == 0 {
		t.Fatal("the client sent no frames")
	}

	settings := map[uint16]uint32{}
	for _, f := range got {
		switch f.typ {
		case h2FrameSettings:
			for i := 0; i+6 <= len(f.payload); i += 6 {
				id := binary.BigEndian.Uint16(f.payload[i : i+2])
				value := binary.BigEndian.Uint32(f.payload[i+2 : i+6])
				settings[id] = value
			}
		case h2FrameWindowUpdate:
			if f.streamID != 0 || len(f.payload) < 4 {
				continue
			}
			inc := binary.BigEndian.Uint32(f.payload[:4]) & 0x7fffffff
			want := uint32(15663105)
			if inc != want {
				t.Errorf("connection WINDOW_UPDATE = %d, want %d", inc, want)
			}
		}
	}

	want := map[uint16]uint32{
		0x1: 65536,   // HEADER_TABLE_SIZE
		0x2: 0,       // ENABLE_PUSH
		0x4: 6291456, // INITIAL_WINDOW_SIZE
		0x6: 262144,  // MAX_HEADER_LIST_SIZE
	}
	for id, wantValue := range want {
		gotValue, ok := settings[id]
		if !ok {
			t.Errorf("SETTINGS 0x%02x missing", id)
			continue
		}
		if gotValue != wantValue {
			t.Errorf("SETTINGS 0x%02x = %d, want %d", id, gotValue, wantValue)
		}
	}
}
