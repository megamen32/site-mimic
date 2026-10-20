package main

import (
	"bufio"
	"bytes"
	"net"
	"testing"
)

func TestReadProxyV2HeaderParsesSignature(t *testing.T) {
	raw := &bytes.Buffer{}
	raw.WriteString(ppv2Signature)
	raw.WriteByte(0x21) // version 2, PROXY command
	raw.WriteByte(0x11) // AF_INET, STREAM
	raw.WriteByte(0x00) // payload length hi
	raw.WriteByte(0x0c) // payload length lo = 12
	payload := make([]byte, 12)
	copy(payload[0:4], net.ParseIP("192.0.2.7").To4())
	copy(payload[4:8], net.ParseIP("198.51.100.1").To4())
	payload[8], payload[9] = 0x1f, 0x90 // src port 8080
	raw.Write(payload)
	raw.WriteString("\x16\x03\x01tls-record-tail")
	br := bufio.NewReader(raw)
	a, ok, err := readProxyV2Header(br, nil)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if a.IP.String() != "192.0.2.7" || a.Port != 8080 {
		t.Fatalf("addr=%v:%d", a.IP, a.Port)
	}
	rest, _ := br.ReadBytes(0)
	if !bytes.HasPrefix(rest, []byte("\x16\x03\x01")) {
		t.Fatalf("tls record not preserved after header: %q", rest)
	}
}

func TestReadProxyV2HeaderDirectConnection(t *testing.T) {
	tlsFront := append([]byte{0x16, 0x03, 0x01}, bytes.Repeat([]byte{0xAA}, 20)...)
	raw := bytes.NewReader(tlsFront)
	br := bufio.NewReader(raw)
	fallback := &net.TCPAddr{IP: net.ParseIP("192.0.2.4"), Port: 51234}
	a, ok, err := readProxyV2Header(br, fallback)
	if err != nil {
		t.Fatalf("direct conn rejected: %v", err)
	}
	if ok {
		t.Fatal("ok=true on a connection without the proxy signature")
	}
	if a.IP.String() != "192.0.2.4" || a.Port != 51234 {
		t.Fatalf("fallback addr=%v:%d", a.IP, a.Port)
	}
	got, _ := br.ReadBytes(0)
	if !bytes.Equal(got, tlsFront) {
		t.Fatal("front bytes were consumed for a direct connection")
	}
}
