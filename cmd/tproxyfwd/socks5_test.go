package main

import (
	"bytes"
	"testing"
)

// TestBuildConnectRequest_WireFormat locks the SOCKS5 CONNECT request layout
// (RFC 1928 section 3):
//
//	VER CMD RSV ATYP | LEN(1 byte) | HOST | PORT(2 bytes)
//
// The domain length is one byte. A two-byte length looks plausible in a
// struct literal and passes every review, but the proxy reads the high
// byte (0x00) as the length, sees an empty host and a port made of the
// leftover length byte plus the first host character. That is exactly what
// happened here: a live capture against a rooted phone produced
// "Error in TCP connection to :3889" for the destination 155.212.204.150:7
// (0x0F = length of the address, 0x31 = '1').
func TestBuildConnectRequest_WireFormat(t *testing.T) {
	host, port := "155.212.204.150", 7
	req, err := buildConnectRequest(host, port)
	if err != nil {
		t.Fatalf("buildConnectRequest: %v", err)
	}

	want := []byte{0x05, 0x01, 0x00, 0x03, 0x0f}
	want = append(want, host...)
	want = append(want, 0x00, 0x07)

	if !bytes.Equal(req, want) {
		t.Fatalf("request bytes:\n got %x\nwant %x", req, want)
	}

	// The length field is exactly one byte: req[4] is the length, req[5] is
	// already the first character of the host.
	if int(req[4]) != len(host) {
		t.Errorf("length byte: got %d, want %d", req[4], len(host))
	}
	if req[5] != host[0] {
		t.Errorf("byte after the length must be the first host character, got %#02x", req[5])
	}
	if got := len(req); got != 5+len(host)+2 {
		t.Errorf("request length: got %d, want %d", got, 5+len(host)+2)
	}
}

func TestBuildConnectRequest_Errors(t *testing.T) {
	if _, err := buildConnectRequest("", 443); err == nil {
		t.Error("empty host must be rejected")
	}
	if _, err := buildConnectRequest(string(make([]byte, 256)), 443); err == nil {
		t.Error("host longer than 255 bytes must be rejected")
	}
	if _, err := buildConnectRequest("example.com", 0); err == nil {
		t.Error("port 0 must be rejected")
	}
	if _, err := buildConnectRequest("example.com", 70000); err == nil {
		t.Error("port above 65535 must be rejected")
	}
}
