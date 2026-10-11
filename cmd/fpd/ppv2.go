package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

// clientAddr is the real client address learned from the proxy-v2 header
// haproxy prepends (send-proxy-v2).
type clientAddr struct {
	IP    net.IP
	Port  int
	Local bool // PROXY command, addresses meaningless
}

var ppv2Signature = "\r\n\r\n\x00\r\nQUIT\n"

// readProxyV2Header consumes a PROXY v2 header when the connection front
// carries the signature (haproxy send-proxy-v2). Direct connections without
// the header are accepted too: nothing is consumed (the bytes belong to the
// TLS record), ok=false is returned and the client address falls back to the
// TCP peer. ok=true marks a parsed proxy header.
func readProxyV2Header(br *bufio.Reader, fallback net.Addr) (a clientAddr, ok bool, err error) {
	head, err := br.Peek(16)
	if err != nil {
		return a, false, err
	}
	if string(head[:12]) != ppv2Signature {
		if fallback != nil {
			if host, ps, serr := net.SplitHostPort(fallback.String()); serr == nil {
				a.IP = net.ParseIP(host)
				a.Port, _ = strconv.Atoi(ps)
			}
		}
		return a, false, nil
	}
	if _, err := br.Discard(16); err != nil {
		return a, false, err
	}
	verCmd := head[12]
	if verCmd>>4 != 2 {
		return a, false, fmt.Errorf("unsupported proxy version %d", verCmd>>4)
	}
	cmd := verCmd & 0x0f
	fam := head[13]
	length := int(binary.BigEndian.Uint16(head[14:16]))
	payload := make([]byte, length)
	if _, err := io.ReadFull(br, payload); err != nil {
		return a, false, err
	}
	if cmd == 0x00 {
		a.Local = true
		return a, true, nil
	}
	switch fam {
	case 0x11: // AF_INET, STREAM
		if length < 12 {
			return a, false, fmt.Errorf("short ipv4 payload")
		}
		a.IP = net.IP(payload[0:4])
		a.Port = int(binary.BigEndian.Uint16(payload[8:10]))
	case 0x21: // AF_INET6, STREAM
		if length < 36 {
			return a, false, fmt.Errorf("short ipv6 payload")
		}
		a.IP = net.IP(payload[0:16])
		a.Port = int(binary.BigEndian.Uint16(payload[32:34]))
	default:
		return a, false, fmt.Errorf("unsupported family/proto %#x", fam)
	}
	return a, true, nil
}
