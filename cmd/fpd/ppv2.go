package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// clientAddr is the real client address learned from the proxy-v2 header
// haproxy prepends (send-proxy-v2).
type clientAddr struct {
	IP    net.IP
	Port  int
	Local bool // PROXY command, addresses meaningless
}

var ppv2Signature = "\r\n\r\n\x00\r\nQUIT\n"

func readProxyV2Header(br *bufio.Reader) (clientAddr, error) {
	var a clientAddr
	head := make([]byte, 16)
	if _, err := io.ReadFull(br, head); err != nil {
		return a, err
	}
	if string(head[:12]) != ppv2Signature {
		return a, errors.New("bad proxy-v2 signature")
	}
	verCmd := head[12]
	if verCmd>>4 != 2 {
		return a, fmt.Errorf("unsupported proxy version %d", verCmd>>4)
	}
	cmd := verCmd & 0x0f
	fam := head[13]
	length := int(binary.BigEndian.Uint16(head[14:16]))
	payload := make([]byte, length)
	if _, err := io.ReadFull(br, payload); err != nil {
		return a, err
	}
	if cmd == 0x00 {
		a.Local = true
		return a, nil
	}
	switch fam {
	case 0x11: // AF_INET, STREAM
		if length < 12 {
			return a, errors.New("short ipv4 payload")
		}
		a.IP = net.IP(payload[0:4])
		a.Port = int(binary.BigEndian.Uint16(payload[8:10]))
	case 0x21: // AF_INET6, STREAM
		if length < 36 {
			return a, errors.New("short ipv6 payload")
		}
		a.IP = net.IP(payload[0:16])
		a.Port = int(binary.BigEndian.Uint16(payload[32:34]))
	default:
		return a, fmt.Errorf("unsupported family/proto %#x", fam)
	}
	return a, nil
}
