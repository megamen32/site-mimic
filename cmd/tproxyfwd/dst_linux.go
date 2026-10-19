//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"syscall"
	"unsafe"
)

// soOriginalDst is SO_ORIGINAL_DST from linux/netfilter_ipv4.h.
const soOriginalDst = 80

// originalDst returns the pre-REDIRECT destination of an accepted socket.
// The kernel keeps the original destination in the socket's per-connection
// state after a nat REDIRECT; getsockopt(SO_ORIGINAL_DST) hands it back.
func originalDst(conn net.Conn) (string, error) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return "", errors.New("not a TCP connection")
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return "", err
	}
	var sa [16]byte
	var sockErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		sockErr = getsockoptOriginalDst(int(fd), sa[:])
	})
	if ctrlErr != nil {
		return "", ctrlErr
	}
	if sockErr != nil {
		return "", sockErr
	}
	// struct sockaddr_in: sin_family(2) sin_port(2) sin_addr(4)
	port := binary.BigEndian.Uint16(sa[2:4])
	ip := net.IPv4(sa[4], sa[5], sa[6], sa[7])
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), nil
}

// getsockoptOriginalDst reads SO_ORIGINAL_DST into buf.
func getsockoptOriginalDst(fd int, buf []byte) error {
	length := uint32(len(buf))
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.IPPROTO_IP), // SOL_IP
		uintptr(soOriginalDst),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&length)),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}
