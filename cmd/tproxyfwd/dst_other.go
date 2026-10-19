//go:build !linux

package main

import (
	"errors"
	"net"
)

// originalDst is Linux-only: SO_ORIGINAL_DST is a netfilter socket option,
// and the transparent redirect it supports exists only there. Off Linux the
// forwarder still works for plain (non-redirected) connections, but it
// cannot recover a rewritten destination.
func originalDst(net.Conn) (string, error) {
	return "", errors.New("SO_ORIGINAL_DST is Linux-only: run tproxyfwd on the phone (Android)")
}
