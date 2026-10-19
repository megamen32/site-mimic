//go:build !linux

package main

import (
	"sync"
	"time"
)

// The packet sniffer is Linux-only: it reads client→:443 packets straight
// off the WAN interface with an AF_PACKET socket (raw sockets, root). On
// other platforms the transport layer still works — the TLS ClientHello is
// peeked in userspace — but the layers a userspace server cannot see (IP
// TTL/DF/TOS/ID and the SYN TCP options) stay empty.
//
// This stub keeps the same API so fpd builds and runs everywhere; the report
// simply has no transport facts for the sniffed flow.

type sniffer struct {
	iface string
	port  uint16

	mu    sync.Mutex
	flows map[flowKey]*flowInfo
}

type flowKey struct {
	ip   [16]byte
	is4  bool
	port uint16
}

type flowInfo struct {
	TTL       int
	DF        bool
	TOS       uint8
	IPID      uint16
	SYN       *synInfo
	Packets   uint64
	FirstSeen time.Time
	LastSeen  time.Time
}

type synInfo struct {
	Window  uint16 `json:"window"`
	Options string `json:"options"`
	MSS     int    `json:"mss"`
	WScale  int    `json:"wscale"` // -1 when absent
	SACK    bool   `json:"sackok"`
	TS      bool   `json:"timestamps"`
}

func newSniffer(iface string, port int) *sniffer {
	return &sniffer{iface: iface, port: uint16(port), flows: map[flowKey]*flowInfo{}}
}

// run is a no-op: there is no raw socket to attach to off Linux.
func (s *sniffer) run() {}

// lookup never finds a flow: nothing is sniffed on this platform.
func (s *sniffer) lookup(ip string, port int) (*flowInfo, bool) {
	return nil, false
}
