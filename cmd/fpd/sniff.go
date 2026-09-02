package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// sniffer watches client→:443 packets on the WAN interface (AF_PACKET,
// root-only) and caches per-flow transport facts a userspace TLS server
// cannot see: IP TTL/DF/TOS/ID and the SYN TCP options.
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

// bpfTCPDst443 is `tcpdump -dd 'tcp dst port 443'` for an Ethernet link.
var bpfTCPDst443 = []unix.SockFilter{
	{Code: 0x28, Jt: 0, Jf: 0, K: 0x0000000c},
	{Code: 0x15, Jt: 0, Jf: 4, K: 0x000086dd},
	{Code: 0x30, Jt: 0, Jf: 0, K: 0x00000014},
	{Code: 0x15, Jt: 0, Jf: 11, K: 0x00000006},
	{Code: 0x28, Jt: 0, Jf: 0, K: 0x00000038},
	{Code: 0x15, Jt: 8, Jf: 9, K: 0x000001bb},
	{Code: 0x15, Jt: 0, Jf: 8, K: 0x00000800},
	{Code: 0x30, Jt: 0, Jf: 0, K: 0x00000017},
	{Code: 0x15, Jt: 0, Jf: 6, K: 0x00000006},
	{Code: 0x28, Jt: 0, Jf: 0, K: 0x00000014},
	{Code: 0x45, Jt: 4, Jf: 0, K: 0x00001fff},
	{Code: 0xb1, Jt: 0, Jf: 0, K: 0x0000000e},
	{Code: 0x48, Jt: 0, Jf: 0, K: 0x00000010},
	{Code: 0x15, Jt: 0, Jf: 1, K: 0x000001bb},
	{Code: 0x6, Jt: 0, Jf: 0, K: 0x00040000},
	{Code: 0x6, Jt: 0, Jf: 0, K: 0x00000000},
}

func (s *sniffer) run() {
	ifi, err := net.InterfaceByName(s.iface)
	if err != nil {
		fmt.Printf("fpd: sniffer: interface %s: %v\n", s.iface, err)
		return
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		fmt.Printf("fpd: sniffer: socket: %v (need root/CAP_NET_RAW)\n", err)
		return
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: ifi.Index, Protocol: htons(unix.ETH_P_ALL)}); err != nil {
		fmt.Printf("fpd: sniffer: bind: %v\n", err)
		return
	}
	prog := unix.SockFprog{Len: uint16(len(bpfTCPDst443)), Filter: &bpfTCPDst443[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
		fmt.Printf("fpd: sniffer: attach bpf: %v\n", err)
	}
	go s.purge()
	buf := make([]byte, 1<<16)
	fmt.Printf("fpd: sniffer live on %s (tcp dst port %d)\n", s.iface, s.port)
	for {
		n, err := unix.Read(fd, buf)
		if n <= 0 {
			if err != nil {
				return
			}
			continue
		}
		s.handle(buf[:n])
	}
}

func htons(v uint16) uint16 { return v<<8 | v>>8 } // swap for the kernel's network byte order constants

func (s *sniffer) handle(frame []byte) {
	if len(frame) < 14 {
		return
	}
	etype := binary.BigEndian.Uint16(frame[12:14])
	payload := frame[14:]
	if etype == 0x8100 { // VLAN
		if len(payload) < 4 {
			return
		}
		etype = binary.BigEndian.Uint16(payload[2:4])
		payload = payload[4:]
	}
	switch etype {
	case 0x0800:
		s.handleIPv4(payload)
	case 0x86DD:
		s.handleIPv6(payload)
	}
}

func (s *sniffer) handleIPv4(b []byte) {
	if len(b) < 20 {
		return
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return
	}
	proto := b[9]
	if proto != 6 {
		return
	}
	var src [16]byte
	copy(src[0:4], b[12:16])
	s.record(flowKey{ip: src, is4: true}, b[8], b[6]&0x40 != 0, b[1],
		binary.BigEndian.Uint16(b[4:6]), b[ihl:])
}

func (s *sniffer) handleIPv6(b []byte) {
	if len(b) < 40 || b[6] != 6 { // no extension-header chasing
		return
	}
	var src [16]byte
	copy(src[:], b[8:24])
	s.record(flowKey{ip: src, is4: false}, b[7], true, 0, 0, b[40:])
}

func (s *sniffer) record(k flowKey, ttl byte, df bool, tos uint8, ipid uint16, tcp []byte) {
	if len(tcp) < 20 {
		return
	}
	sport := binary.BigEndian.Uint16(tcp[0:2])
	dport := binary.BigEndian.Uint16(tcp[2:4])
	if dport != s.port {
		return
	}
	k.port = sport
	flags := tcp[13]
	dataOff := int(tcp[12]>>4) * 4

	s.mu.Lock()
	defer s.mu.Unlock()
	fi := s.flows[k]
	now := time.Now()
	if fi == nil {
		fi = &flowInfo{FirstSeen: now}
		s.flows[k] = fi
	}
	fi.LastSeen = now
	fi.Packets++
	fi.TTL = int(ttl)
	fi.DF = df
	fi.TOS = tos
	fi.IPID = ipid
	if flags&0x02 != 0 && flags&0x10 == 0 { // SYN without ACK
		si := &synInfo{
			Window: binary.BigEndian.Uint16(tcp[14:16]),
			WScale: -1,
		}
		if dataOff >= 20 && dataOff <= len(tcp) {
			opts := tcp[20:dataOff]
			if len(opts) > 0 {
				si.Options = tcpOptionsString(opts)
			}
		}
		for _, o := range tcpOptions(optsOf(tcp, dataOff)) {
			switch o.kind {
			case 2:
				if len(o.data) == 2 {
					si.MSS = int(binary.BigEndian.Uint16(o.data))
				}
			case 3:
				if len(o.data) == 1 {
					si.WScale = int(o.data[0])
				}
			case 4:
				si.SACK = true
			case 8:
				si.TS = true
			}
		}
		fi.SYN = si
	}
}

func optsOf(tcp []byte, dataOff int) []byte {
	if dataOff < 20 || dataOff > len(tcp) {
		return nil
	}
	return tcp[20:dataOff]
}

type tcpOpt struct {
	kind byte
	data []byte
}

func tcpOptions(b []byte) []tcpOpt {
	var out []tcpOpt
	for i := 0; i < len(b); {
		switch b[i] {
		case 0: // EOL
			return out
		case 1: // NOP
			i++
		default:
			if i+1 >= len(b) || i+int(b[i+1]) > len(b) || b[i+1] < 2 {
				return out
			}
			out = append(out, tcpOpt{kind: b[i], data: b[i+2 : i+int(b[i+1])]})
			i += int(b[i+1])
		}
	}
	return out
}

// tcpOptionsString renders options tcpdump-style for the report.
func tcpOptionsString(b []byte) string {
	var parts []string
	for _, o := range tcpOptions(b) {
		switch o.kind {
		case 0:
			parts = append(parts, "eol")
		case 1:
			parts = append(parts, "nop")
		case 2:
			if len(o.data) == 2 {
				parts = append(parts, "mss "+strconv.Itoa(int(binary.BigEndian.Uint16(o.data))))
			}
		case 3:
			if len(o.data) == 1 {
				parts = append(parts, "wscale "+strconv.Itoa(int(o.data[0])))
			}
		case 4:
			parts = append(parts, "sackOK")
		case 8:
			if len(o.data) == 8 {
				parts = append(parts, "TS val "+strconv.FormatUint(uint64(binary.BigEndian.Uint32(o.data[0:4])), 10)+
					" ecr "+strconv.FormatUint(uint64(binary.BigEndian.Uint32(o.data[4:8])), 10))
			}
		default:
			parts = append(parts, fmt.Sprintf("opt-%d", o.kind))
		}
	}
	return strings.Join(parts, ",")
}

// lookup returns the cached transport facts for a client 4-tuple.
func (s *sniffer) lookup(ip string, port int) *flowInfo {
	p := net.ParseIP(ip)
	if p == nil || port <= 0 {
		return nil
	}
	p4 := p.To4()
	var k flowKey
	if p4 != nil {
		copy(k.ip[0:4], p4)
		k.is4 = true
	} else {
		copy(k.ip[:], p.To16())
	}
	k.port = uint16(port)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flows[k]
}

func (s *sniffer) purge() {
	for range time.Tick(time.Minute) {
		s.mu.Lock()
		for k, fi := range s.flows {
			if time.Since(fi.LastSeen) > 15*time.Minute {
				delete(s.flows, k)
			}
		}
		s.mu.Unlock()
	}
}
