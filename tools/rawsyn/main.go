// Command rawsyn rewrites outgoing TCP SYN packets from an NFQUEUE so the
// option ORDER matches Windows (mss, wscale, sackOK) instead of the Linux
// kernel order (mss, sackOK, wscale) — closing the option-order gap the
// verification stand sees on the wire. Anything that is not a plain SYN
// carrying exactly mss/sackOK/wscale is passed through untouched.
//
// Usage (inside tools/win-netns.sh up, as root):
//
//	iptables -A OUTPUT -p tcp --dport 443 --syn -j NFQUEUE --queue-num 100 --queue-bypass
//	rawsyn -queue 100
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"log"
	"os"
	"os/signal"

	nfqueue "github.com/florianl/go-nfqueue"
)

func main() {
	queue := flag.Int("queue", 100, "NFQUEUE number")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	nf, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      uint16(*queue),
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  0xFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 0,
	})
	if err != nil {
		log.Fatalf("nfqueue open: %v", err)
	}
	defer nf.Close()

	errFn := func(e error) int {
		log.Printf("nfqueue error: %v", e)
		return 0 // keep running: transient netlink hiccups are normal
	}
	fn := func(a nfqueue.Attribute) int {
		if a.PacketID == nil || a.Payload == nil {
			return 0
		}
		id := *a.PacketID
		if out, ok := rewriteSyn(*a.Payload); ok {
			if err := nf.SetVerdictModPacket(id, nfqueue.NfAccept, out); err != nil {
				log.Printf("set modified: %v", err)
			}
			return 0
		}
		_ = nf.SetVerdict(id, nfqueue.NfAccept)
		return 0
	}
	if err := nf.RegisterWithErrorFunc(ctx, fn, errFn); err != nil {
		log.Fatalf("register: %v", err)
	}
	log.Printf("rawsyn: rewriting SYNs on queue %d (Windows option order)", *queue)
	<-ctx.Done()
}

// rewriteSyn returns the packet with reordered SYN options when it is an
// IPv4 SYN (no ACK, no payload) whose options are exactly mss/sackOK/wscale
// (in any order, with NOP padding); otherwise ok=false leaves it untouched.
func rewriteSyn(pkt []byte) ([]byte, bool) {
	if len(pkt) < 40 || pkt[0]>>4 != 4 {
		return nil, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl != 20 || pkt[9] != 6 { // no IP options, TCP only
		return nil, false
	}
	tcp := pkt[ihl:]
	if len(tcp) < 20 {
		return nil, false
	}
	doff := int(tcp[12]>>4) * 4
	if doff < 20 || len(tcp) < doff {
		return nil, false
	}
	flags := tcp[13]
	if flags&0x02 == 0 || flags&0x10 != 0 || flags&0x08 != 0 { // plain SYN only
		return nil, false
	}
	opts := tcp[20:doff]
	var mss, wscale []byte
	sackOK := false
	for i := 0; i < len(opts); {
		switch opts[i] {
		case 0: // EOL — kernel padding
			i = len(opts)
			continue
		case 1: // NOP
			i++
		default:
			if i+1 >= len(opts) || i+int(opts[i+1]) > len(opts) || opts[i+1] < 2 {
				return nil, false
			}
			o, data := opts[i], opts[i+2:i+int(opts[i+1])]
			switch o {
			case 2:
				if len(data) != 2 {
					return nil, false
				}
				mss = opts[i : i+int(opts[i+1])]
			case 3:
				if len(data) != 1 {
					return nil, false
				}
				wscale = opts[i : i+int(opts[i+1])]
			case 4:
				sackOK = true
			default: // timestamps or anything unexpected: keep kernel shape
				return nil, false
			}
			i += int(opts[i+1])
		}
	}
	if mss == nil || wscale == nil || !sackOK {
		return nil, false
	}

	// Windows order: mss, wscale, sackOK, EOL-padded.
	newOpts := []byte{}
	newOpts = append(newOpts, mss...)
	newOpts = append(newOpts, wscale...)
	newOpts = append(newOpts, 0x04, 0x02)
	for len(newOpts)%4 != 0 {
		newOpts = append(newOpts, 0x00)
	}

	out := make([]byte, 0, 20+20+len(newOpts))
	out = append(out, pkt[:20]...)        // IP header
	out = append(out, tcp[:20]...)        // fixed TCP header
	out = append(out, newOpts...)         // reordered options
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out))) // IP total length
	out[20+12] = byte((20+len(newOpts))/4) << 4            // TCP data offset

	// TCP checksum over the pseudo-header.
	pseudo := make([]byte, 0, 12+len(out)-20)
	pseudo = append(pseudo, pkt[12:16]...)
	pseudo = append(pseudo, pkt[16:20]...)
	pseudo = append(pseudo, 0x00, 0x06)
	tcpLen := uint16(20 + len(newOpts))
	pseudo = binary.BigEndian.AppendUint16(pseudo, tcpLen)
	seg := append([]byte{}, out[20:]...)
	seg[16], seg[17] = 0, 0
	pseudo = append(pseudo, seg...)
	c := checksum(pseudo)
	binary.BigEndian.PutUint16(out[20+16:20+18], c)
	// IP header checksum.
	hdr := append([]byte{}, out[:20]...)
	hdr[10], hdr[11] = 0, 0
	binary.BigEndian.PutUint16(out[10:12], checksum(hdr))
	return out, true
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
