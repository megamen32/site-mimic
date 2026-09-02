package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// clientHello holds the parsed plaintext ClientHello exactly as it hit
// the wire, plus the selected sub-fields JA3/JA4 need.
type clientHello struct {
	Raw               []byte // record bytes: 0x16 ver len | 0x01 len | body
	Version           uint16 // legacy_version
	CipherSuites      []uint16
	Extensions        []tlsExtension
	SNI               string
	ALPN              []string
	SigAlgs           []uint16
	Groups            []uint16
	PointFormats      []uint16
	SupportedVersions []uint16
}

type tlsExtension struct {
	ID   uint16
	Data []byte
}

var errNotClientHello = errors.New("not a ClientHello record")

func newBufioReader(c net.Conn) *bufio.Reader {
	return bufio.NewReaderSize(c, 1<<16)
}

// readHelloRecords reads the full ClientHello — normally a single TLS
// record, but the handshake message may span several records.
func readHelloRecords(br *bufio.Reader) ([]byte, error) {
	var hs []byte // concatenated handshake message
	for {
		head := make([]byte, 5)
		if _, err := io.ReadFull(br, head); err != nil {
			return nil, err
		}
		if head[0] != 0x16 {
			return nil, fmt.Errorf("record type %#x, want 0x16", head[0])
		}
		recLen := int(head[3])<<8 | int(head[4])
		rec := make([]byte, 5+recLen)
		copy(rec, head)
		if _, err := io.ReadFull(br, rec[5:]); err != nil {
			return nil, err
		}
		if len(hs) == 0 && (recLen < 4 || rec[5] != 0x01) {
			return nil, errNotClientHello
		}
		if recLen < 4 {
			return nil, errors.New("degenerate record")
		}
		hs = append(hs, rec[5:]...)
		if len(hs) < 4 {
			continue
		}
		hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
		if len(hs) >= 4+hsLen {
			out := make([]byte, 0, 5+4+hsLen)
			out = append(out, rec[:5]...)
			out = append(out, hs[:4+hsLen]...)
			return out, nil
		}
	}
}

// parseClientHelloRecord parses the ClientHello from its record bytes.
func parseClientHelloRecord(rec []byte) (*clientHello, error) {
	if len(rec) < 11 || rec[0] != 0x16 || rec[5] != 0x01 {
		return nil, errNotClientHello
	}
	hsLen := int(rec[6])<<16 | int(rec[7])<<8 | int(rec[8])
	if len(rec) < 9+hsLen {
		return nil, errors.New("truncated hello")
	}
	b := rec[9 : 9+hsLen]
	ch := &clientHello{Raw: rec[:9+hsLen]}
	if len(b) < 34 {
		return nil, errors.New("hello too short")
	}
	ch.Version = binary.BigEndian.Uint16(b[0:2])
	b = b[34:] // legacy_version + random
	if len(b) < 1 {
		return nil, errors.New("no session id len")
	}
	sid := int(b[0])
	b = b[1+sid:]
	if len(b) < 2 {
		return nil, errors.New("no cipher len")
	}
	csLen := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if len(b) < csLen+1 {
		return nil, errors.New("truncated ciphers")
	}
	for i := 0; i+2 <= csLen; i += 2 {
		ch.CipherSuites = append(ch.CipherSuites, binary.BigEndian.Uint16(b[i:]))
	}
	b = b[csLen:]
	comp := int(b[0])
	b = b[1+comp:]
	if len(b) < 2 {
		return nil, errors.New("no extension len") // legal but not a browser
	}
	extLen := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if len(b) < extLen {
		return nil, errors.New("truncated extensions")
	}
	b = b[:extLen]
	for len(b) >= 4 {
		id := binary.BigEndian.Uint16(b)
		l := int(binary.BigEndian.Uint16(b[2:]))
		if len(b) < 4+l {
			return nil, fmt.Errorf("truncated ext %#x", id)
		}
		data := b[4 : 4+l]
		ch.Extensions = append(ch.Extensions, tlsExtension{ID: id, Data: data})
		switch id {
		case 0x0000:
			ch.SNI = parseSNI(data)
		case 0x000a:
			ch.Groups = parseList16(data)
		case 0x000b:
			ch.PointFormats = parseList8(data)
		case 0x000d:
			ch.SigAlgs = parseList16(data)
		case 0x0010:
			ch.ALPN = parseALPN(data)
		case 0x002b:
			ch.SupportedVersions = parseList8of16(data)
		}
		b = b[4+l:]
	}
	return ch, nil
}

func parseSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(data))
	_ = listLen
	b := data[2:]
	for len(b) >= 3 {
		typ := b[0]
		l := int(binary.BigEndian.Uint16(b[1:]))
		if len(b) < 3+l {
			return ""
		}
		if typ == 0 {
			return string(b[3 : 3+l])
		}
		b = b[3+l:]
	}
	return ""
}

func parseALPN(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data))
	b := data[2:]
	if len(b) > listLen {
		b = b[:listLen]
	}
	var out []string
	for len(b) >= 1 {
		l := int(b[0])
		if l == 0 || len(b) < 1+l {
			break
		}
		out = append(out, string(b[1:1+l]))
		b = b[1+l:]
	}
	return out
}

func parseList16(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data))
	b := data[2:]
	if len(b) > listLen {
		b = b[:listLen]
	}
	var out []uint16
	for i := 0; i+2 <= len(b); i += 2 {
		out = append(out, binary.BigEndian.Uint16(b[i:]))
	}
	return out
}

func parseList8(data []byte) []uint16 {
	if len(data) < 1 {
		return nil
	}
	listLen := int(data[0])
	b := data[1:]
	if len(b) > listLen {
		b = b[:listLen]
	}
	out := make([]uint16, 0, len(b))
	for _, v := range b {
		out = append(out, uint16(v))
	}
	return out
}

func parseList8of16(data []byte) []uint16 {
	if len(data) < 1 {
		return nil
	}
	listLen := int(data[0])
	b := data[1:]
	if len(b) > listLen {
		b = b[:listLen]
	}
	var out []uint16
	for i := 0; i+2 <= len(b); i += 2 {
		out = append(out, binary.BigEndian.Uint16(b[i:]))
	}
	return out
}
