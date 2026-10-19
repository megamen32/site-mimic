package mimic

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ClientHello is the parsed form of a TLS ClientHello record — the bytes a
// client puts on the wire before the server ever sees them. It is what a
// server fingerprints (JA3/JA4), so the library can compute the same
// numbers a peer would compute.
//
// The JA3/JA4 code is ported from cmd/fpd/ja34.go, which is itself ported
// from tools/ja3_ja4.py (the repo's verified implementation of the
// salesforce/ja3 and FoxIO JA4 specs).
type ClientHello struct {
	Version            uint16
	SessionID          []byte
	CipherSuites       []uint16
	CompressionMethods []uint8
	// Extensions lists the extension ids in wire order.
	Extensions []uint16
	// ExtensionData holds the raw payload of every extension, by id.
	ExtensionData map[uint16][]byte
	Groups        []uint16
	PointFormats  []uint8
	ALPN          []string
	SNI           string
	SigAlgs       []uint16
	// SupportedVersions is the payload of the supported_versions extension
	// (0x002b); empty when the extension is absent.
	SupportedVersions []uint16
}

// ParseClientHello parses a raw ClientHello record — the bytes returned by
// ClientHelloCapture, i.e. record type 0x16, version, length, then the
// handshake message.
func ParseClientHello(record []byte) (*ClientHello, error) {
	if len(record) < 5 {
		return nil, fmt.Errorf("mimic: client hello too short (%d bytes)", len(record))
	}
	if record[0] != 0x16 {
		return nil, fmt.Errorf("mimic: not a handshake record (type %#02x)", record[0])
	}
	body := record[5:]
	if len(body) < 4 || body[0] != 0x01 {
		return nil, fmt.Errorf("mimic: not a ClientHello handshake")
	}
	body = body[4:] // handshake header

	hello := &ClientHello{ExtensionData: map[uint16][]byte{}}
	p := 0
	need := func(n int) error {
		if p+n > len(body) {
			return fmt.Errorf("mimic: client hello truncated at %d", p)
		}
		return nil
	}
	if err := need(2); err != nil {
		return nil, err
	}
	hello.Version = binary.BigEndian.Uint16(body[p:])
	p += 2
	if err := need(34); err != nil {
		return nil, err
	}
	p += 32 // random
	sidLen := int(body[p])
	p++
	if err := need(sidLen); err != nil {
		return nil, err
	}
	hello.SessionID = body[p : p+sidLen]
	p += sidLen
	if err := need(2); err != nil {
		return nil, err
	}
	csLen := int(binary.BigEndian.Uint16(body[p:]))
	p += 2
	if err := need(csLen); err != nil {
		return nil, err
	}
	for i := 0; i+1 < csLen; i += 2 {
		hello.CipherSuites = append(hello.CipherSuites, binary.BigEndian.Uint16(body[p+i:]))
	}
	p += csLen
	if err := need(1); err != nil {
		return nil, err
	}
	compLen := int(body[p])
	p++
	if err := need(compLen); err != nil {
		return nil, err
	}
	hello.CompressionMethods = append([]uint8(nil), body[p:p+compLen]...)
	p += compLen
	if err := need(2); err != nil {
		return nil, err
	}
	extTotal := int(binary.BigEndian.Uint16(body[p:]))
	p += 2
	if err := need(extTotal); err != nil {
		return nil, err
	}
	end := p + extTotal
	for p < end {
		if err := need(4); err != nil {
			return nil, err
		}
		id := binary.BigEndian.Uint16(body[p:])
		length := int(binary.BigEndian.Uint16(body[p+2:]))
		p += 4
		if err := need(length); err != nil {
			return nil, err
		}
		data := body[p : p+length]
		p += length
		hello.Extensions = append(hello.Extensions, id)
		hello.ExtensionData[id] = append([]byte(nil), data...)
		switch id {
		case 0x0000: // server_name
			hello.SNI = parseSNI(data)
		case 0x000a: // supported_groups
			hello.Groups = parseUint16List(data[2:])
		case 0x000b: // ec_point_formats
			hello.PointFormats = append([]uint8(nil), data[1:]...)
		case 0x000d: // signature_algorithms
			hello.SigAlgs = parseUint16List(data[2:])
		case 0x0010: // ALPN
			hello.ALPN = parseALPN(data)
		case 0x002b: // supported_versions
			hello.SupportedVersions = parseUint16List(data[1:])
		}
	}
	return hello, nil
}

func parseSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	nameLen := int(binary.BigEndian.Uint16(data[3:]))
	if 5+nameLen > len(data) {
		return ""
	}
	return string(data[5 : 5+nameLen])
}

func parseALPN(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	list := data[2:]
	var out []string
	for len(list) >= 1 {
		n := int(list[0])
		if 1+n > len(list) {
			break
		}
		out = append(out, string(list[1:1+n]))
		list = list[1+n:]
	}
	return out
}

func parseUint16List(data []byte) []uint16 {
	var out []uint16
	for i := 0; i+1 < len(data); i += 2 {
		out = append(out, binary.BigEndian.Uint16(data[i:]))
	}
	return out
}

var tlsVersionTokens = map[uint16]string{
	0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10",
	0x0300: "s3", 0x0002: "s2",
	0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3",
}

func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a }

func stripGREASE(values []uint16) []uint16 {
	out := make([]uint16, 0, len(values))
	for _, v := range values {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func hex4(values []uint16) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = strings.ToLower(strconv.FormatUint(uint64(v), 16))
		if len(out[i]) < 4 {
			out[i] = strings.Repeat("0", 4-len(out[i])) + out[i]
		}
	}
	return out
}

func sha12(payload string) string {
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])[:12]
}

func joinInts(values []uint16) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, ",")
}

// JA3 returns the JA3 string and its MD5, per the salesforce/ja3 spec.
func (c *ClientHello) JA3() (string, string) {
	ciphers := stripGREASE(c.CipherSuites)
	extensions := stripGREASE(c.Extensions)
	groups := stripGREASE(c.Groups)
	pf := make([]uint16, 0, len(c.PointFormats))
	for _, v := range c.PointFormats {
		pf = append(pf, uint16(v))
	}
	pf = stripGREASE(pf)
	s := strconv.Itoa(int(c.Version)) + "-" +
		joinInts(ciphers) + "-" +
		joinInts(extensions) + "-" +
		joinInts(groups) + "-" +
		joinInts(pf)
	sum := md5.Sum([]byte(s))
	return s, hex.EncodeToString(sum[:])
}

// JA4 returns the FoxIO-spec JA4 string ("t" protocol).
func (c *ClientHello) JA4() string {
	ja4a := "t" + c.ja4VersionToken() + c.ja4SNIToken() +
		pad2(len(stripGREASE(c.CipherSuites))) + pad2(len(stripGREASE(c.Extensions))) + c.ja4ALPNToken()
	return ja4a + "_" + c.ja4B() + "_" + c.ja4C()
}

// JA4R is JA4_r: the original wire order, GREASE removed, SNI/ALPN kept.
func (c *ClientHello) JA4R() string {
	ciphers := strings.Join(hex4(stripGREASE(c.CipherSuites)), ",")
	exts := hex4(stripGREASE(c.Extensions))
	sigAlgs := strings.Join(hex4(stripGREASE(c.SigAlgs)), ",")
	cc := strings.Join(exts, ",")
	if sigAlgs != "" {
		cc += "_" + sigAlgs
	}
	ja4a := "t" + c.ja4VersionToken() + c.ja4SNIToken() +
		pad2(len(stripGREASE(c.CipherSuites))) + pad2(len(stripGREASE(c.Extensions))) + c.ja4ALPNToken()
	return ja4a + "_" + ciphers + "_" + cc
}

func (c *ClientHello) ja4VersionToken() string {
	supported := stripGREASE(c.SupportedVersions)
	best := c.Version
	if len(supported) > 0 {
		best = supported[0]
		for _, v := range supported[1:] {
			if v > best {
				best = v
			}
		}
	}
	if tok, ok := tlsVersionTokens[best]; ok {
		return tok
	}
	return "00"
}

func (c *ClientHello) ja4SNIToken() string {
	if c.SNI == "" {
		return "i"
	}
	return "d"
}

func (c *ClientHello) ja4ALPNToken() string {
	if len(c.ALPN) == 0 || c.ALPN[0] == "" {
		return "00"
	}
	raw := []byte(c.ALPN[0])
	first, last := raw[0], raw[len(raw)-1]
	if len(raw) == 1 {
		return string([]byte{first, first})
	}
	alnum := func(b byte) bool {
		return b >= 0x30 && b <= 0x39 || b >= 0x41 && b <= 0x5A || b >= 0x61 && b <= 0x7A
	}
	if alnum(first) && alnum(last) {
		return string([]byte{first, last})
	}
	const hexdig = "0123456789abcdef"
	hs := make([]byte, 0, 2*len(raw))
	for _, b := range raw {
		hs = append(hs, hexdig[b>>4], hexdig[b&0xf])
	}
	return string([]byte{hs[0], hs[len(hs)-1]})
}

func (c *ClientHello) ja4B() string {
	ciphers := hex4(stripGREASE(c.CipherSuites))
	if len(ciphers) == 0 {
		return "000000000000"
	}
	sort.Strings(ciphers)
	return sha12(strings.Join(ciphers, ","))
}

func (c *ClientHello) ja4C() string {
	var extHex []string
	for _, e := range stripGREASE(c.Extensions) {
		if e == 0x0000 || e == 0x0010 {
			continue // SNI and ALPN live in JA4_a
		}
		extHex = append(extHex, hex4([]uint16{e})[0])
	}
	sort.Strings(extHex)
	payload := strings.Join(extHex, ",")
	sigAlgs := hex4(stripGREASE(c.SigAlgs))
	if len(sigAlgs) > 0 {
		payload += "_" + strings.Join(sigAlgs, ",") // wire order, not sorted
	}
	if payload == "" {
		return "000000000000"
	}
	return sha12(payload)
}

func pad2(n int) string {
	if n > 99 {
		n = 99
	}
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}
