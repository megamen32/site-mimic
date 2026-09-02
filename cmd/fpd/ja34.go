package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// JA3/JA4 computation ported from tools/ja3_ja4.py (the repo's verified
// implementation of the salesforce/ja3 and FoxIO JA4 specs).

var tlsVersionTokens = map[uint16]string{
	0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10",
	0x0300: "s3", 0x0002: "s2",
	0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3",
}

func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a }

func stripGREASE(values []uint16) []uint16 {
	out := values[:0:0]
	for _, v := range values {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func extIDs(ch *clientHello) []uint16 {
	out := make([]uint16, 0, len(ch.Extensions))
	for _, e := range ch.Extensions {
		out = append(out, e.ID)
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

// computeJA3 returns (ja3_string, ja3_md5) per the salesforce/ja3 spec.
func computeJA3(ch *clientHello) (string, string) {
	version := ch.Version
	ciphers := stripGREASE(ch.CipherSuites)
	extensions := stripGREASE(extIDs(ch))
	groups := stripGREASE(ch.Groups)
	pf := stripGREASE(ch.PointFormats)
	s := strconv.Itoa(int(version)) + "-" +
		joinInts(ciphers) + "-" +
		joinInts(extensions) + "-" +
		joinInts(groups) + "-" +
		joinInts(pf)
	sum := md5.Sum([]byte(s))
	return s, hex.EncodeToString(sum[:])
}

func ja4VersionToken(ch *clientHello) string {
	supported := ch.SupportedVersions[:0:0]
	for _, v := range ch.SupportedVersions {
		if !isGREASE(v) {
			supported = append(supported, v)
		}
	}
	best := ch.Version
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

func ja4ALPNToken(ch *clientHello) string {
	if len(ch.ALPN) == 0 || ch.ALPN[0] == "" {
		return "00"
	}
	raw := []byte(ch.ALPN[0])
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
	// FoxIO: first and last characters of the hex representation.
	const hexdig = "0123456789abcdef"
	hs := make([]byte, 0, 2*len(raw))
	for _, b := range raw {
		hs = append(hs, hexdig[b>>4], hexdig[b&0xf])
	}
	return string([]byte{hs[0], hs[len(hs)-1]})
}

func ja4B(ch *clientHello) string {
	ciphers := hex4(stripGREASE(ch.CipherSuites))
	if len(ciphers) == 0 {
		return "000000000000"
	}
	sortStrings(ciphers)
	return sha12(strings.Join(ciphers, ","))
}

func ja4C(ch *clientHello) string {
	var extHex []string
	for _, e := range stripGREASE(extIDs(ch)) {
		if e == 0x0000 || e == 0x0010 {
			continue // SNI and ALPN live in JA4_a
		}
		extHex = append(extHex, hex4u(e))
	}
	sortStrings(extHex)
	payload := strings.Join(extHex, ",")
	sigAlgs := hex4(stripGREASE(ch.SigAlgs))
	if len(sigAlgs) > 0 {
		payload += "_" + strings.Join(sigAlgs, ",") // wire order, not sorted
	}
	if payload == "" {
		return "000000000000"
	}
	return sha12(payload)
}

// computeJA4 returns the FoxIO-spec JA4 string ("t" protocol).
func computeJA4(ch *clientHello) string {
	sniToken := "i"
	if ch.SNI != "" {
		sniToken = "d"
	}
	cipherCount := len(stripGREASE(ch.CipherSuites))
	extCount := len(stripGREASE(extIDs(ch)))
	if cipherCount > 99 {
		cipherCount = 99
	}
	if extCount > 99 {
		extCount = 99
	}
	ja4a := "t" + ja4VersionToken(ch) + sniToken +
		pad2(cipherCount) + pad2(extCount) + ja4ALPNToken(ch)
	return ja4a + "_" + ja4B(ch) + "_" + ja4C(ch)
}

// ja4R is JA4_r: the original wire order, GREASE removed, SNI/ALPN kept.
func ja4R(ch *clientHello) string {
	ciphers := strings.Join(hex4(stripGREASE(ch.CipherSuites)), ",")
	exts := hex4(stripGREASE(extIDs(ch)))
	sigAlgs := strings.Join(hex4(stripGREASE(ch.SigAlgs)), ",")
	c := strings.Join(exts, ",")
	if sigAlgs != "" {
		c += "_" + sigAlgs
	}
	sniToken := "i"
	if ch.SNI != "" {
		sniToken = "d"
	}
	cipherCount := len(stripGREASE(ch.CipherSuites))
	extCount := len(stripGREASE(extIDs(ch)))
	if cipherCount > 99 {
		cipherCount = 99
	}
	if extCount > 99 {
		extCount = 99
	}
	ja4a := "t" + ja4VersionToken(ch) + sniToken +
		pad2(cipherCount) + pad2(extCount) + ja4ALPNToken(ch)
	return ja4a + "_" + ciphers + "_" + c
}

func hex4u(v uint16) string {
	return hex4([]uint16{v})[0]
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

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
