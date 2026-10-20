// Command hellofp parses ClientHello records captured by the site-mimic
// capture pipeline and prints JA3/JA4 fingerprints.
//
// Two input shapes are accepted:
//
//  1. A JSONL stream where each line is a capture record:
//
//     {"kind":"hello","sni":"...","alpn":[...],"raw_b64":"<base64 of the
//     raw ClientHello handshake bytes>"}
//
//     The raw bytes are the bare handshake body, so the record header is
//     rebuilt before parsing.
//
//  2. A JSON envelope as the repository's own fixtures use it:
//
//     {"target":"...","client_hello_b64":"<base64 of a full TLS record>"}
//
//     The bytes are already a record, so they are parsed as they are.
//
// The raw bytes are re-parsed with mimic.ParseClientHello, so the printed
// fingerprints come from the same implementation the library uses — not
// from a third-party tool.
//
// Usage:
//
//	hellofp capture.jsonl
//	hellofp mimic/testdata/node24_clienthello_resumed.json
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/megamen32/site-mimic/mimic"
)

type capture struct {
	Kind   string   `json:"kind"`
	SNI    string   `json:"sni"`
	ALPN   []string `json:"alpn"`
	RawB64 string   `json:"raw_b64"`
	// ClientHelloB64 is the repository fixture shape: a full TLS record.
	ClientHelloB64 string `json:"client_hello_b64"`
	Target         string `json:"target"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: hellofp <capture.jsonl|capture.json>")
		os.Exit(2)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "hellofp:", err)
		os.Exit(1)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	seen := map[string]bool{}
	parsed := 0
	for {
		var rec capture
		if err := dec.Decode(&rec); err != nil {
			break
		}
		// The two shapes differ in what the bytes are: a bare handshake body
		// in the JSONL stream, a full record in the fixture envelope.
		body, isRecord, ok := rec.payload()
		if !ok {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(body)
		if err != nil {
			fmt.Fprintf(os.Stderr, "hellofp: bad base64: %v\n", err)
			continue
		}
		record := raw
		if !isRecord {
			// mimic.ParseClientHello expects a TLS record: type 0x16,
			// version, length, then the handshake message. The JSONL stream
			// stores the bare handshake body, so wrap it into a synthetic
			// record first.
			record = wrapRecord(raw)
		}
		ch, err := mimic.ParseClientHello(record)
		if err != nil {
			fmt.Fprintf(os.Stderr, "hellofp: %v\n", err)
			continue
		}
		parsed++
		ja3, ja3md5 := ch.JA3()
		ja4 := ch.JA4()
		key := ch.SNI + "|" + ja4
		if seen[key] {
			continue
		}
		seen[key] = true
		fmt.Printf("SNI      %s\n", ch.SNI)
		fmt.Printf("ALPN     %s\n", strings.Join(ch.ALPN, ","))
		fmt.Printf("version  %d\n", ch.Version)
		fmt.Printf("ciphers  %d %v\n", len(ch.CipherSuites), ch.CipherSuites)
		fmt.Printf("exts     %v\n", ch.Extensions)
		fmt.Printf("groups   %v\n", ch.Groups)
		fmt.Printf("sigalgs  %v\n", ch.SigAlgs)
		fmt.Printf("sid_len  %d\n", len(ch.SessionID))
		fmt.Printf("JA3      %s\n", ja3)
		fmt.Printf("JA3_MD5  %s\n", ja3md5)
		fmt.Printf("JA4      %s\n", ja4)
		fmt.Printf("JA4R     %s\n", ch.JA4R())
		fmt.Println()
	}
	// A file that yielded no fingerprint is a mistake, not an empty result:
	// the caller asked for fingerprints and got silence. Say so, and fail.
	if parsed == 0 {
		fmt.Fprintf(os.Stderr, "hellofp: no ClientHello records found in %s\n", os.Args[1])
		os.Exit(1)
	}
}

// payload returns the base64 body of a record and whether it already is a
// full TLS record. The second return value is false when the record carries
// no ClientHello at all.
func (c capture) payload() (body string, isRecord bool, ok bool) {
	switch {
	case c.RawB64 != "":
		return c.RawB64, false, true
	case c.ClientHelloB64 != "":
		return c.ClientHelloB64, true, true
	}
	return "", false, false
}

// wrapRecord builds a TLS handshake record around the raw ClientHello bytes.
//
// The capture stores the ClientHello *body* (mitmproxy's
// `client_hello.raw_bytes(wrap_in_record=False)`): legacy_version, random,
// session id, cipher suites, extensions — without the 0x01 handshake header.
// mimic.ParseClientHello wants a full record, so the header is rebuilt here:
//
//	record:     16 03 01 | len(4 + body)   (2 bytes)
//	handshake:  01 | len(body)             (3 bytes) | body
func wrapRecord(body []byte) []byte {
	out := make([]byte, 0, len(body)+9)
	out = append(out, 0x16, 0x03, 0x01)
	out = append(out, byte((len(body)+4)>>8), byte(len(body)+4))
	out = append(out, 0x01, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	return append(out, body...)
}
