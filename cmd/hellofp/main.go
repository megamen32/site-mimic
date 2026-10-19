// Command hellofp parses ClientHello records captured by the site-mimic
// capture pipeline and prints JA3/JA4 fingerprints.
//
// Input is a JSONL stream where each line is a capture record:
//
//	{"kind":"hello","sni":"...","alpn":[...],"raw_b64":"<base64 of the
//	 raw ClientHello handshake bytes>"}
//
// The raw bytes are re-parsed with mimic.ParseClientHello, so the printed
// fingerprints come from the same implementation the library uses — not
// from a third-party tool.
//
// Usage:
//
//	hellofp capture.jsonl
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
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: hellofp <capture.jsonl>")
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
	for {
		var rec capture
		if err := dec.Decode(&rec); err != nil {
			break
		}
		if rec.Kind != "hello" || rec.RawB64 == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(rec.RawB64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "hellofp: bad base64: %v\n", err)
			continue
		}
		// mimic.ParseClientHello expects a TLS record: type 0x16, version,
		// length, then the handshake message. The capture stores the bare
		// handshake body, so wrap it into a synthetic record first.
		ch, err := mimic.ParseClientHello(wrapRecord(raw))
		if err != nil {
			fmt.Fprintf(os.Stderr, "hellofp: %v\n", err)
			continue
		}
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
