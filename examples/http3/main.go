// Command http3 fetches a URL over HTTP/3 with a browser-shaped QUIC
// handshake: the Chrome QUIC ClientHello (11 extensions, 3 cipher suites —
// the QUIC shape, not the TCP one), the transport parameters a real Chrome
// sends, and the profile's headers.
//
// Expected result: HTTP 200 over "HTTP/3.0" — the response line says so
// only when the connection really was h3.
//
// Usage:
//
//	go run .                                  # GET https://example.com/
//	go run . -url https://vk.ru/ -profile ../profiles/windows-chrome152.json
//	go run . -resume          # twice, so the second connection resumes
//
// Note: HTTP/3 is a Go API. The Python and TypeScript clients go through
// fetchd, which speaks TCP. And a QUIC connection needs UDP/443 to be
// reachable — many networks block it, and then the request fails with a
// timeout rather than falling back to TCP. That is deliberate: a silent
// fallback would be a different client than the one you asked for.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/megamen32/site-mimic/mimic"
)

func main() {
	target := flag.String("url", "https://example.com/", "target URL")
	profilePath := flag.String("profile", "", "profile JSON (default: the Chrome 152 profile)")
	timeout := flag.Duration("timeout", 30*time.Second, "request timeout")
	insecure := flag.Bool("insecure", false, "skip TLS certificate verification (for a local test server)")
	resume := flag.Bool("resume", false, "fetch twice, dropping the connection in between, so the second connection resumes")
	resolveHost := flag.String("resolve", "", "host=ip to pin the address of a host (repeatable: -resolve a=1.2.3.4)")
	flag.Parse()

	path := *profilePath
	if path == "" {
		// The QUIC path carries the Chrome QUIC fingerprint, so the profile
		// must not promise a byte-exact Chrome *TCP* TLS layer: mimic.NewHTTP3
		// refuses chrome_exact for that reason. This profile is the Windows
		// Chrome 152 one with the QUIC-suitable identity.
		path = "../profiles/mac-chrome156-h3.json"
	}
	profile, err := mimic.LoadProfile(path)
	if err != nil {
		log.Fatalf("load profile: %v", err)
	}

	var options []mimic.Option
	if *insecure {
		options = append(options, mimic.WithInsecureTLS())
	}
	if *resolveHost != "" {
		host, ip, ok := strings.Cut(*resolveHost, "=")
		if !ok {
			log.Fatalf("-resolve wants host=ip, got %q", *resolveHost)
		}
		options = append(options, mimic.WithResolve(map[string]string{host: ip}))
	}
	client, err := mimic.NewHTTP3(profile, options...)
	if err != nil {
		log.Fatalf("build the HTTP/3 client: %v", err)
	}
	// The transport holds the UDP socket and the QUIC connections it made.
	defer client.Transport.(io.Closer).Close()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	req, err := profile.Request(http.MethodGet, *target, nil)
	if err != nil {
		log.Fatalf("build the request: %v", err)
	}
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		log.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		log.Fatalf("read the body: %v", err)
	}
	fmt.Printf("proto=%s status=%d bytes=%d\n", resp.Proto, resp.StatusCode, len(body))
	if text, ok := printable(body); ok {
		fmt.Printf("%s\n", text)
	} else {
		// The profile sends a browser's accept-encoding, so the body comes
		// back compressed — the stdlib only decompresses when it set that
		// header itself. That is the library-wide behaviour, not something
		// HTTP/3 changes: fidelity to the captured client first.
		fmt.Println("(the body is compressed — the profile asks for it, like a browser)")
	}
	if resp.Proto != "HTTP/3.0" {
		fmt.Fprintln(os.Stderr, "warning: the response did not come over HTTP/3")
	}

	if *resume {
		// A browser that has to dial again offers the ticket it got, and
		// the hello of that connection carries the pre_shared_key
		// extension. Dropping the pooled connection is what makes the
		// second request dial again.
		client.CloseIdleConnections()
		time.Sleep(100 * time.Millisecond)
		ctx2, cancel2 := context.WithTimeout(context.Background(), *timeout)
		defer cancel2()
		req2, err := profile.Request(http.MethodGet, *target, nil)
		if err != nil {
			log.Fatalf("build the second request: %v", err)
		}
		resp2, err := client.Do(req2.WithContext(ctx2))
		if err != nil {
			log.Fatalf("the second request: %v", err)
		}
		defer resp2.Body.Close()
		fmt.Printf("resumed connection: %s\n", resp2.Proto)
	}
}

// printable reports whether the body looks like text, and returns its first
// lines if so.
func printable(body []byte) (string, bool) {
	for _, b := range body {
		if b < 0x20 && b != '\n' && b != '\r' && b != '\t' {
			return "", false
		}
	}
	text := string(body)
	if len(text) > 200 {
		text = text[:200]
	}
	return text, true
}
