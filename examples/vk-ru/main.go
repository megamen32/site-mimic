// Command vk-ru fetches https://vk.ru/ the way a desktop Chrome browser
// does: uTLS chrome_auto ClientHello, ALPN-negotiated HTTP/2, and the header
// set captured from a real navigation. Expected result: HTTP 200 with the
// welcome HTML (server: kittenx).
//
// Usage:
//
//	go run .                       # GET https://vk.ru/
//	go run . -dump ch.json         # also write the raw ClientHello, then:
//	python3 ../../tools/parse_clienthello.py ch.json
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/megamen32/site-mimic/mimic"
)

func main() {
	target := flag.String("url", "https://vk.ru/", "target URL")
	dump := flag.String("dump", "", "write the raw ClientHello record JSON to this path")
	timeout := flag.Duration("timeout", 30*time.Second, "request timeout")
	ttl := flag.Int("ttl", 0, "override IP TTL (e.g. 128 to present as Windows; 0 = profile/kernel default)")
	hello := flag.String("hello", "", "override tls_client_hello (e.g. chrome_152; empty = profile)")
	flag.Parse()

	profile := mimic.MustLoadProfile("profile.json")
	if *hello != "" {
		profile.TLSClientHello = *hello
	}
	opts := []mimic.Option{}
	if *ttl != 0 {
		opts = append(opts, mimic.WithTTL(*ttl))
	}
	client, err := mimic.New(profile, opts...)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if *dump != "" {
		u, err := url.Parse(*target)
		if err != nil {
			log.Fatal(err)
		}
		record, err := mimic.ClientHelloCapture(ctx, u.Hostname(), profile.TLSClientHello)
		if err != nil {
			log.Fatal(err)
		}
		if err := mimic.WriteClientHelloJSON(*dump, u.Host, record); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("clienthello: wrote %s — fingerprint it with:\n", *dump)
		fmt.Printf("  python3 ../../tools/parse_clienthello.py %s\n", *dump)
	}

	req, err := profile.Request("GET", *target, nil)
	if err != nil {
		log.Fatal(err)
	}
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))

	fmt.Printf("status: %s\n", resp.Status)
	fmt.Printf("proto:  %s\n", resp.Proto)
	fmt.Printf("server: %s\n", resp.Header.Get("Server"))
	fmt.Printf("body:   %d bytes; first 100: %.100q\n", len(body), body)
	if resp.StatusCode == http.StatusOK {
		os.Exit(0)
	}
	os.Exit(1)
}
