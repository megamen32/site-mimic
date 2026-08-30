// Command stream-wb-ru fetches https://stream.wb.ru/ the way a desktop
// Chrome browser does on first load.
//
// Expected result: HTTP 498 with `server: wbaas` — Wildberries' anti-bot
// serves a JavaScript challenge page to EVERY first-time browser (real or
// automated) before issuing the `x_wbaas_token` cookie. This example proves
// the transport layer reaches the site with a byte-faithful Chrome
// ClientHello and header set; the challenge layer (browser-check.js,
// behavior-tracker, create-token) is application logic outside the scope of
// transport mimicry — see docs/methodology.md for the layer cake.
//
// Usage:
//
//	go run . -dump ch.json
//	python3 ../../tools/parse_clienthello.py ch.json
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"time"

	"github.com/megamen32/site-mimic/mimic"
)

func main() {
	target := flag.String("url", "https://stream.wb.ru/", "target URL")
	dump := flag.String("dump", "", "write the raw ClientHello record JSON to this path")
	timeout := flag.Duration("timeout", 30*time.Second, "request timeout")
	flag.Parse()

	profile := mimic.MustLoadProfile("profile.json")
	client, err := mimic.New(profile)
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

	switch resp.StatusCode {
	case 498:
		fmt.Println("verdict: anti-bot challenge page (same first-load behaviour a fresh real browser gets).")
		fmt.Println("         Transport layer matched; the JS challenge/token flow is app-layer, not transport.")
	case 200:
		fmt.Println("verdict: passed without a challenge (cookie already valid or site not challenging this client).")
	default:
		fmt.Println("verdict: unexpected status — re-capture the site's current behaviour per skill/SKILL.md.")
	}
}
