// Command vk-ru-windows fetches https://vk.ru/ presenting as a real
// Windows desktop Chrome: the chrome_exact transport (byte-exact
// ClientHello class verified against a live Windows Chrome 151 —
// t13d1516h2_8daaf6152771_806a8c22fdea, captured headed on a Win11 23H2
// machine, see docs/phone-reference.md), the Windows header set and
// sec-ch-ua brand list, and the Windows IP TTL (128) stamped on every
// connection via the profile's ip_ttl field.
//
// Usage:
//
//	go run .                    # GET https://vk.ru/
//	go run . -url https://vk.ru/feed
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/megamen32/site-mimic/mimic"
)

func main() {
	target := flag.String("url", "https://vk.ru/", "target URL")
	timeout := flag.Duration("timeout", 30*time.Second, "request timeout")
	flag.Parse()

	profile := mimic.MustLoadProfile("profile.json")
	client, err := mimic.New(profile)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

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
