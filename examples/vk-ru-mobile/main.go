// Command vk-ru-mobile fetches https://m.vk.ru/ the way a mobile Chrome
// browser does: the chrome_exact transport (byte-exact ClientHello plus
// Chrome's header-order and HTTP/2 frame layers via headless-client) and the
// header set captured from a real Android Chrome 149 navigation on a phone
// (Samsung S21 Ultra, mobile 4G). Expected result: HTTP 200 with the mobile
// welcome HTML.
//
// Unlike the desktop profiles, this one carries the browser's full
// accept-encoding ("gzip, deflate, br, zstd", zstd included — a Chrome 149
// signature): on the chrome_exact path headless-client keeps a caller-set
// Accept-Encoding and transparently decodes br/zstd responses itself.
//
// Usage:
//
//	go run .                            # GET https://m.vk.ru/
//	go run . -url https://m.vk.ru/feed  # any mobile URL
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
	target := flag.String("url", "https://m.vk.ru/", "target URL")
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
