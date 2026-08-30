// Command stand-probe is a kulikov0/headless-client stand-compatible probe:
// it fetches a URL N times with the site-mimic client so the capture stand
// can diff its wire fingerprint against a real Chromium running next to it.
//
// Usage (matches the stand's --role-args convention):
//
//	stand-probe <url> [count] [profile.json]
package main

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/megamen32/site-mimic/mimic"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("usage: %s <url> [count] [profile.json]", os.Args[0])
	}
	target := os.Args[1]
	count := 1
	if len(os.Args) > 2 {
		n, err := strconv.Atoi(os.Args[2])
		if err != nil || n < 1 {
			log.Fatalf("bad count %q", os.Args[2])
		}
		count = n
	}
	profilePath := "profile.json"
	if len(os.Args) > 3 {
		profilePath = os.Args[3]
	}
	profile := mimic.MustLoadProfile(profilePath)
	client, err := mimic.New(profile)
	if err != nil {
		log.Fatal(err)
	}
	for i := 0; i < count; i++ {
		req, err := profile.Request("GET", target, nil)
		if err != nil {
			log.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("req %d: %s proto=%s server=%s\n", i+1, resp.Status, resp.Proto, resp.Header.Get("Server"))
		resp.Body.Close()
	}
}
