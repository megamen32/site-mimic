// Command stand-probe is a kulikov0/headless-client stand-compatible probe:
// it fetches a URL N times with the site-mimic client so the capture stand
// can diff its wire fingerprint against a real Chromium running next to it.
//
// Usage (matches the stand's --role-args convention):
//
//	stand-probe <url> [count] [profile.json]
//
// The stand runs the probe inside its container, where host paths do not
// exist: without a readable profile file it falls back to the embedded
// vk.ru desktop-Chrome profile.
package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/megamen32/site-mimic/mimic"
)

//go:embed profile.json
var embeddedProfile embed.FS

func loadProfile(path string) mimic.Profile {
	raw, err := os.ReadFile(path)
	if err != nil {
		raw, err = embeddedProfile.ReadFile("profile.json")
		if err != nil {
			log.Fatalf("stand-probe: profile %q unreadable and embedded fallback failed: %v", path, err)
		}
	}
	var p mimic.Profile
	if err := json.Unmarshal(raw, &p); err != nil {
		log.Fatalf("stand-probe: parse profile: %v", err)
	}
	return p
}

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
	profilePath := ""
	if len(os.Args) > 3 {
		profilePath = os.Args[3]
	}
	profile := loadProfile(profilePath)
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
