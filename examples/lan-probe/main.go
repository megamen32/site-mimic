// Command lan-probe drives the site-mimic client against a LAN capture
// stand (cmd/fpd on a self-signed cert), where stand-probe's kulikov0-stand
// assumptions (trusted cert, args-only profile) do not hold.
//
// Usage:
//
//	lan-probe <url> [count] [profile.json]
//
// Every iteration builds a fresh mimic client (own transport), so iteration
// 1 produces the full-handshake hello and later ones exercise resumption
// through headless-client's shared session cache — the wire equivalent of
// the real browser's fresh vs hand-off-tab shapes. Iterations are marked
// on the wire with ?m=mimic-<n> for /fp/recent filtering.
package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/megamen32/site-mimic/mimic"
)

//go:embed profile.json
var embeddedProfile embed.FS

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
	if profilePath != "" {
		if _, err := os.Stat(profilePath); err != nil {
			if named := filepath.Join("examples/profiles", profilePath+".json"); fileExists(named) {
				profilePath = named
			}
		}
	}
	profile := loadProfile(profilePath)
	base, err := url.Parse(target)
	if err != nil {
		log.Fatalf("parse target: %v", err)
	}
	var client *http.Client
	for i := 0; i < count; i++ {
		if i > 0 {
			time.Sleep(800 * time.Millisecond)
		}
		if client == nil {
			// one client for the whole run: iteration 1 dials the full
			// handshake, CloseIdleConnections before later iterations forces
			// a new TLS connection that resumes from the transport's shared
			// session cache — the mimic equivalent of the browser hand-off tab
			client, err = mimic.New(profile, mimic.WithInsecureTLS())
			if err != nil {
				log.Fatal(err)
			}
		} else {
			client.CloseIdleConnections()
		}
		marked := *base
		q := marked.Query()
		q.Set("m", fmt.Sprintf("mimic-%d", i+1))
		marked.RawQuery = q.Encode()
		req, err := profile.Request("GET", marked.String(), nil)
		if err != nil {
			log.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("req %d: %s proto=%s\n", i+1, resp.Status, resp.Proto)
		resp.Body.Close()
	}
}

func loadProfile(path string) mimic.Profile {
	var raw []byte
	var err error
	if path == "" {
		raw, err = embeddedProfile.ReadFile("profile.json")
	} else {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		log.Fatalf("lan-probe: profile %q unreadable: %v", path, err)
	}
	var p mimic.Profile
	if err := json.Unmarshal(raw, &p); err != nil {
		log.Fatalf("lan-probe: parse profile: %v", err)
	}
	return p
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
