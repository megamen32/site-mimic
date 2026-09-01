package mimic

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

// Profile is a captured client identity for one site: which TLS ClientHello
// to speak, and which headers a real browser sends. Build profiles from a
// real browser capture (see skill/SKILL.md and docs/methodology.md) and ship
// them next to your code — see examples/ for two worked sites.
type Profile struct {
	Name string `json:"name"`
	// TLSClientHello selects the ClientHello shape:
	// "chrome_exact" (recommended — delegates the transport to
	// github.com/kulikov0/headless-client, whose ClientHello is measured
	// against the current Chrome and matches it byte-for-byte), or a uTLS
	// profile name: chrome_auto (default), firefox_auto, ios_auto, random,
	// random_alpn.
	TLSClientHello string `json:"tls_client_hello"`
	UserAgent      string `json:"user_agent"`
	// HeaderOrder lists the header names in the order the real browser sends
	// them; Headers carries the captured values. Wire-order control is a
	// known limitation (see docs/methodology.md): values and set are applied,
	// ordering follows Go's canonical write.
	HeaderOrder []string          `json:"header_order"`
	Headers     map[string]string `json:"headers"`
	// CookieJar persists site cookies across requests.
	CookieJar http.CookieJar `json:"-"`
	// IPTTL stamps every outgoing connection with this IP TTL (see
	// mimic.WithTTL). Set 128 to present as a Windows-origin client on the
	// wire: the kernel default (64 on Linux/Android, 128 on Windows) alone
	// reveals the OS family. 0 = kernel default.
	IPTTL int `json:"ip_ttl"`
}

// LoadProfile reads a profile JSON file from disk.
func LoadProfile(path string) (Profile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, fmt.Errorf("mimic: read profile: %w", err)
	}
	var p Profile
	if err := json.Unmarshal(raw, &p); err != nil {
		return Profile{}, fmt.Errorf("mimic: parse profile %s: %w", path, err)
	}
	return p, nil
}

// MustLoadProfile is LoadProfile for examples and small CLI tools.
func MustLoadProfile(path string) Profile {
	p, err := LoadProfile(path)
	if err != nil {
		panic(err)
	}
	return p
}

// Request builds an *http.Request with the profile's headers applied on top:
// the User-Agent, then every captured header in HeaderOrder, then any
// remaining profile headers.
//
// accept-encoding is intentionally left to net/http: when Go owns that header
// it transparently decompresses responses. Adding the browser's
// "gzip, deflate, br" value by hand would deliver Brotli bodies the stdlib
// cannot decode.
func (p Profile) Request(method, urlStr string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, urlStr, body)
	if err != nil {
		return nil, fmt.Errorf("mimic: build request: %w", err)
	}
	if p.UserAgent != "" {
		req.Header.Set("User-Agent", p.UserAgent)
	}
	seen := map[string]bool{}
	for _, name := range p.HeaderOrder {
		if v, ok := p.Headers[name]; ok {
			req.Header.Set(name, v)
			seen[name] = true
		}
	}
	for name, v := range p.Headers {
		if !seen[name] {
			req.Header.Set(name, v)
		}
	}
	return req, nil
}
