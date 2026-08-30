package mimic

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"
)

// CookieFileEntry is one row in the cookie JSON file. The shape mirrors
// what DevTools → Application → Cookies shows for a real browser:
//
//	{
//	  "name":      "x_wbaas_token",
//	  "value":     "...",
//	  "domain":    ".stream.wb.ru",
//	  "path":      "/",
//	  "expires":   "2026-09-15T12:34:56Z",   // RFC 3339, or "" for session
//	  "secure":    true,
//	  "httpOnly":  true
//	}
type CookieFileEntry struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	Expires  string `json:"expires"`
	Secure   bool   `json:"secure"`
	HTTPOnly bool   `json:"httpOnly"`
}

// LoadCookieJarFile reads a JSON array of CookieFileEntry values from path
// and returns an http.CookieJar seeded with them. Each entry is bound to a
// synthesized https URL for its domain (leading dot normalized) and applied
// via jar.SetCookies; entries with empty/invalid domain are reported with
// the file path and zero-based entry index.
//
// This is a small, stdlib-only helper for replaying cookies harvested from
// a real browser into Profile.CookieJar. It does not defeat any anti-bot:
// tokens expire, may be IP- or fingerprint-bound, and replayed cookies can
// still yield a JS challenge — see docs/anti-bot.md.
func LoadCookieJarFile(path string) (http.CookieJar, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("mimic: read cookies %s: %w", path, err)
	}
	var entries []CookieFileEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("mimic: parse cookies %s: %w", path, err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("mimic: create cookie jar: %w", err)
	}

	for i, e := range entries {
		domain := strings.TrimPrefix(strings.TrimSpace(e.Domain), ".")
		if domain == "" {
			return nil, fmt.Errorf("mimic: cookies %s entry %d: empty domain", path, i)
		}
		// Bare hostname only — scheme://host/path is what jar.SetCookies wants.
		if strings.ContainsAny(domain, "/ \t\n:") {
			return nil, fmt.Errorf("mimic: cookies %s entry %d: invalid domain %q", path, i, e.Domain)
		}

		path := e.Path
		if path == "" {
			path = "/"
		}
		u, err := url.Parse("https://" + domain + path)
		if err != nil {
			return nil, fmt.Errorf("mimic: cookies %s entry %d: build url: %w", path, i, err)
		}

		c := &http.Cookie{
			Name:     e.Name,
			Value:    e.Value,
			Path:     path,
			Secure:   e.Secure,
			HttpOnly: e.HTTPOnly,
		}
		if e.Expires != "" {
			t, err := time.Parse(time.RFC3339, e.Expires)
			if err != nil {
				return nil, fmt.Errorf("mimic: cookies %s entry %d: parse expires %q: %w", path, i, e.Expires, err)
			}
			c.Expires = t
		}

		jar.SetCookies(u, []*http.Cookie{c})
	}

	return jar, nil
}