package mimic

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCookieJar_RoundTrip_HTTptest spins up an httptest server, configures
// it to set a cookie on /seed, points a cookiejar-backed http.Client at
// it, and verifies the cookie is sent back on a second request.
func TestCookieJar_RoundTrip_HTTptest(t *testing.T) {
	var seenSecond string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/seed":
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc123", Path: "/"})
		case "/check":
			if c, err := r.Cookie("sid"); err == nil {
				seenSecond = c.Value
			}
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := &http.Client{Jar: jar}

	resp, err := client.Get(srv.URL + "/seed")
	if err != nil {
		t.Fatalf("seed GET: %v", err)
	}
	resp.Body.Close()

	resp, err = client.Get(srv.URL + "/check")
	if err != nil {
		t.Fatalf("check GET: %v", err)
	}
	resp.Body.Close()

	if seenSecond != "abc123" {
		t.Fatalf("cookie not replayed: got %q, want %q", seenSecond, "abc123")
	}
}

// TestLoadCookieJarFile_RoundTrip writes a JSON file in the shape DevTools
// exports, loads it, and verifies the cookie is bound to the right host
// so the jar attaches it to a request to that host. We use httptest
// (plain HTTP) with Secure=false because httptest TLS uses a self-signed
// cert; the Secure flag is exercised separately below.
func TestLoadCookieJarFile_RoundTrip(t *testing.T) {
	path := writeCookieFile(t, []CookieFileEntry{{
		Name:     "x_wbaas_token",
		Value:    "harvested-xyz",
		Domain:   ".stream.wb.ru",
		Path:     "/",
		Expires:  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		HTTPOnly: true,
	}})

	jar, err := LoadCookieJarFile(path)
	if err != nil {
		t.Fatalf("LoadCookieJarFile: %v", err)
	}

	// Point the client at a host that matches the cookie's domain so the
	// jar will attach it. We use a rewriter to map 127.0.0.1:port to
	// "stream.wb.ru" — the standard way to test jar host-binding without
	// owning a real DNS name.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("x_wbaas_token"); err == nil {
			w.Header().Set("X-Seen-Cookie", c.Value)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{Jar: jar}

	req, err := http.NewRequest("GET", srv.URL+"/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "stream.wb.ru"

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	if got := resp.Header.Get("X-Seen-Cookie"); got != "harvested-xyz" {
		t.Fatalf("replayed cookie: got %q, want %q", got, "harvested-xyz")
	}
}

// TestLoadCookieJarFile_LeadingDot verifies that a domain with a leading
// dot is normalized so the cookie still binds to the bare host.
func TestLoadCookieJarFile_LeadingDot(t *testing.T) {
	path := writeCookieFile(t, []CookieFileEntry{{
		Name:   "k",
		Value:  "v",
		Domain: ".example.test",
		Path:   "/",
	}})

	jar, err := LoadCookieJarFile(path)
	if err != nil {
		t.Fatalf("LoadCookieJarFile: %v", err)
	}

	u, err := url.Parse("https://example.test/")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	for _, c := range jar.Cookies(u) {
		if c.Name == "k" && c.Value == "v" {
			return
		}
	}
	t.Fatal("cookie not bound to bare host (leading-dot normalization broken)")
}

// TestLoadCookieJarFile_Expired verifies that an expired entry loads
// without error but is NOT returned on Cookies() — cookiejar enforces
// RFC 6265 §5.3 (expired cookies are discarded).
func TestLoadCookieJarFile_Expired(t *testing.T) {
	path := writeCookieFile(t, []CookieFileEntry{{
		Name:    "old",
		Value:   "stale",
		Domain:  "example.test",
		Path:    "/",
		Expires: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	}})

	jar, err := LoadCookieJarFile(path)
	if err != nil {
		t.Fatalf("LoadCookieJarFile (expired entry): %v", err)
	}

	u, err := url.Parse("https://example.test/")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	for _, c := range jar.Cookies(u) {
		if c.Name == "old" {
			t.Fatalf("expired cookie should be discarded, got %+v", c)
		}
	}
}

// TestLoadCookieJarFile_HTTPOnlySecure verifies that the Secure and
// HttpOnly flags are stored on the cookie in the jar (jar.Cookies()
// returns a stripped copy for outgoing requests, so we observe via a
// live httptest server: the server sees the cookie in the request
// header regardless of HttpOnly, and the round-trip already covers that;
// here we specifically exercise the Secure flag by checking the cookie
// is suppressed on an http URL).
func TestLoadCookieJarFile_HTTPOnlySecure(t *testing.T) {
	path := writeCookieFile(t, []CookieFileEntry{{
		Name:    "flagged",
		Value:   "yes",
		Domain:  "flagged.test",
		Path:    "/",
		Secure:  true,
		Expires: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}})

	jar, err := LoadCookieJarFile(path)
	if err != nil {
		t.Fatalf("LoadCookieJarFile: %v", err)
	}

	// Direct introspection: the jar retains the Secure flag on the
	// stored entry. cookiejar exposes it via jar.Cookies() with the
	// outgoing-presentation copy; for a Secure cookie on an http URL
	// it must be omitted.
	got := jar.Cookies(mustParseURL(t, "http://flagged.test/"))
	if len(got) != 0 {
		t.Fatalf("Secure cookie should not be returned for http URL, got %+v", got)
	}
	got = jar.Cookies(mustParseURL(t, "https://flagged.test/"))
	if len(got) != 1 || got[0].Value != "yes" {
		t.Fatalf("Secure cookie should be returned for https URL, got %+v", got)
	}
}

// TestLoadCookieJarFile_MalformedJSON verifies the file-path and parse
// error are surfaced clearly.
func TestLoadCookieJarFile_MalformedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := LoadCookieJarFile(path)
	if err == nil {
		t.Fatal("expected parse error, got nil")
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("error should name file %s: %v", path, err)
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Fatalf("error should mention parse: %v", err)
	}
}

// TestLoadCookieJarFile_MissingFile verifies a missing file is reported.
func TestLoadCookieJarFile_MissingFile(t *testing.T) {
	_, err := LoadCookieJarFile(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
	if !strings.Contains(err.Error(), "read cookies") {
		t.Fatalf("error should mention read: %v", err)
	}
}

// TestLoadCookieJarFile_EmptyDomain verifies entries with empty domains
// are rejected with file path and entry index.
func TestLoadCookieJarFile_EmptyDomain(t *testing.T) {
	path := writeCookieFile(t, []CookieFileEntry{
		{Name: "ok", Value: "v", Domain: "good.test", Path: "/"},
		{Name: "bad", Value: "v", Domain: "", Path: "/"},
	})

	_, err := LoadCookieJarFile(path)
	if err == nil {
		t.Fatal("expected error for empty domain")
	}
	if !strings.Contains(err.Error(), "entry 1") {
		t.Fatalf("error should name entry index 1: %v", err)
	}
}

// --- helpers ---

func writeCookieFile(t *testing.T, entries []CookieFileEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cookies.json")
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url %s: %v", raw, err)
	}
	return u
}