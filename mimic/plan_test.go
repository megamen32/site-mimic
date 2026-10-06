package mimic

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// Subresource steps must use the per-type Sec-Fetch/Accept shape and drop
// navigation-only headers; referer chains must resolve against the site.
func TestStepRequestImageShape(t *testing.T) {
	p := Profile{
		Name:     "t",
		UserAgent: "Mozilla/5.0 test",
		Headers: map[string]string{
			"Accept":                      "text/html,application/xhtml+xml",
			"Sec-Fetch-Site":              "none",
			"Sec-Fetch-User":              "?1",
			"Upgrade-Insecure-Requests":   "1",
			"Sec-Fetch-Dest":              "document",
			"Sec-Fetch-Mode":              "navigate",
		},
		HeaderOrder: []string{"User-Agent", "Accept"},
	}
	base, _ := url.Parse("https://fp.example.test/fp")
	req, err := p.stepRequest(ResourceStep{
		Path:         "/favicon.ico",
		ResourceType: "image",
		Referer:      "/fp",
	}, base)
	if err != nil {
		t.Fatal(err)
	}
	h := req.Header
	if got := h.Get("Sec-Fetch-Dest"); got != "image" {
		t.Fatalf("sec-fetch-dest = %q, want image", got)
	}
	if got := h.Get("Sec-Fetch-Mode"); got != "no-cors" {
		t.Fatalf("sec-fetch-mode = %q, want no-cors", got)
	}
	if got := h.Get("Sec-Fetch-Site"); got != "same-origin" {
		t.Fatalf("sec-fetch-site = %q, want same-origin", got)
	}
	if got := h.Get("Accept"); !strings.HasPrefix(got, "image/avif") {
		t.Fatalf("accept = %q, want the image accept list", got)
	}
	if h.Get("Sec-Fetch-User") != "" || h.Get("Upgrade-Insecure-Requests") != "" {
		t.Fatal("navigation-only headers must be dropped on subresources")
	}
	if got := h.Get("Referer"); got != "https://fp.example.test/fp" {
		t.Fatalf("referer = %q", got)
	}
}

// Document steps keep the captured navigation shape, and the query string
// in a step path survives into the request URL.
func TestStepRequestDocumentQuery(t *testing.T) {
	p := Profile{UserAgent: "UA", Headers: map[string]string{"Accept": "text/html"}}
	base, _ := url.Parse("https://fp.example.test/fp")
	req, err := p.stepRequest(ResourceStep{
		Path:         "/fp?format=json",
		ResourceType: "xhr",
		Referer:      "/fp",
	}, base)
	if err != nil {
		t.Fatal(err)
	}
	if req.URL.RawQuery != "format=json" {
		t.Fatalf("query lost: %q", req.URL.RawQuery)
	}
	if got := req.Header.Get("Sec-Fetch-Mode"); got != "cors" {
		t.Fatalf("sec-fetch-mode = %q, want cors", got)
	}
}

// The session cache must reproduce the browser revalidation cycle: first
// navigation is a plain GET that stores the response validators, the second
// replays them as If-None-Match/If-Modified-Since (earning 304s), and a
// response that stops carrying validators drops its entry so stale values
// are never replayed.
func TestRunPlanSessionConditionalRevalidation(t *testing.T) {
	const (
		etag = `"v1"`
		lm   = "Mon, 05 Oct 2026 10:00:00 GMT"
	)
	var mu sync.Mutex
	var seen []string // "GET" or "GET inm=<..> ims=<..>" per request, in order
	serveValidators := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inm, ims := r.Header.Get("If-None-Match"), r.Header.Get("If-Modified-Since")
		mu.Lock()
		if inm != "" || ims != "" {
			seen = append(seen, "cond inm="+inm+" ims="+ims)
		} else {
			seen = append(seen, "plain")
		}
		mu.Unlock()
		if serveValidators && inm == etag {
			w.Header().Set("ETag", etag)
			w.Header().Set("Last-Modified", lm)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if serveValidators {
			w.Header().Set("ETag", etag)
			w.Header().Set("Last-Modified", lm)
		}
		w.Write([]byte("body"))
	}))
	defer srv.Close()

	p := Profile{
		Name:     "t",
		UserAgent: "Mozilla/5.0 test",
		Headers:  map[string]string{"Accept": "text/html"},
		ResourcePlan: []ResourceStep{
			{Path: "/", ResourceType: "document"},
			{Path: "/logo.png", ResourceType: "image", Referer: "/"},
		},
	}
	base, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	cache := NewPageCache()

	lines, err := p.RunPlanSession(srv.Client(), base, cache)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lines {
		if !strings.HasSuffix(l, "-> 200 OK") {
			t.Fatalf("pass 1 expected 200s, got %q", l)
		}
	}

	lines, err = p.RunPlanSession(srv.Client(), base, cache)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lines {
		if !strings.HasSuffix(l, "-> 304 Not Modified") {
			t.Fatalf("pass 2 expected 304s, got %q", l)
		}
	}

	// pass 3: every resource revalidates one last time with its last known
	// validators (the browser cannot know they vanished until it asks); the
	// validator-less 200s then drop both entries.
	serveValidators = false
	_, err = p.RunPlanSession(srv.Client(), base, cache)
	if err != nil {
		t.Fatal(err)
	}
	// pass 4: with both entries dropped the session is back to plain GETs.
	_, err = p.RunPlanSession(srv.Client(), base, cache)
	if err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 8 {
		t.Fatalf("want 8 requests, saw %d: %v", len(seen), seen)
	}
	if seen[0] != "plain" || seen[1] != "plain" {
		t.Fatalf("pass 1 must be plain GETs: %v", seen[:2])
	}
	for i, s := range seen[2:4] {
		if s != `cond inm=`+etag+` ims=`+lm {
			t.Fatalf("pass 2 request %d missing both validators: %q", i, s)
		}
	}
	for i, s := range seen[4:6] {
		if s != `cond inm=`+etag+` ims=`+lm {
			t.Fatalf("pass 3 request %d should revalidate one last time: %q", i, s)
		}
	}
	for i, s := range seen[6:8] {
		if s != "plain" {
			t.Fatalf("after validator-less 200s the entries must be dropped, request %d: %q", i, s)
		}
	}
}
