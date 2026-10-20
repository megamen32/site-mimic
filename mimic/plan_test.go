package mimic

import (
	"fmt"
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
		Name:      "t",
		UserAgent: "Mozilla/5.0 test",
		Headers: map[string]string{
			"Accept":                    "text/html,application/xhtml+xml",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-User":            "?1",
			"Upgrade-Insecure-Requests": "1",
			"Sec-Fetch-Dest":            "document",
			"Sec-Fetch-Mode":            "navigate",
		},
		HeaderOrder: []string{"User-Agent", "Accept"},
	}
	base, _ := url.Parse("https://fp.example.test/fp")
	req, err := p.stepRequest(ResourceStep{
		Path:         "/favicon.ico",
		ResourceType: "image",
		Referer:      "/fp",
	}, base, "https://fp.example.test/fp")
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
	}, base, "https://fp.example.test/fp")
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
		Name:      "t",
		UserAgent: "Mozilla/5.0 test",
		Headers:   map[string]string{"Accept": "text/html"},
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

// TestPageCacheIsSafeForConcurrentUse guards the session cache against a
// data race: the entries map was written from store and read from
// applyValidators with no lock, and a cache shared between sessions — the
// exported type does not say it is single-goroutine — could hit Go's fatal
// "concurrent map writes".
//
// The race detector finds it; without -race this test only checks that
// nothing panics.
func TestPageCacheIsSafeForConcurrentUse(t *testing.T) {
	cache := NewPageCache()
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 64; i++ {
				key := fmt.Sprintf("key-%d", i%7)
				h := http.Header{}
				h.Set("ETag", fmt.Sprintf("\"%d-%d\"", worker, i))
				cache.applyValidators(h, key)
				cache.store(key, h)
			}
		}(worker)
	}
	wg.Wait()
}

// TestSecFetchSiteFollowsTheInitiator pins the Sec-Fetch-Site value to the
// relation between the initiator and the target.
//
// It used to be a constant: every subresource of every plan said
// "same-origin", including the ones a plan sends to another host — a value
// no browser produces. The value is now computed the way Chrome computes
// it: same origin, same site, cross site, or none when nothing initiated
// the request.
func TestSecFetchSiteFollowsTheInitiator(t *testing.T) {
	cases := []struct {
		name      string
		initiator string
		target    string
		captured  string
		want      string
	}{
		{
			name:      "same origin",
			initiator: "https://fp.example.test/fp",
			target:    "https://fp.example.test/logo.png",
			want:      "same-origin",
		},
		{
			name:      "same site, another host",
			initiator: "https://fp.example.test/fp",
			target:    "https://cdn.example.test/logo.png",
			want:      "same-site",
		},
		{
			name:      "cross site",
			initiator: "https://fp.example.test/fp",
			target:    "https://cdn.other.test/logo.png",
			want:      "cross-site",
		},
		{
			name:      "no initiator",
			initiator: "",
			target:    "https://fp.example.test/logo.png",
			want:      "none",
		},
		{
			name:      "a captured navigation keeps its captured value",
			initiator: "",
			target:    "https://fp.example.test/fp",
			captured:  "cross-site",
			want:      "cross-site",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := stepSecFetchSite(tc.initiator, tc.target, tc.captured)
			if got != tc.want {
				t.Fatalf("sec-fetch-site = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestStepRequestSecFetchSiteIsComputed checks the header on the request
// itself, not only the helper: a subresource of a document on another host
// must not claim to be same-origin.
func TestStepRequestSecFetchSiteIsComputed(t *testing.T) {
	p := Profile{
		Name:    "t",
		Headers: map[string]string{"Accept": "text/html"},
	}
	base, _ := url.Parse("https://fp.example.test/fp")
	req, err := p.stepRequest(ResourceStep{
		Path:         "https://cdn.other.test/logo.png",
		ResourceType: "image",
	}, base, "https://fp.example.test/fp")
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Sec-Fetch-Site"); got != "cross-site" {
		t.Fatalf("sec-fetch-site = %q, want cross-site", got)
	}
}

// TestRunPlanSessionSecFetchSiteFollowsTheDocument checks the wiring in the
// session runner, not only the helper: a subresource is judged against the
// document the plan opened.
//
// The three values come from three relations. The navigation was typed, so
// nothing initiated it ("none"). The first subresource sits on another port
// of the same host ("same-site" — a site ignores the port). The second sits
// on another host ("cross-site").
func TestRunPlanSessionSecFetchSiteFollowsTheDocument(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Host+r.URL.Path+" sec-fetch-site="+r.Header.Get("Sec-Fetch-Site"))
		mu.Unlock()
		w.Write([]byte("body"))
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()
	other := httptest.NewServer(handler)
	defer other.Close()
	// The same machine, another name: a different site.
	elsewhere := strings.Replace(other.URL, "127.0.0.1", "localhost", 1)

	p := Profile{
		Name:      "t",
		UserAgent: "Mozilla/5.0 test",
		Headers:   map[string]string{"Accept": "text/html"},
		ResourcePlan: []ResourceStep{
			{Path: "/", ResourceType: "document"},
			{Path: other.URL + "/logo.png", ResourceType: "image"},
			{Path: elsewhere + "/x.png", ResourceType: "image"},
		},
	}
	base, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.RunPlanSession(srv.Client(), base, NewPageCache()); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	want := []string{
		" sec-fetch-site=none",
		" sec-fetch-site=same-site",
		" sec-fetch-site=cross-site",
	}
	if len(seen) != len(want) {
		t.Fatalf("want %d requests, saw %d: %v", len(want), len(seen), seen)
	}
	for i, suffix := range want {
		if !strings.HasSuffix(seen[i], suffix) {
			t.Fatalf("request %d = %q, want it to end with %q", i, seen[i], suffix)
		}
	}
}
