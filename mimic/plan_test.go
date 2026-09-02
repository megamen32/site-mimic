package mimic

import (
	"net/url"
	"strings"
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
	base, _ := url.Parse("https://test.auto-gram.ru/fp")
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
	if got := h.Get("Referer"); got != "https://test.auto-gram.ru/fp" {
		t.Fatalf("referer = %q", got)
	}
}

// Document steps keep the captured navigation shape, and the query string
// in a step path survives into the request URL.
func TestStepRequestDocumentQuery(t *testing.T) {
	p := Profile{UserAgent: "UA", Headers: map[string]string{"Accept": "text/html"}}
	base, _ := url.Parse("https://test.auto-gram.ru/fp")
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
