package main

import (
	"net/http/httptest"
	"testing"
)

// The static asset must run the full revalidation cycle and stay visible in
// the /fp/recent ring both times, so conditional requests from real browsers
// and the mimic PageCache can be compared on the stand.
func TestServeAssetRevalidation(t *testing.T) {
	rb := newReportBuilder("up:1")
	sn := newSniffer("lo", 443) // no run(): empty flow table is fine

	r1 := httptest.NewRequest("GET", "/fp/dot.png", nil)
	w1 := httptest.NewRecorder()
	rb.serveAsset(w1, r1, sn)
	if w1.Code != 200 {
		t.Fatalf("first fetch: code %d, want 200", w1.Code)
	}
	if got := w1.Header().Get("ETag"); got != pixelETag {
		t.Fatalf("first fetch: etag %q, want %q", got, pixelETag)
	}
	if w1.Header().Get("Last-Modified") == "" || w1.Header().Get("Cache-Control") == "" {
		t.Fatal("first fetch: validators/cache-control missing")
	}
	if len(w1.Body.Bytes()) == 0 {
		t.Fatal("first fetch: empty body")
	}
	if n := len(rb.last(10)); n != 1 {
		t.Fatalf("ring has %d reports after first fetch, want 1", n)
	}

	r2 := httptest.NewRequest("GET", "/fp/dot.png", nil)
	r2.Header.Set("If-None-Match", pixelETag)
	w2 := httptest.NewRecorder()
	rb.serveAsset(w2, r2, sn)
	if w2.Code != 304 {
		t.Fatalf("revalidation: code %d, want 304", w2.Code)
	}
	if got := w2.Header().Get("ETag"); got != pixelETag {
		t.Fatalf("revalidation: etag %q, want %q", got, pixelETag)
	}
	if n := len(rb.last(10)); n != 2 {
		t.Fatalf("ring has %d reports after revalidation, want 2", n)
	}

	r3 := httptest.NewRequest("GET", "/favicon.ico", nil)
	r3.Header.Set("If-None-Match", `"stale"`)
	w3 := httptest.NewRecorder()
	rb.serveAsset(w3, r3, sn)
	if w3.Code != 200 {
		t.Fatalf("mismatched validator: code %d, want 200", w3.Code)
	}
}
