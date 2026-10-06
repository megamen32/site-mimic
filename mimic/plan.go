package mimic

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"time"
)

// ResourceStep is one request of a browser-like session: a navigation
// followed by its subresources, with per-resource-type header shapes and
// human-ish delays. See Profile.ResourcePlan.
type ResourceStep struct {
	Path         string            `json:"path"`
	Method       string            `json:"method,omitempty"`       // default GET
	ResourceType string            `json:"resource_type"`          // document | image | xhr | fetch | font | style | script
	Referer      string            `json:"referer,omitempty"`      // path of the referring step, e.g. "/"
	DelayMinMs   int               `json:"delay_min_ms,omitempty"` // pause before this request
	DelayMaxMs   int               `json:"delay_max_ms,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"` // per-step overrides last
}

// resourceTypeHeaders are the Sec-Fetch/Accept shapes Chrome sends per
// resource type, distilled from the real captures in the fingerprint
// matrix. document keeps the captured navigation headers of the profile;
// subresources drop navigation-only headers (sec-fetch-user,
// upgrade-insecure-requests) and carry a referer.
var resourceTypeHeaders = map[string][][2]string{
	"document": {},
	"image": {
		{"Accept", "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"},
		{"Sec-Fetch-Dest", "image"},
		{"Sec-Fetch-Mode", "no-cors"},
		{"Sec-Fetch-Site", "same-origin"},
	},
	"xhr": {
		{"Accept", "*/*"},
		{"Sec-Fetch-Dest", "empty"},
		{"Sec-Fetch-Mode", "cors"},
		{"Sec-Fetch-Site", "same-origin"},
	},
	"font": {
		{"Accept", "*/*"},
		{"Sec-Fetch-Dest", "font"},
		{"Sec-Fetch-Mode", "cors"},
		{"Sec-Fetch-Site", "same-origin"},
	},
	"style": {
		{"Accept", "text/css,*/*;q=0.1"},
		{"Sec-Fetch-Dest", "style"},
		{"Sec-Fetch-Mode", "no-cors"},
		{"Sec-Fetch-Site", "same-origin"},
	},
	"script": {
		{"Accept", "*/*"},
		{"Sec-Fetch-Dest", "script"},
		{"Sec-Fetch-Mode", "no-cors"},
		{"Sec-Fetch-Site", "same-origin"},
	},
}

// stepRequest builds the request for one plan step: the profile's captured
// navigation headers, reshaped for the resource type, then per-step
// overrides.
func (p Profile) stepRequest(step ResourceStep, base *url.URL) (*http.Request, error) {
	method := step.Method
	if method == "" {
		method = http.MethodGet
	}
	if step.Path == "" {
		return nil, fmt.Errorf("mimic: resource step needs a path")
	}
	ref, err := url.Parse(step.Path)
	if err != nil {
		return nil, fmt.Errorf("mimic: resource step path %q: %w", step.Path, err)
	}
	req, err := p.Request(method, base.ResolveReference(ref).String(), nil)
	if err != nil {
		return nil, err
	}
	// Document steps reuse the captured navigation shape as-is (plus
	// referer override); subresources are reshaped.
	if step.ResourceType != "document" {
		defaults := resourceTypeHeaders[step.ResourceType]
		if defaults == nil {
			return nil, fmt.Errorf("mimic: unknown resource_type %q", step.ResourceType)
		}
		for _, h := range []string{"Sec-Fetch-User", "Upgrade-Insecure-Requests"} {
			req.Header.Del(h)
		}
		for _, kv := range defaults {
			req.Header.Set(kv[0], kv[1])
		}
	}
	if step.Referer != "" {
		req.Header.Set("Referer", base.Scheme+"://"+base.Host+step.Referer)
	}
	for name, value := range step.Headers {
		req.Header.Set(name, value)
	}
	return req, nil
}

// cacheEntry holds the validators (ETag, Last-Modified) of one resource the
// way a browser session cache would.
type cacheEntry struct {
	etag    string
	lastMod string
}

// PageCache is the per-session HTTP cache: validators observed on earlier
// navigations, replayed as conditional request headers on later ones - what
// Chrome does when it revalidates cached resources inside one browser
// session. A nil cache disables revalidation (every request stays a plain
// GET). Freshness lifetimes are deliberately not parsed: every step still
// produces a wire request, so verification stands keep seeing the full
// session instead of silent cache hits.
type PageCache struct {
	entries map[string]cacheEntry
}

// NewPageCache returns an empty session cache.
func NewPageCache() *PageCache {
	return &PageCache{entries: map[string]cacheEntry{}}
}

// applyValidators adds If-None-Match / If-Modified-Since for a stored entry.
// Chrome sends both validators when it has both; per RFC 7232 the ETag wins
// server-side, the date is the heuristic fallback.
func (c *PageCache) applyValidators(h http.Header, key string) {
	if c == nil {
		return
	}
	e, ok := c.entries[key]
	if !ok {
		return
	}
	if e.etag != "" {
		h.Set("If-None-Match", e.etag)
	}
	if e.lastMod != "" {
		h.Set("If-Modified-Since", e.lastMod)
	}
}

// store keeps the validators of a response and drops entries whose responses
// stopped carrying validators, so stale values are never replayed. A 304
// carries the same validators and simply re-confirms the entry.
func (c *PageCache) store(key string, h http.Header) {
	if c == nil {
		return
	}
	e := cacheEntry{etag: h.Get("ETag"), lastMod: h.Get("Last-Modified")}
	if e.etag == "" && e.lastMod == "" {
		delete(c.entries, key)
		return
	}
	c.entries[key] = e
}

// RunPlan walks the profile's ResourcePlan against base: per-step jittered
// delays, one client (connection pool) for the whole session — the way a
// real browser multiplexes a page load over one TLS connection. Returns the
// step statuses.
func (p Profile) RunPlan(client *http.Client, base *url.URL) ([]string, error) {
	return p.RunPlanSession(client, base, nil)
}

// RunPlanSession walks the plan like RunPlan and revalidates through cache:
// the first pass stores each response's ETag/Last-Modified, later passes
// replay them as If-None-Match/If-Modified-Since (server answers 304, the
// entry is kept or refreshed from a 200). Pass the same *PageCache across
// repeat navigations of one session, e.g. one stand-probe run.
func (p Profile) RunPlanSession(client *http.Client, base *url.URL, cache *PageCache) ([]string, error) {
	if len(p.ResourcePlan) == 0 {
		return nil, fmt.Errorf("mimic: profile %q has no resource_plan", p.Name)
	}
	var out []string
	for i, step := range p.ResourcePlan {
		if i > 0 || step.DelayMinMs > 0 {
			lo, hi := step.DelayMinMs, step.DelayMaxMs
			if hi < lo {
				hi = lo
			}
			d := time.Duration(lo) * time.Millisecond
			if hi > lo {
				d += time.Duration(rand.Int63n(int64(hi-lo))) * time.Millisecond
			}
			if d > 0 {
				time.Sleep(d)
			}
		}
		req, err := p.stepRequest(step, base)
		if err != nil {
			return out, fmt.Errorf("step %d (%s): %w", i, step.Path, err)
		}
		key := req.URL.String()
		cache.applyValidators(req.Header, key)
		resp, err := client.Do(req)
		if err != nil {
			return out, fmt.Errorf("step %d (%s): %w", i, step.Path, err)
		}
		out = append(out, fmt.Sprintf("%s %s -> %s", req.Method, step.Path, resp.Status))
		cache.store(key, resp.Header)
		resp.Body.Close()
	}
	return out, nil
}
