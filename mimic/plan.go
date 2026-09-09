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

// RunPlan walks the profile's ResourcePlan against base: per-step jittered
// delays, one client (connection pool) for the whole session — the way a
// real browser multiplexes a page load over one TLS connection. Returns the
// step statuses.
func (p Profile) RunPlan(client *http.Client, base *url.URL) ([]string, error) {
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
		resp, err := client.Do(req)
		if err != nil {
			return out, fmt.Errorf("step %d (%s): %w", i, step.Path, err)
		}
		out = append(out, fmt.Sprintf("%s %s -> %s", req.Method, step.Path, resp.Status))
		resp.Body.Close()
	}
	return out, nil
}
