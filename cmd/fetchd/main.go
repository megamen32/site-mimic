// fetchd is a local HTTP daemon that executes one-off requests through the
// mimic library (uTLS Chrome ClientHello / chrome_exact) — the single truth
// for outbound HTTP from non-Go callers. The python/ package in this repo
// is its Python drop-in client.
//
// Bind: 127.0.0.1:30777 by default (FETCHD_ADDR). Bearer auth optional via
// FETCHD_TOKEN. Endpoint: POST /fetch.
//
// Request JSON:
//
//	{
//	  "method": "GET"|"POST"|…, "url": "https://…",
//	  "profile": "/abs/path/profile.json",   // mimic identity (required)
//	  "headers": {"K": "V"}, "cookies": {"name": "value"},
//	  "body": "…", "body_b64": "…",           // one of body/body_b64
//	  "proxy": "http://…",                    // optional per-request CONNECT proxy
//	  "resolve": {"host": "ip"},              // optional DNS pinning (SNI kept)
//	  "timeout_s": 30                         // optional, default 30
//	}
//
// Response JSON: {"status": 200, "headers": {"K": ["V"]},
// "set_cookies": [{"name","value","domain","path","expires"}],
// "body": "…", "body_b64": "…", "error": ""}.
//
// The daemon never logs bodies or cookie values.
package main

import (
	"sync/atomic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/megamen32/site-mimic/mimic"
)

type fetchRequest struct {
	Method   string            `json:"method"`
	URL      string            `json:"url"`
	Profile  string            `json:"profile"`
	Headers  map[string]string `json:"headers"`
	Cookies  map[string]string `json:"cookies"`
	Body     *string           `json:"body"`
	BodyB64  string            `json:"body_b64"`
	Proxy    string            `json:"proxy"`
	Resolve  map[string]string `json:"resolve"`
	TimeoutS float64           `json:"timeout_s"`
}

type setCookieOut struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Domain  string `json:"domain"`
	Path    string `json:"path"`
	Expires string `json:"expires"`
}

type fetchResponse struct {
	Status     int                 `json:"status"`
	Headers    map[string][]string `json:"headers"`
	SetCookies []setCookieOut      `json:"set_cookies"`
	Body       string              `json:"body"`
	BodyB64    string              `json:"body_b64"`
	Error      string              `json:"error"`
}

var (
	mu      sync.Mutex
	clients = map[string]*http.Client{}
)

// clientFor caches one mimic client per (profile, proxy, resolve) triple so
// connections pool across calls instead of dialing per request.
func clientFor(req fetchRequest) (*http.Client, error) {
	resolveKey := ""
	keys := make([]string, 0, len(req.Resolve))
	for h := range req.Resolve {
		keys = append(keys, h)
	}
	sortStrings(keys)
	for _, h := range keys {
		resolveKey += h + "=" + req.Resolve[h] + ","
	}
	cacheKey := req.Profile + "|" + req.Proxy + "|" + resolveKey

	mu.Lock()
	defer mu.Unlock()
	if c, ok := clients[cacheKey]; ok {
		return c, nil
	}
	profile, err := mimic.LoadProfile(req.Profile)
	if err != nil {
		return nil, err
	}
	opts := []mimic.Option{}
	if req.Proxy != "" {
		opts = append(opts, mimic.WithProxy(req.Proxy))
	}
	if len(req.Resolve) > 0 {
		opts = append(opts, mimic.WithResolve(req.Resolve))
	}
	timeout := 30 * time.Second
	if req.TimeoutS > 0 {
		timeout = time.Duration(req.TimeoutS * float64(time.Second))
	}
	client, err := mimic.New(profile, opts...)
	if err != nil {
		return nil, err
	}
	client.Timeout = timeout
	clients[cacheKey] = client
	return client, nil
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func handleFetch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, fetchResponse{Error: "POST /fetch only"})
		return
	}
	var req fetchRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, fetchResponse{Error: fmt.Sprintf("bad json: %v", err)})
		return
	}
	if req.URL == "" {
		writeJSON(w, http.StatusBadRequest, fetchResponse{Error: "url is required"})
		return
	}
	if req.Profile == "" {
		writeJSON(w, http.StatusBadRequest, fetchResponse{Error: "profile is required (path to a mimic profile.json)"})
		return
	}
	if req.Method == "" {
		req.Method = http.MethodGet
	}

	var body io.Reader
	switch {
	case req.Body != nil:
		body = strings.NewReader(*req.Body)
	case req.BodyB64 != "":
		decoded, err := base64.StdEncoding.DecodeString(req.BodyB64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, fetchResponse{Error: fmt.Sprintf("bad body_b64: %v", err)})
			return
		}
		body = strings.NewReader(string(decoded))
	}

	out := fetchResponse{Headers: map[string][]string{}}
	defer func() {
		if out.BodyB64 != "" {
			out.Body = ""
		}
		writeJSON(w, http.StatusOK, out)
	}()

	httpReq, err := http.NewRequest(strings.ToUpper(req.Method), req.URL, body)
	if err != nil {
		out.Error = fmt.Sprintf("bad request: %v", err)
		return
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}
	if len(req.Cookies) > 0 {
		parts := make([]string, 0, len(req.Cookies))
		for name, value := range req.Cookies {
			parts = append(parts, name+"="+value)
		}
		httpReq.Header.Set("Cookie", strings.Join(parts, "; "))
	}

	client, err := clientFor(req)
	if err != nil {
		out.Error = err.Error()
		return
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		out.Error = err.Error()
		return
	}
	defer func() { _ = resp.Body.Close() }()

	out.Status = resp.StatusCode
	for k, vs := range resp.Header {
		out.Headers[k] = vs
	}
	for _, c := range resp.Cookies() {
		out.SetCookies = append(out.SetCookies, setCookieOut{
			Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path,
			Expires: c.Expires.UTC().Format(time.RFC3339),
		})
	}
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if readErr != nil {
		out.Error = fmt.Sprintf("body read: %v", readErr)
	}
	if isProbablyUTF8(raw) {
		out.Body = string(raw)
	} else {
		out.BodyB64 = base64.StdEncoding.EncodeToString(raw)
	}
}

func isProbablyUTF8(b []byte) bool {
	for _, c := range b {
		if c == 0 {
			return false
		}
	}
	return true
}

func main() {
	addr := os.Getenv("FETCHD_ADDR")
	if addr == "" {
		addr = "127.0.0.1:30777"
	}
	token := os.Getenv("FETCHD_TOKEN")

	var fetchCount atomic.Int64

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", func(w http.ResponseWriter, r *http.Request) {
		if token != "" && r.Header.Get("Authorization") != "Bearer "+token {
			writeJSON(w, http.StatusUnauthorized, fetchResponse{Error: "unauthorized"})
			return
		}
		fetchCount.Add(1)
		handleFetch(w, r)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "requests": fetchCount.Load()})
	})

	log.Printf("fetchd listening on %s (token auth: %v)", addr, token != "")
	server := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("fetchd: %v", err)
	}
}
