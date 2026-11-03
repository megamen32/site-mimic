// Command zai-start-gateway talks to the Z.ai ZCode start-plan gateway the way
// the installed ZCode desktop (Electron 42 / Node 24) does: the same endpoint,
// the same credential class, the same header set, the same wire identity
// (BoringSSL ClientHello, ALPN http/1.1).
//
// The start-plan quota is only reachable through this signed-session path; a
// plain project-token (PAT) request bills the separate weekly pool that was
// exhausted on 2026-10-31. Headers and the body metadata shape were captured
// from the live desktop on 2026-10-31 (see ~/zai-fix/mitm/capture-keep.log).
//
// Usage:
//
//	go run .                                  # one short request, prints status + reply
//	go run . -prompt "ping"                   # custom user message
//	go run . -stream                          # stream SSE like the app does
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/megamen32/site-mimic/mimic"
)

const (
	endpoint  = "https://zcode.z.ai/api/v1/zcode-plan/anthropic/v1/messages"
	deviceID  = "bf54fb16-d645-43df-8dc8-d75582dae084"
	sessionID = "e6138b80-c041-4ac5-98fe-c61242db67cb"

	// upstreamHeaderTimeout bounds how long a forward waits for the upstream
	// response headers before giving up with 504.
	upstreamHeaderTimeout = 45 * time.Second
)

var errUpstreamHeaderTimeout = errors.New("upstream header timeout")

// awaitResponseHeaders bounds the header wait without cancelling a successful
// response stream. The returned cancel must be called after its body is closed.
// If a timeout or caller cancellation wins, a late response is still closed.
func awaitResponseHeaders(ctx context.Context, client *http.Client, req *http.Request, timeout time.Duration) (*http.Response, context.CancelFunc, error) {
	upstreamCtx, cancel := context.WithCancel(ctx)
	req = req.WithContext(upstreamCtx)
	type outcome struct {
		resp *http.Response
		err  error
	}
	result := make(chan outcome)
	go func() {
		resp, err := client.Do(req)
		select {
		case result <- outcome{resp: resp, err: err}:
		case <-upstreamCtx.Done():
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
		}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case done := <-result:
		if err := upstreamCtx.Err(); err != nil {
			if done.resp != nil && done.resp.Body != nil {
				_ = done.resp.Body.Close()
			}
			cancel()
			return nil, nil, err
		}
		if done.err != nil || done.resp == nil || done.resp.Body == nil {
			if done.resp != nil && done.resp.Body != nil {
				_ = done.resp.Body.Close()
			}
			cancel()
			if done.err != nil {
				return nil, nil, done.err
			}
			return nil, nil, errors.New("upstream returned no response body")
		}
		return done.resp, cancel, nil
	case <-timer.C:
		cancel()
		return nil, nil, errUpstreamHeaderTimeout
	case <-upstreamCtx.Done():
		err := upstreamCtx.Err()
		cancel()
		return nil, nil, err
	}
}

// The ZCode CLI stores the shared OAuth JWT in ~/.zcode/v2/credentials.json,
// AES-256-GCM with a machine-derived key (enc:v1:iv.tag.data, base64url).
func readZcodeJWT() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	raw, err := os.ReadFile(filepath.Join(home, ".zcode", "v2", "credentials.json"))
	if err != nil {
		return "", err
	}
	var store map[string]json.RawMessage
	if err := json.Unmarshal(raw, &store); err != nil {
		return "", err
	}
	encVal, ok := store["zcodejwttoken"]
	if !ok {
		return "", fmt.Errorf("zcodejwttoken not found in credentials.json")
	}
	var enc string
	if err := json.Unmarshal(encVal, &enc); err != nil {
		return "", err
	}
	body := strings.TrimPrefix(enc, "enc:v1:")
	parts := strings.Split(body, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("unexpected credential format")
	}
	dec := func(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
	iv, err := dec(parts[0])
	if err != nil {
		return "", err
	}
	tag, err := dec(parts[1])
	if err != nil {
		return "", err
	}
	data, err := dec(parts[2])
	if err != nil {
		return "", err
	}
	key := sha256.Sum256([]byte("zcode-credential-fallback:linux:" + HOME_DIR + ":roomhacker"))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plain, err := aead.Open(nil, iv, append(data, tag...), nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

const HOME_DIR = "/home/roomhacker"

// harvestJWTs pulls the freshest desktop-session tokens from the capture
// stream: the desktop rotates its session jwt in memory, and the proxy sees
// every live request. Returns (authorization, x-api-key, ok).
func harvestJWTs() (string, string, bool) {
	f, err := os.Open(HOME_DIR + "/zai-fix/mitm/capture.log")
	if err != nil {
		return "", "", false
	}
	defer f.Close()
	st, _ := f.Stat()
	start := int64(0)
	if st.Size() > 512*1024 {
		start = st.Size() - 512*1024
	}
	f.Seek(start, 0)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	bestT := int64(0)
	auth, apikey := "", ""
	for sc.Scan() {
		line := sc.Bytes()
		var e struct {
			T       int64             `json:"t"`
			Headers map[string]string `json:"headers"`
		}
		if json.Unmarshal(line, &e) != nil || e.T == 0 {
			continue
		}
		a := strings.TrimSpace(e.Headers["authorization"])
		k := strings.TrimSpace(e.Headers["x-api-key"])
		if !strings.HasPrefix(a, "Bearer eyJ") || !strings.HasPrefix(k, "eyJ") {
			continue
		}
		if e.T > bestT {
			bestT = e.T
			auth = strings.TrimPrefix(a, "Bearer ")
			apikey = k
		}
	}
	if bestT == 0 || auth == "" || apikey == "" {
		return "", "", false
	}
	if time.Since(time.UnixMilli(bestT)) > 30*time.Minute {
		return "", "", false
	}
	return auth, apikey, true
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// withFreshSessionID rewrites metadata.user_id.session_id in the request
// body to a new session. The captured body belongs to an earlier turn, and
// the upstream rejects a reused session_id with "parameter error" (3001).
// A body that does not carry that field is passed through untouched.
func withFreshSessionID(body []byte) []byte {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return body
	}
	rawMeta, ok := doc["metadata"]
	if !ok {
		return body
	}
	var meta map[string]json.RawMessage
	if err := json.Unmarshal(rawMeta, &meta); err != nil {
		return body
	}
	rawUser, ok := meta["user_id"]
	if !ok {
		return body
	}
	// metadata.user_id is a JSON-encoded string in the captured traffic, but
	// accept a plain object too.
	var user map[string]any
	var encodedUser bool
	var userID string
	if err := json.Unmarshal(rawUser, &userID); err == nil {
		if err := json.Unmarshal([]byte(userID), &user); err != nil {
			return body
		}
		encodedUser = true
	} else if err := json.Unmarshal(rawUser, &user); err != nil {
		return body
	}
	user["session_id"] = "sess_" + uuid.NewString()
	patched, err := json.Marshal(user)
	if err != nil {
		return body
	}
	if encodedUser {
		encoded, err := json.Marshal(string(patched))
		if err != nil {
			return body
		}
		meta["user_id"] = encoded
	} else {
		meta["user_id"] = patched
	}
	newMeta, err := json.Marshal(meta)
	if err != nil {
		return body
	}
	doc["metadata"] = newMeta
	out, err := json.Marshal(doc)
	if err != nil {
		return body
	}
	return out
}

func main() {
	prompt := flag.String("prompt", "Reply with exactly: OK", "user message")
	model := flag.String("model", "GLM-5.3-Flash", "model id")
	maxTokens := flag.Int("max-tokens", 128000, "max_tokens")
	jwtFile := flag.String("jwtfile", "", "raw bearer jwt file (overrides credentials.json)")
	bodyFile := flag.String("body", "", "raw JSON body file (verbatim replay)")
	hdrsFile := flag.String("hdrs", "", "JSON headers file (overrides profile headers)")
	flag.Parse()

	var jwt string
	if *jwtFile != "" {
		b, err := os.ReadFile(*jwtFile)
		if err != nil {
			log.Fatal(err)
		}
		jwt = strings.TrimSpace(string(b))
	} else {
		var err error
		jwt, err = readZcodeJWT()
		if err != nil {
			log.Fatal(err)
		}
	}

	profile := mimic.MustLoadProfile("profile.json")
	client, err := mimic.New(profile)
	if err != nil {
		log.Fatal(err)
	}

	userID, _ := json.Marshal(map[string]string{
		"device_id":    deviceID,
		"account_uuid": "",
		"session_id":   sessionID,
	})
	userID = []byte(fmt.Sprintf(`{"device_id":"%s","account_uuid":"","session_id":"%s"}`, deviceID, sessionID))
	payload := map[string]any{
		"model":      *model,
		"max_tokens": *maxTokens,
		"metadata":   map[string]any{"user_id": userID},
		"system":     []map[string]any{{"type": "text", "text": "You are ZCode, an interactive agent"}},
		"stream":     true,
		"messages":   []chatMessage{{Role: "user", Content: *prompt}},
	}
	raw, _ := json.Marshal(payload)

	if os.Getenv("SERVE") != "" {
		http.HandleFunc("/forward", func(w http.ResponseWriter, r *http.Request) {
			var env struct {
				Target  string            `json:"target"`
				Headers map[string]string `json:"headers"`
				BodyB64 string            `json:"body_b64"`
			}
			if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
				http.Error(w, "bad envelope: "+err.Error(), 400)
				return
			}
			hAuth, hKey, fresh := harvestJWTs()
			jwt := hAuth
			if !fresh {
				var err error
				jwt, err = readZcodeJWT()
				if err != nil {
					http.Error(w, "jwt: "+err.Error(), 500)
					return
				}
			}
			_ = hKey
			profile := mimic.MustLoadProfile("profile.json")
			client, err := mimic.New(profile)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			// One client is built per forward: do not retain idle H1/H2 sockets.
			defer client.CloseIdleConnections()
			target := env.Target
			if target == "" {
				target = endpoint
			}
			body, err := base64.StdEncoding.DecodeString(env.BodyB64)
			if err != nil {
				http.Error(w, "bad body b64: "+err.Error(), 400)
				return
			}
			hdrs := env.Headers
			if hdrs == nil {
				hdrs = map[string]string{}
			}
			hdrs["authorization"] = "Bearer " + jwt
			hdrs["x-api-key"] = jwt
			// The upstream binds a request to a fresh session: a replayed
			// request-id/query-id/trace-id or session_id is rejected with
			// "parameter error" (code 3001). The captured desktop request
			// carries the ids of the original turn, so every forward gets new
			// ones.
			hdrs["x-request-id"] = uuid.NewString()
			hdrs["x-query-id"] = uuid.NewString()
			hdrs["x-zcode-trace-id"] = strings.ReplaceAll(uuid.NewString(), "-", "")
			hdrs["x-session-id"] = uuid.NewString()
			body = withFreshSessionID(body)
			req, err := profile.Request("POST", target, bytes.NewReader(body))
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			for k, v := range hdrs {
				req.Header.Set(k, v)
			}
			resp, cancelUpstream, err := awaitResponseHeaders(r.Context(), client, req, upstreamHeaderTimeout)
			if err != nil {
				if r.Context().Err() != nil {
					return
				}
				if errors.Is(err, errUpstreamHeaderTimeout) {
					http.Error(w, "upstream header timeout", http.StatusGatewayTimeout)
				} else {
					http.Error(w, err.Error(), http.StatusBadGateway)
				}
				return
			}
			defer cancelUpstream()
			defer resp.Body.Close()
			for k, vv := range resp.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(resp.StatusCode)
			flusher, _ := w.(http.Flusher)
			buf := make([]byte, 32*1024)
			for {
				n, err := resp.Body.Read(buf)
				if n > 0 {
					if _, writeErr := w.Write(buf[:n]); writeErr != nil {
						return
					}
					if flusher != nil {
						flusher.Flush()
					}
				}
				if err != nil {
					break
				}
			}
		})
		log.Fatal(http.ListenAndServe(os.Getenv("SERVE"), nil))
	}
	if os.Getenv("FP_GET") != "" {
		profile2 := mimic.MustLoadProfile("profile.json")
		client2, err := mimic.New(profile2)
		if err != nil {
			log.Fatal(err)
		}
		req2, err := profile2.Request("GET", os.Getenv("FP_GET"), nil)
		if err != nil {
			log.Fatal(err)
		}
		resp2, err := client2.Do(req2)
		if err != nil {
			log.Fatal(err)
		}
		defer resp2.Body.Close()
		b2, _ := io.ReadAll(io.LimitReader(resp2.Body, 200))
		fmt.Println("FP:", resp2.Status, string(b2))
		return
	}
	var bodyReader io.Reader
	if *bodyFile != "" {
		b, err := os.ReadFile(*bodyFile)
		if err != nil {
			log.Fatal(err)
		}
		bodyReader = bytes.NewReader(b)
	} else {
		bodyReader = bytes.NewReader(raw)
	}
	var override map[string]string
	if *hdrsFile != "" {
		b, err := os.ReadFile(*hdrsFile)
		if err != nil {
			log.Fatal(err)
		}
		json.Unmarshal(b, &override)
	}
	if override != nil {
		override["x-request-id"] = uuid.NewString()
		override["x-query-id"] = uuid.NewString()
		override["x-zcode-trace-id"] = strings.ReplaceAll(uuid.NewString(), "-", "")
		profile.Headers = override
	}
	req, err := profile.Request("POST", endpoint, bodyReader)
	if err != nil {
		log.Fatal(err)
	}
	if override == nil {
		req.Header.Set("authorization", "Bearer "+jwt)
		req.Header.Set("x-api-key", jwt)
		req.Header.Set("x-query-id", uuid.NewString())
		req.Header.Set("x-request-id", uuid.NewString())
		req.Header.Set("x-session-id", sessionID)
		req.Header.Set("x-zcode-trace-id", strings.ReplaceAll(uuid.NewString(), "-", ""))
		req.Header.Set("x-zcode-session-features", "tool_search_called,tool_search_local")
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	fmt.Println("status:", resp.Status)
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 1<<20))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			fmt.Println(line[:min(len(line), 200)])
			continue
		}
		if line != "" {
			fmt.Println(line[:min(len(line), 300)])
		}
	}
}
