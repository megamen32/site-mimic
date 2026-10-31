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
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/megamen32/site-mimic/mimic"
)

const (
	endpoint  = "https://zcode.z.ai/api/v1/zcode-plan/anthropic/v1/messages"
	deviceID  = "bf54fb16-d645-43df-8dc8-d75582dae084"
	sessionID = "e6138b80-c041-4ac5-98fe-c61242db67cb"
)

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

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
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
		"device_id":  deviceID,
		"account_uuid": "",
		"session_id": sessionID,
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

	if os.Getenv("FP_GET") != "" {
		profile2 := mimic.MustLoadProfile("profile.json")
		client2, err := mimic.New(profile2)
		if err != nil { log.Fatal(err) }
		req2, err := profile2.Request("GET", os.Getenv("FP_GET"), nil)
		if err != nil { log.Fatal(err) }
		resp2, err := client2.Do(req2)
		if err != nil { log.Fatal(err) }
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
