// Command minimax-agent-gateway talks to the MiniMax managed LLM gateway the
// way MiniMax Code (Electron 42 / Node 24) does: the same endpoint, the same
// credential, the same header set and the same wire identity (BoringSSL
// ClientHello, ALPN http/1.1).
//
// The public Anthropic-compatible endpoint (api.minimax.io/anthropic) is a
// different product: it bills a platform API key and does not carry the
// M-Plan models. This client uses the managed route instead — see
// docs/minimax-agent-gateway.ru.md for the measured difference.
//
// Usage:
//
//	go run .                                   # one short request with the managed token
//	go run . -prompt "ping" -model MiniMax-M3.1-Flash
//	go run . -dump ch.json                     # capture the raw ClientHello for JA3/JA4
//	python3 ../../tools/parse_clienthello.py ch.json
//	go run . -fingerprint https://host/fp      # fetch a fingerprint report through the mimic client
//
// The token is never printed. It comes from MINIMAX_MANAGED_TOKEN, or from the
// MiniMax Code managed-login state file when that variable is unset.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/megamen32/site-mimic/mimic"
)

const defaultEndpoint = "https://agent.minimax.io/mavis/api/v1/llm/v1/messages"

func main() {
	target := flag.String("url", defaultEndpoint, "managed gateway messages endpoint")
	model := flag.String("model", "MiniMax-M3.1-Flash", "model id")
	prompt := flag.String("prompt", "Reply with the single word: ok", "user message")
	maxTokens := flag.Int("max-tokens", 32, "max_tokens for the request")
	session := flag.String("session", "mvs_profile_probe", "x-mavis-session-id value (the app sends its live session id)")
	stream := flag.Bool("stream", true, "stream the answer like the app does (SSE)")
	dump := flag.String("dump", "", "write the raw ClientHello record JSON to this path")
	fingerprint := flag.String("fingerprint", "", "fetch this URL through the mimic client and print the body (fingerprint stand)")
	insecure := flag.Bool("insecure", false, "skip TLS verification (local capture sinks only)")
	timeout := flag.Duration("timeout", 45*time.Second, "request timeout")
	flag.Parse()

	profile := mimic.MustLoadProfile("profile.json")
	profile.Headers["x-mavis-session-id"] = *session
	opts := []mimic.Option{}
	if *insecure {
		opts = append(opts, mimic.WithInsecureTLS())
	}
	client, err := mimic.New(profile, opts...)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if *dump != "" {
		u, err := url.Parse(*target)
		if err != nil {
			log.Fatal(err)
		}
		record, err := mimic.ClientHelloCapture(ctx, u.Hostname(), profile.TLSClientHello)
		if err != nil {
			log.Fatal(err)
		}
		if err := mimic.WriteClientHelloJSON(*dump, u.Host, record); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("clienthello: wrote %s — fingerprint it with:\n", *dump)
		fmt.Printf("  python3 ../../tools/parse_clienthello.py %s\n", *dump)
	}

	if *fingerprint != "" {
		req, err := profile.Request("GET", *fingerprint, nil)
		if err != nil {
			log.Fatal(err)
		}
		resp, err := client.Do(req.WithContext(ctx))
		if err != nil {
			log.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		fmt.Printf("status: %s\nproto:  %s\n", resp.Status, resp.Proto)
		fmt.Println(string(body))
		return
	}

	token, err := managedToken()
	if err != nil {
		log.Fatal(err)
	}

	payload := messagesRequest{
		Model:     *model,
		MaxTokens: *maxTokens,
		Messages:  []chatMessage{{Role: "user", Content: *prompt}},
		Stream:    *stream,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		log.Fatal(err)
	}

	req, err := profile.Request("POST", *target, bytes.NewReader(raw))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	fmt.Printf("status: %s\n", resp.Status)
	fmt.Printf("proto:  %s\n", resp.Proto)
	fmt.Printf("ua:     %s\n", req.Header.Get("User-Agent"))

	if *stream {
		text, err := readSSE(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("text:   %s\n", text)
		if resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		return
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	var parsed struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		fmt.Printf("body:   %d bytes; first 200: %.200q\n", len(body), body)
		os.Exit(1)
	}
	if parsed.Error != "" {
		fmt.Printf("error:  %s\n", parsed.Error)
		os.Exit(1)
	}
	for _, block := range parsed.Content {
		if block.Type == "text" {
			fmt.Printf("text:   %s\n", block.Text)
		}
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("body:   %d bytes; first 200: %.200q\n", len(body), body)
		os.Exit(1)
	}
}

// messagesRequest mirrors the field order the Anthropic SDK sends, so the
// request body on the wire matches the app's byte for byte.
type messagesRequest struct {
	Model     string        `json:"model"`
	MaxTokens int           `json:"max_tokens"`
	Messages  []chatMessage `json:"messages"`
	Stream    bool          `json:"stream"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// readSSE collects the text deltas of an Anthropic-style SSE stream.
func readSSE(r io.Reader) (string, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	var out strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		var event struct {
			Type  string `json:"type"`
			Delta struct {
				Text string `json:"text"`
			} `json:"delta"`
			ContentBlock struct {
				Text string `json:"text"`
			} `json:"content_block"`
		}
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			continue
		}
		switch event.Type {
		case "content_block_delta":
			out.WriteString(event.Delta.Text)
		case "content_block_start":
			out.WriteString(event.ContentBlock.Text)
		}
	}
	return strings.TrimSpace(out.String()), scanner.Err()
}

// managedToken returns the managed-login token (mmoat_…, audience
// agent-backend) used by MiniMax Code for the built-in models. It is read
// from the environment when set, otherwise from the local MiniMax Code
// auth-state file. The value is never logged.
func managedToken() (string, error) {
	if tok := strings.TrimSpace(os.Getenv("MINIMAX_MANAGED_TOKEN")); tok != "" {
		return tok, nil
	}
	path := managedAuthStatePath()
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("no MINIMAX_MANAGED_TOKEN and cannot read %s: %w", path, err)
	}
	var state struct {
		Records map[string]struct {
			AccessToken string `json:"accessToken"`
		} `json:"records"`
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		return "", fmt.Errorf("parse %s: %w", path, err)
	}
	for _, rec := range state.Records {
		if rec.AccessToken != "" {
			return rec.AccessToken, nil
		}
	}
	return "", fmt.Errorf("no access token in %s", path)
}

func managedAuthStatePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".minimax/auth/prod/en/mcode-public/auth.json"
	}
	return filepath.Join(home, ".minimax", "auth", "prod", "en", "mcode-public", "auth.json")
}
