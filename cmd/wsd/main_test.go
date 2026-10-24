package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/megamen32/headless-client/websocket"
)

// echoServer upgrades every request and echoes each message back in the
// opcode it arrived with.
func echoServer(t *testing.T) *httptest.Server {
	t.Helper()
	up := &websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			mt, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if string(data) == "bye" {
				_ = conn.WriteControl(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, "bye"),
					time.Now().Add(time.Second))
				return
			}
			if err := conn.WriteMessage(mt, data); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// wsURL turns an httptest server into a ws:// URL DialWebSocket accepts.
func wsURL(srv *httptest.Server) string {
	u, _ := url.Parse(srv.URL)
	return "ws://" + u.Host + "/ws"
}

// writeProfile writes a browser-hello profile the daemon can load.
func writeProfile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "profile.json")
	profile := `{
	  "name": "chrome152-ws-test",
	  "tls_client_hello": "chrome_152",
	  "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"
	}`
	if err := os.WriteFile(path, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// call issues one daemon request and decodes the JSON answer.
func call(t *testing.T, method, target string, body []byte) (int, map[string]any) {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, target, reader)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode %s %s: %v", method, target, err)
	}
	return resp.StatusCode, out
}

// TestWSDRelayE2E dials through the daemon, echoes a message in both
// opcodes, reads the server close, and proves the relay is transparent.
func TestWSDRelayE2E(t *testing.T) {
	srv := echoServer(t)
	d := &daemon{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /dial", d.handleDial)
	mux.HandleFunc("POST /conn/{id}/send", d.handleSend)
	mux.HandleFunc("GET /conn/{id}/recv", d.handleRecv)
	mux.HandleFunc("DELETE /conn/{id}", d.handleClose)
	api := httptest.NewServer(mux)
	defer api.Close()
	profile := writeProfile(t)

	dialBody, _ := json.Marshal(map[string]any{
		"url":     wsURL(srv),
		"profile": profile,
		"headers": map[string]string{"Origin": "https://web.max.ru"},
	})
	status, out := call(t, "POST", api.URL+"/dial", dialBody)
	if status != 200 {
		t.Fatalf("dial: status %d: %v", status, out)
	}
	id := fmt.Sprintf("%v", out["conn_id"])

	for _, op := range []string{"binary", "text"} {
		payload := []byte("hello-" + op)
		status, out = call(t, "POST", api.URL+"/conn/"+id+"/send?opcode="+op, payload)
		if status != 200 {
			t.Fatalf("send %s: status %d: %v", op, status, out)
		}
		status, out = call(t, "GET", api.URL+"/conn/"+id+"/recv?timeout_s=10", nil)
		if status != 200 || out["closed"] == true {
			t.Fatalf("recv %s: status %d: %v", op, status, out)
		}
		if got := out["opcode"]; got != op {
			t.Errorf("echo opcode: got %v, want %s", got, op)
		}
		if got, _ := out["data_b64"].(string); got == "" {
			t.Fatalf("recv %s: empty data_b64: %v", op, out)
		} else if dec, err := base64.StdEncoding.DecodeString(got); err != nil || string(dec) != string(payload) {
			t.Errorf("echo %s: got %q (%v), want %q", op, dec, err, payload)
		}
	}

	// The server closes; the next recv must report it with its code.
	call(t, "POST", api.URL+"/conn/"+id+"/send", []byte("bye"))
	status, out = call(t, "GET", api.URL+"/conn/"+id+"/recv?timeout_s=10", nil)
	if status != 200 {
		t.Fatalf("recv close: status %d: %v", status, out)
	}
	if out["closed"] != true {
		t.Fatalf("recv after server close: want closed, got %v", out)
	}
}

// TestWSDRecvIdleTimeout proves an idle connection answers timeout instead
// of hanging.
func TestWSDRecvIdleTimeout(t *testing.T) {
	srv := echoServer(t)
	d := &daemon{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /dial", d.handleDial)
	mux.HandleFunc("GET /conn/{id}/recv", d.handleRecv)
	api := httptest.NewServer(mux)
	defer api.Close()

	dialBody, _ := json.Marshal(map[string]any{"url": wsURL(srv), "profile": writeProfile(t)})
	_, out := call(t, "POST", api.URL+"/dial", dialBody)
	id := fmt.Sprintf("%v", out["conn_id"])

	start := time.Now()
	status, out := call(t, "GET", api.URL+"/conn/"+id+"/recv?timeout_s=1", nil)
	if status != 200 || out["timeout"] != true {
		t.Fatalf("idle recv: status %d: %v", status, out)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("idle recv took %s, want ~1s", elapsed)
	}
}

// TestWSDBadProfile proves a broken dial fails with a clean error instead
// of registering a dead connection.
func TestWSDBadProfile(t *testing.T) {
	d := &daemon{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /dial", d.handleDial)
	api := httptest.NewServer(mux)
	defer api.Close()

	status, out := call(t, "POST", api.URL+"/dial",
		[]byte(`{"url":"ws://127.0.0.1:1/ws","profile":"/nonexistent/profile.json"}`))
	if status != 400 {
		t.Errorf("missing profile: status %d: %v", status, out)
	}
	if !strings.Contains(fmt.Sprint(out["error"]), "read profile") {
		t.Errorf("error text: %v", out)
	}
}
