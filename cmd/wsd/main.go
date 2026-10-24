// wsd is a local HTTP daemon that opens WebSocket connections through the
// mimic library (the same uTLS ClientHello and upgrade-request shape as the
// profile's HTTP client) and relays frames over HTTP — the single truth for
// outbound WebSocket from non-Go callers. The python/ package in this repo
// (site_mimic_client.gows) is its Python drop-in client, the way gohttp.py
// is the client of cmd/fetchd.
//
// Bind: 127.0.0.1:30778 by default (WSD_ADDR). Bearer auth optional via
// WSD_TOKEN. Endpoints:
//
//	POST   /dial                open a connection
//	POST   /conn/{id}/send      one message, raw body = payload
//	GET    /conn/{id}/recv      one message, long-poll
//	DELETE /conn/{id}           graceful close
//	GET    /health              liveness
//
// Dial request JSON:
//
//	{
//	  "url": "wss://…",                      // ws:// or wss://
//	  "profile": "/abs/path/profile.json",   // mimic identity (required)
//	  "headers": {"Origin": "https://…"},    // extra upgrade headers
//	  "proxy": "http://…",                   // optional CONNECT proxy
//	  "resolve": {"host": "ip"},             // optional DNS pinning (SNI kept)
//	  "timeout_s": 30                        // optional dial timeout
//	}
//
// Dial response JSON: {"conn_id": 7, "subprotocol": "",
// "response_headers": {"K": ["V"]}}.
//
// Send: the raw request body is one message payload; the query parameter
// opcode is "binary" (default) or "text". Response {"sent": N}.
//
// Recv: waits up to timeout_s (default 30) for one message and answers
// {"opcode": "binary", "data_b64": "...", "closed": false}; on idle
// {"timeout": true}; after close {"closed": true, "code": 1000,
// "reason": "", "error": ""}. Messages that arrive between calls sit in the
// daemon-side queue and are delivered first — nothing is dropped.
//
// The daemon never logs message bodies.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/megamen32/headless-client/websocket"
	"github.com/megamen32/site-mimic/mimic"
)

func main() {
	addr := os.Getenv("WSD_ADDR")
	if addr == "" {
		addr = "127.0.0.1:30778"
	}
	d := &daemon{token: os.Getenv("WSD_TOKEN")}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /dial", d.handleDial)
	mux.HandleFunc("POST /conn/{id}/send", d.auth(d.handleSend))
	mux.HandleFunc("GET /conn/{id}/recv", d.auth(d.handleRecv))
	mux.HandleFunc("DELETE /conn/{id}", d.auth(d.handleClose))
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true})
	})
	log.Printf("wsd listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

type daemon struct {
	token   string
	mu      sync.Mutex
	nextID  int64
	conns   map[int64]*wsConn
	created map[int64]time.Time
}

// frame is one data message read from the upstream connection.
type frame struct {
	opcode int
	data   []byte
}

// wsConn holds one open upstream WebSocket. Reads happen on a single
// goroutine (gorilla forbids concurrent readers) and fill a queue; writes
// are serialized by a mutex.
type wsConn struct {
	conn *websocket.Conn
	url  string

	writeMu sync.Mutex

	mu      sync.Mutex
	queue   []frame
	closed  bool
	code    int
	reason  string
	errStr  string
	waiters chan struct{} // closed whenever state changes
}

// notify wakes a pending long-poll recv, if any. Called with c.mu held.
func (c *wsConn) notify() {
	if c.waiters != nil {
		close(c.waiters)
		c.waiters = nil
	}
}

// readLoop drains the upstream connection into the queue until it closes.
func (c *wsConn) readLoop() {
	for {
		opcode, data, err := c.conn.ReadMessage()
		if err != nil {
			c.mu.Lock()
			c.closed = true
			c.errStr = err.Error()
			if ce, ok := err.(*websocket.CloseError); ok {
				c.code, c.reason = ce.Code, ce.Text
			}
			c.notify()
			c.mu.Unlock()
			return
		}
		c.mu.Lock()
		c.queue = append(c.queue, frame{opcode: opcode, data: data})
		c.notify()
		c.mu.Unlock()
	}
}

func (d *daemon) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.token != "" && r.Header.Get("Authorization") != "Bearer "+d.token {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

type dialRequest struct {
	URL      string            `json:"url"`
	Profile  string            `json:"profile"`
	Headers  map[string]string `json:"headers"`
	Proxy    string            `json:"proxy"`
	Resolve  map[string]string `json:"resolve"`
	TimeoutS float64           `json:"timeout_s"`
}

func (d *daemon) handleDial(w http.ResponseWriter, r *http.Request) {
	var req dialRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"error": fmt.Sprintf("bad json: %v", err)})
		return
	}
	if req.URL == "" || req.Profile == "" {
		writeJSON(w, 400, map[string]any{"error": "url and profile are required"})
		return
	}
	profile, err := mimic.LoadProfile(req.Profile)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}

	var opts []mimic.Option
	if len(req.Headers) > 0 {
		header := http.Header{}
		for name, value := range req.Headers {
			header.Set(name, value)
		}
		opts = append(opts, mimic.WithWebSocketHeader(header))
	}
	if req.Proxy != "" {
		opts = append(opts, mimic.WithProxy(req.Proxy))
	}
	if len(req.Resolve) > 0 {
		opts = append(opts, mimic.WithResolve(req.Resolve))
	}
	if req.TimeoutS > 0 {
		opts = append(opts, mimic.WithDialTimeout(time.Duration(req.TimeoutS * float64(time.Second))))
	}

	ctx := r.Context()
	timeout := 30 * time.Second
	if req.TimeoutS > 0 {
		timeout = time.Duration(req.TimeoutS * float64(time.Second))
	}
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := mimic.DialWebSocket(ctx, profile, req.URL, opts...)
	if err != nil {
		writeJSON(w, 502, map[string]any{"error": err.Error()})
		return
	}

	wc := &wsConn{conn: conn, url: req.URL}
	d.mu.Lock()
	if d.conns == nil {
		d.conns = map[int64]*wsConn{}
		d.created = map[int64]time.Time{}
	}
	d.nextID++
	id := d.nextID
	d.conns[id] = wc
	d.created[id] = time.Now()
	d.mu.Unlock()

	go wc.readLoop()

	writeJSON(w, 200, map[string]any{
		"conn_id":     id,
		"subprotocol": conn.Subprotocol(),
	})
}

// reap closes daemon-side state for connections idle past the age cap; the
// upstream socket dies with the process-local object.
func (d *daemon) reap() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for id, created := range d.created {
		if time.Since(created) > 24*time.Hour {
			if wc, ok := d.conns[id]; ok {
				_ = wc.conn.Close()
				delete(d.conns, id)
			}
			delete(d.created, id)
		}
	}
}

func (d *daemon) connFromPath(w http.ResponseWriter, r *http.Request) (*wsConn, int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad conn id"})
		return nil, 0, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	wc, ok := d.conns[id]
	if !ok {
		writeJSON(w, 404, map[string]any{"error": "unknown conn"})
		return nil, 0, false
	}
	return wc, id, true
}

func (d *daemon) handleSend(w http.ResponseWriter, r *http.Request) {
	wc, _, ok := d.connFromPath(w, r)
	if !ok {
		return
	}
	opcode := websocket.BinaryMessage
	switch strings.ToLower(r.URL.Query().Get("opcode")) {
	case "", "binary":
	case "text":
		opcode = websocket.TextMessage
	default:
		writeJSON(w, 400, map[string]any{"error": "opcode must be binary or text"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": fmt.Sprintf("read body: %v", err)})
		return
	}

	wc.writeMu.Lock()
	err = wc.conn.WriteMessage(opcode, body)
	wc.writeMu.Unlock()
	if err != nil {
		writeJSON(w, 410, map[string]any{"error": fmt.Sprintf("send: %v", err)})
		return
	}
	writeJSON(w, 200, map[string]any{"sent": len(body)})
}

func (d *daemon) handleRecv(w http.ResponseWriter, r *http.Request) {
	wc, _, ok := d.connFromPath(w, r)
	if !ok {
		return
	}
	timeout := 30 * time.Second
	if v := r.URL.Query().Get("timeout_s"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			timeout = time.Duration(f * float64(time.Second))
		}
	}
	deadline := time.After(timeout)

	for {
		wc.mu.Lock()
		if len(wc.queue) > 0 {
			f := wc.queue[0]
			wc.queue = wc.queue[1:]
			wc.mu.Unlock()
			writeJSON(w, 200, map[string]any{
				"opcode":   opcodeName(f.opcode),
				"data_b64": base64.StdEncoding.EncodeToString(f.data),
				"closed":   false,
			})
			return
		}
		if wc.closed {
			code, reason, errStr := wc.code, wc.reason, wc.errStr
			wc.mu.Unlock()
			writeJSON(w, 200, map[string]any{
				"closed": true,
				"code":   code,
				"reason": reason,
				"error":  errStr,
			})
			return
		}
		// Register the wake-up channel while holding the lock so a frame
		// arriving right now cannot fall between the queue check and the
		// select below (the frame's notify() closes this exact channel).
		if wc.waiters == nil {
			wc.waiters = make(chan struct{})
		}
		wait := wc.waiters
		wc.mu.Unlock()

		select {
		case <-wait: // state changed; loop re-checks the queue
		case <-deadline:
			writeJSON(w, 200, map[string]any{"timeout": true, "closed": false})
			return
		case <-r.Context().Done():
			return
		}
	}
}

func (d *daemon) handleClose(w http.ResponseWriter, r *http.Request) {
	wc, id, ok := d.connFromPath(w, r)
	if !ok {
		return
	}
	d.mu.Lock()
	delete(d.conns, id)
	delete(d.created, id)
	d.mu.Unlock()

	code := 1000
	if v := r.URL.Query().Get("code"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1000 {
			code = n
		}
	}
	_ = wc.conn.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(code, ""),
		time.Now().Add(5*time.Second))
	_ = wc.conn.Close()

	wc.mu.Lock()
	wasClosed := wc.closed
	wc.mu.Unlock()
	writeJSON(w, 200, map[string]any{"closed": true, "already_closed": wasClosed})
}

func opcodeName(opcode int) string {
	switch opcode {
	case websocket.TextMessage:
		return "text"
	case websocket.BinaryMessage:
		return "binary"
	default:
		return strconv.Itoa(opcode)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
