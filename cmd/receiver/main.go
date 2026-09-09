// Command receiver is the public byte-capturing target for site-mimic
// verification runs: deploy it behind nginx (TLS terminates at nginx via the
// shared 127.0.0.1:8444 SNI listener) and it logs the application view of
// every request as JSONL — client IP (X-Forwarded-For chain), method, path,
// protocol, header names and values — and answers with an echo JSON.
//
// The transport layers (raw ClientHello for JA3/JA4, TTL and TCP options)
// are captured wire-side with tcpdump: on `lo port 8444` for the
// haproxy→nginx leg (real ClientHello bytes, SNI passthrough), and on the
// WAN interface for the client's true TTL/TCP SYN options. See
// docs/receiver-stand.md in this repository.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type headerPair struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type entry struct {
	Time   string       `json:"time"`
	Remote string       `json:"remote"`
	XFF    string       `json:"x_forwarded_for"`
	Method string       `json:"method"`
	Path   string       `json:"path"`
	Proto  string       `json:"proto"`
	Header []headerPair `json:"headers"`
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8477", "listen address")
	logPath := flag.String("log", "receiver-access.jsonl", "JSONL access log path")
	flag.Parse()

	out, err := os.OpenFile(*logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		log.Fatalf("receiver: open log: %v", err)
	}
	defer out.Close()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		e := entry{
			Time:   time.Now().UTC().Format(time.RFC3339Nano),
			Remote: r.RemoteAddr,
			XFF:    r.Header.Get("X-Forwarded-For"),
			Method: r.Method,
			Path:   r.URL.RequestURI(),
			Proto:  r.Proto,
		}
		for name, vals := range r.Header {
			e.Header = append(e.Header, headerPair{Name: name, Value: strings.Join(vals, ", ")})
		}
		if line, err := json.Marshal(e); err == nil {
			out.Write(append(line, '\n'))
			out.Sync()
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"ok":       true,
			"receiver": "site-mimic",
			"remote":   e.Remote,
			"xff":      e.XFF,
			"proto":    e.Proto,
			"path":     e.Path,
			"note":     "transport layers are captured wire-side: tcpdump lo:8444 (ClientHello) + WAN (TTL/TCP options)",
		})
	})

	log.Printf("receiver: listening on %s, log %s", *listen, *logPath)
	log.Fatal(http.ListenAndServe(*listen, nil))
}
