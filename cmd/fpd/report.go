package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type reportBuilder struct {
	upstream string

	mu     sync.Mutex
	recent []report // newest first, capped
}

func newReportBuilder(upstream string) *reportBuilder { return &reportBuilder{upstream: upstream} }

// remember keeps the last 50 reports for /fp/recent — the stand's quick
// A/B surface: real browsers are driven at the site, then their reports
// are read back here without any on-screen inspection.
func (rb *reportBuilder) remember(rep report) {
	rb.mu.Lock()
	rb.recent = append([]report{rep}, rb.recent...)
	if len(rb.recent) > 50 {
		rb.recent = rb.recent[:50]
	}
	rb.mu.Unlock()
}

func (rb *reportBuilder) last(n int) []report {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if n > len(rb.recent) {
		n = len(rb.recent)
	}
	return rb.recent[:n]
}

type extOut struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	Len  int    `json:"len"`
	Data string `json:"data_hex,omitempty"`
}

var extNames = map[uint16]string{
	0x0000: "server_name", 0x0001: "max_fragment_length", 0x0002: "client_cert_url",
	0x0005: "status_request", 0x000a: "supported_groups", 0x000b: "ec_point_formats",
	0x000d: "signature_algorithms", 0x0010: "application_layer_protocol_negotiation",
	0x0012: "signed_certificate_timestamp", 0x0015: "padding", 0x0016: "encrypt_then_mac",
	0x0017: "extended_master_secret", 0x001b: "compress_certificate",
	0x001c: "record_size_limit", 0x0023: "session_ticket", 0x0029: "pre_shared_key",
	0x002a: "early_data", 0x002b: "supported_versions", 0x002c: "cookie",
	0x002d: "psk_key_exchange_modes", 0x0031: "certificate_authorities",
	0x0032: "oid_filters", 0x0033: "post_handshake_auth",
	0x4469: "ALPS", 0x44cd: "ALPS", 0x8b60: "encrypted_client_hello",
	0xff01: "renegotiation_info", 0xca24: "unregistered (CA24)", 0xca34: "unregistered (CA34)",
}

type report struct {
	Time  string   `json:"time"`
	Who   who      `json:"client"`
	HTTP  httpV    `json:"http"`
	TLS   *tlsV    `json:"tls"`
	Trans any      `json:"transport"`
	Notes []string `json:"notes"`
}

type who struct {
	IP    string `json:"ip"`
	Port  int    `json:"port"`
	Proxy string `json:"proxy_note,omitempty"`
}

type headerPairOut struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type httpV struct {
	Proto   string          `json:"proto"`
	Method  string          `json:"method"`
	Path    string          `json:"path"`
	UA      string          `json:"user_agent"`
	Headers []headerPairOut `json:"headers"`
}

type tlsV struct {
	NegotiatedProto   string   `json:"negotiated_alpn"`
	NegotiatedCipher  string   `json:"negotiated_cipher_suite"`
	NegotiatedVersion string   `json:"negotiated_version"`
	SNI               string   `json:"sni"`
	ALPN              string   `json:"alpn_offered"`
	JA3               string   `json:"ja3_string"`
	JA3Hash           string   `json:"ja3_hash"`
	JA4               string   `json:"ja4"`
	JA4R              string   `json:"ja4_r"`
	JA4SHA            string   `json:"ja4_sha256"`
	Version           string   `json:"client_version"`
	VersionsOffered   string   `json:"supported_versions"`
	Ciphers           string   `json:"cipher_suites"`
	SigAlgs           string   `json:"signature_algorithms"`
	Groups            string   `json:"supported_groups"`
	PointFormats      string   `json:"ec_point_formats"`
	Extensions        []extOut `json:"extensions"`
	HelloLen          int      `json:"client_hello_bytes"`
	HelloHex          string   `json:"client_hello_hex"`
}

func hexList(values []uint16) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, hex4u(v))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func (rb *reportBuilder) build(r *http.Request, m connMeta, sn *sniffer) report {
	rep := report{
		Time: time.Now().UTC().Format(time.RFC3339Nano),
		Who:  who{Proxy: "address from the haproxy proxy-v2 header (real client)"},
	}
	if m.addr.Local {
		rep.Who.Proxy = "proxy-v2 LOCAL command — address is the local hop"
	}
	rep.Who.IP = m.addr.IP.String()
	rep.Who.Port = m.addr.Port

	rep.HTTP = httpV{
		Proto:  r.Proto,
		Method: r.Method,
		Path:   r.URL.RequestURI(),
		UA:     r.Header.Get("User-Agent"),
	}
	for name, vals := range r.Header {
		rep.HTTP.Headers = append(rep.HTTP.Headers, headerPairOut{Name: name, Value: strings.Join(vals, ", ")})
	}

	if ch := m.hello; ch != nil {
		ja3s, ja3h := computeJA3(ch)
		ja4 := computeJA4(ch)
		j4sum := sha256.Sum256([]byte(ja4))
		exts := make([]extOut, 0, len(ch.Extensions))
		for _, e := range ch.Extensions {
			eo := extOut{ID: hex4u(e.ID), Name: extNames[e.ID], Len: len(e.Data)}
			if len(e.Data) > 0 && len(e.Data) <= 128 {
				eo.Data = hex.EncodeToString(e.Data)
			}
			exts = append(exts, eo)
		}
		rep.TLS = &tlsV{
			SNI:               ch.SNI,
			ALPN:              strings.Join(ch.ALPN, ", "),
			JA3:               ja3s,
			JA3Hash:           ja3h,
			JA4:               ja4,
			JA4R:              ja4R(ch),
			JA4SHA:            hex.EncodeToString(j4sum[:]),
			Version:           hex4u(ch.Version),
			VersionsOffered:   hexList(ch.SupportedVersions),
			Ciphers:           hexList(ch.CipherSuites),
			SigAlgs:           hexList(ch.SigAlgs),
			Groups:            hexList(ch.Groups),
			PointFormats:      hexList(ch.PointFormats),
			Extensions:        exts,
			HelloLen:          len(ch.Raw),
			HelloHex:          hex.EncodeToString(ch.Raw),
			NegotiatedProto:   r.TLS.NegotiatedProtocol,
			NegotiatedCipher:  tlsCipherName(r.TLS.CipherSuite),
			NegotiatedVersion: tlsVersionName(r.TLS.Version),
		}
	}

	if m.addr.Local {
		rep.Trans = map[string]string{"note": "no wire view for LOCAL proxy-v2 connections"}
	} else if fi := sn.lookup(rep.Who.IP, rep.Who.Port); fi != nil {
		t := map[string]any{
			"probe":      "AF_PACKET " + sn.iface,
			"ttl":        fi.TTL,
			"df":         fi.DF,
			"tos":        fi.TOS,
			"ip_id":      fi.IPID,
			"packets":    fi.Packets,
			"first_seen": fi.FirstSeen.UTC().Format(time.RFC3339Nano),
		}
		if fi.SYN != nil {
			t["syn"] = fi.SYN
		} else {
			t["syn"] = "not observed (connection established before fpd started?)"
		}
		rep.Trans = t
	} else {
		rep.Trans = map[string]string{
			"note": "no packets matched client ip:port yet (LAN hairpin usually works; check -iface)",
		}
	}

	rep.Notes = []string{
		"HTTP header order and h2 SETTINGS/frames are not shown live: Go's h2 server does not expose them — capture wire-side (keylog + tshark) for that",
		"everything above is what the server really received: TLS from the peeked ClientHello bytes, TTL/SYN from AF_PACKET on the WAN interface, headers from the request",
	}
	return rep
}

func (rb *reportBuilder) serveRecent(w http.ResponseWriter, r *http.Request) {
	n := 10
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 50 {
		n = v
	}
	only := r.URL.Query().Get("path") // e.g. "/fp" filters by requested path
	var out []report
	for _, rep := range rb.last(50) {
		if only != "" && rep.HTTP.Path != only {
			continue
		}
		out = append(out, rep)
		if len(out) >= n {
			break
		}
	}
	if out == nil {
		out = []report{}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}

type tmplData struct {
	UA, JA4, JA3Hash, IPP, TTL, JSON string
}

func (rb *reportBuilder) serve(w http.ResponseWriter, r *http.Request, sn *sniffer) {
	if strings.HasSuffix(r.URL.Path, "/recent") {
		rb.serveRecent(w, r)
		return
	}
	rep := rb.build(r, metaFrom(r), sn)
	rb.remember(rep)
	forceJSON := r.URL.Query().Get("format") == "json" || r.URL.Query().Get("fmt") == "json"
	wantsHTML := !forceJSON && strings.Contains(r.Header.Get("Accept"), "text/html")

	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.Encode(rep)

	if wantsHTML {
		td := tmplData{JSON: buf.String()}
		if rep.TLS != nil {
			td.JA4 = rep.TLS.JA4
			td.JA3Hash = rep.TLS.JA3Hash
		}
		td.UA = rep.HTTP.UA
		td.IPP = rep.Who.IP + ":" + strconv.Itoa(rep.Who.Port)
		if m, ok := rep.Trans.(map[string]any); ok {
			td.TTL = fmt.Sprint(m["ttl"])
		} else {
			td.TTL = "—"
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		reportTmpl.Execute(w, td)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write([]byte(buf.String()))
}

var reportTmpl = template.Must(template.New("fp").Parse(`<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<title>Полный фингерпринт — test.auto-gram.ru</title>
<style>
 body{background:#111;color:#ddd;font:14px/1.5 monospace;margin:2rem;max-width:70rem}
 h1{color:#7fd08f;font-size:1.3rem} h2{color:#9db8d9;font-size:1rem;margin-top:1.4rem}
 pre{background:#1b1b1b;border:1px solid #333;padding:1rem;overflow:auto;white-space:pre-wrap;word-break:break-all}
 button{background:#2d7d46;border:0;color:#fff;padding:.5rem 1rem;cursor:pointer;font:inherit;border-radius:4px}
 .grid{display:grid;grid-template-columns:max-content 1fr;gap:.15rem 1rem}
 .grid b{color:#9db8d9;font-weight:normal}
</style></head><body>
<h1>Ваш полный фингерпринт</h1>
<p>Всё, что сервер реально видит, когда вы заходите на сайт: HTTP-заголовки, TLS (JA3/JA4 + сырые байты ClientHello), TTL и TCP-опции SYN.</p>
<div class="grid">
 <b>User-Agent</b><span>{{with .UA}}{{.}}{{else}}—{{end}}</span>
 <b>JA4</b><span>{{.JA4}}</span>
 <b>JA3 hash</b><span>{{.JA3Hash}}</span>
 <b>IP:порт</b><span>{{.IPP}}</span>
 <b>TTL</b><span>{{.TTL}}</span>
</div>
<p><button onclick="navigator.clipboard.writeText(document.getElementById('fp').textContent)">Скопировать JSON</button></p>
<h2>Полный отчёт (JSON)</h2>
<pre id="fp">{{.JSON}}</pre>
</body></html>
`))

func tlsCipherName(id uint16) string {
	names := map[uint16]string{
		0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
		0x1303: "TLS_CHACHA20_POLY1305_SHA256",
		0xc02b: "ECDHE-ECDSA-AES128-GCM-SHA256", 0xc02f: "ECDHE-RSA-AES128-GCM-SHA256",
		0xc02c: "ECDHE-ECDSA-AES256-GCM-SHA384", 0xc030: "ECDHE-RSA-AES256-GCM-SHA384",
		0xcca9: "ECDHE-ECDSA-CHACHA20-POLY1305", 0xcca8: "ECDHE-RSA-CHACHA20-POLY1305",
	}
	if n, ok := names[id]; ok {
		return n + " (0x" + hex4u(id) + ")"
	}
	return "0x" + hex4u(id)
}

func tlsVersionName(v uint16) string {
	switch v {
	case 0x0304:
		return "TLS 1.3"
	case 0x0303:
		return "TLS 1.2"
	case 0x0302:
		return "TLS 1.1"
	case 0x0301:
		return "TLS 1.0"
	}
	return "0x" + hex4u(v)
}
