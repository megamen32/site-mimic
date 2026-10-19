# Methodology: how site-mimic fits a Go client to a site

This is the deep version of [skill/SKILL.md](../skill/SKILL.md) — why each
layer exists, what is verified, and what remains Go-shaped.

## The layer cake

A request from a browser to a site is fingerprinted at several independent
layers. Each is a separate gate a defender can close.

| Layer | What it exposes | site-mimic status |
|---|---|---|
| TCP | MSS/TTL/window quirks of Go's stack | **TTL stamped per connection** (`mimic.WithTTL` / profile `ip_ttl`, e.g. 128 = Windows; kernel default otherwise — 64 on Linux/Android); other TCP-options quirks not addressed (rarely gated) |
| TLS ClientHello | cipher/extension/group sets and order → JA3/JA4 | **matched** via uTLS `chrome_auto`; browser-shaped and native-client-shaped specs (`chrome_152`, `node_24`) are custom specs — see below |
| TLS handshake completion | record sizes, key-share behaviour | uTLS Chrome spec |
| ALPN | h2 offer | matched |
| HTTP/2 frames | SETTINGS/WINDOW_UPDATE/PRIORITY values and order (Akamai fp) | **matched on `chrome_exact`** — Chrome's SETTINGS/WINDOW_UPDATE/priority via headless-client; Go default on the uTLS path |
| HTTP headers | names, values, order | **values + wire order matched on `chrome_exact`** — Chrome's h1/h2 order tables via headless-client; values-only on the uTLS path; **order + casing matched on the `http1_wire_order` path** (HTTP/1.1 profiles) |
| Cookies / tokens | session state | `Profile.CookieJar` |
| JavaScript | anti-bot challenges, behaviour tracking | **out of scope** |

Transport parity is necessary but not sufficient against a full anti-bot
stack. `examples/stream-wb-ru` shows the boundary concretely: the Go client
reaches `wbaas` exactly like a fresh browser (HTTP 498 challenge), and the
JS challenge decides from there.

## Why the ClientHello matters most

Stock Go's ClientHello (JA3 like `36b20605…`, no ALPN, no padding/session-
ticket/compressed-certificate extensions) is unique to Go programs: no
browser, no app emits it. That makes it the cheapest possible block rule —
one signature kills every stock Go client regardless of proxy, UA or
behaviour. uTLS replaces the handshake with a per-browser spec
(`HelloChrome_Auto` tracks the current Chrome layout: TLS 1.3 suites first,
16 ciphers, ~18 extensions, GREASE, padding, ALPN `h2, http/1.1`).

Modern Chrome randomizes the order of ClientHello extensions per connection
(so per-connection JA3 is intentionally unstable); the stable identifier is
the JA4-style shape. Our verification loop prints both.

## The verification loop

1. `go run . -dump ch.json` — performs a real uTLS handshake and writes the
   raw ClientHello record (`mimic.ClientHelloCapture`).
2. `python3 tools/parse_clienthello.py ch.json` — decodes the record and
   prints version, cipher/extension counts, ALPN, SNI, JA3 and the
   simplified JA4.
3. Compare against the same artifacts captured from a real browser
   (`tshark -Y 'tls.handshake.type == 1'`).
4. Then verify the business path (status code + `server:` header) and
   classify per skill step 6.

This loop is the same one used to close a measured JA3 gap in a production
traffic-replay engine: baseline capture → engine self-dump → field-by-field
diff → fix → re-diff.

## Header wire order and HTTP/2 frames: what `chrome_exact` closes

Two gaps below were closed by delegating the transport to
`github.com/kulikov0/headless-client` (`tls_client_hello: "chrome_exact"`,
wired in `mimic/exact.go`):

- **Header wire order.** headless-client sorts headers into Chrome's
  per-version tables before writing: navigation and generic orders for
  HTTP/1.1 (`internal/chromehttp1/request.go`,
  `chromeHTTP1NavigationHeaderOrder` / `chromeHTTP1HeaderOrder`) and for
  HTTP/2 (`internal/chromehttp2/internal/httpcommon/request.go`,
  `chromeNavigationHeaderOrder` / `chromeHeaderOrder` rank maps, with
  `priority` demoted to a trailing header). A `Profile.HeaderOrder` is
  therefore advisory on this path — the transport owns the final order.
- **HTTP/2 frame fingerprint.** headless-client ships a vendored
  `x/net/http2` fork tuned to Chrome: SETTINGS
  `INITIAL_WINDOW_SIZE=6291456`, `MAX_HEADER_LIST_SIZE=262144` and a
  connection WINDOW_UPDATE of 15663105, plus Chrome's priority scheduling
  (`internal/chromehttp2/chrome_fingerprint_test.go` asserts these values;
  `writesched_priority_rfc7540.go` / `rfc9218.go`, `client_priority_go126.go`).

## Known gaps (do not overclaim)

Still true on the **uTLS path** (`chrome_auto` etc.):

- **HTTP/2 frame fingerprint.** `x/net/http2` sends its own SETTINGS
  (`HEADER_TABLE_SIZE=4096`, no `ENABLE_CONNECT_PROTOCOL`, one WINDOW_UPDATE
  of 1 GiB…) in its own order. Use `chrome_exact` when the frame layer is
  gated.
- **Header wire order.** Go canonicalizes and reorders; values and the set
  are exact. Use `chrome_exact` when order is gated, or set
  `http1_wire_order: true` with `wire_header_order` in the profile — the
  HTTP/1.1 transport then writes the header block itself, in the captured
  order and casing (see "Fitting a native client" below).
- **accept-encoding.** On this path profiles must not set it: the stdlib
  decompresses transparently only when it owns the header, and it cannot
  decode Brotli or zstd.

Closed on `chrome_exact` (see the section above): header wire order, h2
frames — and **accept-encoding can carry the exact browser value**
(`gzip, deflate, br, zstd`): headless-client only substitutes its own
`Accept-Encoding` when the caller left it empty (`tls.go`,
`chromeRoundTripper.RoundTrip`) and always runs `decompressResponse`, which
transparently decodes gzip/deflate/br/zstd and strips
`Content-Encoding`/`Content-Length`. This is how `examples/vk-ru-mobile`
replays the Android capture verbatim.

Still true everywhere:

- **Simplified JA4.** `tools/ja3_ja4.py` computes a self-consistent JA4-like
  token (version from legacy_version), suitable for diffing our client
  against itself/captures, not for cross-tool equality with FoxIO's JA4
  (tools/ja4_from_pcap.py computes the FoxIO JA4 from pcaps — see
  docs/phone-reference.md).
- **h2-only sites.** On the uTLS path, https is served via
  `http2.Transport`; a host that refuses h2 is remembered and retried over
  HTTP/1.1 with the same uTLS dial.

## Proxy story

`mimic.WithProxy("http://user:pass@host:port")` or the standard
`HTTPS_PROXY`/`HTTP_PROXY` env vars. Because uTLS owns the TLS layer, the
CONNECT tunnel is established by hand before the handshake
(`mimic.proxyConnect`), which is what lets per-session proxy rotation keep a
consistent fingerprint end-to-end.

## Compatibility notes

- `net/http` in current Go populates the h2 handoff state only for
  `*tls.Conn`, so `http.Transport` + custom `DialTLSContext` returning a
  `*utls.UConn` silently drops to HTTP/1.1 against h2-only servers (the
  server's SETTINGS frame then surfaces as a "malformed HTTP response"
  error). site-mimic therefore routes https through `http2.Transport`
  directly — the canonical uTLS pattern.
- Works against Go ≥ 1.24; deps: `refraction-networking/utls`,
  `golang.org/x/net`.

## Fitting a native client (Node/Electron), not a browser

A target is not always a website. When the client is a native app — a
desktop agent, an Electron/Node process, an SDK — the identity to reproduce
is that client's stack, and three of the repo's browser assumptions change:

| Layer | Browser path | Native-client path |
|---|---|---|
| ClientHello | Chrome/Firefox/Safari spec | the client's own TLS stack (`node_24` = Node 24 / Electron 42 / BoringSSL) |
| ALPN / HTTP version | `h2, http/1.1` → HTTP/2 | `http/1.1` only → HTTP/1.1 (undici never negotiates h2) |
| Header order | browser order table | the client's own order **and casing** — undici lowercases `Headers`-set names and keeps object-literal names as written |

`tls_client_hello: "node_24"` (mimic/spec_node.go) reproduces the Node 24
ClientHello: 18 cipher suites, 12 extensions in BoringSSL's fixed order, a
32-byte legacy session id, x25519 as the only key share, ALPN `http/1.1`.
`mimic/fingerprint.go` computes JA3/JA4 from a captured hello, and
`mimic/fingerprint_test.go` pins the spec against three captured hellos of
the real client (fixtures in `mimic/testdata/`) — the spec cannot drift from
the reference without the test failing.

Two implementation notes that cost real debugging time:

- **Resumption trap.** A `ClientHelloSpec` without a `pre_shared_key`
  extension cannot present a session ticket, and uTLS panics
  (`initPskExt failed`) as soon as the shared session cache holds one for
  the host — the second request to the same host kills the process, and
  with it the fetchd daemon. `PreferSkipResumptionOnNilExtension: true`
  skips resumption instead; the hello then stays exactly the captured one.
  Regression test: `mimic/http1_test.go`.
- **One connection per request.** The wire-order transport opens a fresh
  connection for each request (no keep-alive pooling) and does not support
  chunked request bodies.

Worked case with all measurements: `docs/minimax-agent-gateway.ru.md`,
`examples/minimax-agent-gateway/`.

