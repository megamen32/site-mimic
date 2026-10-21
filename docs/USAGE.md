# Using site-mimic

This is the operator's guide: what the ready-made profiles are, how to drive
site-mimic from Go and from Python, and the rules that keep the transport
honest. The method (how to fit a *new* site) lives in
[`skill/SKILL.md`](../skill/SKILL.md) and
[`docs/methodology.md`](methodology.md); this file is about using what is
already here.

## Three ways in

| you are | use | what it is |
| --- | --- | --- |
| writing Go | `mimic.New(profile, opts...)` | an `*http.Client` with a uTLS transport — in-process, no daemon |
| writing Python | `site_mimic_client.gohttp` | a `requests`-shaped client that talks to the `fetchd` daemon |
| writing TypeScript / JavaScript | `site-mimic` (npm) | the same daemon and the same contract, an ESM package with no runtime dependencies |
| an AI agent | [`skill/SKILL.md`](../skill/SKILL.md) | the capture → profile → verify workflow |

### Go

```go
profile := mimic.MustLoadProfile("profile.json")
client, err := mimic.New(profile, mimic.WithTTL(128))   // 128 = present as Windows
resp, err := client.Get("https://example.com/")
```

`mimic.Profile` carries the identity: the TLS ClientHello shape, the header
set and its order, the IP TTL, and an optional resource plan that turns a
single hit into a browser-like session. `mimic.New` takes options for the
proxy, DNS pinning, TLS verification, dial timeout and SNI override.

In a plan, `Sec-Fetch-Site` is computed, not fixed: the value follows the
relation between the page that caused the request and the page it asks for —
`same-origin`, `same-site`, `cross-site`, or `none` when the user typed the
address. A navigation without a referer keeps the value the profile
captured, because the capture is a measurement of a real cross-site
navigation.

Sessions resume on their own: the client keeps TLS session tickets between
connections, so the second connection to a host presents a real
`pre_shared_key` offer instead of a fresh handshake. The ticket store is
shared by every client of a profile — a browser keeps its tickets too — but
namespaced per identity, so a ticket negotiated under one ClientHello is
never offered under another.

### HTTP/3

`mimic.NewHTTP3` is the same client on a QUIC wire: the same profile, the
same options, HTTP/3 instead of HTTP/2. It is a Go API — the Python and
TypeScript clients go through `fetchd`, which speaks TCP.

```go
profile := mimic.MustLoadProfile("profile.json")
client, err := mimic.NewHTTP3(profile)   // h3 over QUIC
if err != nil { ... }
defer client.Transport.(io.Closer).Close()   // releases the UDP socket
```

The QUIC handshake carries the **Chrome QUIC** ClientHello, which is a
different shape from the Chrome TCP one: 12 extensions and 3 cipher suites
against 20 and 16 on TCP. Chrome's two hellos differ, so ours do too — a
server that fingerprints the extension list sees the QUIC one. The hello
comes from the headless-client QUIC stack, whose ClientHello is Chrome's
byte for byte: the post-quantum key share, ALPS, the ECH GREASE pair and the
nine classic signature algorithms.

The transport parameters are the real Chrome's: the same thirteen
parameters with the same values, an empty source connection id in both the
packet and parameter 0x0f — which is what the captured phone hellos send,
not an 8-byte id — and the GREASE parameter with a random id and payload, as
on the browser's side. The google_connection_options parameter carries
Chrome's own token, and the token changes with the release: Chrome 152 sent
"ORIGECCPIW2X", Chrome 155 "ORIG", Chrome 156 "ORIGNOIP". The newest one
measured is what goes on the wire.

The HTTP/3 settings are Chrome's too, measured on the wire against a local
server that printed the client's control stream: QPACK_MAX_TABLE_CAPACITY
65536, MAX_FIELD_SECTION_SIZE 262144, QPACK_BLOCKED_STREAMS 100,
H3_DATAGRAM 1, plus the GREASE setting and the GREASE frame around them.
The profile's user agent is applied the same way as on the TCP path. A
CONNECT proxy is an error here, not a fallback: QUIC does not travel through
one.

Measured on the wire (2026-10-21, against a local HTTP/3 stand, Chrome
156.0.8078.47 on macOS): JA4
`q13d0313h3_55b375c5d22e_eb028bd37c08` — the same value a real Chrome 156
reads. All three parts of the JA4 match, so the QUIC hello is no longer
merely the same shape as the browser's: it is the same fingerprint.

One consequence worth knowing: the SNI rides along when the target is a
hostname, and RFC 6066 forbids an SNI for an IP address — against an IP
the extension leaves the hello and the same fingerprint reads
`q13i0312h3_…`. That is the correct form for an IP target, not a defect.

The QUIC wire always carries that one QUIC fingerprint, so the profile's
`tls_client_hello` must name a Chrome identity — `chrome_auto`,
`android_149`, `chrome_152`, `chrome_152_psk` or `chrome_156`. `chrome_exact` is refused:
it is a byte-exact Chrome *TCP* TLS layer, and over QUIC that layer is
not applied.

### TypeScript / JavaScript

The npm package in `js/` is the twin of the Python client: the same daemon,
the same wire behaviour, the same environment variables.

```sh
npm install site-mimic
```

```ts
import { get } from "site-mimic";

const response = await get("https://example.com/api", {
  headers: { "User-Agent": "…" },
  cookies: { session: "…" },
  profile: "/abs/path/profile.json",
});
console.log(response.statusCode, response.text);
```

No runtime dependencies: Node 18's global `fetch` carries the request to the
daemon, and the daemon does the TLS. The client supervises the daemon the
same way the Python one does — `healthz` before the call, one start and one
retry when the daemon is down. `GOHTTPD_AUTOSTART=0` forbids the start.

### WebSocket

`mimic.DialWebSocket` opens a WebSocket that carries the profile's identity:
the same ClientHello, and an upgrade request in the shape the profile's
client sends.

```go
conn, err := mimic.DialWebSocket(ctx, profile, "wss://example.com/socket")
if err != nil { ... }
defer conn.Close()

_ = conn.WriteMessage(websocket.TextMessage, []byte("ping"))
typ, data, err := conn.ReadMessage()
```

The connection type is `*websocket.Conn` from
`github.com/megamen32/headless-client/websocket` — the vendored, Chrome
patched build of the same client library.

Two things are not obvious:

* **The connection negotiates ALPN "http/1.1" only.** The upgrade request
  is an HTTP/1.1 request, and a connection that became h2 could not carry
  it. Chrome does the same. The rest of the ClientHello stays the captured
  one.
* **A browser and a native client send different headers on the upgrade.**
  Chrome sends no client hints there and adds the cache headers it does
  send; a native client profile keeps its own headers. The profile decides,
  by its `tls_client_hello`.

### Python

The Python side is one module, `site_mimic_client.gohttp`, that speaks to the
`fetchd` daemon over HTTP:

```sh
go build -o fetchd ./cmd/fetchd
./fetchd                     # listens on :30777, optional FETCHD_TOKEN auth
```

```python
from site_mimic_client import gohttp

r = gohttp.get(
    "https://example.com/api/...",
    profile="/path/to/profile.json",
    headers={"Accept": "application/json"},
)
print(r.status, r.text)
```

The client supervises the daemon: if `/healthz` is unreachable it starts
`fetchd` once and retries. Configuration is via the environment —
`GOHTTPD_URL` (default `http://127.0.0.1:30777`), `GOHTTPD_TOKEN`,
`GOHTTPD_BIN`, `GOHTTPD_LOG`.

## The ready-made profiles

### TLS ClientHello specs — the `tls_client_hello` value

| spec | client it imitates | wire reference (JA4) | notes |
| --- | --- | --- | --- |
| `chrome_auto` (default) | Chrome, auto-detected | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | uTLS built-in |
| `android_149` | Android Chrome 149 | same as above | mobile reference |
| `chrome_152` | Chrome 152 desktop / 155 mobile | `t13d1517h2_8daaf6152771_cb7bf5808d99` | custom spec: post-quantum signature algorithms + extension 0xCA34 |
| `chrome_152_psk` | the same, with resumption | — | adds the PSK binder |
| `chrome_156` | Chrome 156, the current stable | `t13d1518h2_8daaf6152771_4980c97edce0` | custom spec: the `chrome_152` layout plus the 0x12E0 extension Chrome 156 added |
| `node_24` | Node.js 24 / Electron 42 (BoringSSL) | `t13d1812h1_5d04281c6031_ef7df7f74e48` | ALPN `http/1.1` only |
| `max_app` | MAX messenger app (`ru.oneme.app`) | `t13d171100_5b57614c22b0_40271e0a5736` | Conscrypt/OkHttp shape, **no ALPN at all**, 17 cipher suites |
| `max_app_psk` | the same, with resumption | `t13d171200_5b57614c22b0_352634941f3a` | 113 of 116 real connections carried a PSK |
| `firefox_auto`, `ios_auto`, `random`, `random_alpn` | Firefox, iOS, random | — | uTLS built-ins |
| `chrome_exact` | real Chrome, byte-for-byte | `t13d1518h2_8daaf6152771_4980c97edce0` | not a uTLS spec: the transport is delegated to [headless-client](https://github.com/megamen32/headless-client) (a fork of [kulikov0's](https://github.com/kulikov0/headless-client)), whose ClientHello is measured against the current stable Chrome. Since the 2026-10-21 fork sync it speaks the same fingerprint as the `chrome_156` spec and our own Chrome 156 capture |

`max_app` is the only spec **without ALPN**: it can only speak HTTP/1.1.
A profile that sets it must also set `http1_wire_order` and
`wire_header_order`, because that is the only path where the header order on
the wire is under our control (see *Known limits*).

### JSON profiles — a ready identity, ready to load

| file | name | target | TLS spec | TTL |
| --- | --- | --- | --- | --- |
| `examples/profiles/android-chrome152.json` | `android-chrome152` | mobile Chrome 152 | `chrome_152` | 64 |
| `examples/profiles/linux-chrome152.json` | `linux-chrome152` | desktop Chrome 152 | `chrome_exact` | — |
| `examples/profiles/mac-chrome153.json` | `mac-chrome153` | Chrome 153 on macOS | `chrome_exact` | — |
| `examples/profiles/windows-chrome152.json` | `windows-chrome152` | Windows Chrome | `chrome_exact` | 128 |
| `examples/profiles/max-app-oneme.json` | `max-app-oneme-26.35.1` | MAX app 26.35.1 | `max_app_psk` | 64 |
| `examples/profiles/max-web-chrome155.json` | `max-web-chrome155` | `web.max.ru` in mobile Chrome 155 | `chrome_152` | 64 |

Each file carries the user agent, the header set and its order, and (where
it was captured) a resource plan. Load one with
`mimic.MustLoadProfile("examples/profiles/windows-chrome152.json")`.

### Worked examples

| example | what it shows |
| --- | --- |
| `examples/vk-ru` | desktop Chrome against `vk.ru` |
| `examples/vk-ru-mobile` | the same site as a mobile browser |
| `examples/vk-ru-windows` | the Windows profile, TTL 128 |
| `examples/stream-wb-ru` | a browser-harvested cookie jar against a 498 anti-bot challenge |
| `examples/stand-probe` | a long-lived client that serves a fingerprint endpoint |
| `examples/lan-probe` | a probe that runs inside a netns with a chosen TCP personality |
| `examples/minimax-agent-gateway` | the transport used by an agent gateway |
| `examples/uquic-probe` | QUIC/initial-packet experiments |

## Fitting a new site

1. **Capture the real client.** A phone, a Windows box or an emulator:
   [`tools/phone/README.md`](../tools/phone/README.md),
   [`tools/win/README.md`](../tools/win/README.md),
   [`tools/avd/README.md`](../tools/avd/README.md).
   The cheap path when you only need JA3/JA4 is `cmd/hello-tap`.
2. **Read the fingerprints** with `cmd/hellofp` (for a site-mimic capture) or
   `tools/ja4_from_pcap.py` (for a pcap). Both parse with the library's own
   code, so the numbers are the ones a server would compute.
3. **Write the spec** in `mimic/spec_*.go` and commit a fixture of the raw
   ClientHello next to it.
4. **Lock it with a test** that performs a **real handshake** and compares the
   fingerprint. A test that only compares the spec's structure cannot catch a
   wrong uTLS constant — that is exactly how a swapped cipher suite survived
   a review once.
5. **Write the profile** into `examples/profiles/` and the notes into
   `docs/`.

The full sequence, with the reasoning behind each step, is in
[`skill/SKILL.md`](../skill/SKILL.md).

## Checking the fingerprint against a real browser

Two canaries put a real browser and our own client on the wire and compare
what they send.

`tools/canary.sh` is the TCP one: it drives a real Chrome at the
verification stand, drives our three variants at the same stand, and diffs
JA4, JA3 and the header names. It knows the two shapes a real Chrome sends
— the fresh handshake and the resumed one — and treats a variant that
matches either as good.

`tools/canary-quic.sh` is the QUIC one, and it needs nothing but this
machine. It starts two HTTP/3 stands (`cmd/h3sniff`), drives a real Chrome
at one and our own h3 client at the other, and diffs what the two put on
the wire: the QUIC ClientHello (its JA4, the extension set, the signature
algorithms), the QUIC transport parameters and the HTTP/3 settings of the
control stream.

```sh
tools/canary-quic.sh          # exit 0 = ours is the reference, 2 = drift
```

Two things it knows that a plain diff does not:

* Chrome refuses to speak QUIC to a loopback address, and it checks the
  certificate even with `--ignore-certificate-errors`. The canary therefore
  runs on the LAN address and trusts its own test CA (once).
* The verdict has two halves. Ours against the pinned reference is a
  failure when it differs — that is us drifting. The browser against the
  reference is only a note: the browser moved on and the pinned measurement
  is old.

## Borrowed from the headless client

`github.com/megamen32/headless-client` is a dependency, not a copy: the
transport of the `chrome_exact` profile, the WebSocket upgrade handshake,
the Chrome header tables and the whole QUIC stack come from it.

The dependency is pinned to the fork's tag `v0.3.0` (2026-10-21), not to a
pseudo-version: a tag is a thing a reader can check, and a pseudo-version
of a fork says only "some commit of somebody's branch". The fork is
[our fork of kulikov0's](https://github.com/kulikov0/headless-client), and
it is upstream's `main` plus three commits: the module path, the Chrome 152
TLS change (the unregistered 0xCA34 extension) that is [an open pull
request against upstream](https://github.com/kulikov0/headless-client/pull/1),
and the Chrome 156 change — the unregistered 0x12E0 extension next to
0xCA34, the same two extensions in the QUIC hello, and the
`google_connection_options "ORIGNOIP"` token. The Chrome 156 change lives in
the fork only: it is a measured wire shape, and it will follow upstream
when there is a pull request for it.
Everything else we use is already upstream — the `Sec-Fetch-Site` per pair
work, for one, was [merged there](https://github.com/kulikov0/headless-client/pull/2)
in September 2026. So the fork exists for one extension, and it can become
the upstream's own tag as soon as that pull request is merged.

What we took:

* the **WebSocket upgrade handshake** — its vendored `websocket` package
  writes the upgrade request in Chrome's header order and verifies the
  accept key;
* the **Chrome WebSocket header table** (`DestWebSocket`): the cache
  headers Chrome sends, the permessage-deflate offer, and the absence of
  client hints on the upgrade;
* the **TCP keep-alive behaviour**: Chrome sends no keep-alive probes and
  neither do we. Go's dialer turns them on by default, so the interval is
  negative — `mimic/keepalive_test.go` guards it, with a second test that
  proves the guard can fail.

What is still on the table: the WebTransport dialer (the CONNECT header
block Chrome sends with it), the resumed QUIC ClientHello shape, and the
per-destination header tables beyond the four the library defines.

## Rules of the road

* **One truth for the Python client.** `python/site_mimic_client/gohttp.py`
  is the canonical copy, and consumer repos install it as a git dependency
  pinned to a tag — there is no file copy to drift. Edit here, bump the
  version, tag, re-pin. Never patch an installed copy: the next reinstall
  silently reverts it.
* **Pin by tag, not by branch.** A consumer depends on
  `site-mimic @ git+https://github.com/megamen32/site-mimic.git@<tag>#subdirectory=python`.
  Release a tag, re-pin, and let the consumer's lockfile record what it
  actually runs.
* **Never claim a fingerprint you have not measured.** A JA4 in a README is
  a measurement; a JA4 copied from another project is a guess. Re-measure
  with this repo's own tools.
* **Leave no root behind.** The mitmproxy CA must not survive a capture:
  not in the phone's system store, not in the zygote mount namespace, not in
  the user store of someone else's Windows machine, not in your own keychain.
  The capture tooling unmounts and deletes it for you — use the tooling.
* **A shared phone is a shared phone.** Take a lease before touching the
  device, and release it when you are done. Two agents fighting over the same
  iptables rules produce a capture that is empty for reasons that have
  nothing to do with the app.
* **Keep the public repo self-contained.** It must not depend on anything
  private: no references to internal paths, hosts or repositories. If a
  piece of tooling is needed, it lives here.

## Known limits

* **HTTP/2 header order** follows Go's canonical write, not the browser's.
  `header_order` documents the intended order; the wire order is only
  controllable for HTTP/1.1 profiles (`http1_wire_order` +
  `wire_header_order`).
* **`chrome_exact` needs the external headless-client**; the pure-uTLS
  specs are close but not byte-exact with a real Chrome.
* **IP TTL is a hint.** It is stamped per connection, but a hairpin hop or
  a middlebox changes what the server sees. `128` is the Windows default;
  `64` is the Linux/Android one.
* **QUIC is a separate constructor.** `mimic.New` speaks HTTP/1.1 and
  HTTP/2 over TCP. HTTP/3 is `mimic.NewHTTP3` — the same profile and the
  same options, a QUIC wire instead of a TCP one. Its QUIC ClientHello is
  the Chrome 152 one and does not follow the profile's `tls_client_hello`.
* **A profile is one client, one site.** The header set of a browser on one
  origin does not transfer to another origin unchanged.

## Map of the repository

| path | what lives there |
| --- | --- |
| `mimic/` | the library: transport, specs, profile handling, fingerprinting |
| `mimic/spec_*.go` | the ClientHello specs; `mimic/testdata/` holds the captured fixtures |
| `mimic/http3.go`, `mimic/quic_spec.go` | the QUIC transport and its Chrome 152 fingerprint |
| `cmd/fetchd` | the daemon for non-Go callers |
| `cmd/hello-tap`, `cmd/hellofp` | capture and fingerprint tooling |
| `cmd/h3sniff` | the HTTP/3 stand: it reads a client's QUIC fingerprint off the wire |
| `internal/quicwire` | the QUIC wire primitives: Initial decryption, transport parameters, h3 settings |
| `cmd/tproxyfwd` | the on-device transparent forwarder for a rooted phone |
| `examples/profiles/` | the ready-to-load JSON profiles |
| `examples/` | worked examples, one per site |
| `python/site_mimic_client/` | the canonical Python client |
| `js/` | the TypeScript/JavaScript client (npm) |
| `tools/phone/`, `tools/win/`, `tools/avd/` | capture tooling per platform |
| `tools/mac/` | the rootless macOS capture path — no root, no CA in the keychain |
| `tools/parse_clienthello.py`, `tools/ja4_from_pcap.py` | fingerprint readers |
| `tools/canary.sh`, `tools/canary-quic.sh` | the canaries: a real browser against ours, over TCP and over QUIC |
| `docs/` | methodology, research notes, per-site documentation |
| `skill/SKILL.md` | the agent workflow for fitting a new site |
