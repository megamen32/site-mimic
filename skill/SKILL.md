---
name: site-mimic-fit
description: >
  Fit a Go HTTP client to a target so its transport fingerprint (TLS
  ClientHello / JA3 / JA4, ALPN, HTTP version) and request headers match what
  the target expects from the real client. Use when a site blocks, captchas
  or challenges Go's default HTTP client, when a JA3/ClientHello-based filter
  (DPI/anti-bot) must be passed, when onboarding a new site into an automated
  client, when an API must be called exactly like a native app calls it
  (Node/Electron client, managed gateway, Android/OkHttp app), or when the
  real client is a phone you have in hand (rooted Android: app traffic and
  mobile web). Worked targets: vk.ru, stream.wb.ru, the MiniMax managed
  gateway, MAX (ru.oneme.app) and web.max.ru.
---

# Fit a Go client to a site (site-mimic)

Library: `github.com/megamen32/site-mimic/mimic`. A profile is a captured
client identity (`profile.json`); the library reproduces its TLS + header
shape. Follow the sequence below for every new site, in order. Do not skip
the verification steps — each one is cheap and catches a different failure.

## The sequence

### 1. Decide which client the site expects

Open the site in a real browser and note the entry URL. Most sites expect a
desktop Chrome navigation for the document and Chrome fetch/XHR for APIs.
Mobile-only sites may expect an Android OkHttp client (use
`tls_client_hello: "chrome_auto"` + a mobile UA + mobile headers instead).

### 2. Capture the real client

Header values (order matters only for documentation — see limits):

- DevTools → Network → first document request → Copy as cURL / view Request
  Headers. Or CDP: `Network.requestWillBeSent` + `requestWillBeSentExtraInfo`.

TLS ClientHello reference (what the server actually sees):

```sh
# mitmproxy sees plaintext; use tshark on the wire for ClientHello:
sudo tshark -i any -f 'tcp port 443' -Y 'tls.handshake.type == 1' \
  -T fields -e tls.handshake.raw
```

Modern Chrome randomizes extension order per connection, so JA3 is
per-connection unstable by design; compare the JA4-style stable shape
(cipher set, extension count, ALPN) instead — `tools/ja3_ja4.py` prints both.

### 3. Encode `profile.json`

Fields: `name`, `tls_client_hello` (`chrome_auto` unless the target is
Firefoxy/iOSy), `user_agent`, `header_order` (documentation), `headers`
(captured values). Copy a starting point from `examples/vk-ru/profile.json`.
Do NOT put `accept-encoding` in `headers` — see limits.

### 4. Wire the client

```go
profile := mimic.MustLoadProfile("profile.json")
client, err := mimic.New(profile) // uTLS + h2 + h1 fallback; honours HTTPS_PROXY
req, _ := profile.Request("GET", "https://example.com/", nil)
resp, _ := client.Do(req)
```

### 5. Verify the transport fingerprint

```sh
go run . -dump ch.json
python3 ../../tools/parse_clienthello.py ch.json
```

Expect: 16 ciphers (TLS 1.3 suites first), ~18 extensions, `alpn: ['h2',
'http/1.1']`, stable JA4 shape `t12d1516h2`. If the site's own captured
ClientHello differs materially (Firefox/IOS profile), switch
`tls_client_hello` and re-verify.

### 6. Verify the business path

Run the request. Read the STATUS and the `server:` header and classify:

- `200` — done (see `examples/vk-ru`).
- `403/429/418` — app-layer WAF: re-check UA/header values and cookies first,
  TLS only after.
- `498/499` + challenge HTML (`browser-check`, `behavior-tracker`,
  `create-token`, captcha site-key) — anti-bot JS layer, same first-load
  behaviour a fresh real browser gets. Transport parity is correct; the
  challenge is out of scope (see `examples/stream-wb-ru`). Carry a token
  cookie harvested in a real browser via `Profile.CookieJar`.

### 7. Iterate on drift

Sites rotate fingerprints rarely but WAF rules often. When a working client
starts failing: re-run step 2, diff headers first, then JA4 shape. Keep the
capture date in `profile.json`'s `name`/README.

## Worked example: vk.ru

1. Real Chrome navigation captured: UA `Chrome/119…`, `sec-fetch-*` quartet,
   `accept` incl. signed-exchange, no cookies for first load.
2. `tls_client_hello: chrome_auto`.
3. Request went out: HTTP/2.0, got `200` from `server: kittenx`
   (2026-08-30). Transport fingerprint: `t12d1516h2`, 16 ciphers, 18
   extensions — indistinguishable from the uTLS Chrome spec at the JA4 level.
4. Full files: `examples/vk-ru/`.

## Worked example: an API behind a native client (not a website)

Some targets are not websites but APIs reached by a native client — a desktop
app, an Electron/Node agent, an SDK, a mobile app. The same method applies,
with two extra steps, because the client identity is not a browser:

1. **Find the real endpoint and the real credential.** The public docs
   endpoint is often a *different product* than the one the app uses
   (MiniMax Code talks to `agent.minimax.io/mavis/api/v1/llm/v1/messages`
   with a managed `mmoat_…` token, while the documented Anthropic-compatible
   endpoint `api.minimax.io/anthropic` bills a platform API key). Read the
   app's own code/config: the endpoint, the auth scheme and the placeholder
   headers are all there.
2. **Capture the raw request bytes, not just DevTools headers.** Point the
   real client at a local TLS sink and keep the bytes: request line, header
   order, header casing, body field order. Go canonicalizes and re-sorts
   headers, so a profile without `http1_wire_order` will not match.
3. **Pick the transport profile from the client stack**, not from a habit:
   a Node/undici client is BoringSSL — `tls_client_hello: "node_24"`,
   ALPN `http/1.1` only, HTTP/1.1. An Android app on Conscrypt/OkHttp
   (`ru.oneme.app`) sends **no ALPN at all**, 17 cipher suites including
   CBC-SHA1, and `status_request` — `tls_client_hello: "max_app"` /
   `"max_app_psk"`, HTTP/1.1, and `http1_wire_order: true` for the header
   block. Browser profiles do not apply to either.
   Gotcha: a custom spec without a `pre_shared_key` extension cannot resume
   — uTLS panics on the second request to the same host unless
   `PreferSkipResumptionOnNilExtension` is set (mimic sets it).
4. **Write the profile with `http1_wire_order: true` and
   `wire_header_order: [...]`** listing the captured names in the captured
   order and casing. Keep secrets out: the profile holds static identity,
   the token is set per request.
5. **Verify on the stand** (`/fp`): JA3/JA4, ALPN and HTTP version must match
   the real client, and the raw request block must match byte for byte
   (same `content-length`). `mimic.ParseClientHello` + `JA3()`/`JA4()`
   compute the fingerprint from captured bytes; keep the captured hello as a
   fixture and assert the spec against it, so the profile cannot drift.
   Assert against a **real handshake**, not against the spec struct: a
   swapped uTLS cipher constant still "looks right" in the literal and only
   shows up in the bytes on the wire (see `mimic/spec_max_app_test.go`).
6. **Verify the business path**: a real request through the mimic client must
   return the same status and payload the app gets.

Full measured case: `docs/minimax-agent-gateway.ru.md`,
`examples/minimax-agent-gateway/`.

## Worked example: the real client is a phone you have in hand

A rooted Android phone is the most honest capture source: the app and the
mobile web version are the real clients, and their fingerprints are not
guessed from a browser profile. Full procedure and toolchain:
`tools/phone/README.md`. The short version:

```sh
# 0. the phone is a shared resource — take a lease first
s21-lease acquire --owner "$USER" --minutes 60 --purpose "capture <app>"

# 1. capture host: SOCKS5 mitmproxy that records ClientHello bytes + headers
mitmdump --mode socks5 --listen-host 0.0.0.0 --listen-port 31896 \
         --set ssl_insecure=true --set connection_strategy=lazy \
         -s tools/phone/mitm_capture_addon.py --set out_jsonl=/tmp/capture.jsonl

# 2. phone: redirect the app's TCP, block QUIC, mount the CA into zygote
GOOS=linux GOARCH=arm64 go build -o /tmp/tproxyfwd ./cmd/tproxyfwd
adb push /tmp/tproxyfwd tools/phone/setup_capture.sh tools/phone/ca_mount.sh \
         /data/local/tmp/
adb shell "su -c 'PKG=ru.oneme.app SOCKS5=<capture-host>:31896 \
                   sh /data/local/tmp/setup_capture.sh start'"

# 3. read the capture with the library's own parser
go run ./cmd/hellofp /tmp/capture.jsonl

# 4. TEAR DOWN — the rules are per-uid and stay on the phone
adb shell "su -c 'PKG=ru.oneme.app sh /data/local/tmp/setup_capture.sh stop'"
s21-lease release <lease-id>
```

What matters and why (each of these cost a full capture attempt):

- **Block QUIC for the target uid** (`iptables -A OUTPUT -p udp -m owner
  --uid-owner <uid> --dport 443 -j REJECT`). A modern app speaks HTTP/3 over
  UDP/443 by default, so there is no TCP ClientHello at all and the capture
  looks empty. This was the real cause of the first failed capture of
  `ru.oneme.app`, not the app's behaviour.
- **Mount the CA into the zygote mount namespace**, not into the app's.
  A per-pid bind-mount is not inherited when the app restarts, so the trust
  silently disappears; zygote's view is inherited by every app forked after
  the mount.
- **The uid is the selector** (`stat -c %u /data/data/<pkg>`), not the
  package: it also covers the app's helper processes, and the browser is
  just another uid.
- **Only the CDN host speaks HTTP.** For `ru.oneme.app`, mitmproxy parsed
  HTTP requests only from `i.oneme.ru`; 116 connections to `api2.oneme.ru`
  produced no request line at all — the API is a binary protocol over TLS.
  Do not assume the API host is HTTP.
- **Always tear down.** A leftover `REJECT` rule breaks QUIC for that uid;
  a leftover redirect sends its traffic into a dead forwarder. `stop` removes
  both rules and kills the forwarder.

### The web version on the same phone: use CDP, not MITM

Capturing the browser's **ClientHello** works with the same chain — mitmproxy
reads it before the client rejects our certificate. Capturing the browser's
**headers** does not: Chrome 155 uses the Chrome Root Store and does not
consult the Android platform trust store, so it refuses the proxy
certificate (`tls alert certificate unknown`). Neither the conscrypt APEX
mount, nor the user store, nor `--ignore-certificate-errors` gets past it.

Use the DevTools protocol instead — Chrome itself reports the headers it is
about to send, and no CA is involved:

```sh
adb forward tcp:9333 localabstract:chrome_devtools_remote
ssh -f -N -L 9334:127.0.0.1:9333 <host-with-the-phone>
python3 tools/phone/cdp_headers.py --cdp 127.0.0.1:9334 \
        --url https://web.max.ru/ --out web.jsonl --seconds 30
```

Two limits to plan for:

- CDP reports **browser-added headers only**. `Host`, `Accept`,
  `Accept-Encoding`, `Accept-Language`, `Sec-Fetch-*` and `Priority` come
  from the network stack and are **not** in `requestWillBeSent` — take them
  from a real navigation or from an existing Chrome profile
  (`examples/profiles/android-chrome152.json`).
- The DevTools websocket must not carry an `Origin` header
  (`suppress_origin=True`).

Result for `web.max.ru`: mobile Chrome 155 → JA4
`t13d1517h2_8daaf6152771_cb7bf5808d99`, ALPN `h2,http/1.1`, 16 ciphers, 19
extensions — the same JA4 the repo's `chrome_152` spec already produces, so
the web profile needs headers only, no new TLS spec.

Full measured case: `docs/max-oneme.ru.md`,
`examples/profiles/max-app-oneme.json`,
`examples/profiles/max-web-chrome155.json`.

## Known limits (do not overclaim)

- HTTP/2 frame shape (SETTINGS/WINDOW_UPDATE values and order) is Go's
  `x/net/http2` default, not the browser's. Sites fingerprinting h2 frames
  (Akamai-style) can still tell Go apart — roadmap.
- Wire header order is Go's, not the browser's. Values and set are exact.
  Closed for HTTP/1.1 profiles with `http1_wire_order` (the transport writes
  the header block itself, in the captured order and casing); browser/h2
  profiles still use Go's canonical write.
- `accept-encoding` is left to Go (transparent gzip; browser value includes
  `br` which Go cannot decode).
- The HTTP/1.1 wire transport always writes `host` first. A client that puts
  it elsewhere (the MAX app puts it fourth) is off by one position.
- CDP (`Network.requestWillBeSent`) reports browser-added headers only —
  `Host`, `Accept`, `Accept-Encoding`, `Accept-Language`, `Sec-Fetch-*` and
  `Priority` are network-stack headers and are missing there. Take them from
  a real navigation.
- JA4 here is the simplified in-repo variant (version token from
  legacy_version); use it for self-comparison, not for cross-repo equality.

## Serving non-Go callers: fetchd (one-truth transport)

When Python callers need browser-grade transport, run the fetch daemon instead
of reimplementing TLS mimicry per language:

```sh
FETCHD_ADDR=127.0.0.1:8899 FETCHD_TOKEN=optional go run ./cmd/fetchd
```

`POST /fetch` contract: `{"method","url","profile" (path to a profile.json),
"headers","cookies","body"|"body_b64","proxy","resolve":{"host":"ip"},
"timeout_s"}` → `{"status","headers","set_cookies","body"|"body_b64","error"}`.
One mimic client is cached per (profile, proxy, resolve); connections pool.
The daemon never logs bodies or cookie values.

Python drop-in — pip package in THIS repo (`python/pyproject.toml`, package
`site_mimic_client`, stdlib-only). Versions live here: bump `version`, tag
`python-vX.Y.Z`, consumers pin the tag:
`site-mimic @ git+https://github.com/megamen32/site-mimic.git@python-v0.1.0#subdirectory=python`
in consumer repos' pyproject/requirements). SHA pins are for hotfix
verification only. Config: set
`GOHTTPD_URL`/`GOHTTPD_TOKEN`, then `gohttp.get/post(url, profile=…, …)` —
same call shape as requests. The daemon call itself bypasses environment
proxies on purpose.

params={"client":"wdp"})` -> 200 with full video JSON through the Go path.
