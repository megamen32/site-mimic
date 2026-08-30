---
name: site-mimic-fit
description: >
  Fit a Go HTTP client to a target website so its transport fingerprint
  (TLS ClientHello / JA3 / JA4, ALPN, HTTP/2) and request headers match what
  the site expects from a real browser. Use when a site blocks, captchas or
  challenges Go's default HTTP client, when a JA3/ClientHello-based filter
  (DPI/anti-bot) must be passed, or when onboarding a new site into an
  automated client. Worked sites: vk.ru, stream.wb.ru.
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

## Known limits (do not overclaim)

- HTTP/2 frame shape (SETTINGS/WINDOW_UPDATE values and order) is Go's
  `x/net/http2` default, not the browser's. Sites fingerprinting h2 frames
  (Akamai-style) can still tell Go apart — roadmap.
- Wire header order is Go's, not the browser's. Values and set are exact.
- `accept-encoding` is left to Go (transparent gzip; browser value includes
  `br` which Go cannot decode).
- JA4 here is the simplified in-repo variant (version token from
  legacy_version); use it for self-comparison, not for cross-repo equality.
