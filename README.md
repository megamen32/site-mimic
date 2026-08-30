# site-mimic

Make a Go HTTP client present the same wire-level identity a target site
expects from a real browser — TLS ClientHello (JA3/JA4 shape), ALPN,
HTTP/2 and the captured header set. Stock Go TLS is trivially
distinguishable and is increasingly what DPI middleboxes and anti-bot
layers flag first.

site-mimic packages the uTLS-based transport we run in production, plus the
methodology that makes it repeatable: an AI-agent skill that walks a new
site from capture to verified request, and two fully worked examples.

## What you get

- `mimic` Go package — uTLS handshake (`chrome_auto` by default), HTTP/2 via
  ALPN with per-host HTTP/1.1 fallback, CONNECT-proxy support (explicit or
  `HTTPS_PROXY`), profile-driven headers, ClientHello self-dump.
- [`skill/SKILL.md`](skill/SKILL.md) — the fit-a-site sequence for AI agents:
  capture → profile → wire → verify fingerprint → verify business path.
- `examples/vk-ru` — verified: HTTP 200 over HTTP/2 from `vk.ru`
  (`server: kittenx`).
- `examples/stream-wb-ru` — verified: reaches Wildberries' `wbaas` anti-bot
  challenge exactly as a fresh real browser does (HTTP 498 first load), with
  an honest layer-by-layer verdict.

## Install

```sh
go get github.com/megamen32/site-mimic/mimic
```

## Start in minutes

```sh
git clone https://github.com/megamen32/site-mimic && cd site-mimic/examples/vk-ru
go run . -dump ch.json
python3 ../../tools/parse_clienthello.py ch.json   # JA3/JA4 of our ClientHello
```

Expect `status: 200 OK`, `proto: HTTP/2.0` and a Chrome-shaped fingerprint.
Then fit a new site with [skill/SKILL.md](skill/SKILL.md).

## Learn more

- [Fit-a-site methodology (for AI agents)](skill/SKILL.md)
- [How it works, limits and roadmap](docs/methodology.md)
- [vk.ru example](examples/vk-ru/) · [stream.wb.ru example](examples/stream-wb-ru/)
- [Русское резюме](docs/README.ru.md)

## Honest limits

Header values and the TLS layer are exact; wire header order and the HTTP/2
SETTINGS frame shape are Go's defaults — see
[docs/methodology.md](docs/methodology.md) before claiming full
fingerprint parity. Anti-bot JavaScript challenges (the stream.wb.ru layer)
are out of scope by design.

MIT licensed. Not affiliated with VK or Wildberries.
