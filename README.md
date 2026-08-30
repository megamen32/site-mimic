# site-mimic

[Русский](docs/README.ru.md) · [中文](docs/README.zh-CN.md) · [HANDOFF](HANDOFF.md)

> Make a Go HTTP client present the same wire-level identity a target site
> expects from a real browser — TLS ClientHello (JA3/JA4), ALPN, HTTP/2 and
> the captured header set. Stock Go TLS is trivially distinguishable, and
> ClientHello-level signatures are exactly what DPI middleboxes block first.

site-mimic packages a production-proven uTLS transport plus the methodology
that makes browser-fitting repeatable: an AI-agent skill that walks a new
site from capture to verified request, capture/verification tooling, and two
fully worked examples.

## Verified (2026-08-30, against vk.ru)

| Client | JA4 (stand, pinned Chromium) | Result |
|---|---|---|
| uTLS `chrome_auto` | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | 200 OK over HTTP/2; near-match (extension set differs) |
| `chrome_exact` (delegates TLS to [headless-client](https://github.com/kulikov0/headless-client)) | `t13d1516h2_8daaf6152771_806a8c22fdea` | **byte-exact JA4 match with the browser** |
| Real phone (Samsung S21 Ultra, Android Chrome 149, 4G) | `t13d1516h2_8daaf6152771_d8a2da3f94cd` — same fingerprint class ([phone reference](docs/phone-reference.md)) | confirms the desktop reference |

Also verified: `stream.wb.ru` returns the same 498 `wbaas` anti-bot
challenge a fresh real browser gets — transport parity is correct, the JS
challenge is app-layer (see `examples/stream-wb-ru`).

## Credits: headless-client is the more accurate transport

**[kulikov0/headless-client](https://github.com/kulikov0/headless-client) is
better at the transport layer, and site-mimic builds on it.** Its
ClientHello is hand-measured against the current stable Chrome (including
post-quantum signature algorithms), which is why it matches the browser
byte-for-byte, while the off-the-shelf uTLS `chrome_auto` profile lags
slightly behind. Its HTTP part additionally covers header order, HTTP/2
SETTINGS framing and connection reuse, and its capture stand
(`stand/`) diffs your binary against a real Chromium on the wire —
the verification loop we now recommend everywhere.

site-mimic's own value is the layer around the transport: the fit-a-site
skill for AI agents, capture→profile→verify tooling, site profiles and
worked examples. `tls_client_hello: "chrome_exact"` delegates the TLS/HTTP2
layers to headless-client (MIT, thank you), `chrome_auto` and friends stay
available as pure-uTLS fallbacks.

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

Expect `status: 200 OK`, `proto: HTTP/2.0` (`server: kittenx`). Then fit a
new site with [skill/SKILL.md](skill/SKILL.md).

## Learn more

- [Fit-a-site methodology (AI-agent skill)](skill/SKILL.md)
- [How it works, limits, roadmap](docs/methodology.md)
- [HANDOFF — verified state and remaining work](HANDOFF.md)
- [vk.ru example](examples/vk-ru/) · [m.vk.ru mobile example](examples/vk-ru-mobile/) · [stream.wb.ru example](examples/stream-wb-ru/) · [stand probe](examples/stand-probe/)
- [Anti-bot boundary & cookie replay](docs/anti-bot.md) · [Desktop/phone JA4 references](docs/phone-reference.md)
- [Public capture receiver: test.auto-gram.ru](docs/receiver-stand.md)

## Honest limits

With `chrome_exact` the TLS layer is byte-exact, and the header wire order
plus Chrome-shaped HTTP/2 framing come from headless-client too (see
[docs/methodology.md](docs/methodology.md) for what is closed vs still
Go-shaped on the uTLS-only path). QUIC/DTLS are not covered. Anti-bot
JavaScript challenges are out of scope by design — replay support for
browser-harvested cookies is in [docs/anti-bot.md](docs/anti-bot.md).

MIT licensed. Not affiliated with VK or Wildberries.
