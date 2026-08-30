# Example: stream.wb.ru

Desktop-Chrome first navigation to `https://stream.wb.ru/` — and an honest
look at what transport mimicry can and cannot pass.

- **Capture source:** real desktop Chrome navigation to `https://stream.wb.ru/`
  (document request + anti-bot flow, 2026-08-30).
- **Expected result:** HTTP 498, `server: wbaas`, an HTML page loading
  `/__wbaas/challenges/antibot/` statics (`browser-check.js`,
  `challenge-solver`, `behavior-tracker`, a `create-token` API call).
- **Why 498 is the CORRECT outcome:** a fresh real browser gets the same 498
  challenge first; after its JavaScript solves it the site issues the
  `x_wbaas_token` cookie and reloads. Our client reproduces the transport and
  header layer byte-faithfully — the challenge layer is browser JavaScript,
  which no TLS/header parity can (or should) fake. To get past it, harvest a
  token in a real browser and carry the cookie via `Profile.CookieJar`.

```sh
go run .
go run . -dump ch.json && python3 ../../tools/parse_clienthello.py ch.json
```

Layer verdicts to expect:

| Layer | Status |
|---|---|
| TLS ClientHello (JA3/JA4) | matched (`chrome_auto`) |
| ALPN / HTTP/2 | matched |
| Header set + values | matched (capture) |
| Anti-bot JS challenge | out of scope (app layer) |
