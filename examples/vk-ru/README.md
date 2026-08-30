# Example: vk.ru

Desktop-Chrome navigation to `https://vk.ru/` from a Go client.

- **Capture source:** real desktop Chrome navigation to `https://vk.ru/`
  (document request, 2026-08-30). Header values in `profile.json` are that
  capture; refresh from your own browser per `skill/SKILL.md` when you need a
  different client shape.
- **Expected result:** HTTP 200, `proto: HTTP/2.0`, `server: kittenx`, ~50 KB
  of windows-1251 HTML.
- **accept-encoding note:** the browser capture carries
  `accept-encoding: gzip, deflate, br`; the example intentionally lets Go own
  that header so responses are transparently decompressed (Go cannot decode
  Brotli). See `docs/methodology.md`.

```sh
go run .
go run . -dump ch.json && python3 ../../tools/parse_clienthello.py ch.json
```

`HTTPS_PROXY`/`HTTP_PROXY` (or `mimic.WithProxy`) route the client through a
CONNECT proxy; the uTLS handshake then happens inside the tunnel.
