# HANDOFF completion — site-mimic

Started at 2026-08-30T16:31+03:00 (host clock). Branch main (primary checkout),
clean at start. Estimate: min 30 / max 90 active minutes.

## Minimal path

Result: all 7 items of HANDOFF.md "Remaining work" closed or precisely
documented as blocked.
Canary: `go run ./examples/vk-ru` → 200 (existing), new
`examples/vk-ru-mobile` → 200 on m.vk.ru, JA4 tool reproduces the stand's
byte-exact browser JA4 from the captured pcaps, `go test ./...` green.
Slice: parallel fast-agent workers on disjoint files; L integrates, tests,
commits, pushes, tags v0.1.0.

## Key facts established (2026-08-30, verified in module cache)

- kulikov0/headless-client@v0.0.0-20260830084403 already implements BOTH
  header wire-order (h1: internal/chromehttp1/request.go order tables; h2:
  internal/chromehttp2/internal/httpcommon/request.go chromeNavigationHeaderOrder
  ranks) AND Chrome h2 frame fingerprint (internal/chromehttp2 fork:
  InitialWindowSize 6291456, MaxHeaderListSize 262144, conn WINDOW_UPDATE
  15663105; chrome_fingerprint_test.go). Items 1+3 = audit + docs, not code.
- Android Chrome 149 header reference (exact values): 
  video_watching/.tmpbin/captures/phone-headers.txt (UA Chrome/149.0.0.0
  Mobile, sec-ch-ua v=149, zstd in accept-encoding).
- Phone pcap for item 4: video_watching/.tmpbin/captures/phone-vk.pcap;
  stand browser/probe pcaps: video_watching/.tmpbin/captures/vk-site-mimic/
  browser.pcap + probe.pcap. Target browser JA4:
  t13d1516h2_8daaf6152771_806a8c22fdea (byte-exact, verified on stand).

## Worker assignments (disjoint file ownership, no git)

- W1 items 1+3: docs/methodology.md only.
- W2 item 2: examples/vk-ru-mobile/** (canary: m.vk.ru 200).
- W3 item 4: tools/ja3_ja4.py, tools/parse_clienthello.py, docs/phone-reference.md
  (canary: FoxIO JA4 of browser.pcap == t13d1516h2_8daaf6152771_806a8c22fdea).
- W4 item 5: mimic/cookiejar.go, examples/stream-wb-ru/main.go, docs/anti-bot.md.
- W5 item 6: .github/workflows/ci.yml.
- L: item 7 (tag v0.1.0) + integration, README/HANDOFF updates, commits, push.

## Status

- [x] Recon complete (code, headless-client API, captures, fast-agent CLI).
- [ ] W1..W5 results integrated.
- [ ] Real-surface tests green.
- [ ] Commits + push + tag v0.1.0.
