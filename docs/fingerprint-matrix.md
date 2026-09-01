# Fingerprint matrix — every captured reference, by platform/version/conditions

All values captured and verified on the wire with our tools
(`tools/ja4_from_pcap.py`, FoxIO-spec JA4; cross-checked against peet.ws and
the kulikov0/headless-client capture stand). Dates 2026-08-30 — 2026-09-01.
Mimic profiles map to these references 1:1.

## The matrix

| # | Platform | Client | Version | Conditions | JA4 | TTL | Headers / notes |
|---|---|---|---|---|---|---|---|
| 1 | Android 10, Samsung S21 Ultra (SM-G998B) | Chrome | 149.0.7827.200 | mobile 4G, PCAPdroid (MITM addon) capture | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | 64 | UA `…Android 10; K) … Chrome/149.0.0.0 Mobile Safari/537.36`, sec-ch-ua v=149, `gzip, deflate, br, zstd`; re-verified 2026-09-01 byte-for-byte |
| 2 | Android 10, same phone | Chrome | 152.0.7977.64 | same capture method | `t13d1518h2_8daaf6152771_e2d80978ab2e` | 64 | UA `Chrome/152.0.0.0 Mobile`, sec-ch-ua `"Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"`; **post-quantum sig algs 0x0904-0906 present**, ext 0xCA24 present, 18 exts (mobile set is wider than desktop) |
| 3 | Linux x64 (this host) | Chrome | 152.0.7977.64 | headless **and** headed/Xvfb — TLS identical | `t13d1517h2_8daaf6152771_cb7bf5808d99` | 64 | UA `Chrome/152.0.0.0` (headed) vs `HeadlessChrome/152.0.0.0` (headless); sec-ch-ua v=152 shuffled brand list; `gzip, deflate, br, zstd`; `Priority: u=0, i` |
| 4 | Windows 11 23H2 (192.168.2.190) | Chrome | 151.0.7922.174 | **headed, AdGuard ENABLED** (AdguardSvc + browser extension; TLS layer unaffected by it) | `t13d1516h2_8daaf6152771_806a8c22fdea` (+ per-connection 17-ext `t13d1517h2_8daaf6152771_a87ad97598a9`) | **128** | UA `Windows NT 10.0; Win64; x64 … Chrome/151.0.0.0`, sec-ch-ua `"Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"`, sec-ch-ua-platform `"Windows"`, `gzip, deflate, br, zstd`, `Priority: u=0, i` → `examples/vk-ru-windows` |
| 5 | Windows 11 23H2 | Chrome | 151.0.7922.174 | headless | same class (measured via IP: `t13i1515h2_8daaf6152771_806a8c22fdea`) | 128 | insecure-context caveat: over http no client hints, only `gzip, deflate` |
| 6 | Windows 11 23H2 | curl (Schannel) | 8.13.0 | native Windows TLS | `t13i2511h1_f5a23f7cfd7b_36bf25f296df` (25 ciphers, 11 exts, h1) | 128 | what "native Windows app" looks like vs Windows Chrome |
| 7 | Linux x64 | BrowserOS (Chromium) | 148 | OS-default browser, live instance | `t13d1813h1_85036bcba153_d339722ba4af` (dominant) | 64 | **not a Chrome substitute**: h1-only ALPN, 18-cipher set, 13 extensions, no ECH/ALPS/PQ; headers `sec-ch-ua: "Not/A)Brand";v="99", "Chromium";v="148"` |
| 8 | — | AdGuard OFF comparison (Windows) | — | AdGuard was disabled (2026-09-01 evening, user-confirmed); remote re-capture attempt blocked: interactive-session Chrome launch stopped responding (screen locked?) — **pending one manual navigation** to https://test.auto-gram.ru/ from that machine, receiver + wire capture pick it up automatically | — | — | with AdGuard ON the TLS ClientHello was untouched (WFP mode, no TLS MITM): JA4 stayed genuine-Chrome; header-level influence still to be A/B'd |

## Mimic profile mapping

| Target | Profile in repo | tls_client_hello | ip_ttl |
|---|---|---|---|
| Desktop Linux Chrome 152 | `examples/vk-ru/profile.json` | `chrome_exact` (byte-exact TLS+h2+header-order via headless-client) | — (64) |
| Android Chrome 149 | `examples/vk-ru-mobile/profile.json` | `android_149` (field-identical to the device: same ciphers/exts/classic sig algs/groups incl. X25519MLKEM768, per-connection shuffling) | — |
| Android Chrome 152 | reference only (row 2) — profile pending: needs PQ sig algs + 0xCA24 in a custom spec | — | — |
| Windows Chrome 151 | `examples/vk-ru-windows/profile.json` | `chrome_exact` | 128 |

## Facts that hold across the matrix

- **TTL is the cheapest OS tell**: Windows 128, Linux/Android 64 — and
  site-mimic forges it (`WithTTL` / `ip_ttl`).
- **Headed vs headless**: no TLS difference, no header-set difference on
  secure contexts; only the UA token differs.
- **Insecure context (http)**: Chrome sends no client hints and no br/zstd —
  captures must use HTTPS.
- **Chrome 149 → 152 changes**: post-quantum signature algorithms
  (0x0904-0906), new unregistered extension 0xCA24 (51764), shuffled
  sec-ch-ua brand list; JA4 third segment shifts accordingly on every
  platform.
- **Per-connection randomness** (extension order shuffle, GREASE values)
  exists on real Chrome and on our clients alike; JA4 is stable, JA3 is
  intentionally per-connection — a *stable* JA3 is itself a red flag.
- Android mobile hello (18 exts at 152) is wider than desktop (17): the
  mobile reference must be captured from a phone, not assumed from desktop.
