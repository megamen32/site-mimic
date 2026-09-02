# Fingerprint matrix — every captured reference, by platform/version/conditions

All values captured and verified on the wire with our tools
(`tools/ja4_from_pcap.py`, FoxIO-spec JA4; cross-checked against peet.ws and
the kulikov0/headless-client capture stand). Dates 2026-08-30 — 2026-09-01.
Mimic profiles map to these references 1:1.

## The matrix

| # | Platform | Client | Version | Conditions | JA4 | TTL | Headers / notes |
|---|---|---|---|---|---|---|---|
| 1 | Android 10, Samsung S21 Ultra (SM-G998B) | Chrome | 149.0.7827.200 | mobile 4G, PCAPdroid (MITM addon) capture | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | 64 | UA `…Android 10; K) … Chrome/149.0.0.0 Mobile Safari/537.36`, sec-ch-ua v=149, `gzip, deflate, br, zstd`; re-verified 2026-09-01 byte-for-byte |
| 2 | Android 10, same phone | Chrome | 152.0.7977.64 | PCAPdroid MITM capture — **superseded 2026-09-02**: the addon re-encrypts TLS with its own Chromium client, so the "18 exts / e2d80978ab2e" value was the MITM client, not the phone. Real end-to-end phone Chrome 152 (direct to the stand, no MITM) = `t13d1517h2_8daaf6152771_cb7bf5808d99`, 17 exts — identical to desktop | `t13d1517h2_8daaf6152771_cb7bf5808d99` (real e2e, 2026-09-02) | 64 (49 on carrier 4G) | real e2e headers: sec-ch-ua v=152, zstd, `Priority: u=0, i`; SYN `mss 1300,sackOK,TS,wscale 10`, ttl 49→50 carrier path |
| 3 | Linux x64 (this host) | Chrome | 152.0.7977.64 | headless **and** headed/Xvfb — TLS identical | `t13d1517h2_8daaf6152771_cb7bf5808d99` | 64 | UA `Chrome/152.0.0.0` (headed) vs `HeadlessChrome/152.0.0.0` (headless); sec-ch-ua v=152 shuffled brand list; `gzip, deflate, br, zstd`; `Priority: u=0, i` |
| 4 | Windows 11 23H2 (192.168.2.190) | Chrome | 151.0.7922.174 | **headed, AdGuard ENABLED** (AdguardSvc + browser extension; TLS layer untouched by it — JA4 stayed genuine-Chrome) | `t13d1516h2_8daaf6152771_806a8c22fdea` (+ per-connection 17-ext `t13d1517h2_8daaf6152771_a87ad97598a9`) | **128** | UA `Windows NT 10.0; Win64; x64 … Chrome/151.0.0.0`, sec-ch-ua `"Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"`, sec-ch-ua-platform `"Windows"`, `gzip, deflate, br, zstd`, `Priority: u=0, i` → `examples/vk-ru-windows` |
| 4b | Windows 11 23H2 | Chrome | 152.0.7977.64 | **headed, AdGuard DISABLED** (user exited it; auto-update 151→152 happened between the A/B runs). **Re-measured 2026-09-02 via the live stand (`/fp`)**: `t13d1517h2_8daaf6152771_cb7bf5808d99` (17 exts) — the 18-ext `e2d80978ab2e` set with `pre_shared_key`+`0xCA34` was a server-side (Finch) experiment, switched off by Google overnight; platform-wide all Chrome 152 now show the 17-ext desktop set | `t13d1517h2_8daaf6152771_cb7bf5808d99` (2026-09-02, live stand) — was `t13d1518h2_…e2d80978ab2e` on 2026-09-01 | **128** (127 over hairpin hop) | live-stand headers 13 names incl `Priority: u=0, i`, sec-ch-ua v=152 shuffled, zstd; SYN `mss 1460,wscale 8,sackOK` no-TS (matches our win-tcp-preset set; option ORDER differs: Windows `mss,wscale,sack` vs Linux `mss,sack,wscale`) |
| 5 | Windows 11 23H2 | Chrome | 151.0.7922.174 | headless | same class (measured via IP: `t13i1515h2_8daaf6152771_806a8c22fdea`) | 128 | insecure-context caveat: over http no client hints, only `gzip, deflate` |
| 6 | Windows 11 23H2 | curl (Schannel) | 8.13.0 | native Windows TLS | `t13i2511h1_f5a23f7cfd7b_36bf25f296df` (25 ciphers, 11 exts, h1) | 128 | what "native Windows app" looks like vs Windows Chrome |
| 7 | Linux x64 | BrowserOS (Chromium) | 148 | OS-default browser, live instance | `t13d1813h1_85036bcba153_d339722ba4af` (dominant) | 64 | **not a Chrome substitute**: h1-only ALPN, 18-cipher set, 13 extensions, no ECH/ALPS/PQ; headers `sec-ch-ua: "Not/A)Brand";v="99", "Chromium";v="148"` |
| 7b | **macOS 15.7.8** (Mac mini 2012 x86_64, 192.168.2.4) | curl (LibreSSL) | 8.7.1 | native macOS TLS stack | `t13i4906h2_0d8feac7bc37_7395dae3b2f3` (49 ciphers, 6 exts, h2) | 64 | instantly distinguishable from every browser |
| 7c | macOS 15.7.8 | BrowserOS "neo" (Chromium) | 148.0.7985.97 | headless (over SSH) | `t13i1515h2_8daaf6152771_d8a2da3f94cd` (+ per-connection 17-ext `…b6f405a00624`) | 64 | macOS build is Chrome-like (unlike the Windows BrowserOS build!) — chrome_auto-class, same as the phone-149 reference. UA `Macintosh; Intel Mac OS X 10_15_7 … HeadlessChrome/148`; insecure-context caveat applies (no client hints, `gzip, deflate` only) |
| 7d | macOS 15.7.8 | Safari | 18.6 (system, Version/18.6 Safari/605.1.15) | manual GUI launch by the user (Safari refuses RBS/SSH launch); attributed on the wire by 3 independent signals: SYN time == receiver log second-for-second (02:44:25Z), hairpin path via router (not an external bot), TTL 63 = 64−1 router hop + macOS TCP options | `t13d2014h2_a09f3c656075_e42f34c56612` (20 ciphers, 14 exts, h2; appears exactly once in the whole capture) | 64 (63 over hairpin) | UA `…Macintosh; Intel Mac OS X 10_15_7 … Version/18.6 Safari/605.1.15`; **no sec-ch-ua client hints at all** (genuine Safari trait), accept-encoding `gzip, deflate, br` (no zstd), accept-language `ru`, `Priority: u=0, i`, full sec-fetch navigation set. TCP SYN: `[mss 1460,nop,wscale 6,nop,nop,TS,sackOK,eol]`, win 65535 — EOL padding is a macOS-stack signature |
| 8 | Windows 11 23H2 | AdGuard ON vs OFF A/B | — | ON: AdguardSvc + extension (WFP mode, 2026-09-01 morning, Chrome 151); OFF: user exited the app (evening, Chrome 152) | TLS hello genuine-Chrome in BOTH states — AdGuard did not alter the ClientHello at any layer; header name-set identical in both states (receiver application view) | 128 both | A/B confound: Chrome auto-updated 151→152 between the runs; platform set: Windows 152 = 18 exts (same as Android 152) vs Linux 152 = 17 exts |

## Mimic profile mapping

| Target | Profile in repo | tls_client_hello | ip_ttl |
|---|---|---|---|
| Desktop Linux Chrome 152 | `examples/vk-ru/profile.json` | `chrome_exact` (byte-exact TLS+h2+header-order via headless-client) | — (64) |
| Android Chrome 149 | `examples/vk-ru-mobile/profile.json` | `android_149` (field-identical to the device: same ciphers/exts/classic sig algs/groups incl. X25519MLKEM768, per-connection shuffling) | — |
| Android/Windows Chrome 152 | built-in | `chrome_152` (custom spec: PQ sig algs 0x0904-0906 + GREASE, 0xCA34, pre_shared_key; JA4 `t13d1518h2_8daaf6152771_e2d80978ab2e` wire-verified 2026-09-01) — **stale since 2026-09-02**: Google switched the Finch experiment off; current real value is the 17-ext desktop set `cb7bf5808d99` (= use `chrome_exact` with an up-to-date Chromium until the spec is rebuilt) | — |
| Windows Chrome 151 | `examples/vk-ru-windows/profile.json` | `chrome_exact` | 128 |
| QUIC/h3 (Chrome-QUIC class) | prototype in `.tmp/uquic-probe/` (uQUIC + Chrome 115 QUIC preset) | wire-verified `q13d0310h3_55b375c5d22e_cd85d2d88918`; exact-152 QUIC preset pending | — |

## Facts that hold across the matrix

- **TTL is the cheapest OS tell**: Windows 128, Linux/Android 64 — and
  site-mimic forges it (`WithTTL` / `ip_ttl`). Fleet-level (2026-09-02,
  по запросу): хосты 192.168.2.100 и 192.168.2.5 (server44) закреплены
  на Windows L3/L4 нативно — `/etc/sysctl.d/60-win-tcp-mimic.conf`
  (TTL 128, no-TS, wscale 8), на проводе TTL 127 после hairpin-хопа
  без всяких оверрайдов (tools/win-tcp-preset.sh apply). Mac mini
  оставлен нативным (macOS TTL 64, BSD-опции) по решению владельца;
  server88 (192.168.2.75) недоступен для настройки — нет SSH
  (открыты только 3128/80/443).
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
