# HANDOFF — what is left to finish

State of this repository, what is already verified, and the ranked list of
remaining work. Written 2026-08-30 after the first capture-stand comparison
against `kulikov0/headless-client`.

## Verified so far (2026-08-30)

- `mimic` client works against the real sites: vk.ru returns 200 over
  HTTP/2 (server `kittenx`); stream.wb.ru returns the expected 498 `wbaas`
  anti-bot challenge (same first-load behaviour as a fresh real browser).
- Capture-stand comparison (kulikov0/headless-client `stand`, pinned
  Chromium, vk.ru):
  - uTLS `chrome_auto`: JA4 `t13d1516h2_8daaf6152771_d8a2da3f94cd` —
    protocol, cipher set and counters match the browser; the extension-set
    hash differs (uTLS's bundled Chrome spec lags the current Chrome, e.g.
    post-quantum signature algorithms).
  - **`chrome_exact` (transport delegated to headless-client): JA4
    `t13d1516h2_8daaf6152771_806a8c22fdea` — byte-exact match with the
    browser. VERIFIED on the stand.** This is now the recommended profile
    value.
- Real-phone reference capture (Samsung S21 Ultra SM-G998B, Android Chrome
  149, mobile 4G, PcapDroid pcap + adb-reverse header logger):
  - Android Chrome header reference captured, exact order: Host,
    Connection, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform,
    Upgrade-Insecure-Requests, User-Agent, Accept, Sec-Fetch-Site/Mode/Dest,
    Accept-Encoding (`gzip, deflate, br, zstd` — note zstd on Chrome 149),
    Accept-Language.
  - ClientHellos parsed from the pcap: same fingerprint class as the stand
    Chromium (TLS 1.3, 16 ciphers incl. GREASE, ALPN h2, per-connection
    extension shuffling). Conclusion: the Docker Chromium reference is a
    legitimate modern-Chrome fingerprint at the JA4 level.
- Connection reuse works (2 TCP flows for 3 requests on one client).

## Remaining work, ranked

1. **Header sequence on the wire.** Our profiles carry captured header
   values, but wire order is Go's. headless-client claims header-order
   coverage — audit what it does for h1 and h2, adopt the mechanism or
   document precisely why values-only is sufficient for the sites we care
   about.
2. **Mobile profile.** Build `examples/vk-ru-mobile` from the captured
   Android Chrome 149 header reference (UA `Chrome/149… Mobile`, zstd
   caveat: Go cannot decode zstd — drop it from accept-encoding like br).
3. **HTTP/2 frame fingerprint.** SETTINGS/WINDOW_UPDATE/PRIORITY values and
   order are still Go's `x/net/http2` defaults. Check what headless-client
   does at the frame layer; adopt or build a custom framer.
4. **Exact-vs-phone JA4 diff.** Compute a FoxIO-comparable JA4 for the
   phone's m.vk.ru hello (the in-repo pcap parser uses its own simplified
   JA4) and pin it next to the stand's browser JA4 as the mobile reference.
5. **Challenge/token flows.** For anti-bot sites (stream.wb.ru `wbaas`):
   document + implement cookie/token harvest in a real browser and replay
   via `Profile.CookieJar`.
6. **CI.** A docker job that builds the stand image, runs browser+probe
   against a stable target and diffs JA4; plus a rate-limited vk.ru 200
   canary.
7. **Release mechanics.** Tag v0.1.0 so the module resolves on pkg.go.dev.

## Phone-capture runbook (adb only, verified)

1. `adb devices` — if the device is missing: `adb kill-server && adb
   start-server`.
2. Headers: `adb reverse tcp:8899 tcp:8899` + a local raw-header logger
   (see `.tmpbin/header_logger.py` pattern) → navigate Chrome to
   `http://127.0.0.1:8899/` → exact header order without any CA setup.
3. ClientHello: PCAPdroid on the phone, pcap_file mode. NOTE: the
   `CaptureCtrl` intent API silently no-ops on this phone; drive the UI
   instead (coordinates verified on a 720x1600 screen): turn OFF the
   "Целевые приложения" filter (tap the row's switch at ~(655,921), then
   deselect the app in the picker at ~(655,205)), tap the play button at
   ~(517,99), navigate Chrome to the target, tap stop at ~(517,99), then
   `adb pull /sdcard/Download/PCAPdroid/<file>.pcap`.
4. Parse: `PYTHONPATH=tools/rutube-replay client/.venv/bin/python
   tools/rutube-replay/transport_parity/pcap_parser.py captures/phone.pcap`.
5. Chrome on 4G ignores Android's global `http_proxy` setting after the
   first process start — do not waste time on it; use (2) instead.

## Quick verification loop

## Quick verification loop

```sh
go run ./examples/vk-ru -dump ch.json
python3 tools/parse_clienthello.py examples/vk-ru/ch.json
# full parity check against real Chromium:
#   clone kulikov0/headless-client, cd stand
#   ./stand.sh build
#   ./stand.sh run --secs 30 --url https://vk.ru/ \
#     --role probe:<path-to>/stand-probe --role-args probe:"https://vk.ru/ 3" \
#     --out ./captures/vk
#   ./stand.sh diff ./captures/vk
```

Note for the stand on Docker hosts where seccomp blocks `mount`: the
container needs `--privileged` (plain `--cap-add=NET_ADMIN --cap-add=SYS_ADMIN`
is not enough for `ip netns add`).
