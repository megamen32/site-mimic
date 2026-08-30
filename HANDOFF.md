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

## L3/L4 (TCP/IP) layer — first data (2026-08-30 evening)

SYN fingerprints extracted from the same pcaps (`.tmpbin/tcp_fp.py` pattern):

| Stack | TTL | Window | SYN options |
|---|---|---|---|
| Phone (Android, via PcapDroid tun) | 64 | 65535 | `MSS=9960, SACKok, TS, NOP, WS=10` |
| Chromium in stand container | 64 | 64240 | `MSS=1460, SACKok, TS, NOP, WS=7` |
| **Our probe (chrome_exact, Go, same container)** | 64 | 64240 | `MSS=1460, SACKok, TS, NOP, WS=7` — **identical to Chromium** |

Findings:
- At L3/L4 a Go client on Linux is already kernel-identical to Chrome on
  Linux (SYN comes from the kernel, not the app). TTL 64 = Linux/Android
  class; a Windows-origin client (128) is what TTL exposes.
- The PcapDroid tun-side view DISTORTS L4 (`MSS=9960` is a tun-MTU artifact;
  a native 4G SYN carries ~1340-1420, and TTL crosses the radio leg
  decremented). Only a receiver-side capture shows the true bytes.
- Phone-as-proxy leg is live: `com.gptadmin.cellularproxy` on the phone
  (HTTP CONNECT on :3126, reached via `adb forward tcp:3126 tcp:3126`;
  NOTE the service needs a UI launch — the exported-intent start is
  blocked, `am start-foreground-service` fails with not-exported). Our
  chrome_exact client through the phone reached vk.ru with 200 OK over
  HTTP/2, and tls.peet.ws confirmed the egress IP is the phone's carrier
  (178.176.77.182), not the host's.
- Still missing: receiver-side TTL/TCP-options truth for the full chain
  (our client → phone proxy → a byte-capturing endpoint). Needs a public
  byte-capturing target address (peet.ws shows TLS/h2 but not TTL).

## Remaining work — closed 2026-08-30 (this list is done)

All seven items from the original handoff are complete:

1. **Header sequence on the wire — CLOSED.** headless-client (the
   `chrome_exact` transport) owns h1 and h2 wire order (Chrome order tables
   in `internal/chromehttp1/request.go` and
   `internal/chromehttp2/internal/httpcommon/request.go`). Documented in
   [docs/methodology.md](docs/methodology.md): closed on `chrome_exact`,
   Go-shaped on the uTLS-only path.
2. **Mobile profile — CLOSED.** `examples/vk-ru-mobile` replays the Android
   Chrome 149 capture verbatim (UA `Chrome/149… Mobile`, full
   `gzip, deflate, br, zstd` — the `chrome_exact` transport decodes br/zstd
   itself). Canary: `go run . -url https://m.vk.ru/` → 200 OK.
3. **HTTP/2 frame fingerprint — CLOSED.** headless-client ships a Chrome-tuned
   http2 fork (SETTINGS `INITIAL_WINDOW_SIZE=6291456`,
   `MAX_HEADER_LIST_SIZE=262144`, WINDOW_UPDATE 15663105, Chrome priority
   scheduling). Documented in [docs/methodology.md](docs/methodology.md).
4. **Exact-vs-phone JA4 diff — CLOSED.** `tools/ja4_from_pcap.py` implements
   the FoxIO JA4 (validated: reproduces the stand's byte-exact
   `t13d1516h2_8daaf6152771_806a8c22fdea` from `browser.pcap` and the
   documented `chrome_auto` value from `probe.pcap`); QUIC Initials decrypt
   via `tools/quic_initial.py`. Mobile reference pinned in
   [docs/phone-reference.md](docs/phone-reference.md):
   `t13d1516h2_8daaf6152771_d8a2da3f94cd` (same extension hash as uTLS
   `chrome_auto`).
5. **Challenge/token flows — CLOSED (as far as transport can go).**
   `mimic.LoadCookieJarFile` + `-cookies` in `examples/stream-wb-ru` replay
   browser-harvested `wbaas` cookies; the boundary (498 + JS challenge, and
   the harvest runbook) is documented in [docs/anti-bot.md](docs/anti-bot.md).
6. **CI — CLOSED.** `.github/workflows/ci.yml`: build+vet+test on push/PR;
   single-request vk.ru 200 canary on push to main; manual-only
   `transport-parity` job builds the stand and diffs JA4 (experimental,
   `continue-on-error`).
7. **Release mechanics — DONE.** Tagged v0.1.0.

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
