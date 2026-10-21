# ClientHello references: desktop stand vs real phone

FoxIO JA4 values computed with `tools/ja4_from_pcap.py` (spec:
FoxIO-LLC/ja4 `technical_details/JA4.md`; implementation validated by
reproducing the stand's byte-exact browser value below). All captures:
2026-08-30.

## Desktop — capture stand (kulikov0/headless-client, pinned Chromium)

- `browser.pcap` (real Chromium in the stand's network namespace):
  `t13d1516h2_8daaf6152771_806a8c22fdea`

  **Superseded 2026-10-20**: the headless-client fork was synced with Kulikov's
  stream, and the captured Chrome moved to the next generation. The
  `chrome_exact` path now produces `t13d1517h2_8daaf6152771_cb7bf5808d99` —
  the same fingerprint as our own Chrome 152/155 capture. The value above is
  what the 2026-08-30 capture produced; the guard for the current one is
  `mimic/exact_capture_test.go`.
- `probe.pcap` (site-mimic `tls_client_hello: "chrome_auto"`):

  `t13d1516h2_8daaf6152771_d8a2da3f94cd`

  (the stand run with `chrome_exact` matches the browser byte-for-byte —
  verified 2026-08-30, see HANDOFF.md; this pcap is from the `chrome_auto`
  comparison, which differs only in the extension-set hash)

Reproduce:

```sh
python3 tools/ja4_from_pcap.py \
  ./captures/vk-site-mimic/browser.pcap \
  ./captures/vk-site-mimic/probe.pcap
```

## Mobile — a rooted Android phone, Chrome 149, mobile 4G

Source: PCAPdroid pcap-file capture, `phone-vk.pcap` (Chrome navigated to
m.vk.ru). Per-connection extension shuffling is why per-connection JA3 moves;
JA4 sorts, so it is stable except for Chrome's per-connection optional
extensions (one extra extension appears on some connections):

- m.vk.ru, first navigation:
  `t13d1516h2_8daaf6152771_d8a2da3f94cd`
- m.vk.ru, second connection:
  `t13d1517h2_8daaf6152771_b6f405a00624` (one extension more)

Re-verified 2026-09-01 with a fresh PCAPdroid capture on the same device
(Chrome still 149.0.7827.200 at that moment): m.vk.ru again
`t13d1516h2_8daaf6152771_d8a2da3f94cd`, identical on every vk.ru flow —
the 149 reference was stable across days and connections, and the
navigation header capture reproduced the existing
`examples/vk-ru-mobile/profile.json` byte-for-byte.

**Chrome updated on the device to 152.0.7977.64 (2026-09-01) and
re-captured**: m.vk.ru now
`t13d1518h2_8daaf6152771_e2d80978ab2e` — 18 extensions (mobile set is
wider than desktop's 17), **with** the post-quantum signature algorithms
and 0xCA34. Headers: sec-ch-ua `"Chromium";v="152", "Not?A_Brand";v="24",
"Google Chrome";v="152"`, UA `Chrome/152.0.0.0 Mobile Safari/537.36`.
The full cross-platform reference table lives in
[fingerprint-matrix.md](fingerprint-matrix.md).

**Field-level equivalence, wire-verified 2026-09-01**: a field-by-field diff
of the phone hello against our transports shows the phone's ClientHello
equals uTLS `HelloChrome_Auto` exactly — same cipher list (with GREASE),
same extension set (incl. ALPS 17613, ECH 65037), same signature algorithms
(classic set, **no** post-quantum entries at 149), same groups (incl.
X25519MLKEM768), same supported_versions — with per-connection extension
shuffling on both sides and per-connection GREASE values on both sides. The
`chrome_exact` path, by contrast, adds the post-quantum signature algorithms
0x0904-0906 (headless-client patches them in for current desktop Chrome).
Profiles can therefore target the phone explicitly with
`tls_client_hello: "android_149"` (alias of chrome_auto) — live captures of
our client reproduce the phone JA4 `t13d1516h2_8daaf6152771_d8a2da3f94cd`
with a different JA3 every connection, exactly like the device.
`examples/vk-ru-mobile` uses it (canary m.vk.ru 200 OK).

Across the capture's Chrome flows the 16-extension value dominates
(39 vs 5), so the mobile reference is:

```text
Android Chrome 149 (mobile): t13d1516h2_8daaf6152771_d8a2da3f94cd
Desktop stand Chromium:      t13d1516h2_8daaf6152771_806a8c22fdea
```

## Mobile re-capture (2026-10-21) — Chrome 155, Yandex.Browser, MAX

The phone was on USB, rooted, and the whole chain of `tools/phone` was run
again: `mitmdump --mode socks5` on the capture host, the on-device forwarder
over the phone's Wi-Fi, the CA mounted into the zygote view. The captures
are committed as `mimic/testdata/phone_chrome155_clienthello.json` and
`mimic/testdata/yandex_browser_clienthello.json`, and `mimic/phone_capture_test.go`
pins their fingerprints.

**Chrome 155.0.8059.81 on the phone** (the browser's own hello to m.vk.ru):

- TCP: JA4 `t13d1517h2_8daaf6152771_cb7bf5808d99` — seventeen extensions,
  0xCA34 included, post-quantum signature algorithms, ML-KEM768 key share.
  **The same fingerprint desktop Chrome 155 produces**: the mobile extension
  set is the desktop one. (The mobile reference of 2026-09-01, Chrome 152
  with eighteen extensions, was a different generation; the mobile set is
  not "wider" after all — it caught up.)
- QUIC: JA4 `q13d0312h3_55b375c5d22e_178839b6cec1` by name
  (`q13i0311h3_…` by address) — twelve extensions, the 0xCA34 payload
  byte-for-byte the desktop one, `google_connection_options "ORIG"`, the
  same as desktop Chrome 155. The resumed shape is
  `q13d0314h3_55b375c5d22e_79cc91d6b50c`: fourteen extensions, the
  pre_shared_key (0x0029) and signed_certificate_timestamp (0x002a) added.
- Headers (over CDP, no CA needed): UA
  `Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko)
  Chrome/155.0.0.0 Mobile Safari/537.36`, `sec-ch-ua: "Google Chrome";v="155",
  "Chromium";v="155", "Not(A:Brand";v="24"`, `sec-ch-ua-mobile: ?1`,
  `sec-ch-ua-platform: "Android"`, `Upgrade-Insecure-Requests: 1`.

**The google_connection_options token follows the Chrome version, not the
platform**: the phone's Chrome 152 sent "ORIGECCPIW2X", the phone's Chrome
155 sends "ORIG" — the same token desktop Chrome 155 sends. A token measured
on one platform must not be assumed for another.

**Yandex.Browser 26.8.7.49 on the phone** (hello to api.browser.yandex.net):

- TCP: JA4 `t13d1516h2_8daaf6152771_806a8c22fdea` — **sixteen** extensions
  and **no 0xCA34**. Yandex's Chromium fork lags the upstream patch level:
  its hello is the shape of Chrome 151. The post-quantum signature
  algorithms and the ML-KEM768 group are there, so the fork is recent, but
  it does not send the unregistered extension. For a client that has to look
  like Yandex's own browser, sending 0xCA34 is a tell.

**The Yandex app (com.yandex.searchapp, 26.87)** carries the same main
shape as the browser — `t13d1516h2_8daaf6152771_806a8c22fdea`, sixteen
extensions — because the app embeds the browser. It also carries two other
shapes, and they are worth knowing about:

- `t13d1513h2_8daaf6152771_eca864cca44a` — thirteen extensions, no ALPS,
  no ECH GREASE, no post-quantum signature algorithms: a different TLS
  stack inside the app (the one behind `yandex.ru`, `yastatic.net`,
  `favicon.yandex.net`);
- `t12d1409h1_...` and `t12d1410h1_...` — TLS 1.2, HTTP/1.1 only: the
  Rustore statistics SDK.

So "Yandex" is not one client but three, and the browser's shape is the one
that speaks to the Yandex sites. The app was disabled on the device and was
enabled only for the capture.

**MAX (ru.oneme.app)** re-measured the same day: JA4
`t13d171100_5b57614c22b0_40271e0a5736`, JA3 md5
`fb1972c15d60b7be0427edfbd00affde` — identical to the reference committed
on 2026-10-20, so the app's hello has not moved.

A note on the QUIC path from a phone: Chrome does not try QUIC for an
origin it has never seen (no Alt-Svc yet), so a local QUIC stand gets
nothing unless the origin was already told to use QUIC. The working way is
a packet capture of the real thing: `tcpdump` on the phone (root) over
`udp port 443`, then `tools/ja4_from_pcap.py` decrypts the Initial packets
and prints the hello.

## Desktop Chrome 152 stable — what changed after 149

Measured 2026-08-30 on this workstation (Google Chrome 152.0.7977.64,
headless, hello captured via https://tls.peet.ws/api/all — our FoxIO JA4
implementation reproduces peet.ws's value exactly):

```text
Chrome 152: t13d1517h2_8daaf6152771_cb7bf5808d99
```

Differences vs Chrome 149 (the whole extension set is otherwise identical):

- **Post-quantum signature algorithms** `0x0904/0x0905/0x0906` (ML-DSA-44/65/87)
  appear in signature_algorithms; the 149 hello still offered the classic
  RSA/ECDSA/Ed25519 set only. This is the fingerprint-visible TLS novelty of
  the 150 line.
- A new **unregistered extension `0xCA34` (51764)** carrying a structured
  multi-record payload (no public documentation found; IANA lists nothing) —
  it pushes the extension count 16 → 17 and changes the JA4 third segment.
- Over HTTP the `sec-ch-ua` brand list is now shuffled per request
  (`"Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"`)
  where 149 sent a fixed order — headers, not TLS.

So "149" in this file and in the mobile profile is the capture-day version
(the phone's auto-update lagged); the current stable is 152 and its JA4 is
the one to diff future `chrome_exact` stand runs against until the pinned
stand Chromium is bumped. `examples/vk-ru/profile.json` now carries the
Chrome 152 header capture (headed-browser UA form: the raw capture said
`HeadlessChrome/152.0.0.0`; headed Chrome sends `Chrome/152.0.0.0`).

Both share the cipher hash `8daaf6152771`; they differ in the extension-set
hash: the stand's pinned Chromium and the phone's Android Chrome 149 ship
different extension sets (and the phone's extension hash equals the uTLS
`chrome_auto` value `d8a2da3f94cd`) — for this mobile target uTLS
`chrome_auto` already JA4-matches the real device, while `chrome_exact`
matches the desktop stand byte-for-byte. Note that none of the 149 hellos
offer the post-quantum signature algorithms — that starts with the 150 line
(see the Chrome 152 section above).

Over QUIC the same phone offers `q13d0311h3_55b375c5d22e_653d80c3fe9d`
(QUIC hellos are TLS 1.3-only: 3 cipher suites, ALPN h3 — a different
fingerprint class from TCP).

```sh
python3 tools/ja4_from_pcap.py \
  ./captures/phone-vk.pcap
```

## Headed vs headless vs OS browser (2026-08-31, this workstation)

Captured live on Xvfb (real windowed Chrome, tcpdump on the wire, our
ja4_from_pcap tool):

| Browser | JA4 | Notes |
|---|---|---|
| Chrome 152, **headed** on Xvfb, vk.ru | `t13d1517h2_8daaf6152771_cb7bf5808d99` | **identical** to the headless measurement; UA sends `Chrome/152.0.0.0` (headless sends `HeadlessChrome/…`) |
| Chrome 152, headless (2026-08-30, peet.ws) | `t13d1517h2_8daaf6152771_cb7bf5808d99` | same |
| BrowserOS (Chromium **148**, the OS default browser) | `t13d1813h1_85036bcba153_d339722ba4af` (dominant, ×1546) | **nothing like real Chrome**: no h2 ALPN (h1 only), 18 ciphers (different set), 13 extensions, no ECH/ALPS/post-quantum; also downgraded to a TLS-1.2 hello (`t13d1812h1`) once. Trivially distinguishable from Chrome by any JA4 gate |
| (host background traffic during the capture) | `t13d1516h2_8daaf6152771_d8a2da3f94cd` ×10 | our own Go clients on the machine — their `chrome_exact`/`chrome_auto` hellos match the 149-class references |

## Windows 11 23H2 (LAN reference machine)

Captured passively on the wire while driving requests over SSH:

| Client from Windows | JA4 | L3/L4 (SYN) |
|---|---|---|
| Chrome 151 headless → local TLS | `t13i1515h2_8daaf6152771_806a8c22fdea` (+ per-connection 16-ext variant `…a87ad97598a9`) | **ttl 128**, win 64240, `mss 1460,nop,wscale 8,nop,nop,sackOK` (no TS) |
| curl 8.13 (Schannel) → local TLS | `t13i2511h1_f5a23f7cfd7b_36bf25f296df` (25 ciphers, 11 exts, h1) | same as above |
| Linux/Go client (reference) | — | **ttl 64**, win 64240, `mss 1460,sackOK,TS,nop,wscale 7` |

Windows Chrome 151 keeps the `806a8c22fdea` extension hash of the stand's
Chromium class — the post-quantum + `0xCA34` shift arrives with the 152
line. The L3/L4 layer separates OS families cleanly: **TTL 128 (Windows)
vs 64 (Linux/Android)** plus the TCP-options layout (no timestamps on this
Windows box, wscale 8 vs 7). TTL is set by the kernel — site-mimic now
forged it: `mimic.WithTTL(128)` or a profile `"ip_ttl": 128` stamps every
connection (verified on the wire: the client's SYN carries ttl 128 with the
option and ttl 64 without it; `examples/vk-ru -ttl 128` reproduces). TCP
option-layout quirks (timestamps off, wscale 8) remain kernel-owned and are
not forged.

**Headed Windows Chrome 151, full navigation (2026-09-01).** Driven through
the interactive session (scheduled task `/it`) to the trusted public
receiver `https://fp.example.test/` (Chrome mapped it to our nginx via
`--host-resolver-rules`; the receiver logged the application view, tcpdump
caught the ClientHello):

- JA4: `t13d1516h2_8daaf6152771_806a8c22fdea` (per-connection 17-ext variant
  `t13d1517h2_8daaf6152771_a87ad97598a9`), TTL 128 on the wire — same class
  as the stand Chromium, confirming platform-independence of the hello.
- Headers (application view): UA `Mozilla/5.0 (Windows NT 10.0; Win64; x64)
  … Chrome/151.0.0.0 Safari/537.36`, `sec-ch-ua: "Not=A?Brand";v="99",
  "Google Chrome";v="151", "Chromium";v="151"`, `sec-ch-ua-platform:
  "Windows"`, full `Accept-Encoding: gzip, deflate, br, zstd`, and a
  `Priority: u=0, i` header. Note: over plain http (insecure context) the
  same browser sends NO client hints and only `gzip, deflate` — captures
  must go over HTTPS to reflect real-site behaviour.
- Packaged as `examples/vk-ru-windows/` (profile carries `ip_ttl: 128`);
  canary vk.ru 200 OK.

Conclusion: headless mode does not change Chrome's transport fingerprint —
captures made headless are valid for TLS/JA4 and (on this build) for the
navigation header set; only the UA token differs. A Chromium-based OS
browser (BrowserOS 148) is NOT a Chrome substitute for fingerprint work.

Caveats, stated plainly: the phone pcap contains PCAPdroid tag segments that
corrupt naive TCP reassembly (the tool filters them and cross-checks with
per-segment and per-start extraction); TLS ClientHellos over QUIC need
Initial decryption (tools/quic_initial.py, `cryptography` required).
