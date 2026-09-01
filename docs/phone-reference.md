# ClientHello references: desktop stand vs real phone

FoxIO JA4 values computed with `tools/ja4_from_pcap.py` (spec:
FoxIO-LLC/ja4 `technical_details/JA4.md`; implementation validated by
reproducing the stand's byte-exact browser value below). All captures:
2026-08-30.

## Desktop — capture stand (kulikov0/headless-client, pinned Chromium)

- `browser.pcap` (real Chromium in the stand's network namespace):
  `t13d1516h2_8daaf6152771_806a8c22fdea`
- `probe.pcap` (site-mimic `tls_client_hello: "chrome_auto"`):

  `t13d1516h2_8daaf6152771_d8a2da3f94cd`

  (the stand run with `chrome_exact` matches the browser byte-for-byte —
  verified 2026-08-30, see HANDOFF.md; this pcap is from the `chrome_auto`
  comparison, which differs only in the extension-set hash)

Reproduce:

```sh
python3 tools/ja4_from_pcap.py \
  /home/roomhacker/PycharmProjects/video_watching/.tmpbin/captures/vk-site-mimic/browser.pcap \
  /home/roomhacker/PycharmProjects/video_watching/.tmpbin/captures/vk-site-mimic/probe.pcap
```

## Mobile — Samsung S21 Ultra (SM-G998B), Android Chrome 149, mobile 4G

Source: PCAPdroid pcap-file capture, `phone-vk.pcap` (Chrome navigated to
m.vk.ru). Per-connection extension shuffling is why per-connection JA3 moves;
JA4 sorts, so it is stable except for Chrome's per-connection optional
extensions (one extra extension appears on some connections):

- m.vk.ru, first navigation:
  `t13d1516h2_8daaf6152771_d8a2da3f94cd`
- m.vk.ru, second connection:
  `t13d1517h2_8daaf6152771_b6f405a00624` (one extension more)

Across the capture's Chrome flows the 16-extension value dominates
(39 vs 5), so the mobile reference is:

```text
Android Chrome 149 (mobile): t13d1516h2_8daaf6152771_d8a2da3f94cd
Desktop stand Chromium:      t13d1516h2_8daaf6152771_806a8c22fdea
```

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
- A new **unregistered extension `0xCA24` (51764)** carrying a structured
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
  /home/roomhacker/PycharmProjects/video_watching/.tmpbin/captures/phone-vk.pcap
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

## Windows on the LAN (2026-08-31, Win11 23H2 `BeyondInfinity.lan` 192.168.2.190)

Captured passively on the wire while driving requests over SSH:

| Client from Windows | JA4 | L3/L4 (SYN) |
|---|---|---|
| Chrome 151 headless → local TLS | `t13i1515h2_8daaf6152771_806a8c22fdea` (+ per-connection 16-ext variant `…a87ad97598a9`) | **ttl 128**, win 64240, `mss 1460,nop,wscale 8,nop,nop,sackOK` (no TS) |
| curl 8.13 (Schannel) → local TLS | `t13i2511h1_f5a23f7cfd7b_36bf25f296df` (25 ciphers, 11 exts, h1) | same as above |
| Linux/Go client (reference) | — | **ttl 64**, win 64240, `mss 1460,sackOK,TS,nop,wscale 7` |

Windows Chrome 151 keeps the `806a8c22fdea` extension hash of the stand's
Chromium class — the post-quantum + `0xCA24` shift arrives with the 152
line. The L3/L4 layer separates OS families cleanly: **TTL 128 (Windows)
vs 64 (Linux/Android)** plus the TCP-options layout (no timestamps on this
Windows box, wscale 8 vs 7). TTL is set by the kernel — site-mimic now
forged it: `mimic.WithTTL(128)` or a profile `"ip_ttl": 128` stamps every
connection (verified on the wire: the client's SYN carries ttl 128 with the
option and ttl 64 without it; `examples/vk-ru -ttl 128` reproduces). TCP
option-layout quirks (timestamps off, wscale 8) remain kernel-owned and are
not forged.

Conclusion: headless mode does not change Chrome's transport fingerprint —
captures made headless are valid for TLS/JA4 and (on this build) for the
navigation header set; only the UA token differs. A Chromium-based OS
browser (BrowserOS 148) is NOT a Chrome substitute for fingerprint work.

Caveats, stated plainly: the phone pcap contains PCAPdroid tag segments that
corrupt naive TCP reassembly (the tool filters them and cross-checks with
per-segment and per-start extraction); TLS ClientHellos over QUIC need
Initial decryption (tools/quic_initial.py, `cryptography` required).
