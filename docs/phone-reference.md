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

Caveats, stated plainly: the phone pcap contains PCAPdroid tag segments that
corrupt naive TCP reassembly (the tool filters them and cross-checks with
per-segment and per-start extraction); a QUIC Initial with SNI inside
`userapi.com`/google CDNs decrypted fully, and no m.vk.ru QUIC Initial was
captured completely — the m.vk.ru reference above comes from TCP, which is
also the transport site-mimic speaks.
