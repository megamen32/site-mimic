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

Both share the cipher hash `8daaf6152771`; they differ in the extension-set
hash: the phone's modern Chrome 149 carries a different extension/signature
set (including post-quantum signature algorithms) from the stand's older
pinned Chromium. Notably the phone's extension hash equals the uTLS
`chrome_auto` value (`d8a2da3f94cd`) — for this mobile target uTLS
`chrome_auto` already JA4-matches the real device, while `chrome_exact`
matches the desktop stand byte-for-byte.

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
