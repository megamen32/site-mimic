# fpd — live full-fingerprint display on test.auto-gram.ru

- **Wanted**: user opens the site and sees/copies the visitor's FULL fingerprint (UA, headers, JA3/JA4, raw ClientHello, TTL, SYN options).
- **Canary**: open `https://test.auto-gram.ru/fp` from a real client → report shows correct JA4 + real TTL.
- **Slice**: new `cmd/fpd` (PPv2 accept → raw ClientHello peek → JA3/JA4 → crypto/tls h2 → /fp display, else reverse-proxy to receiver:8477; AF_PACKET sniffer for TTL/SYN) + haproxy SNI ACL `test.auto-gram.ru → be_fpd (send-proxy-v2)` + systemd unit. nginx 8444 / receiver 8477 untouched.

**Not built (YAGNI)**: h2 frame-level (SETTINGS/Akamai) live display (post-hoc via keylog+tshark), header-order preservation, QUIC/h3, ASN/geo, auth.

**Notable during work**: JA4 ALPN edge-token bug fixed in both Go port and `tools/ja3_ja4.py` (first/last char of full hex, FoxIO examples); `tools/ja4_from_pcap.py` trace dump now carries per-flow first-packet timestamps.

Status: **DONE 2026-09-02** — deployed (systemd `fpd`, haproxy ACL, backup `haproxy.cfg.bak-fpd`); verified: python h1 (TTL 63 hairpin, SYN options), fpd selftest (PPv2), chrome_exact h2 probe (saw own `t13d1516h2_8daaf6152771_806a8c22fdea`), HTML page live. Browser screenshot locally blocked: local headless Chrome cannot finish ANY page load right now (example.com included) — pre-existing env breakage after mass chrome process kill, unrelated to the site; user does the visual check.
