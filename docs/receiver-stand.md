# Receiver stand: `test.auto-gram.ru` — byte-level capture target

Public verification target for site-mimic: point any client (our probes, a
real phone, curl) at it and read back what the server actually received —
at the application layer from the receiver log, and at the transport layer
(L3/L4 + raw ClientHello) from tcpdump captures taken on this host.

Status: **LIVE** (2026-08-30). HTTPS works end-to-end through Cloudflare.
The DNS record `test.auto-gram.ru A 95.165.165.65` was created **DNS-only**
(no CF proxy) via BrowserOS dashboard automation, but direct-to-origin
byte-truth is still gated: inbound :443 from the internet is not forwarded
to this host yet — see "Remaining steps".

## Architecture

```
client ──► Cloudflare edge (orange, TLS #1) ──► router :443 DNAT
        ──► haproxy 192.168.2.100:443 (TCP, SNI router, PASSTHROUGH)
        ──► nginx 127.0.0.1:8444 ssl (TLS #2, LE cert test.auto-gram.ru)
        ──► receiver (Go, systemd --user site-receiver.service, 127.0.0.1:8477)
```

- `mimic/cmd/receiver` — the Go receiver: JSONL log (remote IP, XFF chain,
  method, path, proto, header names/values) + echo JSON response.
- nginx vhost: `nginx-dev/state/files/sites-available/test.auto-gram.ru`
  (LE cert `/etc/letsencrypt/live/test.auto-gram.ru/`, ACME webroot
  `/var/www/letsencrypt`).
- Deployed through the nginx-dev git flow (`nginxctl refresh/enable/apply`;
  NOTE: `state/manifest.json` is root-owned after `adopt` — run nginxctl
  with `sudo -n`; local push remote is currently broken
  (`megamen32/agent-bootstrap.git` 404) — changes are applied locally, git
  history is local-only until the remote is fixed.

## What is already measured (receiver-side, 2026-08-30)

- **ClientHello capture works end-to-end**: our `chrome_exact` client hit
  the target and the haproxy→nginx passthrough delivered its original
  ClientHello — captured on `lo:8444` and parsed independently:
  `sni=test.auto-gram.ru ja3=6ce3dda888fd1f4f ja4=5108ac8881770d5b
  ciphers=16 exts=18 alpn=[h2, http/1.1]`. The ja4 hash matches the
  client-side self-dump of the same profile (pipeline consistency).
- External reachability: check-host.net nodes (DE/IR/RU) all got HTTP 200
  from `https://test.auto-gram.ru/capture` direct to `95.165.165.65` after
  the DNS-only flip. The router DNAT `wan:443 → 192.168.2.100:443` was
  verified live on OpenWRT (`root@192.168.2.1`, uci firewall) — no router
  changes were needed.
- TLS/h2 through Cloudflare: peet.ws view of our `chrome_exact` client shows
  the Go `x/net/http2` SETTINGS fingerprint
  (`1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`) — the documented h2
  gap, now receiver-verified.
- L3/L4 SYN fingerprints (from `.tmpbin/tcp_fp.py` over pcaps):
  Go-on-Linux and Chromium-on-Linux emit byte-identical SYNs
  (`ttl=64 win=64240 MSS=1460 SACKok TS NOP WS=7`); the Android phone stack
  differs (`win=65535 WS=10`), and through a VPN/tun capture its MSS is
  distorted (`9960` tun artifact) — receiver-side capture is the only truth.
- Known quirk: nginx 8444 (nginx 1.18) serves HTTP/1.1 only on that
  listener: the `chrome_exact` transport (h2-first) completes the TLS
  handshake but fails after with `PROTOCOL_ERROR`. h1 clients (curl) and
  the uTLS path work. Fix (infra todo): dedicated
  `listen 127.0.0.1:8445 ssl http2` vhost + haproxy SNI ACL for
  `test.auto-gram.ru`.
- Phone note: an Android device on cellular reaching the target does NOT
  need adb at all — Chrome on the phone hits the public URL directly. The
  adb/USB issues seen earlier only affected driving the phone and the
  `:3126` phone-proxy leg.

## Remaining steps to full byte-truth

1. ~~Direct-to-origin path~~ **DONE**: `test.auto-gram.ru A 95.165.165.65`
   created DNS-only via BrowserOS dashboard automation (the zone's NS is
   Cloudflare; reg.ru is only the registrar — its API cannot edit this
   zone). The `*.auto-gram.ru` wildcard stays proxied for the other
   subdomains.
2. **Inbound reachability without CF.** A 4G client hitting
   `95.165.165.65:443` currently times out — the router does not forward
   :443 to this host for arbitrary internet sources (only CF's path works).
   Either add a router port-forward for :443 (and confirm with the phone),
   or, as a LAN fallback: enable Wi-Fi on the phone temporarily
   (`svc wifi enable`, restore `svc wifi disable` after) — the phone's
   TCP/IP stack (TTL/TCP options) is identical on Wi-Fi, only the radio path
   differs. Then point Chrome at `https://192.168.2.100/capture` (the
   handshake completes on the default cert; the SYN/TCP layer is what we
   capture).
3. **Capture (sudo, while the client runs):**
   ```sh
   sudo tcpdump -i enp28s0f2np2 'tcp dst port 443 and tcp[tcpflags] & tcp-syn != 0' -w wan.pcap
   sudo tcpdump -i lo 'tcp port 8444' -w lo.pcap
   ```
   Parse: `.tmpbin/tcp_fp.py wan.pcap` (TTL/TCP options of the client),
   `tools/parse_clienthello.py` on the extracted ClientHello from lo.pcap
   (JA3/JA4 byte-truth).
4. **h2 frames (optional).** TLS keys are not logged yet; add
   `ssl_key_log` (nginx ≥1.27) or terminate TLS in the receiver with
   `KeyLogWriter` + tshark to decrypt the client's real SETTINGS/HEADERS
   frames.

## Quick reproduction

```sh
# receiver health
curl -s https://test.auto-gram.ru/capture
# client through the phone (mobile IP), SNI pinned to the origin
PROXY=http://127.0.0.1:3126 SNI=test.auto-gram.ru \
  go run ./examples/stand-probe https://95.165.165.65/capture 1
# transport-layer capture while clients run (see step 3)
```
