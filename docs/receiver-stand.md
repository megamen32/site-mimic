# Receiver stand: `test.auto-gram.ru` — byte-level capture target

Public verification target for site-mimic: point any client (our probes, a
real phone, curl) at it and read back what the server actually received —
at the application layer from the receiver log, and at the transport layer
(L3/L4 + raw ClientHello) from tcpdump captures taken on the stand host.

The live stand's own address and topology are private: its IP addresses,
interface names and machine-local paths are not published here. The LAN
recipe at the end of this file is the reproducible, self-hosted version of
the same stand — run it on any host and you get the same measurements.

Status: **LIVE** (2026-08-30). HTTPS works end-to-end through Cloudflare.
The DNS record `test.auto-gram.ru A <stand-ip>` was created **DNS-only**
(no CF proxy) via the DNS dashboard, but direct-to-origin byte-truth is still
gated: inbound :443 from the internet is not forwarded to the stand host
yet — see "Remaining steps".

## Architecture

```
client ──► Cloudflare edge (orange, TLS #1) ──► router :443 DNAT
        ──► haproxy <stand-ip>:443 (TCP, SNI router, PASSTHROUGH)
        ├─ sni test.auto-gram.ru ──► fpd (Go, systemd fpd.service, 127.0.0.1:8478,
        │                               send-proxy-v2, TLS #2 = Go crypto/tls, h2)
        │                               └─ every path except /fp proxied to receiver
        └─ everything else ──► nginx 127.0.0.1:8444 ssl (TLS #2, LE cert)
                                ──► receiver (Go, systemd --user site-receiver.service,
                                    127.0.0.1:8477)
```

- `mimic/cmd/receiver` — the Go receiver: JSONL log (remote IP, XFF chain,
  method, path, proto, header names/values) + echo JSON response.
- `cmd/fpd` — the live full-fingerprint display (2026-09-02): open
  `https://test.auto-gram.ru/fp` (browsers get HTML with a copy button,
  everything else JSON) and read back the visitor's complete fingerprint:
  UA + all headers, JA3/JA4 (`ja4`, `ja4_r`, `ja4_sha256`, full
  `client_hello_hex` + decoded extensions) computed from the raw
  ClientHello fpd peeks before crypto/tls takes over, the real client
  IP:port from the haproxy `send-proxy-v2` header, and IP TTL / SYN TCP
  options from fpd's built-in AF_PACKET sniffer on `<nic>`
  (BPF `tcp dst port 443`, per-flow cache keyed by client ip:port).
  TLS session keys append to `<stand-keylog>` (`FPD_KEYLOG`)
  for post-hoc h2 frame decryption. Redeploy:
  `go build -o /usr/local/bin/fpd ./cmd/fpd && sudo systemctl restart fpd`.
  haproxy routes by an ACL block added to the haproxy config
  (`sni_test_fpd` → `backend be_fpd_test`, backup at
  `haproxy.cfg.bak-fpd`). NOT shown live: header order and h2
  SETTINGS/Akamai fingerprint (Go's h2 server does not expose them — use
  the keylog + tshark). Because TLS now terminates at fpd, the old
  nginx-8444 h1-only quirk no longer applies to this hostname: h2
  clients complete requests (wire-verified with the chrome_exact probe,
  which saw its own `t13d1516h2_8daaf6152771_806a8c22fdea` in the
  report). tcpdump note: ClientHellos for this SNI no longer appear on
  `lo:8444` — capture the WAN leg or read `/fp` / the keylog instead.
- nginx vhost: a git-managed site config named after the stand hostname
  (LE cert `<stand-cert-dir>`, ACME webroot `/var/www/letsencrypt`).
- The vhost is applied through the nginx git flow (refresh → enable →
  apply); the config is applied locally, and its history lands in the config
  repo whenever that repo's remote is reachable.

## What is already measured (receiver-side, 2026-08-30)

- **ClientHello capture works end-to-end**: our `chrome_exact` client hit
  the target and the haproxy→nginx passthrough delivered its original
  ClientHello — captured on `lo:8444` and parsed independently:
  `sni=test.auto-gram.ru ja3=6ce3dda888fd1f4f ja4=5108ac8881770d5b
  ciphers=16 exts=18 alpn=[h2, http/1.1]`. The ja4 hash matches the
  client-side self-dump of the same profile (pipeline consistency).
- External reachability: check-host.net nodes (DE/IR/RU) all got HTTP 200
  from `https://test.auto-gram.ru/capture` direct to `<stand-ip>` after
  the DNS-only flip. The router DNAT `wan:443 → <stand-ip>:443` was
  verified live on the router (OpenWRT, uci firewall) — no router
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
- **Receiver-side truth for the real phone (4G → origin direct, after the
  DNS-only flip):** 116 SYNs from the phone's carrier IP
  (`<phone-carrier-ip>`): `ttl=49 id=0 df=0 win=65535
  [MSS=1300, NOP, WS=6, NOP, NOP, TS, SACKok, EOL]`. Compare with what the
  PcapDroid tun-side capture showed (`ttl=64 df=1 MSS=9960
  [MSS,SACKok,TS,NOP,WS=10]`): the carrier path rewrites id/df/mss and the
  option ORDER differs from desktop Linux — so a desktop-origin client can
  be told apart from a true Android one at L4 even before TLS. Also visible
  in the same window: Cloudflare-edge SYNs (`104.22.x/172.69.x/172.71.x`,
  `ttl=43-45 win=65535 WS=13`) for the still-proxied sibling subdomains —
  the receiver cleanly separates CF-origin traffic from direct clients by
  source TTL/options.
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

1. ~~Direct-to-origin path~~ **DONE**: the stand's A record
   (`test.auto-gram.ru A <stand-ip>`) was created DNS-only via the DNS
   dashboard (the zone's NS is Cloudflare — the registrar's API cannot edit
   the zone; only the registrar writes the NS, the zone is served through
   the DNS provider's dashboard). The `*.auto-gram.ru` wildcard stays
   proxied for the other subdomains.
2. **Inbound reachability without CF.** A 4G client hitting
   `<stand-ip>:443` currently times out — the router does not forward
   :443 to the stand host for arbitrary internet sources (only CF's path
   works). Either add a router port-forward for :443 (and confirm with the
   phone), or, as a LAN fallback: enable Wi-Fi on the phone temporarily
   (`svc wifi enable`, restore `svc wifi disable` after) — the phone's
   TCP/IP stack (TTL/TCP options) is identical on Wi-Fi, only the radio path
   differs. Then point Chrome at `https://192.0.2.100/capture` (the stand's
   LAN address; the handshake completes on the default cert; the SYN/TCP
   layer is what we capture).
3. **Capture (sudo, while the client runs):**
   ```sh
   # IFACE = the stand host's WAN interface (the one facing the internet)
   IFACE=eth0
   sudo tcpdump -i "$IFACE" 'tcp dst port 443 and tcp[tcpflags] & tcp-syn != 0' -w wan.pcap
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
  go run ./examples/stand-probe https://<stand-ip>/capture 1
# transport-layer capture while clients run (see step 3)
```

## LAN stand (no haproxy, high port) — 2026-10-12 recipe

This is the reproducible, self-hosted version of the stand above: no
haproxy, no DNS, no public address. Set `STAND_IP` to the stand host's LAN
address and `IFACE` to the interface you want sniffed — everything else runs
as written.

fpd also serves direct connections now: the PPv2 signature is treated as
optional (without it the client address falls back to the TCP peer), and
the TTL/SYN sniffer BPF is parameterised by `-sport` instead of the
hard-coded 443. That makes a purely local byte-truth stand possible on any
port >30000, no haproxy/DNS needed:

```sh
# 1. self-signed cert for the stand
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -subj "/CN=fp.example.test" \
  -addext "subjectAltName=DNS:fp.example.test,IP:192.0.2.100" \
  -keyout fpd-key.pem -out fpd-cert.pem

# 2. receiver (upstream for pass-through paths) + fpd (root: AF_PACKET)
# IFACE = the interface to sniff on (your WAN NIC), STAND_IP = the stand's address
IFACE=eth0 STAND_IP=192.0.2.100
go build -o bin/receiver ./cmd/receiver && go build -o bin/fpd ./cmd/fpd
bin/receiver -listen 127.0.0.1:31778 -log receiver-access.jsonl &
sudo env FPD_KEYLOG=$PWD/sslkeylog.txt bin/fpd \
  -listen "$STAND_IP:31777" -cert fpd-cert.pem -key fpd-key.pem \
  -iface "$IFACE" -sport 31777 -upstream http://127.0.0.1:31778 &

# 3. wire capture (independent ground truth for SYN/TTL/ClientHello)
sudo tcpdump -i "$IFACE" 'host <client-ip> and tcp port 31777' -U -w stand.pcap
```

Clients: the real browser needs `--ignore-certificate-errors` (self-signed
cert) plus `SSLKEYLOGFILE=<path>` so tshark can decrypt h2 post-hoc; run
`examples/lan-probe` for the mimic side (same as stand-probe, but
`WithInsecureTLS` and one client across iterations so resumption can
engage). Read back per-connection truth from `GET /fp/recent?limit=50`
(each report: JA3/JA4/ja4_r, full header set, TTL/DF/IP-ID/SYN options,
`client_hello_hex`). Wire order + h2 frames:

```sh
tshark -r stand.pcap -o tls.keylog_file:<merged-keylogs> -Y 'http2' \
  -T fields -e tcp.stream -e ip.src -e http2.type \
  -e http2.settings.header_table_size -e http2.settings.initial_window_size \
  -e http2.header.name
```

Captured 2026-10-12 (Mac mini Chrome 153 headed/headless × fresh/resumed vs
`mac-chrome153`): JA4 fresh variant, header set/order, SETTINGS values and
order, conn WINDOW_UPDATE, TTL and SYN options — all byte-identical; the
real browser's resumed PSK shape is the one remaining gap (see
fingerprint-matrix row 9b). Teardown: kill the fpd/receiver PIDs and the
tcpdump, do not leave the stand listening.
