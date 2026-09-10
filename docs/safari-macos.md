# Safari on macOS — wire reference (Safari 18.6, macOS 15.7.8)

Captured 2026-09-10 from real Macs: a Mac mini 2012 (x86_64, macOS 15.7.8
build 24G824, Safari 18.6) and a MacBook Pro M1 (arm64, macOS 26.6 build
25G5052e, Safari 27.0)
visiting a capture receiver: full ClientHello hex, JA3/JA4, HTTP/2 header
order. A transport spec (uTLS ClientHelloSpec) for this profile is pending —
this page is the measured ground truth to build and verify against.

## JA4 / JA3

| Field | Value |
|---|---|
| JA4 | `t13d2014h2_a09f3c656075_e42f34c56612` |
| JA4_r | `t13d2014h2_1301,1302,1303,c02c,c02b,cca9,c030,c02f,cca8,c00a,c009,c014,c013,009d,009c,0035,002f,c008,c012,000a_0000,0017,ff01,000a,000b,0010,0005,000d,0012,0033,002d,002b,001b,0015_0403,0804,0401,0503,0805,0805,0501,0806,0601,0201` |
| JA3 hash | `dab37c84ba3313a8df8498ba9942ba8a` |
| Record/client version | `0303` (Safari keeps the 1.2 record version; no 0304) |
| supported_versions | GREASE(`fafa`), `0304`, `0303`, `0302`, `0301` |
| ALPN | `h2, http/1.1` (negotiated h2) |
| ClientHello size | 517 bytes (padding `0015` fills to this) |

## Distinguishing quirks (vs Chrome)

- **Duplicated signature algorithm `0805`** in sig_algs
  (`0403,0804,0401,0503,0805,0805,0501,0806,0601,0201`) — a real Safari
  quirk, reproduce it byte-for-byte.
- Safari uses **non-Chrome GREASE values** on this hello: cipher `baba`,
  extension `eaea`, `0a0a`, group `1a1a`, version `fafa`.
- 20 cipher suites (Chrome 15x ships 15-18): Apple adds
  `c00a,c009,c014,c013,009d,009c,0035,002f,c008,c012,000a` legacy tail.
- `key_share` carries a single x25519 entry; groups
  GREASE(`1a1a`), x25519, secp256r1, secp384r1, secp521r1.
- Extensions (14 + GREASE): server_name, extended_master_secret,
  renegotiation_info, supported_groups, ec_point_formats, alpn,
  status_request, signature_algorithms, sct, key_share,
  psk_key_exchange_modes, supported_versions, compress_certificate,
  GREASE(`0a0a`), padding.
- **No encrypted_client_hello (0xfe0d), no 0xca34, no ALPS, no
  application_settings, no post-quantum sig algs** — Safari is far behind
  Chrome here.

## HTTP/2 header order (as received)

    Sec-Fetch-Site: none
    Sec-Fetch-Mode: navigate
    Accept-Language: ru
    Priority: u=0, i
    Accept-Encoding: gzip, deflate, br
    Sec-Fetch-Dest: document
    User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8

Notes: `Accept-Language` is the bare locale (`ru`, no q-values);
`Accept-Encoding` has **no zstd** (Chrome ships `br, zstd`); **no
`sec-ch-ua` client hints at all** (Safari does not send them).

## Raw ClientHello

    <see captures-fp-recent-sample.json → [0].tls.client_hello_hex>

A full sample of the receiver report (TLS + headers + notes) is committed as
`captures-fp-recent-sample.json` for offline diffing.

## L3

macOS stays native: TTL 64, BSD SYN options (see fingerprint-matrix.md).


---

# Safari 27.0 (macOS 26.6, Apple Silicon) — the current reference

| Field | Value |
|---|---|
| JA4 | `t13d2013h2_a09f3c656075_7f0f34a4126d` |
| JA4_r | `t13d2013h2_1302,1303,1301,c02c,c02b,cca9,c030,c02f,cca8,c00a,c009,c014,c013,009d,009c,0035,002f,c008,c012,000a_0000,0017,ff01,000a,000b,0010,0005,000d,0012,0033,002d,002b,001b_0403,0804,0401,0503,0805,0805,0501,0806,0601,0201` |
| Cipher set | same 20 suites as 18.6 (hash `a09f3c656075`); wire order rotates 1301/1302/1303 |
| Extensions | 13 + GREASE: server_name, extended_master_secret, renegotiation_info, supported_groups, ec_point_formats, alpn, status_request, signature_algorithms, sct, key_share, psk_key_exchange_modes, supported_versions, compress_certificate |
| supported_versions | GREASE, `0304`, `0303` — TLS 1.2/1.1 dropped from the extension |
| ClientHello size | 1540 bytes, **no padding extension** |
| sig_algs | still `…,0805,0805,…` duplicated — the quirk survives |

What changed vs 18.6 — each of these is a version tell:

- **Post-quantum key exchange**: `supported_groups` now leads with
  `X25519MLKEM768 (0x11ec)` between GREASE and x25519
  (18.6 had no PQ group). The big key_share is why the hello is 1540
  bytes and why padding is gone.
- **zstd arrived**: `Accept-Encoding: gzip, deflate, br, zstd` (18.6 had no zstd).
- **Header order changed**: `UA, Accept, Sec-Fetch-Site, Sec-Fetch-Mode,
  Accept-Language, Priority, Accept-Encoding, Sec-Fetch-Dest`
  (18.6 led with Sec-Fetch-*).
- supported_versions no longer lists `0302/0301`.
- GREASE values are random per connection (`3a3a`,`dada`,`fafa`,`9a9a`,
  `11ec`-adjacent quirks) — never hardcode them; JA4 ignores them, JA3
  intentionally varies.

UA is still the frozen `Macintosh; Intel Mac OS X 10_15_7` form with
`Version/27.0 Safari/605.1.15` — Apple keeps OS version frozen in UA even
on macOS 26.

## n>1 stability (2026-09-10, stand sampling)

Per-client fresh-connection samples (Safari restarted between samples so
every request rides a new TCP flow):

| client | n | JA4 variants | JA3 variants | TTL | SYN |
|---|---|---|---|---|---|
| real Safari 27.0 (M1) | 3 fresh conns | 1 | 1 (`f725b961…`) | 63 | `mss 1460,wscale 6,TS,sackOK`, win 65535 |
| site-mimic SafariMacOS | 6 | 1 | 1 (`f725b961…` — matches) | 127 (win-preset host) | `mss 1460,wscale 8,sackOK` |
| real Chrome 151 (Win11) | 3 | 1 (`t13d1517h2_…cb7bf5808d99`) | **3** (random GREASE per conn) | 127 (hairpin; native 128) | `mss 1460,wscale 8,sackOK` |

Take-aways:

- **Safari 27 does not randomize GREASE per connection** — JA3 is stable,
  so the parrot must (and now does) reproduce Safari's exact GREASE
  values and the rotated cipher head `1302,1303,1301`; both JA4 and JA3
  then match byte-for-byte.
- **Chrome does randomize GREASE per connection** (3 connections → 3 JA3
  hashes, 1 JA4) — any JA3 gate must GREASE-normalize; JA4 gates are safe.
- TTL/SYN rows are L3-layer facts: Safari profiles still need
  site-mimic's `WithTTL(64)` + a macOS-style SYN preset (wscale 6, TS,
  EOL) to match the L3 leg; the Linux test host above runs the
  win-tcp-preset (TTL 127 on the wire after one hairpin hop).
