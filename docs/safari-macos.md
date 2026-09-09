# Safari on macOS — wire reference (Safari 18.6, macOS 15.7.8)

Captured 2026-09-10 from a real Mac mini (x86_64, macOS 15.7.8 build 24G824)
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
