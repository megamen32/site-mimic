# minimax-agent-gateway

Calls the MiniMax **managed** gateway the way MiniMax Code (Electron 42 /
Node 24) does: same endpoint, same credential, same header block, same wire
identity (BoringSSL ClientHello, ALPN `http/1.1`, HTTP/1.1).

This is not the public Anthropic-compatible endpoint
(`https://api.minimax.io/anthropic`) — that is a different product with
platform-key billing. Measured difference, credentials, header block and
verification method: **[docs/minimax-agent-gateway.ru.md](../../docs/minimax-agent-gateway.ru.md)**.

## Run

```sh
go run .                                   # one request, managed token from local login state
go run . -prompt "ping" -model MiniMax-M3.1-Flash
MINIMAX_MANAGED_TOKEN=mmoat_… go run .      # explicit token
go run . -stream=false                      # non-streaming answer instead of SSE
```

The token is never printed and never stored in the profile: `Authorization` is
set per request from `MINIMAX_MANAGED_TOKEN`, falling back to
`~/.minimax/auth/prod/en/mcode-public/auth.json`.

## Verify the transport

```sh
go run . -fingerprint https://test.auto-gram.ru/fp   # JA3/JA4 + ALPN + HTTP version
go run . -dump ch.json && python3 ../../tools/parse_clienthello.py ch.json
```

Expected against the real client: JA3
`771-4865,4866,4867,49199,49195,49200,49196,49191,52393,52392,49161,49171,49162,49172,156,157,47,53-0,23,65281,10,11,35,16,13,51,45,43,21-29,23,24-0`,
JA4 `t13d1812h1_5d04281c6031_ef7df7f74e48`, ALPN `http/1.1`, HTTP/1.1.

## Profile

`profile.json` carries the static identity only:

- `tls_client_hello: "node_24"` — the Node 24 / BoringSSL ClientHello
  (`mimic/spec_node.go`).
- `http1_wire_order: true` + `wire_header_order` — the request block is
  written by hand, in the captured order and casing, because Go's
  `net/http` canonicalizes and re-sorts header names
  (`mimic/http1.go`).
- `headers` — the captured static values. `x-mavis-session-id` and
  `Authorization` are per-request.
