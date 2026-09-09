# Anti-bot boundary: what `stream.wb.ru` shows and what replay can and cannot do

This note accompanies [docs/methodology.md](methodology.md) and the
`examples/stream-wb-ru` example. It documents the boundary a defensive
client hits after the transport layer is matched — and the narrow path
cookies can buy you.

## What `stream.wb.ru` actually does

A fresh `GET https://stream.wb.ru/` against `stream.wb.ru` returns:

```
HTTP/1.1 498
Server: wbaas
Content-Type: text/html; charset=utf-8
```

The body is a JS challenge page (`browser-check.js`, `behavior-tracker`,
`create-token`) that the browser executes locally; on success the site
issues a token cookie (commonly `x_wbaas_token`) that subsequent requests
must present. The 498 is the same response a fresh real Chrome gets on
its very first visit — it is **not** a transport-layer block. The
`examples/stream-wb-ru` example's `verdict` line confirms this:

```
verdict: anti-bot challenge page (same first-load behaviour a fresh real browser gets).
         Transport layer matched; the JS challenge/token flow is app-layer, not transport.
```

site-mimic covers the transport layer (TCP, TLS ClientHello, ALPN,
HTTP/2 settings, header set/order) but not the application challenge.
See the layer cake in [docs/methodology.md](methodology.md) — JS is
explicitly out of scope.

## Harvest runbook: cookies from a real browser

Replay cannot generate a token (the JS challenge has to run), but it
can re-use one. To harvest a working token cookie set:

1. On a real desktop Chrome, visit `https://stream.wb.ru/` once and let
   the JS challenge complete normally. Chrome stores the resulting
   cookies for the site.
2. Export the cookies. Two practical ways:
   - **DevTools**: open DevTools → **Application** → **Cookies** →
     `https://stream.wb.ru`. Read off the name, value, domain, path,
     expiry, and the Secure / HttpOnly flags.
   - **Export extension**: any of the well-known cookie-export browser
     extensions that produce JSON. Reshape the output into the schema
     below if it does not already match.
3. Save the result as a JSON array — one entry per cookie — in this
   shape:

```json
[
  {
    "name": "x_wbaas_token",
    "value": "PASTE_VALUE_FROM_DEVTOOLS",
    "domain": ".stream.wb.ru",
    "path": "/",
    "expires": "2026-09-15T12:34:56Z",
    "secure": true,
    "httpOnly": true
  }
]
```

Schema notes:

- `domain` may have a leading dot (RFC 6265); `mimic/cookiejar.go`
  normalizes it. Bare host (`stream.wb.ru`) is also accepted.
- `expires` is RFC 3339, e.g. `2026-09-15T12:34:56Z`. Use `""` for a
  session cookie. Expired entries are loaded but discarded by the jar.
- `path` defaults to `/` when empty.

## Replay

### From the command line

```bash
go run ./examples/stream-wb-ru -cookies harvested.json
```

This loads the file into `Profile.CookieJar` via
`mimic.LoadCookieJarFile` before `mimic.New` builds the client. Default
behaviour (no flag) is unchanged.

### From your own code

```go
jar, err := mimic.LoadCookieJarFile("harvested.json")
if err != nil { log.Fatal(err) }
profile := mimic.MustLoadProfile("profile.json")
profile.CookieJar = jar
client, err := mimic.New(profile)
```

## Honest limits

Replay does not defeat the `wbaas` challenge. State plainly:

- **Tokens expire.** Most anti-bot tokens have a short TTL. A
  `harvested.json` older than the cookie's `expires` will silently send
  nothing.
- **Tokens may be bound.** Some sites bind a token to the IP, TLS
  fingerprint, or browser-instance signature observed when it was
  issued. A Go client with a different fingerprint may receive a 498
  even when presenting the cookie — this is by design.
- **Replay can still yield 498.** If the cookie is missing, expired, or
  the server invalidated it, you will see the same challenge page as
  without cookies. `verdict: anti-bot challenge page …` in the example
  output is the expected surface; it is not a bug.
- **Transport parity helps validity, not access.** Matching the
  Chrome ClientHello, ALPN, and header set maximizes the chance the
  server accepts the cookie, but the JS challenge layer remains out of
  scope. Running a real browser (or a full automation stack that
  executes JS) is the only way to solve the challenge; `site-mimic`
  does not pretend otherwise.

## What this is good for

- Hitting authenticated/cookie-gated endpoints that the wbaas challenge
  does not guard, once a token is already on disk.
- Reproducing a real browser's cookie state across requests in tests.
- Bridging the gap between "transport matched" and "app challenge
  solved" without claiming the latter — pair this with a real-browser
  harvest step.

## Related files

- `mimic/cookiejar.go` — `LoadCookieJarFile(path string) (http.CookieJar, error)`
- `mimic/cookiejar_test.go` — round-trip and shape tests
- `examples/stream-wb-ru/main.go` — `-cookies` flag, same default flow
- `docs/methodology.md` — layer cake and the JS-is-out-of-scope framing