# site-mimic — JavaScript / TypeScript client

`site-mimic` is the Node client for the `fetchd` daemon (`cmd/fetchd`): it
sends HTTP requests through the daemon, which owns the uTLS ClientHello and
therefore the wire identity a target site sees. No runtime dependencies, ESM,
Node 18 or newer.

It is the JavaScript twin of the Python client in
`python/site_mimic_client/gohttp.py` — same daemon, same contract, one source
of truth for what a request to a protected site looks like.

## Install

```sh
npm install site-mimic
```

From a checkout of this repository:

```sh
npm install ./js
```

or from a packed tarball:

```sh
cd js && npm pack && npm install ./site-mimic-0.1.0.tgz
```

## Quick start

```ts
import { get, post } from "site-mimic";

const response = await get("https://example.com/api", {
  headers: { "Accept-Language": "ru-RU" },
  cookies: { session: "…" },
  profile: "/abs/path/profile.json",
});

console.log(response.statusCode, response.text);
const data = response.json();

const created = await post("https://example.com/api", { json: { name: "value" } });
```

`profile` is the path to a site-mimic `profile.json` — it selects the
transport identity (the uTLS spec) the request is made with. The daemon
refuses a request without one, so pass it explicitly or set `GOHTTP_PROFILE`.

## API

| Export | What it does |
|---|---|
| `request(method, url, options?)` | one request through the daemon |
| `get(url, options?)` | GET via `request` |
| `post(url, options?)` | POST via `request` |
| `SiteMimicResponse` | the response class (implements `Response`) |
| `SiteMimicError` | raised for every failure of the client |
| `ensureDaemon()` | make sure the daemon runs, starting it when it does not |
| `healthz()` | whether the daemon answers `/healthz` right now |
| `setDaemonSpawner(fn)` / `resetDaemonSpawner()` | replace how the daemon is started |
| `daemonUrl()`, `daemonBinary()`, `siteMimicDir()`, `autoStartEnabled()` | configuration helpers |

`RequestOptions`:

| Field | Meaning |
|---|---|
| `headers` | request headers, sent verbatim to the target |
| `cookies` | cookies, sent as a single `Cookie` header |
| `json` | JSON body — encoded by the client, sent with a JSON content type |
| `data` | raw body: a string goes as is, bytes travel base64-encoded |
| `profile` | path to the mimic profile; falls back to `GOHTTP_PROFILE` |
| `proxy` | per-request CONNECT proxy |
| `resolve` | DNS pinning, `host` → `ip`, with the original SNI kept |
| `timeout` | request timeout in seconds (default 30) |

`Response`:

| Field | Meaning |
|---|---|
| `statusCode` | HTTP status of the target response |
| `headers` | response headers; a header with several values keeps all of them |
| `text` | body decoded as UTF-8 |
| `content` | body as raw bytes |
| `ok` | whether the status is 2xx |
| `url` | the URL that was requested |
| `cookies` | cookies the target set, by name |
| `json()` | parse the body as JSON |
| `raiseForStatus()` | throw on a 4xx/5xx status |
| `setCookieEntries()` | full `Set-Cookie` entries (name/value/domain/path/expires) |

## Errors

Every failure raises `SiteMimicError`:

- the daemon answered with a filled `error` field — the error text is the
  message of the exception, verbatim;
- the daemon answered with a non-2xx status (a missing profile, a wrong
  token) — the message carries the status and the daemon's `error` text;
- the daemon could not be reached — the message says so, and `error.cause`
  holds the underlying failure.

`error.status` is the status the daemon answered with, and `0` when the
daemon never answered at all.

## Config (env)

The environment is read on every call, not once at import time, so a host
application may change it at any point.

| Variable | Default | Meaning |
|---|---|---|
| `GOHTTPD_URL` | `http://127.0.0.1:30777` | base URL of the daemon |
| `GOHTTPD_TOKEN` | — | bearer token, when the daemon runs with `FETCHD_TOKEN` |
| `GOHTTPD_BIN` | — | path to the `fetchd` binary; when set it is the only candidate |
| `SITE_MIMIC_DIR` | — | site-mimic checkout used to find or build `fetchd` |
| `GOHTTPD_LOG` | `<tmpdir>/fetchd.log` | where a spawned daemon writes its output |
| `GOHTTP_PROFILE` | — | default mimic profile for requests without an explicit one |
| `GOHTTPD_AUTOSTART` | `1` | set to `0` to forbid the client from starting the daemon |

## Self-supervision

The daemon is the transport: without it there is no request. The client
therefore probes `/healthz` before a call and, when the daemon is dead,
starts it and replays the request once.

The daemon is started as a detached `fetchd` process. It is found in this
order:

1. `GOHTTPD_BIN` — used as is, never second-guessed;
2. `fetchd` in the `SITE_MIMIC_DIR` checkout;
3. `fetchd` built from a site-mimic checkout (looked up through
   `SITE_MIMIC_DIR`, the checkout this package runs from, or `~/site-mimic`).

A deployment that supervises the daemon itself can turn the whole mechanism
off with `GOHTTPD_AUTOSTART=0`, or replace it with `setDaemonSpawner()`:

```ts
import { setDaemonSpawner } from "site-mimic";
import { execFile } from "node:child_process";

setDaemonSpawner(async () => {
  // Anything that ends with a healthy daemon on GOHTTPD_URL works here.
  await new Promise((resolve) => execFile("systemctl", ["restart", "fetchd"], resolve));
  return true;
});
```

## Notes

- ESM only. From CommonJS, reach the package with `await import("site-mimic")`.
- The package ships no runtime dependencies: the global `fetch` of Node 18+
  and `node:child_process` are all it needs.
- `setCookieEntries()` reports the attributes the daemon sends. `secure`,
  `httpOnly` and `sameSite` are present only when the daemon reports them —
  it currently reports name, value, domain, path and expires.

## Tests

```sh
npm install
npm run build
npm test
```

The suite stubs the global `fetch`, so it needs neither a Go toolchain nor a
network: the daemon contract is asserted on the exact payload and headers the
client puts on the wire.

## Release convention

Versions live in `js/package.json`. Bump `version`, tag the commit as
`js-vX.Y.Z` and publish from `js/`.

MIT licensed — see [LICENSE](LICENSE).
