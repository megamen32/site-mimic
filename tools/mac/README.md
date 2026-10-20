# Capture from a Mac's Chrome

The macOS leg of the capture toolkit: a real Chrome on your Mac, its own
TLS ClientHello and request headers, written to one JSONL file.

No phone, no root, no lease, no iptables, no CA in the system trust store.
The chain is the same one the phone uses — mitmproxy reads the ClientHello
before the certificate is presented, and the DevTools protocol reports the
headers the browser is about to send — but on macOS the proxy is *explicit*
and belongs to one Chrome launch instead of the whole device.

Proven end to end on macOS 26.7.2 with Chrome 155.0.8059.85 (2026-10-20).

| file | what it does |
| --- | --- |
| `capture.sh` | one command: mitmproxy + a dedicated Chrome instance + the CDP header capture, one JSONL out |
| `measure.sh` | JA3/JA4 for a capture, through the repository's own `cmd/hellofp` |
| `../phone/mitm_capture_addon.py` | the addon that writes the `hello` and `http` records (reused as is) |
| `../phone/cdp_headers.py` | the DevTools-protocol header capture (reused as is) |
| `../cmd/hellofp` | the parser that prints JA3/JA4 for a capture |

## The chain

```
Chrome (own --user-data-dir) ──CONNECT──▶ mitmproxy 127.0.0.1:18080
        │                                      │
        │ CDP (--remote-debugging-port)        │ mitm_capture_addon.py
        ▼                                      ▼
   cdp_headers.py ───────────────────▶ capture.jsonl (hellos + headers)
```

Two legs, because neither one alone is enough:

* **the proxy leg** reads the ClientHello off the wire (`kind: "hello"`) and
  the full request as it went out (`kind: "http"`) — including `Accept`,
  `Accept-Encoding`, `Accept-Language` and the `sec-fetch-*` quartet;
* **the CDP leg** reports what Chrome itself is about to send
  (`kind: "request"`).

CDP reports the **browser-added** headers only: `Host`, `Accept`,
`Accept-Encoding`, `Accept-Language`, `Connection` and the `sec-fetch-*`
quartet are added by the network stack and are **not** in
`requestWillBeSent`. The proxy leg has them, so both legs go into the same
file and are read together. Every record carries `source`: `"mitm"` or
`"cdp"`.

## Run it

```sh
tools/mac/capture.sh https://example.com/
```

The output lands in `./mac-capture/capture.jsonl` (override with `--out`).
The first run creates the mitmproxy virtualenv — see below.

```sh
tools/mac/capture.sh https://example.com/ \
    --out /tmp/cap.jsonl --seconds 25
```

| flag | meaning |
| --- | --- |
| `<url>` | the page to load |
| `--out FILE` | where the JSONL goes (default `./mac-capture/capture.jsonl`) |
| `--seconds N` | how long the CDP leg watches (default 25) |
| `--headless` | headless Chrome — it changes the UA, so the default is a real window |

## Measure it

```sh
tools/mac/measure.sh mac-capture/capture.jsonl
# or, without the wrapper:
go run ./cmd/hellofp mac-capture/capture.jsonl
```

`hellofp` parses the captured bytes with the library's own
`mimic.ParseClientHello`, so the numbers are the ones a server would compute
— not a third-party implementation's.

A Chrome 155 on macOS, measured 2026-10-20:

```
SNI      example.com
ALPN     h2,http/1.1
version  771
ciphers  16 [6682 4865 4866 4867 49195 49199 49196 49200 52393 52392 49171 49172 156 157 47 53]
exts     [43690 0 35 10 51764 45 51 11 5 16 13 18 43 27 65037 17613 65281 23 6682]
JA3_MD5  bf1442c578c36293c2e84fc63a564c9a
JA4      t13d1517h2_8daaf6152771_cb7bf5808d99
```

That JA4 is the desktop Chrome value the repository already carries
(`docs/phone-reference.md`, the `chrome_exact` line) — the Mac capture
reproduces it byte for byte. The JA3 moves per connection (GREASE and the
extension order shuffle), the JA4 does not; that is the browser, not the
tool.

## What the venv is for

mitmproxy runs in a virtualenv under your home:

```
~/.local/share/site-mimic/venv          # SITE_MIMIC_VENV overrides it
```

It is created on first use (`python3 -m venv` + `pip install mitmproxy
websocket-client`) and needs PyPI once. **No sudo, no system-wide install,
nothing added to the repository's `go.mod`** — the capture chain is Python
and shell. `websocket-client` is what the CDP leg imports; `mitmproxy` is
what the proxy leg runs.

## What is NOT touched

This is the part that matters on a work machine, so it is worth spelling
out. The script cannot reach your Chrome, your keychain or your network
settings:

* **Your Chrome profile.** The capture runs a *separate* Chrome instance
  with `--user-data-dir` pointing at a fresh temp directory. Your running
  Chrome is a different PID and is never signalled: the script kills by the
  PID it recorded, never by a pattern (a pattern would also match your own
  browser and the script's own command line).
* **Your keychain.** The capture's Chrome runs with `--use-mock-keychain`
  and `--password-store=basic`: it stores nothing in the login keychain and
  never asks for it. The script itself runs no `security` command.
* **Your system proxy.** The proxy is a flag on one Chrome launch
  (`--proxy-server=http://127.0.0.1:<port>`). `scutil --proxy` and
  `networksetup -getwebproxy` are unchanged after a run.
* **Your CA stores.** The mitmproxy CA is **not** installed anywhere — not in
  the system keychain, not in a Chrome profile. Chrome is told to ignore
  certificate errors for this one instance
  (`--ignore-certificate-errors`, plus `Security.setIgnoreCertificateErrors`
  over CDP), so an untrusted CA is enough. And it does not matter: the
  ClientHello is read before the certificate is presented.

Verified on this Mac: during a capture the set of files that changed under
`~/Library/Application Support/Google/Chrome` was a strict subset of the set
that changed in an idle window with no capture running (the running browser
writes its own cookies and favicons either way) — nothing the capture
added, and the capture's Chrome held **zero** open files under that
directory.

## Cleanup

The script cleans up after itself, on success and on failure (`trap` on
`EXIT`/`INT`/`TERM`):

* the Chrome instance it started is killed **by PID**, together with its
  helper processes (they are its children);
* the mitmproxy it started is killed **by PID**;
* the temp directory it created — profile, logs, raw capture — is removed
  **by explicit path**, and only if it matches the name this script gave it.

The output file survives (it is copied out of the temp directory before the
cleanup), and the venv survives — it is a tool, not a capture artifact.

Nothing is left running: after a run `pgrep -fl mitmdump` is empty and no
Chrome holds the temp profile.

## When the capture is empty

* **No `hello` records at all.** The proxy never saw a ClientHello: the
  browser did not reach the proxy, or it spoke QUIC instead of TCP. The
  script passes `--disable-quic` for exactly this reason (the phone path
  needs the iptables `REJECT` rule for the same trap) — but a site that
  only answers over HTTP/3 has no TCP hello to take.
* **Hellos but no `http` records.** The handshake was captured, the request
  was not: Chrome refused the proxy certificate and stopped there. The
  hello is still valid — it is read before the certificate — but the headers
  are missing.
* **No `request` records (CDP leg).** The DevTools port did not open, or
  `websocket-client` is missing from the venv. The proxy leg still holds
  the hello; the run says so (`WARN: the CDP leg failed`).
* **The wrong headers.** Remember the split: `Host`, `Accept`,
  `Accept-Encoding`, `Accept-Language`, `Connection` and `sec-fetch-*` are
  in the `http` records (the proxy leg), not in the `request` records (the
  CDP leg).
* **The port.** `MITM_PORT` (18080) and `CDP_PORT` (19222) are shifted to a
  free port if something already listens there; the port actually used is
  printed at the start of the run.

## Honest limits of the Mac path

The Mac path is a **desktop** capture. It is the right tool for profiling a
desktop site, and it is the wrong tool for a mobile app:

* it measures **desktop Chrome**, not an app's TLS stack — an Android app
  (MAX, for instance) has a different hello, and a Mac cannot produce it;
* it cannot reach a phone-only endpoint behind a mobile network;
* the phone path can capture an app with a patched APK and a mounted CA;
  the Mac path captures the browser only;
* Chrome's own hello is what the `chrome_exact` / `chrome_auto` profiles
  already reproduce, so the Mac path is most useful for the *headers* and
  for confirming a profile on the machine you actually work on.

The reference chain for a real device stays `../phone/README.md`.
