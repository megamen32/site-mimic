# Windows capture — real Chrome, real headers

mitmproxy-based capture of a **real Chrome on a Windows host**: the browser
speaks to mitmdump as an HTTP CONNECT proxy, mitmdump decrypts, and every
flow lands in a JSONL file with the request and response headers **in wire
order** plus body-capped bodies.

Use this when you need the HTTP layer of a Windows browser (header order,
beacon parameters, cookies) and the target trusts your CA.

| file | what it does |
| --- | --- |
| `capture.py` | the driver: starts mitmdump, launches a headless Chrome through it, drives the pages, stops both, prints a summary |
| `addon.py` | the mitmproxy addon: one JSON line per flow |
| `trust_ca.ps1` | adds the mitm CA to the **current-user** Root store (no admin) |
| `untrust_ca.ps1` | removes exactly that CA again |

The transport layer (TLS ClientHello / JA3 / JA4) is **not** measured here —
mitmproxy has its own fingerprint, not Chrome's. For that, capture a pcap on
the same host and run it through the repo's own parser:

```sh
python3 tools/ja4_from_pcap.py capture.pcap        # FoxIO JA4 per ClientHello
```

For the Windows *TCP* presentation (SYN options, TTL) see
[`../win-netns.sh`](../win-netns.sh) and
[`../win-tcp-preset.sh`](../win-tcp-preset.sh).

## Setup

```bat
:: 1. deps
C:\Python312\python.exe -m pip install "mitmproxy>=12.0,<13.0" websocket-client

:: 2. generate the mitm CA (any mitmdump run creates it)
C:\Python312\Scripts\mitmdump.exe --listen-port 18080
::   (Ctrl-C after a second; the CA now exists at ~\.mitmproxy\mitmproxy-ca-cert.cer)
```

### Trusting the CA — two paths

**Path A (preferred): install the CA, nothing else changes.**
`trust_ca.ps1` adds the mitm CA to the current-user Root store; Chrome
trusts it. `untrust_ca.ps1` removes it. Nothing outside the current user is
touched.

**Path B (when Windows policy blocks silent Root writes).** Recent Windows
builds block programmatic writes to the Root store as anti-malware protection
(`certutil -user -addstore Root` and the .NET `X509Store.Add` both return
`ERROR_NOT_SUPPORTED`). On such hosts `trust_ca.ps1` fails, so `capture.py`
launches its dedicated, isolated, headless capture Chrome with
`--ignore-certificate-errors` instead — no trust-store change, scoped to
that throwaway profile and that run only. Set `IGNORE_CERT_ERRORS=0` to
require a trusted CA instead.

For a persistent trusted CA on a locked-down host, install
`~\.mitmproxy\mitmproxy-ca-cert.cer` interactively (RDP/AnyDesk) →
*Install Certificate* → *Current User* → *Trusted Root Certification
Authorities*.

## Capture a session

```bat
set TARGET_URL=https://www.example.com/
C:\Python312\python.exe capture.py
```

Environment knobs (see the docstring in `capture.py`): `CHROME`, `MITMDUMP`,
`OUT_DIR`, `TARGET_URL`, `SECOND_URL`, `PROXY_PORT`, `DEBUG_PORT`,
`HOME_SECONDS`, `SECOND_SECONDS`, `LINK_SELECTOR`, `IGNORE_CERT_ERRORS`,
and for the addon `CAPTURE_FLOWS`, `CAPTURE_BODY_CAP`,
`CAPTURE_CATEGORIES`.

Output: `%USERPROFILE%\site-mimic-capture\flows.jsonl` — one JSON object per
flow, safe to tail while the capture is running.

## Clean up

```bat
powershell -ExecutionPolicy Bypass -File untrust_ca.ps1
```

Leave the machine as you found it: the CA is a root of trust for every
HTTPS request the current user makes, and it is not something to leave
behind on someone else's workstation.
