#!/usr/bin/env python3
"""Capture the HTTP request headers a mobile browser sends, via CDP.

Why this exists
---------------
On a rooted phone the MITM CA can be injected into the platform trust store
(conscrypt APEX), and Android apps then accept the proxy certificate. Modern
Chromium builds (Chrome Root Store) ignore the platform store for *browser*
traffic, so the browser refuses the proxy and the request never leaves the
phone — no headers to capture.

The DevTools protocol solves this without any certificate trick: Chrome itself
reports the request headers it is about to send. `Security.setIgnoreCertificateErrors`
additionally lets the page load through the intercepting proxy, so the request
actually reaches the wire.

The capture is therefore a browser-side view of the same traffic, and it needs
no CA trust at all.

Usage:
    python3 cdp_headers.py [--cdp 127.0.0.1:9333] [--url https://web.max.ru/]
                            [--out capture.jsonl] [--seconds 25]
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request

import websocket


def http_json(base: str, path: str):
    with urllib.request.urlopen(base + path, timeout=10) as fh:
        return json.load(fh)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cdp", default="127.0.0.1:9333")
    ap.add_argument("--url", default="https://web.max.ru/")
    ap.add_argument("--out", default="-")
    ap.add_argument("--seconds", type=int, default=25)
    args = ap.parse_args()

    base = "http://" + args.cdp
    targets = http_json(base, "/json/list")
    page = next(
        (t for t in targets if t.get("type") == "page" and "web.max.ru" in t.get("url", "")),
        None,
    ) or next((t for t in targets if t.get("type") == "page"), None)
    if not page:
        print("no page target", file=sys.stderr)
        return 1

    ws_url = page["webSocketDebuggerUrl"]
    # Chrome's DevTools endpoint rejects websocket handshakes that carry an
    # Origin header it did not expect. Send none.
    ws = websocket.create_connection(ws_url, timeout=20, origin=None, suppress_origin=True)
    msg_id = 0
    out = []

    def send(method: str, params=None, sid=None):
        nonlocal msg_id
        msg_id += 1
        frame = {"id": msg_id, "method": method}
        if params is not None:
            frame["params"] = params
        if sid is not None:
            frame["sessionId"] = sid
        ws.send(json.dumps(frame))
        return msg_id

    send("Security.setIgnoreCertificateErrors", {"value": True})
    send("Network.enable", {})
    send("Page.enable", {})
    time.sleep(0.5)
    send("Page.navigate", {"url": args.url})

    deadline = time.time() + args.seconds
    while time.time() < deadline:
        try:
            ws.settimeout(max(1.0, deadline - time.time()))
            raw = ws.recv()
        except Exception:
            break
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except Exception:
            continue
        method = msg.get("method")
        params = msg.get("params") or {}
        if method == "Network.requestWillBeSent":
            req = params.get("request", {})
            rec = {
                "kind": "request",
                "url": req.get("url"),
                "method": req.get("method"),
                "http_version": req.get("httpVersion"),
                "headers": req.get("headers", {}),
                "post_data": (req.get("postData") or "")[:2000],
            }
            out.append(rec)
            print("REQ", rec["method"], rec["url"][:90], file=sys.stderr)
        elif method == "Network.responseReceived":
            resp = params.get("response", {})
            out.append(
                {
                    "kind": "response",
                    "url": resp.get("url"),
                    "status": resp.get("status"),
                    "http_version": resp.get("httpVersion"),
                    "headers": resp.get("headers", {}),
                    "protocol": resp.get("protocol"),
                }
            )
        elif method == "Network.loadingFinished":
            out.append({"kind": "finished", "url": params.get("requestId")})

    ws.close()
    text = "\n".join(json.dumps(r, ensure_ascii=False) for r in out)
    if args.out == "-":
        print(text)
    else:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"wrote {len(out)} records to {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
