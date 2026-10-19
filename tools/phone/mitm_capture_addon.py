"""mitmproxy addon: capture a native app's ClientHello + HTTP headers to JSONL.

Used for site-mimic profiling of a real mobile client (e.g. MAX / ru.oneme.app)
tunnelled through the rooted phone's SOCKS5 leg into mitmdump --mode socks5.

Emits two record kinds, distinguished by "kind":

  {"kind":"hello", ...}  one per TLS ClientHello the client sent
  {"kind":"http",  ...}  one per HTTP request/response pair

The ClientHello record keeps the RAW handshake bytes (base64) so the profile
builder can re-parse them with site-mimic's own JA3/JA4 code instead of
trusting a third-party implementation. The raw bytes are the handshake body
(without the 0x01 handshake header) — mimic.ParseClientHello takes a full TLS
record, so wrap them:

    record = 16 03 01 | len(4 + body) | 01 | len(body) | body

Usage:

    mitmdump --mode socks5 --listen-host 0.0.0.0 --listen-port 31896 \
             -s mitm_capture_addon.py --set out_jsonl=/tmp/max_capture.jsonl

Flags worth knowing:

    --set out_jsonl=/path/capture.jsonl   where the records go
    --set ssl_insecure=true                skip upstream certificate checks
                                          (needed when the target's own chain
                                          does not validate — ru.oneme.ru's
                                          api2 host does not)
    --set connection_strategy=lazy         only connect upstream when the
                                          client actually talks
"""
from __future__ import annotations

import base64
import json
import os
import time

from mitmproxy import ctx, http

MAX_BODY = 2000
# Hosts of interest; empty == record everything.
HOSTS = tuple(
    h for h in os.environ.get("MITM_CAPTURE_HOSTS", "").split(",") if h
)


def _want(host: str) -> bool:
    if not HOSTS:
        return True
    return any(host == h or host.endswith("." + h) for h in HOSTS)


def _out() -> str:
    return ctx.options.out_jsonl or os.environ.get(
        "MITM_CAPTURE_OUT", "/tmp/mitm_capture.jsonl"
    )


def _write(rec: dict) -> None:
    rec["ts"] = time.time()
    with open(_out(), "a", buffering=1) as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


class Capture:
    def load(self, loader):
        loader.add_option(
            "out_jsonl", str, "", "Path of the JSONL capture output file."
        )

    def tls_clienthello(self, data) -> None:
        ch = data.client_hello
        raw = ch.raw_bytes(wrap_in_record=False)
        _write(
            {
                "kind": "hello",
                "sni": ch.sni,
                "alpn": [p.decode("latin-1") for p in ch.alpn_protocols],
                "cipher_suites": list(ch.cipher_suites),
                "extensions": [[t, len(b)] for t, b in ch.extensions],
                "raw_len": len(raw),
                "raw_b64": base64.b64encode(raw).decode("ascii"),
            }
        )

    def request(self, flow: http.HTTPFlow) -> None:
        if not _want(flow.request.host):
            return
        body = flow.request.raw_content or b""
        _write(
            {
                "kind": "http",
                "event": "request",
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "host": flow.request.host,
                "path": flow.request.path,
                "http_version": flow.request.http_version,
                "headers": [[k, v] for k, v in flow.request.headers.items(multi=True)],
                "body_len": len(body),
                "body_head": body[:MAX_BODY].decode("utf-8", "replace"),
            }
        )

    def response(self, flow: http.HTTPFlow) -> None:
        if not _want(flow.request.host):
            return
        body = flow.response.raw_content or b""
        _write(
            {
                "kind": "http",
                "event": "response",
                "status": flow.response.status_code,
                "url": flow.request.pretty_url,
                "host": flow.request.host,
                "http_version": flow.response.http_version,
                "headers": [[k, v] for k, v in flow.response.headers.items(multi=True)],
                "body_len": len(body),
                "body_head": body[:MAX_BODY].decode("utf-8", "replace"),
            }
        )


addons = [Capture()]
