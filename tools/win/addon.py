"""mitmproxy addon for the Windows capture (see README.md).

Records every HTTP(S) flow to a single JSONL file: full request and response
headers (in wire order) and body-capped bodies. One JSON object per line, so
the file stays safe to tail or partially read even if mitmdump is killed.

Each record:
  {
    "ts": float,          # seconds since addon start
    "wall_ts": float,     # unix epoch
    "category": str,      # from CAPTURE_CATEGORIES, else "other"
    "method": str,
    "scheme": str, "host": str, "path": str, "query": dict,
    "http_version": str,
    "status_code": int|null,
    "request_headers": [[k,v],...],
    "request_body": str,  # capped at BODY_CAP bytes
    "response_headers": [[k,v],...],
    "response_body": str  # capped at BODY_CAP bytes
  }

Bodies are capped (default 8 KB) so beacon and analytics payloads come
through whole while media segments are truncated. Raise the cap with the
CAPTURE_BODY_CAP env var if you need full media.

Categories are opt-in: set CAPTURE_CATEGORIES to a comma-separated list of
"host-fragment=category" pairs, e.g.
    CAPTURE_CATEGORIES="goya.example.com=beacon,*.cdn.example.net=cdn"
Everything that does not match is "other".
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from mitmproxy import http, ctx

BODY_CAP = int(os.environ.get("CAPTURE_BODY_CAP", "8192"))
OUTPUT = os.environ.get(
    "CAPTURE_FLOWS",
    str(Path.home() / "site-mimic-capture" / "flows.jsonl"))

# host-fragment -> category
_CATEGORIES: list[tuple[str, str]] = []
for _pair in os.environ.get("CAPTURE_CATEGORIES", "").split(","):
    _pair = _pair.strip()
    if not _pair or "=" not in _pair:
        continue
    _frag, _cat = _pair.split("=", 1)
    _CATEGORIES.append((_frag.strip().lower(), _cat.strip()))


def _category(host: str) -> str:
    h = (host or "").lower()
    for frag, cat in _CATEGORIES:
        if frag in h:
            return cat
    return "other"


def _cap(b: bytes | None) -> str:
    if not b:
        return ""
    s = b[:BODY_CAP].decode("utf-8", "replace")
    if len(b) > BODY_CAP:
        s += f"... <{len(b) - BODY_CAP} more bytes>"
    return s


def _headers(h) -> list[list[str]]:
    return [[str(k), str(v)] for k, v in h.items()] if h else []


class Capture:
    def __init__(self) -> None:
        self.counts: dict[str, int] = {}
        self._t0 = time.monotonic()

    def load(self, _loader) -> None:
        Path(OUTPUT).parent.mkdir(parents=True, exist_ok=True)
        open(OUTPUT, "w").close()  # truncate per run
        ctx.log.info(f"[capture] writing flows to {OUTPUT} (body_cap={BODY_CAP})")

    def response(self, flow: http.HTTPFlow) -> None:
        host = flow.request.host or ""
        parsed = urlparse(flow.request.url)
        record = {
            "ts": round(time.monotonic() - self._t0, 3),
            "wall_ts": time.time(),
            "category": _category(host),
            "method": flow.request.method,
            "scheme": flow.request.scheme,
            "host": host,
            "path": parsed.path,
            "query": {k: (v[0] if len(v) == 1 else v)
                      for k, v in parse_qs(parsed.query).items()},
            "http_version": flow.request.http_version,
            "status_code": flow.response.status_code if flow.response else None,
            "request_headers": _headers(flow.request.headers),
            "request_body": _cap(flow.request.raw_content or b""),
            "response_headers": _headers(flow.response.headers) if flow.response else [],
            "response_body": _cap(flow.response.raw_content if flow.response else b""),
        }
        with open(OUTPUT, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        self.counts[record["category"]] = self.counts.get(record["category"], 0) + 1

    def done(self) -> None:
        ctx.log.info("[capture] captured: " +
                     ", ".join(f"{k}={v}" for k, v in sorted(self.counts.items())))


addons = [Capture()]
