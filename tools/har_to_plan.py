#!/usr/bin/env python3
"""Convert a DevTools HAR export into a site-mimic resource_plan.

A human records the target site once in their own browser (DevTools ->
Network -> Export HAR...): that is a real browsing session, no automation on
the wire. This tool turns it into the ``resource_plan`` JSON for a mimic
profile: per-step path/method/resource_type/referer and the MEASURED delay
between consecutive requests, expressed as a jittered delay_min_ms/delay_max_ms
pair (default +-20%).

Limitations, on purpose:
- delays are gaps between request STARTS, so parallel fan-out (css + js at
  once) is approximated by a sequential walk with small gaps;
- subresource types come from DevTools' _resourceType; "other"/"ping"/
  "manifest"/"websocket" entries are skipped (the plan vocabulary covers
  document/image/xhr/font/style/script);
- cookies/POST bodies are not modeled; only the request graph is.

Usage:
    tools/har_to_plan.py capture.har [--jitter 0.2] [-o plan.json]
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from urllib.parse import urlsplit


# DevTools _resourceType -> mimic resource_type (None = skip the entry)
TYPE_MAP = {
    "document": "document",
    "stylesheet": "style",
    "script": "script",
    "image": "image",
    "font": "font",
    "xhr": "xhr",
    "fetch": "xhr",
    "other": None,
    "ping": None,
    "manifest": None,
    "websocket": None,
    "eventsource": None,
    "preflight": None,
    "csp-report": None,
}

SKIP_STATUSES = {204, 205, 304}  # validator revalidations: the PageCache replays them itself


def parse_time(value: str) -> datetime:
    # 2026-10-06T12:34:56.789Z (DevTools always emits Z)
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def header(headers: list, name: str) -> str:
    low = name.lower()
    for h in headers:
        if h.get("name", "").lower() == low:
            return h.get("value", "")
    return ""


def to_step(entry: dict, origin: str, index: int, delay_ms: int, jitter: float) -> dict | None:
    req = entry.get("request", {})
    rtype = TYPE_MAP.get(entry.get("_resourceType", ""), None)
    status = entry.get("response", {}).get("status", 0)
    if rtype is None or status in SKIP_STATUSES:
        return None
    url = req.get("url", "")
    split = urlsplit(url)
    if rtype == "document" and index == 0:
        origin = f"{split.scheme}://{split.netloc}"
    path = url[len(origin):] if url.startswith(origin) else url
    step = {"path": path, "resource_type": rtype}
    if req.get("method", "GET") != "GET":
        step["method"] = req["method"]
    ref = header(req.get("headers", []), "Referer")
    if ref and ref.startswith(origin):
        ref_path = ref[len(origin):] or "/"
        if ref_path != path:
            step["referer"] = ref_path
    lo = max(0, round(delay_ms * (1 - jitter)))
    hi = max(lo + 1, round(delay_ms * (1 + jitter)))
    if delay_ms <= 0:
        step["delay_min_ms"] = 0
    else:
        step["delay_min_ms"] = lo
        step["delay_max_ms"] = hi
    return step


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("har", help="DevTools HAR export (JSON)")
    ap.add_argument("--jitter", type=float, default=0.2,
                    help="delay jitter fraction around the measured value (default 0.2)")
    ap.add_argument("-o", "--out", help="write the plan here instead of stdout")
    args = ap.parse_args()

    with open(args.har, encoding="utf-8") as f:
        har = json.load(f)
    entries = sorted(har.get("log", {}).get("entries", []),
                     key=lambda e: e.get("startedDateTime", ""))
    if not entries:
        print("har_to_plan: no entries in HAR", file=sys.stderr)
        return 1

    doc = entries[0].get("request", {}).get("url", "")
    ds = urlsplit(doc)
    origin = f"{ds.scheme}://{ds.netloc}"

    steps, prev_t, skipped = [], None, 0
    for i, e in enumerate(entries):
        try:
            t = parse_time(e.get("startedDateTime", ""))
        except ValueError:
            skipped += 1
            continue
        delay = 0 if prev_t is None else max(0, int((t - prev_t).total_seconds() * 1000))
        prev_t = t
        step = to_step(e, origin, i, delay, args.jitter)
        if step is None:
            skipped += 1
            continue
        steps.append(step)

    out = json.dumps(steps, indent=1, ensure_ascii=False)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out + "\n")
    else:
        print(out)
    print(f"har_to_plan: {len(steps)} steps from {len(entries)} entries "
          f"({skipped} skipped), origin {origin}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
