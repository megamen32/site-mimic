#!/usr/bin/env python3
"""Find a UI node in a uiautomator dump and print its tap centre.

The dump is an XML file produced by `uiautomator dump` on the device
(`phone_ui_drive.sh uidump` pulls it). This script locates a node by
substring and prints the centre of its bounds in device pixels, so a tap can
be aimed without hard-coding coordinates that break the moment the screen
resolution or the app layout changes.

Usage:
    phone_ui_find.py <substr> [<substr2> ...] [--file path.xml]
    adb shell uiautomator dump /data/local/tmp/ui.xml | phone_ui_find.py --file -

Every substring must match (case-insensitively). Clickable nodes win over
non-clickable ones, because a container often carries the same text as the
button inside it.

Prints "x y", or NOTFOUND. Exit code is 0 in both cases, so a caller can
just read the output.
"""
from __future__ import annotations

import re
import sys

BOUNDS_RE = re.compile(r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"')
NODE_RE = re.compile(r"<node[^>]*>")


def find(xml: str, patterns: list[str]) -> tuple[int, int] | None:
    fallback = None
    for match in NODE_RE.finditer(xml):
        tag = match.group(0)
        if not all(p.lower() in tag.lower() for p in patterns):
            continue
        bounds = BOUNDS_RE.search(tag)
        if not bounds:
            continue
        left, top, right, bottom = map(int, bounds.groups())
        node = ((left + right) // 2, (top + bottom) // 2)
        if 'clickable="true"' in tag:
            return node
        fallback = fallback or node
    return fallback


def main() -> None:
    argv = sys.argv[1:]
    path = None
    patterns: list[str] = []
    i = 0
    while i < len(argv):
        if argv[i] == "--file" and i + 1 < len(argv):
            path = argv[i + 1]
            i += 2
            continue
        patterns.append(argv[i])
        i += 1

    if not patterns:
        print("usage: phone_ui_find.py <substr> [...] [--file path.xml]", file=sys.stderr)
        print("NOTFOUND")
        return

    if path in (None, "-"):
        xml = sys.stdin.read()
    else:
        with open(path, errors="replace") as fh:
            xml = fh.read()

    node = find(xml, patterns)
    if node:
        print(node[0], node[1])
    else:
        print("NOTFOUND")


if __name__ == "__main__":
    main()
