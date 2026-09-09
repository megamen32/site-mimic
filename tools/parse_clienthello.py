#!/usr/bin/env python3
"""Parse a raw TLS ClientHello record and print JA3 / JA4 fingerprints.

Input: the JSON envelope written by mimic.WriteClientHelloJSON (or a raw
base64 string via --b64):

    {"target": "vk.ru:443", "client_hello_b64": "<base64 of the TLS record>"}

Wire shape parsed:
    record:     type(1)=0x16 + version(2) + length(2)
    handshake:  type(1)=0x01 + length(3) + ClientHello body
    clienthello: version(2) + random(32) + session_id + ciphers + compression
                 + extensions[type(2) length(2) data]

Standard library only. Pair with tools/ja3_ja4.py.
"""
from __future__ import annotations

import argparse
import base64
import json
import struct
import sys

from ja3_ja4 import compute_ja3, compute_ja4

_EXTENSION_SNI = 0x0000
_EXTENSION_GROUPS = 0x000A
_EXTENSION_POINT_FORMATS = 0x000B
_EXTENSION_ALPN = 0x0010
_EXTENSION_SIG_ALGS = 0x000D
_EXTENSION_SUPPORTED_VERSIONS = 0x002B


def parse_clienthello(record: bytes) -> dict:
    """Decode raw ClientHello record bytes into a ja3_ja4-compatible trace."""
    if len(record) < 9 or record[0] != 0x16:
        raise ValueError("not a TLS handshake record (first byte != 0x16)")
    pos = 5  # skip record header
    if record[pos] != 0x01:
        raise ValueError("not a ClientHello (handshake type != 0x01)")
    pos += 4  # skip handshake type + 3-byte length

    (legacy_version,) = struct.unpack_from(">H", record, pos)
    pos += 2
    pos += 32  # random
    session_id_len = record[pos]
    pos += 1 + session_id_len
    (ciphers_len,) = struct.unpack_from(">H", record, pos)
    pos += 2
    cipher_suites = list(
        struct.unpack_from(f">{ciphers_len // 2}H", record, pos)
    )
    pos += ciphers_len
    comp_len = record[pos]
    pos += 1 + comp_len
    (ext_total,) = struct.unpack_from(">H", record, pos)
    pos += 2

    extensions: list[int] = []
    extension_data: dict[str, str] = {}
    groups: list[int] = []
    point_formats: list[int] = []
    alpn: list[str] = []
    signature_algorithms: list[int] = []
    supported_versions: list[int] = []
    sni = ""
    end = min(pos + ext_total, len(record))
    while pos + 4 <= end:
        ext_type, ext_len = struct.unpack_from(">HH", record, pos)
        pos += 4
        data = record[pos : pos + ext_len]
        pos += ext_len
        extensions.append(ext_type)
        extension_data[f"{ext_type:#06x}"] = data.hex()
        if ext_type == _EXTENSION_SNI and len(data) >= 5:
            name_len = struct.unpack_from(">H", data, 3)[0]
            sni = data[5 : 5 + name_len].decode("utf-8", "replace")
        elif ext_type == _EXTENSION_GROUPS and len(data) >= 2:
            (n,) = struct.unpack_from(">H", data, 0)
            groups = list(struct.unpack_from(f">{n // 2}H", data, 2))
        elif ext_type == _EXTENSION_POINT_FORMATS and len(data) >= 1:
            n = data[0]
            point_formats = list(data[1 : 1 + n])
        elif ext_type == _EXTENSION_ALPN and len(data) >= 2:
            (n,) = struct.unpack_from(">H", data, 0)
            off = 2
            while off + 1 <= n:
                plen = data[off]
                alpn.append(data[off + 1 : off + 1 + plen].decode("ascii", "replace"))
                off += 1 + plen
        elif ext_type == _EXTENSION_SIG_ALGS and len(data) >= 2:
            (n,) = struct.unpack_from(">H", data, 0)
            signature_algorithms = list(struct.unpack_from(f">{n // 2}H", data, 2))
        elif ext_type == _EXTENSION_SUPPORTED_VERSIONS and len(data) >= 1:
            n = data[0]
            supported_versions = list(struct.unpack_from(f">{n // 2}H", data, 1))

    return {
        "tls_version_offered": legacy_version,
        "cipher_suites": cipher_suites,
        "extensions": extensions,
        "supported_groups": groups,
        "ec_point_formats": point_formats,
        "alpn": alpn,
        "signature_algorithms": signature_algorithms,
        "supported_versions": supported_versions,
        "extension_data": extension_data,
        "sni": sni,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("envelope", nargs="?", help="clienthello.json written by the Go side")
    ap.add_argument("--b64", help="raw ClientHello record as base64 (overrides envelope)")
    args = ap.parse_args()

    if args.b64:
        record = base64.b64decode(args.b64)
        target = "?"
    elif args.envelope:
        with open(args.envelope, encoding="utf-8") as fh:
            env = json.load(fh)
        record = base64.b64decode(env["client_hello_b64"])
        target = env.get("target", "?")
    else:
        ap.error("give a clienthello.json envelope or --b64")
        return 2

    trace = parse_clienthello(record)
    ja3_str, ja3_hash = compute_ja3(trace)
    ja4_str, _ = compute_ja4(trace)
    print(f"target:          {target}")
    print(f"tls version:     0x{trace['tls_version_offered']:04x}")
    print(f"ciphers:         {len(trace['cipher_suites'])}")
    print(f"extensions:      {len(trace['extensions'])}")
    print(f"alpn:            {trace['alpn'] or '(none)'}")
    print(f"sni:             {trace['sni']}")
    print(f"ja3_string:      {ja3_str}")
    print(f"ja3_hash:        {ja3_hash}")
    print(f"ja4_foxio:       {ja4_str}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
