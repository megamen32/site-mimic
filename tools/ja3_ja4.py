"""JA3 / JA4 computation from parsed ClientHello fields.

Standard library only.

JA3 follows the classic salesforce/ja3 spec: a deterministic "-"-joined
string and an MD5 hash, GREASE stripped before hashing.

JA4 follows the FoxIO spec (FoxIO-LLC/ja4, technical_details/JA4.md):
JA4 = JA4_a + "_" + JA4_b + "_" + JA4_c where JA4_a is the visible shape
(protocol, TLS version, SNI presence, cipher/extension counts, first ALPN),
JA4_b hashes the GREASE-free cipher list sorted in hex order, and JA4_c
hashes the GREASE-free extension list (SNI 0x0000 and ALPN 0x0010 removed)
sorted in hex order, followed by "_" and the signature algorithms in wire
order. Sorting the lists makes JA4 stable across Chrome's per-connection
extension shuffling.
"""
from __future__ import annotations
import hashlib
from typing import Optional, Tuple

_GREASE_TLS_VERSIONS = {0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A,
                        0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
                        0xCACA, 0xDADA, 0xEAEA, 0xFAFA}
_TLS_VERSION_TOKENS = {
    0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10",
    0x0300: "s3", 0x0002: "s2",
    0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3",
}


def _is_grease(value: int) -> bool:
    """True for IANA GREASE values (0x?a?a pattern, e.g. 0xFF01)."""
    return (value & 0x0F0F) == 0x0A0A


def _strip_grease(values: list[int]) -> list[int]:
    return [v for v in values if not _is_grease(v)]


def _hex4(values: list[int]) -> list[str]:
    return [f"{v:04x}" for v in values]


def compute_ja3(trace: dict) -> Tuple[str, str]:
    """Compute (ja3_string, ja3_md5_hex) from a ConnectionTrace-like dict.

    JA3 = MD5( TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats )
    where each list is GREASE-stripped and joined by '-', with inner joins by ','.
    """
    version = trace["tls_version_offered"]
    ciphers = _strip_grease(trace["cipher_suites"])
    extensions = _strip_grease(trace["extensions"])
    groups = _strip_grease(trace.get("supported_groups", []))
    pf = _strip_grease(trace.get("ec_point_formats", []))
    ja3_str = (
        f"{version}-"
        f"{','.join(str(c) for c in ciphers)}-"
        f"{','.join(str(e) for e in extensions)}-"
        f"{','.join(str(g) for g in groups)}-"
        f"{','.join(str(p) for p in pf)}"
    )
    ja3_hash = hashlib.md5(ja3_str.encode("ascii")).hexdigest()
    return ja3_str, ja3_hash


def _ja4_version_token(trace: dict) -> str:
    """Highest supported_versions value (GREASE ignored), else legacy version."""
    supported = [v for v in trace.get("supported_versions", []) if v not in _GREASE_TLS_VERSIONS]
    if supported:
        best = max(supported)
    else:
        best = trace["tls_version_offered"]
    return _TLS_VERSION_TOKENS.get(best, "00")


def _ja4_alpn_token(trace: dict) -> str:
    """First and last characters of the first ALPN value; FoxIO edge rules."""
    alpn_list = trace.get("alpn") or []
    if not alpn_list:
        return "00"
    value = alpn_list[0]
    if not value:
        return "00"
    raw = value.encode("latin-1", "replace")
    first, last = raw[0], raw[-1]
    if len(raw) == 1:
        return chr(first) * 2
    def alnum(b: int) -> bool:
        return 0x30 <= b <= 0x39 or 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A
    if alnum(first) and alnum(last):
        return chr(first) + chr(last)
    # FoxIO: first and last characters of the hex representation.
    hx = raw.hex()
    return hx[0] + hx[-1]


def _ja4_b(trace: dict) -> str:
    ciphers = _hex4(_strip_grease(trace["cipher_suites"]))
    if not ciphers:
        return "0" * 12
    return hashlib.sha256(",".join(sorted(ciphers)).encode("ascii")).hexdigest()[:12]


def _ja4_c(trace: dict) -> str:
    extensions = [
        e for e in _strip_grease(trace["extensions"])
        if e not in (0x0000, 0x0010)  # SNI and ALPN live in JA4_a
    ]
    ext_hex = sorted(_hex4(extensions))
    if not ext_hex:
        return "0" * 12
    payload = ",".join(ext_hex)
    # GREASE is ignored anywhere it appears (FoxIO spec), signature list included
    sig_algs = _hex4(_strip_grease(trace.get("signature_algorithms", [])))
    if sig_algs:
        payload += "_" + ",".join(sig_algs)  # wire order, not sorted
    return hashlib.sha256(payload.encode("ascii")).hexdigest()[:12]


def compute_ja4(trace: dict, protocol: str = "t") -> Tuple[str, str]:
    """Compute (ja4_string, ja4_sha256_full_hex) per the FoxIO spec.

    Implements technical_details/JA4.md exactly: counts ignore GREASE
    (SCSV/experimental values still count), SNI contributes "d" when the
    extension is present ("i" when absent), the ALPN token is the first and
    last alphanumeric of the first protocol, and the hashes cover the
    hex-sorted cipher list and the hex-sorted extension list (minus SNI and
    ALPN) followed by the signature algorithms in wire order.
    protocol is "t" (TLS over TCP), "q" (QUIC) or "d" (DTLS).
    """
    sni_token = "d" if trace.get("sni") else "i"
    cipher_count = min(len(_strip_grease(trace["cipher_suites"])), 99)
    ext_count = min(len(_strip_grease(trace["extensions"])), 99)
    ja4_a = (
        f"{protocol}{_ja4_version_token(trace)}{sni_token}"
        f"{cipher_count:02d}{ext_count:02d}{_ja4_alpn_token(trace)}"
    )
    ja4_str = f"{ja4_a}_{_ja4_b(trace)}_{_ja4_c(trace)}"
    return ja4_str, hashlib.sha256(ja4_str.encode("ascii")).hexdigest()


def compute(trace: dict) -> Tuple[Optional[str], Optional[str]]:
    """Convenience: return (ja3_hash, ja4_string) for the comparison core."""
    try:
        _, ja3 = compute_ja3(trace)
        ja4_str, _ = compute_ja4(trace)
        return ja3, ja4_str
    except (KeyError, TypeError):
        return None, None
