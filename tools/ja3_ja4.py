"""JA3 / JA4 computation from parsed ClientHello fields.

Standard library only. Implements the parts of the JA3 / JA4 spec that the
comparison core actually consumes: a deterministic string and an MD5 hash,
with GREASE values stripped before hashing (per FoxIO spec).
"""
from __future__ import annotations
import hashlib
from typing import Optional, Tuple


def _is_grease(value: int) -> bool:
    """True for IANA GREASE values (0x?a?a pattern, e.g. 0xFF01)."""
    return (value & 0x0F0F) == 0x0A0A


def _strip_grease(values: list[int]) -> list[int]:
    return [v for v in values if not _is_grease(v)]


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


def compute_ja4(trace: dict) -> Tuple[str, str]:
    """Compute (ja4_string, ja4_sha256_hex_truncated) from a ConnectionTrace-like dict.

    Implements only the JA4_a (ClientHello) shape we need:
    JA4_a = {protocol}{version}{SNI}{cipher_count}{ext_count}{ALPN}
    followed by an underscore-separated suffix of sorted cipher hashes.

    This is a SIMPLIFIED JA4 sufficient for fingerprint comparison; not for
    full FoxIO spec compliance. The exact field set is locked by the test.
    """
    version_hex = trace["tls_version_offered"]
    # JA4 uses the wire version number: TLS 1.2 = "12", TLS 1.3 = "13"
    if version_hex == 0x0304:
        ver_token = "13"
    elif version_hex == 0x0303:
        ver_token = "12"
    else:
        ver_token = f"{version_hex & 0xFFFF:02x}"
    sni = trace.get("sni") or ""
    # Try to parse as IP; if it does, token "i", else "d"
    import ipaddress
    try:
        ipaddress.ip_address(sni)
        sni_token = "i"
    except (ValueError, TypeError):
        sni_token = "d" if sni else "x"
    ciphers = _strip_grease(trace["cipher_suites"])
    extensions = _strip_grease(trace["extensions"])
    alpn_list = trace.get("alpn", [])
    alpn_token = alpn_list[0].replace("/", "") if alpn_list else "x"
    ja4_a = f"t{ver_token}{sni_token}{len(ciphers):02d}{len(extensions):02d}{alpn_token}"
    # Simplified suffix: sorted cipher hashes joined by ","
    ciph_suffix = ",".join(
        hashlib.sha256(str(c).encode()).hexdigest()[:4] for c in sorted(ciphers)
    ) or "_"
    ja4_str = f"{ja4_a}_{ciph_suffix}"
    ja4_hash = hashlib.sha256(ja4_str.encode("ascii")).hexdigest()[:32]
    return ja4_str, ja4_hash


def compute(trace: dict) -> Tuple[Optional[str], Optional[str]]:
    """Convenience: return (ja3_hash, ja4_hash) for the comparison core."""
    try:
        _, ja3 = compute_ja3(trace)
        _, ja4 = compute_ja4(trace)
        return ja3, ja4
    except (KeyError, TypeError):
        return None, None