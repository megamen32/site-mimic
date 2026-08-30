"""Extract TLS ClientHellos from QUIC Initial packets (QUIC v1).

Chrome reaches m.vk.ru over QUIC/HTTP-3, so a phone capture contains the
ClientHello not in a TCP stream but encrypted inside UDP Initial packets.
RFC 9001 protects them with keys derived deterministically from the
destination connection ID — no secret material involved:

    initial_secret       = HKDF-Extract(salt, DCID)
    client_initial_secret = HKDF-ExpandLabel(initial_secret, "client in")
    key/iv/hp            = HKDF-ExpandLabel(client_initial_secret,
                                            "quic key"/"quic iv"/"quic hp")

Header protection is stripped with AES-ECB(hp), the payload decrypts with
AES-128-GCM, and the CRYPTO frames concatenate into a TLS handshake stream
that starts with the ClientHello. Requires the `cryptography` package for
AES only; HKDF is implemented on hashlib+hmac.

Standard library + cryptography.
"""
from __future__ import annotations

import hashlib
import hmac
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_QUIC_V1_INITIAL_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

try:  # optional dependency: only QUIC extraction needs it
    from cryptography.hazmat.primitives.ciphers import Cipher  # noqa: F401
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
    _HAS_CRYPTO = True
except ImportError:  # pragma: no cover
    _HAS_CRYPTO = False


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand_label(secret: bytes, label: str, length: int) -> bytes:
    # HKDF-ExpandLabel per RFC 8446 §7.1: length(2) || "tls13 "+label || empty context
    info = (
        length.to_bytes(2, "big")
        + bytes([6 + len(label)]) + b"tls13 " + label.encode()
        + b"\x00"
    )
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(secret, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def _quic_varint(data: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(data):
        raise IndexError("varint past end")
    prefix = data[pos] >> 6
    length = 1 << prefix
    if pos + length > len(data):
        raise IndexError("varint truncated")
    value = int.from_bytes(data[pos : pos + length], "big") & ((1 << (length * 8 - 2)) - 1)
    return value, pos + length


def _parse_long_header(datagram: bytes):
    """Return (dcid, header_len, header_bytes, pn_bytes, payload) for Initials."""
    if len(datagram) < 6 or not datagram[0] & 0x80:
        return None
    if (datagram[0] & 0x30) >> 4 != 0:  # not an Initial (type bits are unmasked)
        return None
    version = struct.unpack_from(">I", datagram, 1)[0]
    if version != 1:  # QUIC v1 Initials only
        return None
    try:
        pos = 5
        dcid_len = datagram[pos]
        pos += 1
        dcid = datagram[pos : pos + dcid_len]
        if len(dcid) < dcid_len:
            return None
        pos += dcid_len
        scid_len = datagram[pos]
        pos += 1 + scid_len
        if pos > len(datagram):
            return None
        token_len, pos = _quic_varint(datagram, pos)
        pos += token_len
        length, pos = _quic_varint(datagram, pos)
    except IndexError:
        return None
    header_bytes = datagram[:pos]
    pn_and_payload = datagram[pos : pos + length]
    if len(pn_and_payload) < 20:  # smallest legal: 4 (sample) + 16 (tag)
        return None
    return dcid, header_bytes, pn_and_payload


def _decrypt_initial(dcid: bytes, header_bytes: bytes, pn_and_payload: bytes):
    """Return decrypted payload frames or None."""
    if not _HAS_CRYPTO:
        return None
    secret = _hkdf_expand_label(
        _hkdf_extract(_QUIC_V1_INITIAL_SALT, dcid), "client in", 32
    )
    key = _hkdf_expand_label(secret, "quic key", 16)
    iv = _hkdf_expand_label(secret, "quic iv", 12)
    hp = _hkdf_expand_label(secret, "quic hp", 16)

    if len(pn_and_payload) < 4 + 16 + 16:  # pn + 16-byte sample + 16-byte tag
        return None
    # RFC 9001 §5.4.2: the sample starts 4 bytes after the packet-number
    # field (its maximum length), regardless of the actual pn length.
    sample = pn_and_payload[4 : 4 + 16]
    ecb = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = ecb.update(sample) + ecb.finalize()

    # The mask covers the packet's FIRST byte (low nibble on long headers)
    # and then the packet-number bytes.
    first = header_bytes[0] ^ (mask[0] & 0x0F)
    if (first & 0x30) >> 4 != 0:  # packet type must be Initial after unmask
        return None
    pn_len = (first & 0x03) + 1
    pn_bytes = bytes(
        b ^ m for b, m in zip(pn_and_payload[0:pn_len], mask[1 : 1 + pn_len])
    )
    pn = int.from_bytes(pn_bytes, "big")

    full_header = bytes([first]) + header_bytes[1:] + pn_bytes
    nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, "big")))
    try:
        return AESGCM(key).decrypt(nonce, pn_and_payload[pn_len:], full_header)
    except Exception:
        return None


def _crypto_frames(payload: bytes) -> list[tuple[int, bytes]]:
    """Collect (offset, data) CRYPTO chunks; tolerate PADDING/PING/ACK."""
    chunks, pos = [], 0
    while pos < len(payload):
        frame = payload[pos]
        if frame == 0x00 or frame == 0x01:  # PADDING / PING
            pos += 1
        elif frame == 0x06:  # CRYPTO
            offset, pos = _quic_varint(payload, pos + 1)
            length, pos = _quic_varint(payload, pos)
            chunks.append((offset, payload[pos : pos + length]))
            pos += length
        elif frame in (0x02, 0x03):  # ACK / ACK_ECN
            _, pos = _quic_varint(payload, pos + 1)  # largest acked
            _, pos = _quic_varint(payload, pos)  # ack delay
            ranges, pos = _quic_varint(payload, pos)
            for _ in range(ranges):
                _, pos = _quic_varint(payload, pos)
                _, pos = _quic_varint(payload, pos)
            if frame == 0x03:
                for _ in range(3):
                    _, pos = _quic_varint(payload, pos)
        else:
            break  # unknown frame here: stop, keep what we have
    return chunks


def quic_clienthellos(datagrams: list[bytes]):
    """Yield parsed ClientHello traces from a UDP flow's datagrams.

    Reassembles the CRYPTO stream across Initial packets (Chrome's hello
    spans several), then wraps the handshake message in a synthetic TLS
    record for the shared parser.
    """
    from parse_clienthello import parse_clienthello

    by_dcid: dict[bytes, list[tuple[int, bytes]]] = {}
    for datagram in datagrams:
        parsed = _parse_long_header(datagram)
        if parsed is None:
            continue
        dcid, header_bytes, pn_and_payload = parsed
        payload = _decrypt_initial(dcid, header_bytes, pn_and_payload)
        if payload is None:
            continue
        by_dcid.setdefault(dcid, []).extend(_crypto_frames(payload))

    for chunks in by_dcid.values():
        stream = bytearray()
        expected = 0
        for offset, data in sorted(chunks):
            if offset != expected:  # gap: the hello prefix collected so far
                break                    # is still parseable below
            stream.extend(data)
            expected = offset + len(data)
        if len(stream) < 4 or stream[0] != 0x01:
            continue
        msg_len = int.from_bytes(stream[1:4], "big")
        if 4 + msg_len > len(stream):
            continue
        message = bytes(stream[: 4 + msg_len])  # type + length + body
        record = b"\x16\x03\x03" + len(message).to_bytes(2, "big") + message
        try:
            yield parse_clienthello(record)
        except (ValueError, struct.error):
            continue
