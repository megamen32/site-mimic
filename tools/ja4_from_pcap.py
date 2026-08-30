#!/usr/bin/env python3
"""Extract TLS ClientHellos from a pcap and print their FoxIO JA4.

Usage:
    python3 tools/ja4_from_pcap.py captures/browser.pcap [more.pcap ...]

Supports classic pcap files (both byte orders, micro- and nanosecond
variants) with Ethernet, Linux cooked (SLL) or raw-IP link layers, IPv4 and
IPv6 over TCP. Segments are reassembled per flow direction by sequence
number, then scanned for handshake records; every ClientHello is decoded
with tools/parse_clienthello.py and fingerprinted with the FoxIO JA4 from
tools/ja3_ja4.py.

Standard library only.
"""
from __future__ import annotations

import argparse
import ipaddress
import struct
import sys
from collections import Counter

from ja3_ja4 import compute_ja4
from parse_clienthello import parse_clienthello

_MAGIC_LE_USEC = 0xA1B2C3D4
_MAGIC_BE_USEC = 0xD4C3B2A1
_MAGIC_LE_NSEC = 0xA1B23C4D
_MAGIC_BE_NSEC = 0x4D3CB2A1


def _read_pcap(path: str):
    """Yield (linktype, payload) per packet; handles both byte orders."""
    with open(path, "rb") as fh:
        global_header = fh.read(24)
        if len(global_header) < 24:
            raise ValueError(f"{path}: truncated pcap header")
        magic = struct.unpack("<I", global_header[:4])[0]
        if magic in (_MAGIC_LE_USEC, _MAGIC_LE_NSEC):
            endian = "<"
        elif magic in (_MAGIC_BE_USEC, _MAGIC_BE_NSEC):
            endian = ">"
        else:
            raise ValueError(f"{path}: not a pcap file (magic {magic:#x})")
        _vmaj, _vmin, _tz, _sig, _snap, linktype = struct.unpack(
            endian + "HHiIII", global_header[4:24]
        )
        while True:
            packet_header = fh.read(16)
            if len(packet_header) < 16:
                return
            _ts, _tus, incl_len, _orig = struct.unpack(endian + "IIII", packet_header)
            data = fh.read(incl_len)
            if len(data) < incl_len:
                return
            yield linktype, data


def _parse_link(linktype: int, frame: bytes):
    """Return (ether_type, bytes-after-link-header) or None."""
    if linktype == 1:  # Ethernet
        if len(frame) < 14:
            return None
        ethertype = struct.unpack_from(">H", frame, 12)[0]
        offset = 14
        while ethertype in (0x8100, 0x88A8):  # VLAN tags
            if len(frame) < offset + 4:
                return None
            ethertype = struct.unpack_from(">H", frame, offset + 2)[0]
            offset += 4
        return ethertype, frame[offset:]
    if linktype == 113:  # Linux cooked (SLL)
        if len(frame) < 16:
            return None
        return struct.unpack_from(">H", frame, 14)[0], frame[16:]
    if linktype == 101:  # raw IP
        if not frame:
            return None
        return (0x86DD if frame[0] >> 4 == 6 else 0x0800), frame
    return None


def _parse_network(ether_type: int, data: bytes):
    """Return (src, dst, proto, payload) for IPv4/IPv6, else None."""
    if ether_type == 0x0800 and len(data) >= 20:
        ihl = (data[0] & 0x0F) * 4
        if len(data) < ihl:
            return None
        src = str(ipaddress.IPv4Address(data[12:16]))
        dst = str(ipaddress.IPv4Address(data[16:20]))
        return src, dst, data[9], data[ihl:]
    if ether_type == 0x86DD and len(data) >= 40:
        src = str(ipaddress.IPv6Address(data[8:24]))
        dst = str(ipaddress.IPv6Address(data[24:40]))
        return src, dst, data[6], data[40:]
    return None


def _parse_tcp(segment: bytes):
    """Return (sport, dport, seq, payload) or None."""
    if len(segment) < 20:
        return None
    sport, dport, seq = struct.unpack_from(">HHI", segment, 0)
    offset = (segment[12] >> 4) * 4
    if len(segment) < offset:
        return None
    return sport, dport, seq, segment[offset:]


def _reassemble(segments: list[tuple[int, bytes]]) -> bytes:
    """Concatenate TCP payload by sequence order, dropping retransmissions."""
    if not segments:
        return b""
    segments = sorted(segments, key=lambda s: s[0])
    stream = bytearray()
    expected = segments[0][0]
    for seq, payload in segments:
        end = seq + len(payload)
        if end <= expected:
            continue  # fully retransmitted
        start = max(seq, expected)
        stream.extend(payload[start - seq :])
        expected = end
    return bytes(stream)


def _clienthellos(stream: bytes):
    """Yield raw ClientHello records found in a TCP byte stream."""
    pos = 0
    while pos + 5 <= len(stream):
        if stream[pos] != 0x16:  # not a handshake record: resync
            pos += 1
            continue
        record_len = struct.unpack_from(">H", stream, pos + 3)[0]
        if pos + 5 + record_len > len(stream):
            return  # truncated tail
        record = stream[pos : pos + 5 + record_len]
        pos += 5 + record_len
        if record[5] != 0x01:  # not a ClientHello
            continue
        try:
            yield parse_clienthello(record)
        except (ValueError, struct.error):  # false record header inside app data
            continue


def _complete_hello_in_segment(segment: bytes):
    """Return a ClientHello record if one sits complete inside one segment.

    Fallback for captures where synthetic metadata segments overlap the
    real data by sequence number and corrupt stream reassembly (observed
    with PCAPdroid): a full record is self-describing, so a whole hello
    inside a single segment can be lifted out verbatim.
    """
    for pos in range(0, max(0, len(segment) - 10)):
        if segment[pos] != 0x16:
            continue
        if pos + 9 > len(segment):
            break
        if segment[pos + 1] != 0x03 or segment[pos + 2] not in (0x00, 0x01, 0x02, 0x03, 0x04):
            continue
        record_len = struct.unpack_from(">H", segment, pos + 3)[0]
        end = pos + 5 + record_len
        if end > len(segment) or segment[pos + 5] != 0x01:
            continue
        try:
            return parse_clienthello(segment[pos:end])
        except ValueError:
            continue
    return None


def _parse_udp(segment: bytes):
    """Return (sport, dport, payload) or None."""
    if len(segment) < 8:
        return None
    sport, dport = struct.unpack_from(">HH", segment, 0)
    return sport, dport, segment[8:]


def _drop_tag_segments(flows: dict) -> dict:
    """Remove PCAPdroid tag segments and sequence conflicts.

    PCAPdroid captures interleave small, byte-identical "tag" segments whose
    sequence numbers collide with the real data (they repeat across flows,
    so they identify themselves by repetition). Small payloads seen in many
    flows are dropped; among same-seq survivors the longest payload wins.
    """
    counts: Counter = Counter()
    for segments in flows.values():
        for _seq, data in segments:
            if len(data) <= 64:
                counts[data] += 1
    tags = {data for data, count in counts.items() if count >= 5}
    cleaned = {}
    for flow, segments in flows.items():
        by_seq: dict[int, bytes] = {}
        for seq, data in segments:
            if data in tags:
                continue
            if seq not in by_seq or len(data) > len(by_seq[seq]):
                by_seq[seq] = data
        cleaned[flow] = sorted(by_seq.items())
    return cleaned


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pcaps", nargs="+", help="pcap files to scan")
    ap.add_argument("--sni", help="only print hellos whose SNI contains this substring")
    args = ap.parse_args()

    try:
        from quic_initial import quic_clienthellos
    except ImportError:
        quic_clienthellos = None

    exit_code = 0
    for path in args.pcaps:
        flows: dict[tuple, list[tuple[int, bytes]]] = {}
        udp_flows: dict[tuple, list[bytes]] = {}
        for linktype, frame in _read_pcap(path):
            link = _parse_link(linktype, frame)
            if link is None:
                continue
            net = _parse_network(*link)
            if net is None:
                continue
            src, dst, proto, payload = net
            if proto == 6:  # TCP
                tcp = _parse_tcp(payload)
                if tcp is None or not tcp[3]:
                    continue
                sport, dport, seq, data = tcp
                flows.setdefault((src, sport, dst, dport), []).append((seq, data))
            elif proto == 17 and quic_clienthellos is not None:  # UDP (QUIC)
                udp = _parse_udp(payload)
                if udp is None or not udp[2]:
                    continue
                sport, dport, data = udp
                udp_flows.setdefault((src, sport, dst, dport), []).append(data)
        flows = _drop_tag_segments(flows)
        printed_for_file = 0
        for flow, segments in flows.items():
            seen: set[str] = set()
            src, sport, dst, dport = flow

            def emit(ja4: str, sni: str) -> None:
                nonlocal printed_for_file
                print(f"{path} {src}:{sport} > {dst}:{dport} sni={sni or '-'} ja4={ja4}")
                printed_for_file += 1

        for trace in _clienthellos(_reassemble(segments)):
            ja4, _ = compute_ja4(trace)
            sni = trace.get("sni") or ""
            if args.sni and args.sni.lower() not in sni.lower():
                continue
            seen.add(ja4)
            emit(ja4, sni)
        # Fallback 1: lift whole hellos out of individual segments
        # (deduplicated per flow by JA4).
        for _seq, data in segments:
            trace = _complete_hello_in_segment(data)
            if trace is None:
                continue
            ja4, _ = compute_ja4(trace)
            if ja4 in seen:
                continue
            sni = trace.get("sni") or ""
            if args.sni and args.sni.lower() not in sni.lower():
                continue
            seen.add(ja4)
            emit(ja4, sni)
        # Fallback 2: PCAPdroid-style captures carry synthetic metadata
        # segments whose sequence numbers overlap the real data and corrupt
        # strict reassembly. Rebuild the stream starting at each segment
        # that itself begins a ClientHello and re-scan from there.
        for start, data in segments:
            if not data[:1] == b"\x16" or len(data) < 6 or data[5:6] != b"\x01":
                continue
            tail = [s for s in segments if s[0] >= start]
            for trace in _clienthellos(_reassemble(tail)):
                ja4, _ = compute_ja4(trace)
                if ja4 in seen:
                    continue
                sni = trace.get("sni") or ""
                if args.sni and args.sni.lower() not in sni.lower():
                    continue
                seen.add(ja4)
                emit(ja4, sni)
        for flow, datagrams in udp_flows.items():
            if 443 not in (flow[1], flow[3]):
                continue
            src, sport, dst, dport = flow
            seen: set[str] = set()
            for trace in quic_clienthellos(datagrams):
                ja4, _ = compute_ja4(trace, protocol="q")
                if ja4 in seen:
                    continue
                seen.add(ja4)
                sni = trace.get("sni") or ""
                if args.sni and args.sni.lower() not in sni.lower():
                    continue
                print(f"{path} {src}:{sport} > {dst}:{dport} sni={sni or '-'} ja4={ja4}")
                printed_for_file += 1
        if printed_for_file == 0:
            print(f"{path}: no ClientHello found", file=sys.stderr)
            exit_code = 1
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
