#!/usr/bin/env python3
"""Reassemble WebSocket binary frames from a pcap and extract embedded JPEGs.

Pipeline:
  pcap  ->  per-TCP-flow byte stream (sorted by seq, gaps ignored)
        ->  detect HTTP/WebSocket upgrade, skip handshake
        ->  walk WebSocket frames (RFC 6455), strip frame headers
        ->  concatenate binary-frame payloads (opcode 2 + continuations)
        ->  strip the device's 1-byte type tag prefix on each frame
            (observed: 0x00 = JSON, 0x02 = JPEG, 0x04 = other binary)
        ->  scan for FF D8 FF ... FF D9 and write each JPEG out

Usage:
    python3 tools/extract_jpeg.py path/to/capture.pcap [out_prefix]
"""

import os
import struct
import sys
from collections import defaultdict


def parse_pcap(path):
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) < 24 or struct.unpack("<I", data[0:4])[0] != 0xa1b2c3d4:
        sys.stderr.write("not a classic little-endian pcap file\n")
        return []
    offset = 24
    records = []
    while offset + 16 <= len(data):
        ts_sec, ts_us, cap_len, _ = struct.unpack("<IIII", data[offset:offset + 16])
        offset += 16
        if offset + cap_len > len(data): break
        records.append(data[offset:offset + cap_len])
        offset += cap_len
    return records


def parse_ipv4_tcp(frame):
    if len(frame) < 34 or frame[12:14] != b"\x08\x00": return None
    ip = frame[14:]
    if (ip[0] >> 4) != 4 or ip[9] != 6: return None
    ihl = (ip[0] & 0xF) * 4
    total = struct.unpack(">H", ip[2:4])[0]
    total = min(total, len(ip))
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    tcp = ip[ihl:]
    sport, dport, seq = struct.unpack(">HHI", tcp[0:8])
    doff = (tcp[12] >> 4) * 4
    if doff < 20 or doff > len(tcp): return None
    return (src, sport, dst, dport), seq, tcp[doff:total - ihl]


def reassemble_streams(records):
    segments = defaultdict(list)
    for frame in records:
        parsed = parse_ipv4_tcp(frame)
        if not parsed: continue
        flow_key, seq, payload = parsed
        if payload: segments[flow_key].append((seq, payload))
    streams = {}
    for flow_key, items in segments.items():
        items.sort(key=lambda x: x[0])
        out = bytearray()
        last_seq = None
        for seq, payload in items:
            if last_seq is None or seq >= last_seq:
                out.extend(payload)
                last_seq = seq + len(payload)
        streams[flow_key] = bytes(out)
    return streams


def find_ws_offset(stream):
    """Locate the byte offset right after the HTTP upgrade handshake, or -1."""
    if b"Upgrade: websocket" not in stream and b"Upgrade: WebSocket" not in stream:
        return -1
    end = stream.find(b"\r\n\r\n")
    return end + 4 if end >= 0 else -1


def walk_ws_binary_payloads(stream, start):
    """Yield (frame_index, payload_bytes) for each WS binary/continuation frame."""
    off = start
    idx = 0
    while off + 2 <= len(stream):
        b0, b1 = stream[off], stream[off + 1]
        opcode = b0 & 0xF
        masked = (b1 >> 7) & 1
        length = b1 & 0x7F
        hdr = 2
        if length == 126:
            if off + hdr + 2 > len(stream): return
            length = struct.unpack(">H", stream[off + hdr:off + hdr + 2])[0]
            hdr += 2
        elif length == 127:
            if off + hdr + 8 > len(stream): return
            length = struct.unpack(">Q", stream[off + hdr:off + hdr + 8])[0]
            hdr += 8
        mask_key = b""
        if masked:
            if off + hdr + 4 > len(stream): return
            mask_key = stream[off + hdr:off + hdr + 4]
            hdr += 4
        end = off + hdr + length
        if end > len(stream): return
        if opcode in (2, 0):  # binary or continuation
            payload = stream[off + hdr:end]
            if mask_key:
                payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
            yield idx, payload
        off = end
        idx += 1


def extract_jpegs_from_blob(blob, prefix_path):
    out_paths = []
    pos = 0
    while True:
        start = blob.find(b"\xff\xd8\xff", pos)
        if start < 0: break
        end = blob.find(b"\xff\xd9", start + 3)
        if end < 0:
            sys.stderr.write(f"  JPEG SOI at {start} but no EOI found\n")
            break
        end += 2
        path = f"{prefix_path}_{len(out_paths)}.jpg"
        with open(path, "wb") as fh:
            fh.write(blob[start:end])
        out_paths.append((path, end - start))
        pos = end
    return out_paths


# The device emits LSB-first bit order; PBM "P4" expects MSB-first, so we
# reverse each byte before writing.
_BITREV_TABLE = bytes(int(f"{b:08b}"[::-1], 2) for b in range(256))
_PRINT_HEAD_WIDTH = 384


def extract_print_bitmaps(blob, prefix_path):
    """Save the blob as a 1-bit-per-pixel PBM matching the print head width."""
    bytes_per_row = _PRINT_HEAD_WIDTH // 8
    if len(blob) % bytes_per_row != 0:
        return []
    height = len(blob) // bytes_per_row
    if not (8 <= height <= 4096):
        return []
    path = f"{prefix_path}_w{_PRINT_HEAD_WIDTH}x{height}.pbm"
    with open(path, "wb") as fh:
        fh.write(f"P4\n{_PRINT_HEAD_WIDTH} {height}\n".encode())
        fh.write(blob.translate(_BITREV_TABLE))
    return [(path, _PRINT_HEAD_WIDTH, height)]


def main(argv):
    if len(argv) < 2:
        sys.stderr.write("usage: extract_jpeg.py capture.pcap [out_prefix]\n")
        return 1
    pcap_path = argv[1]
    out_prefix = argv[2] if len(argv) > 2 else os.path.splitext(pcap_path)[0]

    records = parse_pcap(pcap_path)
    sys.stderr.write(f"parsed {len(records)} pcap records\n")
    streams = reassemble_streams(records)

    total = 0
    for flow_key, stream in streams.items():
        ws_start = find_ws_offset(stream)
        if ws_start < 0: continue
        sys.stderr.write(f"\nflow {flow_key}: WebSocket starts at byte {ws_start}\n")

        # Group payload bytes by their 1-byte type prefix and reassemble per type.
        by_type = defaultdict(bytearray)
        n_frames = 0
        for idx, payload in walk_ws_binary_payloads(stream, ws_start):
            if not payload: continue
            type_tag = payload[0]
            by_type[type_tag].extend(payload[1:])
            n_frames += 1
        sys.stderr.write(f"  {n_frames} binary frames; type tags: "
                         f"{ {k: len(v) for k, v in by_type.items()} }\n")

        for tag, blob in by_type.items():
            prefix = f"{out_prefix}_flow{flow_key[0]}-{flow_key[1]}_tag0x{tag:02x}"
            jpegs = extract_jpegs_from_blob(blob, prefix)
            for path, size in jpegs:
                sys.stderr.write(f"  extracted JPEG {size} bytes -> {path}\n")
                total += 1
            if tag == 0x04:
                bitmaps = extract_print_bitmaps(blob, prefix)
                for path, w, h in bitmaps:
                    sys.stderr.write(f"  extracted bitmap {w}x{h} -> {path}\n")
                    total += 1

    sys.stderr.write(f"\nextracted {total} artifact(s)\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
