#!/usr/bin/env python3
"""Demux the esp32-logger UART framed stream into a .pcap file plus log text.

Reads from a serial port (default /dev/cu.usbserial-0001 at 921600 baud),
synchronises on the framer magic, and dispatches each record by type:
  - kFrameTypeLog (0x01)  -> printed to stderr, prefixed with "[esp]"
  - kFrameTypePcap (0x02) -> bytes appended to the chosen pcap output

The pcap output can be a file path or "-" to write to stdout (useful with
"tshark -i -" or "wireshark -k -i -").

Usage:
    python3 tools/capture.py [--port DEV] [--baud N] [-o capture.pcap]
"""

import argparse
import os
import struct
import sys

try:
    import serial  # pyserial
except ImportError:
    sys.stderr.write("Missing dependency: pyserial. Install with `pip install pyserial`.\n")
    sys.exit(1)

MAGIC = b"\xe5\xc0\x32\x70"
TYPE_LOG = 0x01
TYPE_PCAP = 0x02

# Classic pcap global header (little-endian, link-type Ethernet, snaplen 1518).
PCAP_GLOBAL_HEADER = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 1518, 1)


def find_magic(ser: serial.Serial) -> None:
    """Read bytes until we've seen the 4-byte magic."""
    window = b""
    while True:
        b = ser.read(1)
        if not b:
            continue
        window = (window + b)[-4:]
        if window == MAGIC:
            return
        # Any byte before sync is treated as pre-stream UART noise; drop silently.


def read_exact(ser: serial.Serial, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = ser.read(n - len(buf))
        if not chunk:
            continue
        buf.extend(chunk)
    return bytes(buf)


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", default="/dev/cu.usbserial-0001",
                        help="Serial device path")
    parser.add_argument("--baud", type=int, default=921600,
                        help="Serial baud rate")
    parser.add_argument("-o", "--output", default="capture.pcap",
                        help='pcap output path, or "-" for stdout')
    args = parser.parse_args(argv[1:])

    if args.output == "-":
        pcap_out = sys.stdout.buffer
        close_pcap = False
    else:
        pcap_out = open(args.output, "wb")
        close_pcap = True
        sys.stderr.write(f"[capture] writing pcap to {args.output}\n")

    pcap_out.write(PCAP_GLOBAL_HEADER)
    pcap_out.flush()

    ser = serial.Serial(args.port, args.baud, timeout=0.5)
    sys.stderr.write(f"[capture] reading from {args.port} @ {args.baud}\n")

    log_bytes = 0
    pcap_bytes = 0
    records = 0
    try:
        while True:
            find_magic(ser)
            type_byte = read_exact(ser, 1)[0]
            length = int.from_bytes(read_exact(ser, 4), "little")
            if length > 64 * 1024:
                sys.stderr.write(f"[capture] suspiciously large frame len={length}, resync\n")
                continue
            payload = read_exact(ser, length)
            if type_byte == TYPE_LOG:
                text = payload.decode("utf-8", errors="replace").rstrip()
                sys.stderr.write(f"[esp] {text}\n")
                log_bytes += length
            elif type_byte == TYPE_PCAP:
                pcap_out.write(payload)
                pcap_out.flush()
                pcap_bytes += length
                records += 1
            else:
                sys.stderr.write(f"[capture] unknown frame type 0x{type_byte:02x}, dropping {length} bytes\n")
    except KeyboardInterrupt:
        sys.stderr.write(f"\n[capture] stopped: pcap_records={records} "
                         f"pcap_bytes={pcap_bytes} log_bytes={log_bytes}\n")
    finally:
        if close_pcap:
            pcap_out.close()


if __name__ == "__main__":
    main(sys.argv)
