#!/usr/bin/env python3
"""What a tap on the seed saw of one downloader, in file offsets.

`wire_ranges.py <pcap>:<seed ip>... [--since <unix>] [--json out]` rebuilds each TCP stream of
each tap, walks its eD2k frames, and prints the bytes the seeds delivered,
counted once and in all, and the bytes the downloader asked for. The eD2k client
frames only, plain links only: a rig run leaves obfuscation off. `--since` keeps
the streams opened after that moment.
"""

import json
import socket
import struct
import sys
from collections import defaultdict


def packets(path):
    with open(path, "rb") as f:
        head = f.read(24)
        magic = struct.unpack("<I", head[:4])[0]
        order = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
        linktype = struct.unpack(order + "I", head[20:24])[0]
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                return
            sec, frac, incl, _ = struct.unpack(order + "IIII", rec)
            data = f.read(incl)
            yield sec + frac / 1e6, linktype, data


def tcp(linktype, data):
    off = 14 if linktype == 1 else 16
    if linktype == 1 and data[12:14] != b"\x08\x00":
        return None
    if linktype != 1 and data[14:16] != b"\x08\x00":
        return None
    ip = data[off:]
    if ip[9] != 6:
        return None
    ihl = (ip[0] & 15) * 4
    total = struct.unpack(">H", ip[2:4])[0]
    seg = ip[ihl:total]
    sport, dport, seq = struct.unpack(">HHI", seg[:8])
    doff = (seg[12] >> 4) * 4
    return socket.inet_ntoa(ip[12:16]), sport, socket.inet_ntoa(ip[16:20]), dport, seq, seg[12 + 1], seg[doff:]


def streams(path):
    flows = defaultdict(dict)
    times = {}
    for t, link, data in packets(path):
        row = tcp(link, data)
        if not row:
            continue
        src, sport, dst, dport, seq, flags, payload = row
        key = (src, sport, dst, dport)
        times.setdefault(key, t)
        if payload and seq not in flows[key]:
            flows[key][seq] = payload
    for key, segs in flows.items():
        out = bytearray()
        # The first segment seen opens the stream; sequence numbers wrap at 2^32.
        start = next(iter(segs), 0)
        for seq in sorted(segs, key=lambda seq: (seq - start) & 0xFFFFFFFF):
            at = (seq - start) & 0xFFFFFFFF
            piece = segs[seq]
            if at + len(piece) <= len(out):
                continue
            if at > len(out):
                out.extend(bytes(at - len(out)))
            out[at:] = piece
        yield key, times[key], bytes(out)


def frames(buf):
    at = 0
    while at + 6 <= len(buf):
        proto = buf[at]
        if proto not in (0xE3, 0xC5, 0xD4):
            return
        length = struct.unpack_from("<I", buf, at + 1)[0]
        if length == 0 or at + 5 + length > len(buf):
            return
        yield proto, buf[at + 5], buf[at + 6 : at + 5 + length]
        at += 5 + length


def merge(ranges):
    out = []
    for a, b in sorted(ranges):
        if out and a <= out[-1][1]:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return out


def main():
    args = sys.argv[1:]
    out = None
    if "--json" in args:
        at = args.index("--json")
        out = args[at + 1]
        del args[at : at + 2]
    since = 0.0
    if "--since" in args:
        at = args.index("--since")
        since = float(args[at + 1])
        del args[at : at + 2]
    delivered, asked, opcodes = [], [], defaultdict(int)
    for tap in args:
        pcap, seed = tap.rsplit(":", 1)
        for (src, sport, dst, dport), first, buf in streams(pcap):
            if first < since:
                continue
            for proto, opcode, body in frames(buf):
                if src == seed or dst == seed:
                    opcodes[f"{'seed' if src == seed else 'peer'} 0x{proto:02x}/0x{opcode:02x}"] += 1
                if src == seed and proto == 0xE3 and opcode == 0x46:
                    a, b = struct.unpack_from("<II", body, 16)
                    delivered.append((a, b))
                elif dst == seed and proto == 0xE3 and opcode == 0x47:
                    starts = struct.unpack_from("<3I", body, 16)
                    ends = struct.unpack_from("<3I", body, 28)
                    asked.extend((a, b) for a, b in zip(starts, ends) if b > a)
    total = sum(b - a for a, b in delivered)
    once = sum(b - a for a, b in merge(delivered))
    print(f"delivered_total={total} delivered_once={once} refetched={total - once} "
          f"asked_total={sum(b - a for a, b in asked)} asked_once={sum(b - a for a, b in merge(asked))}")
    if out:
        with open(out, "w") as sink:
            json.dump({"delivered": delivered, "asked": asked, "opcodes": opcodes}, sink)


if __name__ == "__main__":
    main()
