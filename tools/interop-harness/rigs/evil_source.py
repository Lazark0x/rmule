#!/usr/bin/env python3
"""A scripted source that breaks one rule of the wire on purpose.

A stimulus, not a counterparty: no stock body sends a block of the wrong file or
a hash set of the wrong count, so this script does, and the downloader in front
of it (stock aMule or rmule) is what is observed. It logs in to the eD2k server
High ID, offers two synthetic files, holds them, and serves them over plain eD2k
frames with one fault:

  control        no fault; the files transfer whole and prove the staging
  late-block     inside the slot, answers a block ask with a block of the other file
  hashset-corrupt  answers the hash ask with hashes whose MD4 is not the file's
  hashset-count    answers the hash ask with one hash too few
  reset-after-ask  says nothing to a peer's first slot ask and resets the link at
                   40 s, as a stock source that stopped reading does; later links
                   of that peer are served

Run as `evil_source.py <mode> <seconds> <server host:port> <address> <dir> <size>`.
It writes `a.bin`, `b.bin` and `links.txt` under <dir>, and prints one JSON object
per line: `stimulus` when the fault left, `closed` when the peer ended the link,
with `after_stimulus_s`, and `summary` at the end.
"""

import json
import os
import socket
import struct
import sys
import threading
import time

USER_HASH = bytes.fromhex("6e31c57e0e29440fb96dd2718e6f4a3d")
PART = 9_728_000
CHUNK = 10_240
state = {"stimulus_at": None, "first_close": None, "blocks": 0}
stalled = set()
lock = threading.Lock()


def emit(**row):
    row["t"] = round(time.time(), 3)
    print(json.dumps(row), flush=True)


def md4(data):
    def f(x, y, z):
        return (x & y) | (~x & z)

    def g(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def h(x, y, z):
        return x ^ y ^ z

    def rotl(v, n):
        v &= 0xFFFFFFFF
        return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

    length = len(data)
    data = data + b"\x80" + bytes((55 - length) % 64) + struct.pack("<Q", length * 8)
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for off in range(0, len(data), 64):
        x = struct.unpack_from("<16I", data, off)
        aa, bb, cc, dd = a, b, c, d
        for i in range(0, 16, 4):
            a = rotl(a + f(b, c, d) + x[i], 3)
            d = rotl(d + f(a, b, c) + x[i + 1], 7)
            c = rotl(c + f(d, a, b) + x[i + 2], 11)
            b = rotl(b + f(c, d, a) + x[i + 3], 19)
        for i in range(4):
            a = rotl(a + g(b, c, d) + x[i] + 0x5A827999, 3)
            d = rotl(d + g(a, b, c) + x[i + 4] + 0x5A827999, 5)
            c = rotl(c + g(d, a, b) + x[i + 8] + 0x5A827999, 9)
            b = rotl(b + g(c, d, a) + x[i + 12] + 0x5A827999, 13)
        for i in (0, 2, 1, 3):
            a = rotl(a + h(b, c, d) + x[i] + 0x6ED9EBA1, 3)
            d = rotl(d + h(a, b, c) + x[i + 8] + 0x6ED9EBA1, 9)
            c = rotl(c + h(d, a, b) + x[i + 4] + 0x6ED9EBA1, 11)
            b = rotl(b + h(c, d, a) + x[i + 12] + 0x6ED9EBA1, 15)
        a, b, c, d = [(p + q) & 0xFFFFFFFF for p, q in zip((a, b, c, d), (aa, bb, cc, dd))]
    return struct.pack("<4I", a, b, c, d)


class File:
    def __init__(self, path, size):
        if not os.path.exists(path):
            with open(path, "wb") as out:
                out.write(os.urandom(size))
        with open(path, "rb") as src:
            self.bytes = src.read()
        self.name = os.path.basename(path)
        self.parts = [md4(self.bytes[o : o + PART]) for o in range(0, size, PART)]
        if size % PART == 0:
            self.parts.append(md4(b""))
        self.hash = md4(b"".join(self.parts)) if len(self.parts) > 1 else self.parts[0]

    def link(self):
        return f"ed2k://|file|{self.name}|{len(self.bytes)}|{self.hash.hex().upper()}|/"


def frame(proto, opcode, payload):
    return struct.pack("<BIB", proto, len(payload) + 1, opcode) + payload


def tag_u32(name_id, value):
    return struct.pack("<BHBI", 0x03, 1, name_id, value)


def tag_str(name_id, value):
    raw = value.encode()
    return struct.pack("<BHB", 0x02, 1, name_id) + struct.pack("<H", len(raw)) + raw


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return buf


def hello_answer(client_id):
    tags = (
        tag_str(0x01, "evil-source")
        + tag_u32(0x11, 0x3C)
        + tag_u32(0xFB, (0 << 24) | (2 << 17) | (3 << 10) | (3 << 7))
    )
    payload = USER_HASH + struct.pack("<IHI", client_id, 4662, 3) + tags
    return frame(0xE3, 0x4C, payload + struct.pack("<IH", 0, 0))


def stimulus(kind):
    with lock:
        if state["stimulus_at"] is None:
            state["stimulus_at"] = time.time()
    emit(event="stimulus", kind=kind)


def block_frames(file, start, end):
    for at in range(start, end, CHUNK):
        stop = min(at + CHUNK, end)
        body = file.hash + struct.pack("<II", at, stop) + file.bytes[at:stop]
        yield frame(0xE3, 0x46, body)


def answer_hash_set(mode, file, payload):
    hashes = file.parts
    if mode == "hashset-corrupt":
        stimulus("hash set whose MD4 is not the file's")
        hashes = [bytes(16 * [i + 1]) for i in range(len(hashes))]
    elif mode == "hashset-count":
        stimulus("hash set one hash short")
        hashes = hashes[:-1]
    return frame(0xE3, 0x52, payload[:16] + struct.pack("<H", len(hashes)) + b"".join(hashes))


def serve_blocks(mode, conn, file, other, payload):
    starts = struct.unpack_from("<3I", payload, 16)
    ends = struct.unpack_from("<3I", payload, 28)
    for start, end in zip(starts, ends):
        if end <= start:
            continue
        if mode == "late-block":
            stimulus(f"block of {other.name} inside the slot of {file.name}")
            body = other.hash + struct.pack("<II", start, start + CHUNK)
            conn.sendall(frame(0xE3, 0x46, body + other.bytes[start : start + CHUNK]))
            return
        for piece in block_frames(file, start, end):
            conn.sendall(piece)
        with lock:
            state["blocks"] += 1


def reset_link(conn, peer):
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("<ii", 1, 0))
    conn.shutdown(socket.SHUT_RD)
    conn.close()
    emit(event="reset", peer=peer[0])


def serve(conn, peer, mode, files, client_id, is_server):
    by_hash = {file.hash: file for file in files}
    if not is_server:
        emit(event="connected", peer=peer[0])
    try:
        while True:
            proto, length = struct.unpack("<BI", recv_exact(conn, 5))
            body = recv_exact(conn, length)
            opcode, payload = body[0], body[1:]
            if not is_server:
                emit(event="received", peer=peer[0], frame=f"0x{proto:02x}/0x{opcode:02x}")
            if (proto, opcode) == (0xE3, 0x01):
                conn.sendall(hello_answer(client_id))
            elif (proto, opcode) == (0xE3, 0x58):
                name = by_hash[payload[:16]].name.encode()
                conn.sendall(frame(0xE3, 0x59, payload[:16] + struct.pack("<H", len(name)) + name))
            elif (proto, opcode) == (0xE3, 0x4F):
                conn.sendall(frame(0xE3, 0x50, payload[:16] + struct.pack("<H", 0)))
            elif (proto, opcode) == (0xE3, 0x51):
                conn.sendall(answer_hash_set(mode, by_hash[payload[:16]], payload))
            elif (proto, opcode) == (0xE3, 0x54):
                if mode == "reset-after-ask" and peer[0] not in stalled:
                    stalled.add(peer[0])
                    threading.Timer(40, reset_link, args=(conn, peer)).start()
                    continue
                conn.sendall(frame(0xE3, 0x55, b""))
            elif (proto, opcode) == (0xE3, 0x47):
                file = by_hash[payload[:16]]
                other = next(f for f in files if f is not file)
                serve_blocks(mode, conn, file, other, payload)
    except (ConnectionError, OSError) as error:
        if not is_server:
            at = state["stimulus_at"]
            after = round(time.time() - at, 3) if at else None
            with lock:
                if at and state["first_close"] is None:
                    state["first_close"] = after
            emit(event="closed", peer=peer[0], reason=str(error), after_stimulus_s=after)
    finally:
        conn.close()


def login_and_offer(server, files):
    sock = socket.create_connection(server, timeout=30)
    tags = tag_str(0x01, "evil-source") + tag_u32(0x11, 0x3C) + tag_u32(0x20, 0)
    sock.sendall(frame(0xE3, 0x01, USER_HASH + struct.pack("<IHI", 0, 4662, 3) + tags))
    client_id = None
    while client_id is None:
        _proto, length = struct.unpack("<BI", recv_exact(sock, 5))
        body = recv_exact(sock, length)
        if body[0] == 0x40:
            (client_id,) = struct.unpack_from("<I", body, 1)
    offer = struct.pack("<I", len(files))
    for file in files:
        offer += file.hash + struct.pack("<IHI", client_id, 4662, 2)
        offer += tag_str(0x01, file.name) + tag_u32(0x02, len(file.bytes))
    sock.sendall(frame(0xE3, 0x15, offer))
    emit(event="offered", client_id=client_id, high_id=client_id >= 0x01000000)

    def drain():
        try:
            while sock.recv(65536):
                pass
        except OSError:
            pass

    threading.Thread(target=drain, daemon=True).start()
    return sock


def accept_loop(listener, mode, files, client_id, server_ip):
    while True:
        try:
            conn, peer = listener.accept()
        except socket.timeout:
            continue
        threading.Thread(
            target=serve,
            args=(conn, peer, mode, files, client_id, peer[0] == server_ip),
            daemon=True,
        ).start()


def main():
    mode, seconds = sys.argv[1], float(sys.argv[2])
    host, port = sys.argv[3].rsplit(":", 1)
    server = (socket.gethostbyname(host), int(port))
    address, directory, size = sys.argv[4], sys.argv[5], int(sys.argv[6])
    files = [File(os.path.join(directory, name), size) for name in ("a.bin", "b.bin")]
    with open(os.path.join(directory, "links.txt"), "w") as out:
        out.write("".join(file.link() + "\n" for file in files))
    client_id = struct.unpack("<I", socket.inet_aton(address))[0]
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((address, 4662))
    listener.listen(8)
    listener.settimeout(1)
    threading.Thread(
        target=accept_loop, args=(listener, mode, files, client_id, server[0]), daemon=True
    ).start()
    emit(event="listening", mode=mode)
    link = login_and_offer(server, files)
    time.sleep(seconds)
    link.close()
    emit(
        event="summary",
        mode=mode,
        stimulus=state["stimulus_at"] is not None,
        closed_after_s=state["first_close"],
        blocks=state["blocks"],
    )


if __name__ == "__main__":
    main()
