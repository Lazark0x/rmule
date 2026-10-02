#!/usr/bin/env python3
"""Offer-set stimulus for the announce-switch flow.

Asks a live eD2k server what it does with a client's offered files when the
client offers again, offers an empty list, and hangs up. A publisher link
offers files; a second link (the searcher, another user hash) asks a keyword
search after every step. What the probe sends is Stimulus; the server's
`OP_IDCHANGE` and `OP_SEARCHRESULT` payloads, retained as hex beside each
decoded row, are the evidence.

Run as `offer_probe.py <publisher|searcher> <server host:port> <sync dir>`,
one role per container: Lugdunum drops a second concurrent login from one
address, so the two links need two addresses. The roles step in lockstep
through marker files in the shared sync dir; searches stay six seconds
apart, clear of Lugdunum's same-second empty answer and its strike rule.

Output: one JSON object per line on stdout.
"""

import json
import os
import socket
import struct
import sys
import threading
import time
import zlib

OP_EDONKEY = 0xE3
OP_PACKED = 0xD4
OP_LOGINREQUEST = 0x01
OP_HELLO = 0x01
OP_HELLOANSWER = 0x4C
OP_OFFERFILES = 0x15
OP_SEARCHREQUEST = 0x16
OP_SEARCHRESULT = 0x33
OP_IDCHANGE = 0x40

KEYWORD = "annswprobe"
# Asymmetric identities and file hashes (never one repeated byte).
PUBLISHER_HASH = bytes.fromhex("5c1e8a3f02d94b7e6a0f1c2d3e4b5a69")
SEARCHER_HASH = bytes.fromhex("91a4d7e0336f4c0e8b2a57d1f60c9e43")
FILES = [
    (bytes.fromhex("0d3c9a1f7e2b48c5a6e1f04b9d27c813"), "annswprobe alpha.bin", 1_048_577),
    (bytes.fromhex("e47b02c95a1d4f36b8c07e2a91d5f460"), "annswprobe beta.bin", 2_097_155),
    (bytes.fromhex("7a26e5b1c04f4d98a3b61c0e5f2d8479"), "annswprobe gamma.bin", 3_145_733),
]


def emit(**row):
    row["t"] = round(time.time(), 3)
    print(json.dumps(row), flush=True)


def frame(opcode, payload):
    return struct.pack("<BIB", OP_EDONKEY, len(payload) + 1, opcode) + payload


def tag_str(name_id, value):
    raw = value.encode()
    return struct.pack("<BHB", 0x02, 1, name_id) + struct.pack("<H", len(raw)) + raw


def tag_u32(name_id, value):
    return struct.pack("<BHBI", 0x03, 1, name_id, value)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return buf


def read_frame(sock):
    proto, length = struct.unpack("<BI", recv_exact(sock, 5))
    body = recv_exact(sock, length)
    opcode, payload = body[0], body[1:]
    if proto == OP_PACKED:
        payload = zlib.decompress(payload)
    return proto, opcode, payload


def skip_tag(buf, pos):
    kind = buf[pos]
    pos += 1
    if kind & 0x80:
        kind &= 0x7F
        pos += 1
    else:
        (name_len,) = struct.unpack_from("<H", buf, pos)
        pos += 2 + name_len
    if 0x11 <= kind <= 0x20:
        return pos + (kind - 0x10)
    sizes = {0x03: 4, 0x04: 4, 0x08: 2, 0x09: 1, 0x0B: 8, 0x01: 16, 0x05: 1}
    if kind == 0x02:
        (n,) = struct.unpack_from("<H", buf, pos)
        return pos + 2 + n
    if kind == 0x07:
        (n,) = struct.unpack_from("<I", buf, pos)
        return pos + 4 + n
    if kind in sizes:
        return pos + sizes[kind]
    raise ValueError(f"tag type 0x{kind:02x} at {pos}")


def decode_results(payload):
    (count,) = struct.unpack_from("<I", payload, 0)
    pos = 4
    hashes = []
    for _ in range(count):
        hashes.append(payload[pos : pos + 16].hex())
        pos += 16 + 4 + 2
        (tags,) = struct.unpack_from("<I", payload, pos)
        pos += 4
        for _ in range(tags):
            pos = skip_tag(payload, pos)
    return hashes


def answer_port_test(listener, user_hash, port):
    """Answer the server's port test so the publisher logs in High ID."""
    while True:
        try:
            conn, peer = listener.accept()
        except OSError:
            return
        try:
            conn.settimeout(10)
            _, opcode, _ = read_frame(conn)
            if opcode == OP_HELLO:
                tags = tag_str(0x01, "annswprobe") + tag_u32(0x11, 0x3C)
                payload = (
                    user_hash
                    + struct.pack("<IHI", 0, port, 2)
                    + tags
                    + struct.pack("<IH", 0, 0)
                )
                conn.sendall(frame(OP_HELLOANSWER, payload))
                emit(event="port_test_answered", peer=f"{peer[0]}:{peer[1]}")
            time.sleep(1)
        except Exception as error:  # noqa: BLE001 - a failed test only costs the High ID
            emit(event="port_test_error", error=str(error))
        finally:
            conn.close()


class Link:
    def __init__(self, role, server, user_hash, port):
        self.role = role
        self.sock = socket.create_connection(server, timeout=30)
        tags = tag_str(0x01, f"annswprobe-{role}") + tag_u32(0x11, 0x3C) + tag_u32(0x20, 0)
        payload = user_hash + struct.pack("<IHI", 0, port, 3) + tags
        self.sock.sendall(frame(OP_LOGINREQUEST, payload))
        self.client_id = None
        self.tcp_flags = None
        deadline = time.time() + 30
        while self.client_id is None and time.time() < deadline:
            _, opcode, body = read_frame(self.sock)
            if opcode == OP_IDCHANGE:
                (self.client_id,) = struct.unpack_from("<I", body, 0)
                # A server that grants nothing may send the id alone.
                flags = struct.unpack_from("<I", body, 4)[0] if len(body) >= 8 else None
                self.tcp_flags = flags
                emit(
                    event="login",
                    role=role,
                    client_id=self.client_id,
                    high_id=self.client_id >= 0x01000000,
                    tcp_flags=None if flags is None else f"0x{flags:08x}",
                    idchange_hex=body.hex(),
                )
        if self.client_id is None:
            raise RuntimeError(f"{role}: no OP_IDCHANGE")
        self.port = port

    def offer(self, files, step):
        payload = struct.pack("<I", len(files))
        for file_hash, name, size in files:
            payload += file_hash + struct.pack("<IHI", self.client_id, self.port, 2)
            payload += tag_str(0x01, name) + tag_u32(0x02, size)
        self.sock.sendall(frame(OP_OFFERFILES, payload))
        emit(event="offered", step=step, entries=len(files), hashes=[f[0].hex() for f in files])

    def search(self, step):
        raw = KEYWORD.encode()
        self.sock.sendall(frame(OP_SEARCHREQUEST, b"\x01" + struct.pack("<H", len(raw)) + raw))
        deadline = time.time() + 20
        while time.time() < deadline:
            proto, opcode, body = read_frame(self.sock)
            if opcode == OP_SEARCHRESULT:
                found = decode_results(body)
                emit(
                    event="search",
                    step=step,
                    found=len(found),
                    hashes=sorted(found),
                    packed=proto == OP_PACKED,
                    result_hex=body.hex(),
                )
                return found
        emit(event="search", step=step, found=None, note="no OP_SEARCHRESULT in 20 s")
        return None

    def close(self):
        self.sock.close()


def wait_for(path, timeout=120):
    deadline = time.time() + timeout
    while not os.path.exists(path):
        if time.time() > deadline:
            raise TimeoutError(path)
        time.sleep(0.2)


def touch(path):
    with open(path, "w") as handle:
        handle.write(str(time.time()))


# (step, what the publisher does before the searcher asks, seconds to wait)
STEPS = [
    ("after_offer_two", "offer_two", 6),
    ("after_second_set", "offer_second_set", 6),
    ("after_empty_offer", "offer_empty", 6),
    ("after_offer_all", "offer_all_three", 6),
    ("after_disconnect_6s", "disconnect", 6),
    ("after_disconnect_36s", "wait", 30),
]


def listen(user_hash, port=4662):
    """Answer the server's port test on `port`, so the link logs in High ID."""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", port))
    listener.listen(4)
    threading.Thread(target=answer_port_test, args=(listener, user_hash, port), daemon=True).start()
    return port


def publisher(server, sync):
    link = Link("publisher", server, PUBLISHER_HASH, listen(PUBLISHER_HASH))
    sets = {
        "offer_two": FILES[:2],
        "offer_second_set": FILES[1:],
        "offer_empty": [],
        "offer_all_three": FILES,
    }
    for step, action, wait in STEPS:
        if action in sets:
            link.offer(sets[action], action)
        elif action == "disconnect":
            link.close()
            emit(event="publisher_closed")
        time.sleep(wait)
        touch(f"{sync}/{step}.ready")
        wait_for(f"{sync}/{step}.done")
    emit(event="done", role="publisher")


def searcher(server, sync):
    link = Link("searcher", server, SEARCHER_HASH, listen(SEARCHER_HASH))
    seen = {}
    for step, _, _ in STEPS:
        wait_for(f"{sync}/{step}.ready")
        seen[step] = link.search(step)
        touch(f"{sync}/{step}.done")
    link.close()
    alpha = FILES[0][0].hex()

    def found(step):
        return "none" if seen[step] is None else str(len(seen[step]))

    def flag(value):
        return "unknown" if value is None else str(value).lower()

    second = seen["after_second_set"]
    print(
        "offer-set-summary"
        f" searcher_tcp_flags={'none' if link.tcp_flags is None else hex(link.tcp_flags)}"
        f" baseline_found={found('after_offer_two')}"
        f" later_offer_additive={flag(None if second is None else alpha in second)}"
        f" after_empty_offer_found={found('after_empty_offer')}"
        f" after_disconnect_6s_found={found('after_disconnect_6s')}"
        f" after_disconnect_36s_found={found('after_disconnect_36s')}",
        flush=True,
    )
    emit(event="done", role="searcher")


def main():
    role, target, sync = sys.argv[1], sys.argv[2], sys.argv[3]
    host, port = target.rsplit(":", 1)
    server = (socket.gethostbyname(host), int(port))
    {"publisher": publisher, "searcher": searcher}[role](server, sync)


if __name__ == "__main__":
    main()
