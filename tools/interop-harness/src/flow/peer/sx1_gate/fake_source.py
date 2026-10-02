#!/usr/bin/env python3
"""A fake eMule-family source that states one source-exchange version.

**A fake, not a counterparty**: stock aMule 2.3.3 and every bench body
advertise SX1 version 3 or SourceExchange2, so no stock body can state SX1
version 1; this script stands in for that one row and proves nothing about
interop. It answers rmule's hello with `CT_EMULE_VERSION` and a
`CT_EMULE_MISCOPTIONS1` whose SX1 nibble is the given version (no
`MISCOPTIONS2`, so no SourceExchange2, no multipacket), names the file,
states it complete, queues rmule, and records every frame rmule sends.

The fake logs in to the eD2k server itself and offers the file, High ID (it
answers the server's port test with the same hello answer), because rmule's
link reader takes no `sources` field: the server is where rmule finds it.

Run as `fake_source.py <sx1 version> <seconds> <server host:port> <file hash>[,<file hash>...]`;
several hashes are offered in the one `OP_OFFERFILES`. One JSON object per line on
stdout, closing with `sx1-gate-summary sx1=<v> requestsources=<n>
requestsources2=<n> connections=<n>`.
"""

import json
import socket
import struct
import sys
import threading
import time

USER_HASH = bytes.fromhex("8a31c57e0e29440fb96dd2718e6f4a3c")
counts = {"0xc5/0x81": 0, "0xc5/0x83": 0}
connections = 0
lock = threading.Lock()


def emit(**row):
    row["t"] = round(time.time(), 3)
    print(json.dumps(row), flush=True)


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


def hello_answer(sx1):
    # MiscOptions1: SX1 nibble at bits [12..16); nothing else claimed.
    misc1 = (sx1 & 0x0F) << 12
    tags = (
        tag_str(0x01, "sx1-gate-fake")
        + tag_u32(0x11, 0x3C)
        + tag_u32(0xFB, (0 << 24) | (2 << 17) | (3 << 10) | (3 << 7))
        + tag_u32(0xFA, misc1)
    )
    payload = USER_HASH + struct.pack("<IHI", 0x0A0B0C0D, 4662, 4) + tags + struct.pack("<IH", 0, 0)
    return frame(0xE3, 0x4C, payload)


def serve(conn, peer, sx1, counted, idle):
    global connections
    with lock:
        connections += counted
    try:
        conn.settimeout(idle)
        while True:
            proto, length = struct.unpack("<BI", recv_exact(conn, 5))
            body = recv_exact(conn, length)
            opcode, payload = body[0], body[1:]
            key = f"0x{proto:02x}/0x{opcode:02x}"
            with lock:
                if counted and key in counts:
                    counts[key] += 1
            emit(event="received", peer=f"{peer[0]}:{peer[1]}", frame=key, bytes=len(payload))
            if (proto, opcode) == (0xE3, 0x01):
                conn.sendall(hello_answer(sx1))
            elif (proto, opcode) == (0xE3, 0x58):
                name = b"sx1-gate.bin"
                conn.sendall(frame(0xE3, 0x59, payload[:16] + struct.pack("<H", len(name)) + name))
            elif (proto, opcode) == (0xE3, 0x4F):
                conn.sendall(frame(0xE3, 0x50, payload[:16] + struct.pack("<H", 0)))
            elif (proto, opcode) == (0xE3, 0x54):
                conn.sendall(frame(0xC5, 0x60, struct.pack("<H", 7) + bytes(10)))
    except (ConnectionError, OSError) as error:
        emit(event="closed", peer=f"{peer[0]}:{peer[1]}", reason=str(error))
    finally:
        conn.close()


def login_and_offer(server, file_hashes):
    """Log in to the server, offer the files, and keep the link drained."""
    sock = socket.create_connection(server, timeout=30)
    tags = tag_str(0x01, "sx1-gate-fake") + tag_u32(0x11, 0x3C) + tag_u32(0x20, 0)
    sock.sendall(frame(0xE3, 0x01, USER_HASH + struct.pack("<IHI", 0, 4662, 3) + tags))
    client_id = None
    while client_id is None:
        proto, length = struct.unpack("<BI", recv_exact(sock, 5))
        body = recv_exact(sock, length)
        if body[0] == 0x40:
            (client_id,) = struct.unpack_from("<I", body, 1)
    offer = struct.pack("<I", len(file_hashes))
    for file_hash in file_hashes:
        offer += file_hash + struct.pack("<IHI", client_id, 4662, 2)
        offer += tag_str(0x01, "sx1-gate.bin") + tag_u32(0x02, 9_728_000)
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


def main():
    sx1, seconds = int(sys.argv[1]), float(sys.argv[2])
    host, port = sys.argv[3].rsplit(":", 1)
    server = (socket.gethostbyname(host), int(port))
    file_hashes = [bytes.fromhex(h) for h in sys.argv[4].split(",")]
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", 4662))
    listener.listen(8)
    listener.settimeout(1)
    emit(event="listening", sx1=sx1)
    threading.Thread(target=accept_loop, args=(listener, sx1, server[0], seconds), daemon=True).start()
    link = login_and_offer(server, file_hashes)
    time.sleep(seconds)
    link.close()
    with lock:
        print(
            f"sx1-gate-summary sx1={sx1} requestsources={counts['0xc5/0x81']} "
            f"requestsources2={counts['0xc5/0x83']} connections={connections}",
            flush=True,
        )


def accept_loop(listener, sx1, server_ip, idle):
    while True:
        try:
            conn, peer = listener.accept()
        except socket.timeout:
            continue
        # The server's port test is answered, not counted.
        counted = peer[0] != server_ip
        threading.Thread(target=serve, args=(conn, peer, sx1, counted, idle), daemon=True).start()


if __name__ == "__main__":
    main()
