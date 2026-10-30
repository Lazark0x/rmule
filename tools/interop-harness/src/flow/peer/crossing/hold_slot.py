#!/usr/bin/env python3
"""Hold rmule's upload slot for as long as the reask leg needs.

Stimulus for `peer-crossing --leg serve-reask`. A stock aMule cannot hold a
slot through a reask period: capped low, it stops reading and rmule releases it
as silent (run `1793368694`). This client says its hello, asks for the file,
takes the grant, and asks one block every `ASK_EVERY` seconds, so the slot
moves and stays. Nothing about the race under test touches it.

Run as `hold_slot.py <rmule host:port> <file hash hex>`; ends at SIGTERM.
"""

import signal
import socket
import struct
import sys
import time

OP_EDONKEY = 0xE3
OP_HELLO = 0x01
OP_REQUESTPARTS = 0x47
OP_SETREQFILEID = 0x4F
OP_STARTUPLOADREQ = 0x54
OP_ACCEPTUPLOADREQ = 0x55
OP_REQUESTFILENAME = 0x58

USER_HASH = bytes.fromhex("6b3e19d2a0c74f58913e2d7a5c0b84f2")
LISTEN_PORT = 4662
BLOCK = 10240
ASK_EVERY = 15


def frame(opcode, payload):
    return struct.pack("<BIB", OP_EDONKEY, len(payload) + 1, opcode) + payload


def hello():
    tags = struct.pack("<BHB", 0x02, 1, 0x01) + struct.pack("<H", 9) + b"hold-slot"
    tags += struct.pack("<BHBI", 0x03, 1, 0x11, 0x3C)
    payload = b"\x10" + USER_HASH + struct.pack("<IHI", 0, LISTEN_PORT, 2) + tags
    return frame(OP_HELLO, payload + struct.pack("<IH", 0, 0))


def frames(sock):
    """Every frame read off `sock` until it goes quiet, as opcodes."""
    buf = b""
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            raise SystemExit("rmule closed the link")
        buf += chunk
        while len(buf) >= 6:
            size = struct.unpack_from("<I", buf, 1)[0]
            if len(buf) < 5 + size:
                break
            yield buf[5]
            buf = buf[5 + size :]


def main():
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    host, port = sys.argv[1].rsplit(":", 1)
    file_hash = bytes.fromhex(sys.argv[2])
    sock = socket.create_connection((socket.gethostbyname(host), int(port)), timeout=30)
    sock.sendall(hello())
    sock.settimeout(30)
    time.sleep(1)
    sock.sendall(
        frame(OP_REQUESTFILENAME, file_hash)
        + frame(OP_SETREQFILEID, file_hash)
        + frame(OP_STARTUPLOADREQ, file_hash)
    )
    read = frames(sock)
    while next(read) != OP_ACCEPTUPLOADREQ:
        pass
    print("granted", flush=True)
    sock.settimeout(1)
    start = 0
    while True:
        ranges = struct.pack("<IIIIII", start, 0, 0, start + BLOCK, 0, 0)
        sock.sendall(frame(OP_REQUESTPARTS, file_hash + ranges))
        start += BLOCK
        deadline = time.time() + ASK_EVERY
        while time.time() < deadline:
            try:
                next(read)
            except socket.timeout:
                pass


if __name__ == "__main__":
    main()
