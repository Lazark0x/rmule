#!/usr/bin/env python3
"""Two connections, one client: does the second hello close the first socket?

Stimulus for the `two-hellos` leg. From one address, the probe opens a first
peer-TCP connection to a High-ID aMule and says `OP_HELLO` as user hash H on
listen port P; then a second connection says the same hello. Stock aMule
2.3.3's `CClientList::AttachToAlreadyKnown` (ClientList.cpp:386-403) deletes
the known client's socket when the new hello matches it by IP and port. The
control repeats the pair with the second hello naming another port, which the
same function refuses instead (it keeps the first socket).

Run as `hello_twice.py <amule host:port> <same-port|other-port>`, each leg from
an address of its own: a second user hash from an address aMule already
tracks is banned for "Userhash changed" (BaseClient.cpp:687), which would
decide the control for it. What the probe sends is Stimulus;
whether aMule closed the first socket (EOF or reset on it) and what each
connection received are the evidence. One JSON object per line on stdout.
"""

import json
import socket
import struct
import sys
import time

OP_EDONKEY = 0xE3
OP_HELLO = 0x01
OP_HELLOANSWER = 0x4C

# Asymmetric test identities (never one repeated byte).
USER_HASH = bytes.fromhex("6b3e19d2a0c74f58913e2d7a5c0b84f1")
CONTROL_HASH = bytes.fromhex("2f8c61e9b3d04a7795c1e4082a6fd3b5")


def emit(**row):
    row["t"] = round(time.time(), 3)
    print(json.dumps(row), flush=True)


def hello(user_hash, port):
    tags = struct.pack("<BHB", 0x02, 1, 0x01) + struct.pack("<H", 10) + b"two-hellos"
    tags += struct.pack("<BHBI", 0x03, 1, 0x11, 0x3C)
    payload = b"\x10" + user_hash + struct.pack("<IHI", 0, port, 2) + tags + struct.pack("<IH", 0, 0)
    return struct.pack("<BIB", OP_EDONKEY, len(payload) + 1, OP_HELLO) + payload


def drain(sock, seconds):
    """Read what arrives for `seconds`; return (opcodes, state)."""
    sock.settimeout(0.5)
    deadline = time.time() + seconds
    buf = b""
    state = "open"
    while time.time() < deadline:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            continue
        except ConnectionResetError:
            state = "reset"
            break
        if not chunk:
            state = "eof"
            break
        buf += chunk
    opcodes = []
    pos = 0
    while pos + 6 <= len(buf):
        proto, length = struct.unpack_from("<BI", buf, pos)
        opcodes.append(f"0x{proto:02x}/0x{buf[pos + 5]:02x}")
        pos += 5 + length
    return opcodes, state


def pair(target, label, first, second):
    one = socket.create_connection(target, timeout=10)
    one.sendall(hello(*first))
    got, state = drain(one, 3)
    emit(leg=label, conn=1, event="hello", port=first[1], received=got, state=state)
    two = socket.create_connection(target, timeout=10)
    two.sendall(hello(*second))
    got2, state2 = drain(two, 3)
    emit(leg=label, conn=2, event="hello", port=second[1], received=got2, state=state2)
    after, after_state = drain(one, 6)
    emit(leg=label, conn=1, event="after_second_hello", received=after, state=after_state)
    emit(
        leg=label,
        event="verdict",
        first_socket_closed=after_state in ("eof", "reset"),
        second_answered=any(op.endswith(f"/0x{OP_HELLOANSWER:02x}") for op in got2),
    )
    one.close()
    two.close()


def main():
    host, port = sys.argv[1].rsplit(":", 1)
    target = (socket.gethostbyname(host), int(port))
    leg = sys.argv[2]
    if leg == "same-port":
        pair(target, leg, (USER_HASH, 4662), (USER_HASH, 4662))
    elif leg == "other-port":
        pair(target, leg, (CONTROL_HASH, 4662), (CONTROL_HASH, 4670))
    else:
        raise SystemExit(f"unknown leg {leg}")


if __name__ == "__main__":
    main()
