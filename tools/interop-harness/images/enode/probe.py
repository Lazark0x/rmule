#!/usr/bin/env python3
"""eD2k stimulus probe for the eNode feasibility spike.

This is a *stimulus* only: it sends minimal, standard eD2k client packets and
reports the bytes eNode (the independent server counterparty) sends back. eNode's
responses are the evidence; this script authors no server (ADR-0045). The formal
crypt-ping and global-search byte captures use rmule-tools as the client-under-test — this probe just
answers the feasibility question "does eNode emit the axis-relevant bytes at
all", which the emulated Lugdunum eserver does not.

Axes:
  A  crypt advert   : UDP 0x96 GLOBSERVSTATREQ -> 0x97 (read SRV UDP flags,
                      obfuscation ports, serverKey)
  B  concurrent >=12: N TCP logins offering one file hash -> TCP 0x19 GETSOURCES
                      -> 0x42 FOUNDSOURCES count (no concurrent-login drop)
  C  global search  : TCP OFFERFILES then UDP 0x98 GLOBSEARCHREQ -> 0x99 result
"""
import socket
import struct
import sys
import time

E3 = 0xE3
OP_LOGINREQUEST = 0x01
OP_OFFERFILES = 0x15
OP_GETSOURCES = 0x19
OP_FOUNDSOURCES = 0x42
OP_IDCHANGE = 0x40
OP_GLOBSERVSTATREQ = 0x96
OP_GLOBSERVSTATRES = 0x97
OP_GLOBSEARCHREQ = 0x98
OP_GLOBSEARCHRES = 0x99
TYPE_STRING = 0x02
TYPE_UINT32 = 0x03
TAG_NAME = 0x01
TAG_SIZE = 0x02


def tcp_frame(op, body):
    return struct.pack("<BIB", E3, len(body) + 1, op) + body


def udp_frame(op, body):
    return struct.pack("<BB", E3, op) + body


def tag_string(code, s):
    b = s.encode()
    return struct.pack("<BHB", TYPE_STRING, 1, code) + struct.pack("<H", len(b)) + b


def tag_uint32(code, v):
    return struct.pack("<BHB", TYPE_UINT32, 1, code) + struct.pack("<I", v)


def login_body(client_hash, port):
    # hash(16) + id(u32=0) + port(u16) + tags(count u32 = 0)
    return client_hash + struct.pack("<IHI", 0, port, 0)


def offer_body(file_hash, size, name):
    tags = tag_string(TAG_NAME, name) + tag_uint32(TAG_SIZE, size)
    # count(u32=1) + hash(16) + id(u32 complete) + port(u16 complete) + tags(count + tags)
    return (
        struct.pack("<I", 1)
        + file_hash
        + struct.pack("<IH", 0xFBFBFBFB, 0xFBFB)
        + struct.pack("<I", 2)
        + tags
    )


def read_frames(sock, seconds):
    sock.settimeout(seconds)
    buf = b""
    frames = []
    end = time.time() + seconds
    while time.time() < end:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        while len(buf) >= 5:
            proto, size = struct.unpack("<BI", buf[:5])
            if len(buf) < 5 + size:
                break
            op = buf[5]
            body = buf[6 : 5 + size]
            frames.append((op, body))
            buf = buf[5 + size :]
    return frames


def hexb(b):
    return b.hex()


def axis_a(ip, udp_port):
    print("=== AXIS A: crypt advert (UDP 0x96 -> 0x97) ===")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    s.sendto(udp_frame(OP_GLOBSERVSTATREQ, struct.pack("<I", 0xAABBCCDD)), (ip, udp_port))
    try:
        data, _ = s.recvfrom(4096)
    except socket.timeout:
        print("  RESULT: NO 0x97 answer (timeout)")
        return
    print("  0x97 raw:", hexb(data))
    # E3 97 challenge(4) clients(4) files(4) max(4) soft(4) hard(4) udpflags(4)
    #   lowid(4) udpObfPort(2) tcpObfPort(2) serverKey(4)
    if len(data) >= 2 and data[0] == E3 and data[1] == OP_GLOBSERVSTATRES:
        p = 2
        challenge, clients, files, mx, soft, hard, udpflags, lowid = struct.unpack_from("<8I", data, p)
        p += 32
        udp_obf, tcp_obf = struct.unpack_from("<2H", data, p)
        p += 4
        (serverkey,) = struct.unpack_from("<I", data, p)
        print("  udp_flags=0x%x  UDP_OBFUSCATION(0x200)=%s  TCP_OBFUSCATION(0x400)=%s"
              % (udpflags, bool(udpflags & 0x200), bool(udpflags & 0x400)))
        print("  obf_udp_port=%d  obf_tcp_port=%d  serverKey=0x%x" % (udp_obf, tcp_obf, serverkey))
        print("  RESULT: %s" % ("ADVERT-PRESENT" if udpflags & 0x200 else "no udp obf bit"))
    else:
        print("  RESULT: unexpected opcode")
    s.close()


def axis_c(ip, tcp_port, udp_port):
    print("=== AXIS C: global UDP search (offer then 0x98 -> 0x99) ===")
    name = "spikefileC.dat"
    fhash = bytes(range(16))
    size = 4096
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, tcp_port))
    s.sendall(tcp_frame(OP_LOGINREQUEST, login_body(bytes([0xC1] * 16), 4662)))
    read_frames(s, 4)  # drain login replies (idchange etc.)
    s.sendall(tcp_frame(OP_OFFERFILES, offer_body(fhash, size, name)))
    time.sleep(1)
    us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    us.settimeout(5)
    search_body = struct.pack("<BH", 0x01, len(name)) + name.encode()
    us.sendto(udp_frame(OP_GLOBSEARCHREQ, search_body), (ip, udp_port))
    got = []
    try:
        while True:
            data, _ = us.recvfrom(8192)
            got.append(data)
    except socket.timeout:
        pass
    if got:
        for d in got:
            op = d[1] if len(d) > 1 else 0
            print("  datagram op=0x%x len=%d %s" % (op, len(d), hexb(d[:48])))
        print("  RESULT: 0x99 ANSWERED (%d datagram(s))" % len(got))
    else:
        print("  RESULT: NO 0x99 (timeout) -- server did not answer global search")
    us.close()
    s.close()


def axis_b(ip, tcp_port, n):
    print("=== AXIS B: %d concurrent logins offering one hash -> getsources ===" % n)
    fhash = bytes([0xB0] * 16)
    size = 8192
    conns = []
    for i in range(n):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((ip, tcp_port))
        except OSError as e:
            print("  login %d connect failed: %s" % (i, e))
            continue
        chash = bytes([i + 1] + [0x0B] * 15)
        s.sendall(tcp_frame(OP_LOGINREQUEST, login_body(chash, 4700 + i)))
        conns.append(s)
    time.sleep(3)  # let logins settle (each does a 2s back-connect firewall probe)
    logged = 0
    for s in conns:
        for op, body in read_frames(s, 2):
            if op == OP_IDCHANGE:
                logged += 1
                break
    print("  logins accepted (saw IDCHANGE): %d / %d" % (logged, n))
    for i, s in enumerate(conns):
        s.sendall(tcp_frame(OP_OFFERFILES, offer_body(fhash, size, "spikefileB.dat")))
    time.sleep(2)
    q = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    q.connect((ip, tcp_port))
    q.sendall(tcp_frame(OP_LOGINREQUEST, login_body(bytes([0xBB] * 16), 4799)))
    read_frames(q, 3)
    q.sendall(tcp_frame(OP_GETSOURCES, fhash + struct.pack("<I", size)))
    count = None
    for op, body in read_frames(q, 5):
        if op == OP_FOUNDSOURCES and len(body) >= 17:
            count = body[16]
            print("  0x42 FOUNDSOURCES: hash=%s count=%d" % (hexb(body[:16]), count))
    if count is None:
        print("  RESULT: no 0x42 answer")
    else:
        print("  RESULT: server held/returned %d concurrent sources for one hash" % count)
    q.close()
    for s in conns:
        s.close()


import hashlib

MAGIC_UDP_SYNC_SERVER = 0x13EF24D5
MAGIC_UDP_SERVERCLIENT = 0xA5  # server -> client key material
MAGIC_UDP_CLIENTSERVER = 0x6B  # client -> server key material


def rc4_ksa(key):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (key[i % len(key)] + s[i] + j) % 256
        s[i], s[j] = s[j], s[i]
    return {"s": s, "x": 0, "y": 0}


def rc4_crypt(st, data):
    s, x, y = st["s"], st["x"], st["y"]
    out = bytearray()
    for b in data:
        x = (x + 1) % 256
        y = (s[x] + y) % 256
        s[x], s[y] = s[y], s[x]
        out.append(b ^ s[(s[x] + s[y]) % 256])
    st["x"], st["y"] = x, y
    return bytes(out)


def udp_key(server_key, magic, index):
    seed = struct.pack("<I", server_key) + bytes([magic]) + struct.pack("<H", index)
    return rc4_ksa(hashlib.md5(seed).digest())


def axis_a_crypt(ip, obf_udp_port, server_key=0x12345678):
    # Axis A "SPEAK": send an OBFUSCATED 0x96 status ping to the obfuscated UDP
    # port and decrypt the reply -- the exact crypt_ping_answered fact Lugdunum
    # fails (advert-only). Server-UDP obfuscation scheme per eNode udpcrypt.js /
    # eMule EncryptedDatagramSocket.
    print("=== AXIS A (SPEAK): obfuscated crypt-ping (UDP %d) ===" % obf_udp_port)
    client_key = 0x1234
    inner = udp_frame(OP_GLOBSERVSTATREQ, struct.pack("<I", 0x11223344))
    plaintext = struct.pack("<IB", MAGIC_UDP_SYNC_SERVER, 0) + inner
    enc = rc4_crypt(udp_key(server_key, MAGIC_UDP_CLIENTSERVER, client_key), plaintext)
    packet = bytes([0x00]) + struct.pack("<H", client_key) + enc
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(6)
    s.sendto(packet, (ip, obf_udp_port))
    try:
        data, _ = s.recvfrom(4096)
    except socket.timeout:
        print("  RESULT: NO obfuscated answer (timeout)")
        s.close()
        return
    # reply = [randproto][randomKey u16][ RC4(sendKey)( SYNC + pad + 0x97pkt ) ]
    random_key = struct.unpack_from("<H", data, 1)[0]
    dec = rc4_crypt(udp_key(server_key, MAGIC_UDP_SERVERCLIENT, random_key), data[3:])
    sync = struct.unpack_from("<I", dec, 0)[0]
    if sync != MAGIC_UDP_SYNC_SERVER:
        print("  RESULT: reply did not decrypt (sync=0x%x) -- crypt mismatch" % sync)
        s.close()
        return
    pad = dec[4]
    inner_reply = dec[5 + pad:]
    op = inner_reply[1] if len(inner_reply) > 1 else 0
    print("  decrypted inner op=0x%x  raw=%s" % (op, inner_reply[:24].hex()))
    print("  RESULT: %s" % ("CRYPT-PING ANSWERED (obfuscated 0x97 decrypted)"
                            if op == OP_GLOBSERVSTATRES else "unexpected inner op"))
    s.close()


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    ip = sys.argv[2] if len(sys.argv) > 2 else "203.0.113.10"
    tcp_port = int(sys.argv[3]) if len(sys.argv) > 3 else 4661
    udp_port = int(sys.argv[4]) if len(sys.argv) > 4 else 4665
    obf_udp_port = int(sys.argv[5]) if len(sys.argv) > 5 else 4677
    if mode in ("all", "a"):
        axis_a(ip, udp_port)
        print()
    if mode in ("all", "crypt"):
        axis_a_crypt(ip, obf_udp_port)
        print()
    if mode in ("all", "c"):
        axis_c(ip, tcp_port, udp_port)
        print()
    if mode in ("all", "b"):
        axis_b(ip, tcp_port, 14)
