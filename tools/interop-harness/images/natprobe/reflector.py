#!/usr/bin/env python3
"""The Reflector Probe's server half: two addresses x two UDP ports, plus the
optional Pinned-Port Sink.

Answers one request line with one reply line, from whichever of its four
(address, port) sockets the request asked for. That "answer from somewhere the
client never sent to" is the whole trick RFC 5780's filtering discovery turns
on, and the second address is what its mapping discovery turns on.

`NATPROBE_PINNED_PORT` adds one more socket, on the PRIMARY address only: the
gateway's pinned client port. RFC 5780's five tests address the reflector's own
two ports and therefore can never see a gateway rule keyed on the pinned port -
which is how an unscoped prerouting DNAT once survived four
`natgw-selfproof` runs. A datagram to this socket is the one thing that proves
the LAN can still reach the WAN on that port. It answers from itself whatever
change is asked for: `other()` is defined over the reflector's own port PAIR,
and the pinned port is not a member of it, so a change request here would have
no meaning to honour.

Wire protocol (ASCII, one datagram per line, no framing):

    request  RMULE-NATPROBE/1 REQ <txid> <change>
    reply    RMULE-NATPROBE/1 RES <txid> <mapped-ip> <mapped-port> \
                                  <from-ip> <from-port> <asked-ip> <asked-port>

`<change>` selects the reply socket relative to the one the request landed on:

    none   same address, same port          - RFC 5780 Test I / II / III
    port   same address, the other port     - the Address-Dependent Filtering test
    ip     the other address, same port
    both   the other address, the other port - the Endpoint-Independent Filtering test

`<mapped-ip> <mapped-port>` is the source the reflector observed, i.e. the
client's address after translation - the XOR-MAPPED-ADDRESS analogue. `<from-*>`
is the socket the reply actually left from, so the client can verify the
reflector honoured the change it asked for instead of inferring it. `<asked-*>`
echoes the socket the request arrived on, which is what makes a reply
attributable to one test when several are in flight.

The reflector never initiates and holds no state: every reply is a pure function
of the datagram that caused it, so a pcap of this bridge holds only traffic the
client actually provoked.
"""

import os
import selectors
import socket
import sys

PROTOCOL = "RMULE-NATPROBE/1"
CHANGES = ("none", "port", "ip", "both")


def bind(address, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((address, port))
    return sock


def other(value, pair):
    """The element of `pair` that is not `value`."""
    return pair[1] if value == pair[0] else pair[0]


def main():
    primary = os.environ.get("NATPROBE_PRIMARY_ADDR")
    secondary = os.environ.get("NATPROBE_SECONDARY_ADDR")
    if not primary or not secondary:
        print(
            "natprobe: NATPROBE_PRIMARY_ADDR and NATPROBE_SECONDARY_ADDR are required",
            file=sys.stderr,
        )
        return 2
    primary_port = int(os.environ.get("NATPROBE_PRIMARY_PORT", "3478"))
    secondary_port = int(os.environ.get("NATPROBE_SECONDARY_PORT", "3479"))
    pinned_port = os.environ.get("NATPROBE_PINNED_PORT")
    pinned_port = int(pinned_port) if pinned_port else None

    addresses = (primary, secondary)
    ports = (primary_port, secondary_port)

    sockets = {}
    selector = selectors.DefaultSelector()
    for address in addresses:
        for port in ports:
            sock = bind(address, port)
            sockets[(address, port)] = sock
            selector.register(sock, selectors.EVENT_READ, (address, port))
    if pinned_port is not None and (primary, pinned_port) not in sockets:
        sock = bind(primary, pinned_port)
        sockets[(primary, pinned_port)] = sock
        selector.register(sock, selectors.EVENT_READ, (primary, pinned_port))

    print(
        "rmule-natprobe-ready addresses={},{} ports={},{} pinned_port={}".format(
            primary, secondary, primary_port, secondary_port, pinned_port or "-"
        ),
        flush=True,
    )

    while True:
        for key, _ in selector.select():
            landed_address, landed_port = key.data
            payload, source = key.fileobj.recvfrom(2048)
            reply = respond(
                payload, source, landed_address, landed_port, addresses, ports, pinned_port
            )
            if reply is None:
                continue
            reply_socket, line = reply
            sockets[reply_socket].sendto(line.encode("ascii"), source)


def respond(payload, source, landed_address, landed_port, addresses, ports, pinned_port=None):
    """The reply socket and line for one request, or None for a malformed one.

    A malformed datagram is dropped in silence on purpose: the reflector sits on
    a bench bridge that also carries eD2k and Kad traffic, and an error reply to
    a stray datagram would put bytes on the wire that no test asked for.
    """
    try:
        fields = payload.decode("ascii").strip().split()
    except UnicodeDecodeError:
        return None
    if len(fields) != 4 or fields[0] != PROTOCOL or fields[1] != "REQ":
        return None
    txid, change = fields[2], fields[3]
    if change not in CHANGES:
        return None

    reply_address = landed_address
    reply_port = landed_port
    # The Pinned-Port Sink answers from itself, whatever was asked: its port is
    # not a member of the reflector's own pair, so `other()` would name a socket
    # this request has no relationship to.
    if landed_port == pinned_port:
        change = "none"
    if change in ("ip", "both"):
        reply_address = other(landed_address, addresses)
    if change in ("port", "both"):
        reply_port = other(landed_port, ports)

    line = "{} RES {} {} {} {} {} {} {}\n".format(
        PROTOCOL,
        txid,
        source[0],
        source[1],
        reply_address,
        reply_port,
        landed_address,
        landed_port,
    )
    return (reply_address, reply_port), line


if __name__ == "__main__":
    sys.exit(main() or 0)
