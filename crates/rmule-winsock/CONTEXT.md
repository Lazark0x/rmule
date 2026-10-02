# rmule-winsock

The one WinSock call rmule needs that no safe wrapper offers, kept in a crate of its own so every other crate keeps `unsafe_code = "forbid"`. It owns no socket: `rmule-net` binds every socket and hands each unconnected UDP one here once, at the bind. Off Windows its function does nothing.

## Language

**ICMP-reset switch**:
`SIO_UDP_CONNRESET` and `SIO_UDP_NETRESET` set to `FALSE` on a UDP socket. Windows otherwise answers a datagram that drew an ICMP port- or net-unreachable with an error on the socket's next receive, even on an unconnected socket and whichever peer the datagram went to; a run of them ends a receive pump. Linux and macOS never report these on an unconnected socket, so the switch makes Windows receive as they do. A connected socket does not take it: there the ICMP answer is the reply that ends the exchange early, on every platform.
_Avoid_: connreset fix, ICMP workaround, WSA hack

**The unsafe waiver**:
This crate's lint table relaxes `unsafe_code` to `deny`, and the one exported function waives it for a single `unsafe` block, the `WSAIoctl` call. `scripts/guards.sh` refuses a second block here and any `unsafe` outside this crate.
_Avoid_: unsafe module, FFI layer
