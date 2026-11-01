# Preserve unknown well-formed tags and packets; reject only malformed bytes

## Context

eD2k decoding is strict about malformed bytes: a bad frame length or a truncated
payload is a typed error (ADR-0008). Well-formed input that rmule simply does not model
is a different case. aMule forks and community-modded servers and clients emit tag IDs
and opcodes outside the historical specification. If a closed decoder rejected them,
every such peer or server would force a hard disconnect, which breaks the
interoperability stance of ADR-0003 and turns every new opcode into a breaking change
for callers running against real networks.

## Decision

rmule preserves well-formed input it does not understand and rejects only malformed
bytes, at both levels of the eD2k TCP protocols:

- **Tags.** Decoders keep unknown well-formed tags rather than failing, so a new tag
  ID does not break decoding. Types that read tags keep the ones they do not type in an
  unknown-tag tail, as `ServerIdentity` does (ADR-0017).
- **Packets.** `ServerPacket` and `ClientPacket` (`rmule-ed2k`) and `PeerPacket`
  (`rmule-peer`) are closed enums of typed variants for every opcode rmule decodes,
  plus an `Unknown` catch-all that keeps a well-formed frame's opcode, its protocol
  byte where that matters, and its payload byte for byte.

Malformed frames still reject. Only the payload-interpretation step is
forward-compatible. The session layer surfaces an unknown packet as a diagnostic event
and keeps the connection alive. The Kad UDP codecs, where no connection is at stake,
report an unknown opcode as a typed error of its own, distinct from malformed bytes.

On a peer link, what a frame costs is stock's handler's ruling, not the decoder's. The
link closes where aMule's reader throws, since `PacketReceived`'s catch disconnects
(2.3.3 `ClientTCPSocket.cpp:2018-2047`), and stays where it returns or never reads: a
frame before the hello, an answer about a file the link never asked, a hash set or AICH
answer nobody asked for all close; a body stock does not look at, a cut block, a key or
signature it logs and drops all stay, parked as `Unknown` by shape alone. `frame_gate`
holds that ruling, leg by leg, and `tests/peer/peer_frame_legs.rs` is its table.

## Consequences

- An unknown opcode or tag from a fork or modded server is visible in diagnostics and
  captures instead of ending the session.
- Promoting an unknown opcode to a typed variant does not disturb any caller that
  already handles `Unknown`.
- The preserved bytes let a replay or an inspector account for everything that
  arrived.
