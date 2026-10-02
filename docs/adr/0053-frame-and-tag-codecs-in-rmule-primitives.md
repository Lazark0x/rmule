# Frame and tag codecs live in rmule-primitives, with one packed-frame mechanism and per-surface policy

## Context

The eD2k **Packet Frame** (`Packet`, `PacketProtocol`: protocol byte `0xE3`, `0xC5` or
`0xD4`, then a little-endian length) and the tag codec (`Tag`, `TagName`,
`TagNameEncoding`) are shared by `rmule-ed2k` and `rmule-peer`, which each add only their
own opcode-to-variant table and an `Unknown` catch-all (ADR-0018). Kad does not use this
frame: `KadEnvelope` has a two-byte header, no length field and its own protocol bytes
(`0xE4`, and `0xE5` for zlib-packed).

`0xD4` (`OP_PACKEDPROT`) is a zlib-packed frame whose meaning depends on context.
Servers send packed search, source and welcome packets; clients send packed
`OP_OFFERFILES` when the server grants compression; peers pack source-exchange answers.
The first live server welcome capture carried one
(`crates/rmule-ed2k/tests/fixtures/server/captured/welcome-burst-2026-05-17/04_undecoded_tail.bin`
inflates to another `OP_SERVERMESSAGE`).

aMule's complete TCP `PackPacket()` call-site set is source-exchange answers on the peer
side and `OP_OFFERFILES` on the server side. It always packs an `OP_ANSWERSOURCES` above
354 bytes
([KnownFile.cpp#L1072](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/KnownFile.cpp#L1072),
[PartFile.cpp#L2681](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/PartFile.cpp#L2681)),
so a peer that cannot inflate loses exactly the large source lists of popular files.
`crates/rmule-peer/tests/fixtures/source_exchange/captured/amule-233-packed-answer-20260728`
holds such a packed answer from aMule.

## Decision

**Frame and tag codecs stay in `rmule-primitives`**, beside each other, with no separate
codec crate. Kad keeps its own envelope and its own `0xE5` handling in `rmule-kad`.

**One packed-frame mechanism, all policy per surface.** `rmule_primitives::packed_frame`
provides:

- `inflate(packet, cap, target_protocol)`: single-shot zlib inflate under a flat byte
  ceiling, independent of the compression ratio, returning a plain `Packet` re-attributed
  to the caller's protocol with the same opcode. Nested `0xD4` is impossible by
  construction.
- `pack_if_smaller(packet)`: zlib level 9 (aMule's `Z_BEST_COMPRESSION`,
  [Packet.cpp#L254](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/Packet.cpp#L254)),
  emitting `0xD4` with the same opcode only when the compressed body is strictly smaller;
  otherwise the packet goes plain, as aMule falls back.

`Packet::decode` never inflates. The frame layer keeps raw compressed wire bytes for
byte-exact captures, and each protocol session inflates into the logical packet it
dispatches. `flate2` is a private dependency and never appears in a public API.

**Server policy (`rmule-ed2k`).** Inbound cap `SERVER_COMPRESSED_FRAME_LIMIT` = 250 000,
matching aMule's server path, re-attributed to eDonkey. `OP_OFFERFILES` is
pack-attempted whenever the session's server grants include `SRV_TCPFLG_COMPRESSION`
(ADR-0047), with no size threshold, as aMule always tries
([SharedFileList.cpp#L748](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/SharedFileList.cpp#L748)).
Before the grant is known, nothing is packed.

**Peer policy (`rmule-peer`).** Inbound cap `PEER_COMPRESSED_FRAME_LIMIT` = 50 000
(aMule's default,
[Packet.h#L60](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/Packet.h#L60)),
always re-attributed to eMule as aMule does after unpacking
([Packet.cpp#L301](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/Packet.cpp#L301)),
then decoded normally. A source-exchange answer above `PEER_PACK_THRESHOLD` = 354 bytes
is pack-attempted. Nothing else is packed on either surface: searches, logins and upload
traffic stay plain.

**A failed inflate is not terminal.** aMule logs and drops the packet and keeps the
connection
([ClientTCPSocket.cpp#L1982](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientTCPSocket.cpp#L1982)).
Each session raises `CompressedFrameSkipped { opcode, compressed_len, reason }`
(`Ed2kEvent` or `PeerEvent`) with a typed `CompressedFrameSkipReason`
(`InflateFailed`, `DecompressedSizeLimitExceeded { limit }`) and stays open. Captures
record the event with its reason label, so the evidence explains why a packed frame
produced no logical packet.

## Consequences

- aMule's 50 000 is not a checked limit but a fixed output buffer of
  `min(size * 10 + 300, 50000)`
  ([Packet.cpp#L275](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/Packet.cpp#L275)),
  so it drops high-ratio frames under the cap that rmule accepts. The divergence is
  receive-side only, never visible in what rmule sends, and strictly more tolerant of
  legal zlib.
- The deterministic tier covers a golden packed `0x82` inflating to received sources,
  corrupt zlib and over-cap frames producing a skip with the session still open,
  `pack_if_smaller` round trips including the incompressible fallback, and
  `OP_OFFERFILES` packing gated both ways on the grant.
- The server-emit proof is the server's reaction to a packed `OP_OFFERFILES` after an
  `OP_IDCHANGE` that grants compression, against a server that really advertises the
  flag; the flag is never faked.

## Considered options

- **A `rmule-codec` or compression crate.** Rejected: no consumer needs one, and it would
  sever `Tag` from its `TagValue` and `Ed2kText` neighbours.
- **Folding `KadEnvelope` under the shared frame.** Rejected: an incompatible wire shape
  that would hide a two-protocol branch behind one seam.
- **A zlib helper duplicated in each protocol crate.** Rejected: two codecs drift apart.
- **Auto-inflating in `Packet::decode` or the transport framing.** Rejected: it loses the
  raw bytes captures need, and skip events belong to the surface session; transports
  stay byte pumps.
- **Emulating aMule's `min(size * 10 + 300, 50000)` buffer.** Rejected: it replicates an
  allocation artifact, not a protocol rule, and eMule's ceiling differs anyway.
- **Trying eMule, then eDonkey dispatch after inflating.** Rejected: no client does it,
  and aMule hard-codes the extended dispatch.
- **A size threshold on the `OP_OFFERFILES` pack attempt.** Rejected: aMule packs on the
  grant alone, and `pack_if_smaller` already prevents bloated frames.
