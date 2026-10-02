# Peer multipacket: one semantic core, bundled and separate wire shapes

## Context

`OP_MULTIPACKET` (`0x92`) and `OP_MULTIPACKET_EXT` (`0xA4`) bundle a peer's per-file
negotiation (name, part status, sources, AICH root) into one request, answered by one
`OP_MULTIPACKETANSWER` (`0x93`). It collapses the dominant chatter on every new source
into one round trip per direction.

Wire facts, from aMule 2.3.3:

- The request is `<hash16>` (`0xA4` inserts `<size8>`) followed by an **unframed**
  sub-opcode stream: `0x58` name request (with a part-status trailer when the sender's
  negotiated extended-requests level is above 0), `0x4F` set-req-id (empty), `0x81` or
  `0x83` source request (SX2 adds `<ver1><opts2>`), and `0x9E` AICH-root request
  ([DownloadClient.cpp#L267](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/DownloadClient.cpp#L267)).
- The answer is `<hash16>` plus subs `0x59` (name), `0x50` (part status) and `0x9D`
  (master hash). Each sub payload is the standalone payload minus its leading hash, and
  aMule funnels both forms into the same handlers
  ([ClientTCPSocket.cpp#L1041](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientTCPSocket.cpp#L1041),
  [#L1192](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientTCPSocket.cpp#L1192)).
- aMule's `SendFileRequest` opens every file, one part or many, with one bundle toward
  a MultiPacket peer: `0x58`, then `0x4F` only for more than one part, then the source
  ask, then `0x9E` when it wants the AICH root. For a one-part file the name answer is
  the whole probe: a complete source, with no `OP_FILESTATUS` (`ProcessFileInfo`).
  aMule's standalone `OP_REQUESTSOURCES2` arm accepts 16 bytes only
  (`ClientTCPSocket.cpp` L1528-L1535 @ kno `ab483654`), so a standalone 19-byte SX2 ask
  makes it throw and drop the link.
- aMule never packs `0x93` (ADR-0053).

Evidence: `crates/rmule-peer/tests/fixtures/multipacket/captured/` holds aMule's forward
answer, its answer to a one-part bundle (name only) and to an extended-requests level 1
bundle, and emule-qt's level 1 name ask;
`crates/rmule-peer/tests/fixtures/reverse_serve/captured/amule-233-serve-consume-20260726`
holds aMule's request to rmule as a server.

## Decision

**Full symmetric support: one semantic core, two wire shapes.**

- **Codec.** `rmule_peer::multipacket` has `MultiPacketRequest { file_hash, file_size,
  items }` and `MultiPacketAnswer { file_hash, items }` over `RequestItem` and
  `AnswerItem`, with a dedicated sub-opcode walker and composer. It does not re-enter the
  standalone packet codecs: sub payloads are hash-stripped fragments, not packets.
- **Consume.** Each decoded item fans into the existing standalone handler, so a bundle
  yields exactly the state and events the separate packets would. There is no parallel
  multipacket state machine.
- **Serve.** The `0x93` is composed from the same serve callbacks that answer standalone
  requests. A file not shared, a large file the peer cannot handle, or a `size8`
  mismatch gets a plain `OP_FILEREQANSNOFIL` (`0x48`) and no bundle. The AICH sub is
  omitted unless the hashset is complete. Source subs are routed to source-exchange
  serving (ADR-0055), which answers them as a separate `0x82`, never bundled, as aMule
  does. An answer that would hold only the hash is not sent.
- **Emit.** Bundle when the peer advertised MultiPacket (`MiscOptions1` bit 1); frame as
  `0xA4`, always with `size8`, when it advertised ExtMultiPacket (`MiscOptions2` bit 5),
  as aMule selects on that bit alone. The items are the fold of rmule's per-packet send
  decisions, in aMule's order: `0x58` always (with the verified-part bitmap at the
  negotiated extended-requests level, ADR-0047), `0x4F` only for more than one part, the
  source ask per the source-exchange policy, `0x9E` when the download lacks an AICH root
  (ADR-0038). A non-MultiPacket peer gets the same decisions as separate packets, and a
  standalone source ask is always the 16-byte `0x81` (ADR-0055).
- **One-part files.** Every file opens with a file request. For a one-part file the
  probe's bitmap is known before the answer, the name answer completes it, and a late or
  unsolicited `OP_FILESTATUS` folds onto an already-available probe's bitmap rather than
  reopening it, as aMule's `ProcessFileStatus` only updates availability once a file is
  known.
- **Capabilities.** Both bits are registry entries (ADR-0047), lit together.

**Walker error policy.** A truncated or malformed item closes with `ProtocolViolation`,
as aMule's `CEOFException` disconnects. An unknown sub-opcode stops the walk: rmule acts
on the parsed prefix, emits one non-terminal diagnostic (sub-opcode and remaining
length) and stays open. The remainder is unparseable by construction, since the stream
has no length framing.

**Tolerance follows the house rule.** A pre-handshake bundle lands in the same
preserve-unknown arm as any pre-handshake request (ADR-0018). An answer for a file rmule
never solicited is dropped without creating state or disconnecting, in both shapes.
Duplicate items are processed one by one, as in aMule.

## Consequences

- The deterministic tier covers both walkers (full decode, truncated item, unknown sub),
  the composition property (bundle items equal the separate-packet set the same state
  emits), the serve rules and the pre-handshake arm.
- The base `0x92` form has no compliant capture, because aMule always chooses `0xA4`
  toward an ExtMultiPacket peer. It differs only by the absent `size8` and is covered by
  the deterministic tier.
- rmule diverges from aMule only on inbound tolerance, which compliant peers never
  exercise: aMule garbage-walks payload bytes after an unknown sub and disconnects on a
  pre-handshake bundle or an answer for the wrong file.

## Considered options

- **Consume and serve only, emitting separate packets.** Rejected: emit reuses the same
  codec, and staying the old client forfeits the round-trip saving.
- **Bundle items as `PeerPacket` variants re-entering `PeerPacket::decode`.** Rejected:
  the payloads are fragments, and wrapping synthetic packets puts wire fiction into
  dispatch.
- **Mirroring aMule's garbage walk on unknown subs.** Rejected: it can fabricate a parse,
  such as a fake file status.
- **Mirroring aMule's pre-handshake and wrong-hash disconnects.** Rejected: it
  contradicts the preserve-unknown arm the fan-in lands in.
- **Advertising MultiPacket without ExtMultiPacket.** Rejected: `0xA4` costs one
  `size8` read, and a split advert invents a client shape not found in the wild.
- **Opening a one-part file with a standalone SX2 source ask.** Rejected: aMule throws on
  it and drops the link.
