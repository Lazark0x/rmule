# eD2k peer protocol

**Status:** implemented. The two scopes below record the first two steps of the peer work: the handshake, then a one-peer transfer.
**Scope:** the client-to-client TCP and UDP protocol that carries hello / hello-answer, file requests, slot queue management, part exchange, hash-set requests, AICH, chat, SUI, and compressed parts. Owned by `rmule-peer` (sans-I/O service) and `rmule-peer-net` (Tokio runtime). See ADR-0081 for the naming choice over `rmule-transfer`.

## Concepts

- **Peer handshake**: initial TCP exchange where two clients identify each other (`OP_HELLO` then `OP_HELLOANSWER`), exchange tag-based capability bits, and may probe SUI.
- **File probe**: client asks peer "do you have this file?" via `OP_REQUESTFILENAME` / `OP_REQFILENAMEANSWER` (with `OP_FILEREQANSNOFIL` as the negative answer) and learns part availability via `OP_SETREQFILEID` / `OP_FILESTATUS`.
- **Part hash set exchange**: when a peer joins a transfer without a full `p=` list, they request it from a peer or the server via `OP_HASHSETREQUEST` / `OP_HASHSETANSWER`.
- **Upload queue**: each peer maintains a slot queue for upload requests; rank advances with wait time and is modified by credit (see `secure-ident.md`). Client signals "I want a slot" via `OP_STARTUPLOADREQ`; peer answers with queue position via `OP_QUEUERANKING`, polite refusal via `OP_OUTOFPARTREQS`, or grant via `OP_ACCEPTUPLOADREQ`.
- **Part request**: receiving client asks for a contiguous range inside an `ED2K Part`; typically 180 KiB blocks for finer-grained recovery. Sent via `OP_REQUESTPARTS` (small files, u32 offsets) or `OP_REQUESTPARTS_I64` (large files > 4 GiB, u64 offsets); peer delivers bytes via `OP_SENDINGPART` / `OP_SENDINGPART_I64`.
- **Compressed parts**: eMule-extension peers can send zlib-compressed data parts under protocol byte `0xD4`.
- **Low ID callback**: when a Low ID peer (typically behind NAT) is the target of a connection, the contacting High ID peer asks the server to relay an invitation; the Low ID peer then dials out to the High ID peer. The inbound notification arrives over the existing eD2k server connection as an `OP_CALLBACK`-family server packet.

## First scope: the peer handshake

Outbound TCP peer handshake to a High ID `PeerEndpoint`, plus inbound `OP_CALLBACK`-driven dial-out so a Low ID rmule client behind NAT can receive peer contact through server mediation. Explicit non-goals: no outbound `OP_CALLBACKREQUEST`, no inbound peer listener, no slot, no parts, no hash sets, no AICH, no SUI, no chat, no compressed parts, no NAT traversal.

## Second scope: one-peer transfer

Open the eD2k peer transfer flow end-to-end against one peer: file probe, hash-set request, slot queue, and part transfer including both small-file and large-file (`_I64`) wire variants. Demonstrate by downloading one part of a known file from one peer through the integration example, with hashes verified at the consumer. See ADRs 0024-0026.

### In-scope opcodes (cited from aMule `377ec8d9` `src/include/protocol/ed2k/Client2Client/TCP.h`)

`(protocol, opcode)` is the dispatch key — opcode `0x60` means `OP_ASKSHAREDFILESDIRANS` over `OP_EDONKEYPROT` (out of slice) and `OP_QUEUERANKING` over `OP_EMULEPROT` (in slice). The Protocol column is load-bearing.

| Opcode | Value | Protocol | Direction | Payload |
| ------ | ----- | -------- | --------- | ------- |
| `OP_REQUESTFILENAME` | `0x58` | `OP_EDONKEYPROT` | client → peer | `file_hash` (rmule sends minimum form; aMule may append extended fields when `GetExtendedRequestsVersion() > 0`, ignored in this slice) |
| `OP_REQFILENAMEANSWER` | `0x59` | `OP_EDONKEYPROT` | peer → client | `file_hash` + u16 LE `file_name` length + `file_name` bytes (ed2k text). TCP.h comment `<len 4>` is lossy; `SafeFile.cpp` `ReadString` defaults to `lenBytes = 2`. |
| `OP_FILEREQANSNOFIL` | `0x48` | `OP_EDONKEYPROT` | peer → client | `file_hash` |
| `OP_SETREQFILEID` | `0x4F` | `OP_EDONKEYPROT` | client → peer | `file_hash` |
| `OP_FILESTATUS` | `0x50` | `OP_EDONKEYPROT` | peer → client | `file_hash` + u16 LE `part_count` + `((part_count + 7) / 8)` bitmap bytes |
| `OP_HASHSETREQUEST` | `0x51` | `OP_EDONKEYPROT` | client → peer | `file_hash` |
| `OP_HASHSETANSWER` | `0x52` | `OP_EDONKEYPROT` | peer → client | `file_hash` + u16 LE `part_count` + `part_count × 16`-byte hashes. TCP.h comment omits the leading `file_hash`; `DownloadClient.cpp` `ProcessHashSet` reads it as `md4cmp(packet, ...)`. |
| `OP_STARTUPLOADREQ` | `0x54` | `OP_EDONKEYPROT` | client → peer | `file_hash` |
| `OP_QUEUERANKING` | `0x60` | `OP_EMULEPROT` | peer → client | exactly 12 bytes: u16 LE `rank` + 10 zero pad. Trailing pad documented as "purpose unknown" in eMule spec §6.5.4; aMule receiver reads first 2 bytes via `PeekUInt16`, ignores rest, rejects size ≠ 12. |
| `OP_OUTOFPARTREQS` | `0x57` | `OP_EDONKEYPROT` | peer → client | empty. The TCP "no slot right now" signal; spec §6.4.13 "no actual action is taken by the receiving client". Replaces plan's earlier `OP_QUEUEFULL` reference — `OP_QUEUEFULL = 0x93` is UDP-only and out of slice. |
| `OP_ACCEPTUPLOADREQ` | `0x55` | `OP_EDONKEYPROT` | peer → client | empty |
| `OP_REQUESTPARTS` | `0x47` | `OP_EDONKEYPROT` | client → peer | `file_hash` + 3 × u32 LE `start` + 3 × u32 LE `end` (unused range slots are zero-padded) |
| `OP_REQUESTPARTS_I64` | `0xA3` | `OP_EMULEPROT` | client → peer | `file_hash` + 3 × u64 LE `start` + 3 × u64 LE `end` |
| `OP_SENDINGPART` | `0x46` | `OP_EDONKEYPROT` | peer → client | `file_hash` + u32 LE `start` + u32 LE `end` + `(end - start)` payload bytes |
| `OP_SENDINGPART_I64` | `0xA2` | `OP_EMULEPROT` | peer → client | `file_hash` + u64 LE `start` + u64 LE `end` + `(end - start)` payload bytes |

### Transfer-scope design corrections

These corrections to the plan emerged from citing aMule + eMule source at the pinned commits and override any earlier assumption. Treat the entries here as the locked design.

- **`QueueRanking` rank is `u16`, not `u32`.** Wire payload is 12 bytes (rank u16 + 10 zero pad); aMule send (`UploadClient.cpp:575-594`) and receive (`ClientTCPSocket.cpp:1331-1349`) both confirm. `OP_QUEUERANK = 0x5C` (standard protocol, u32, legacy) has never been sent by any aMule version (git history search returned zero hits); decoded as `PeerPacket::Unknown` per ADR-0018 until evidence appears.
- **`OP_QUEUEFULL` (0x93) is UDP, not TCP, and out of scope.** The transfer scope models `OP_OUTOFPARTREQS (0x57)` as the TCP slot-rejection signal. Session-level event `QueueRejected { file_hash }` + `SlotReleased { QueueRejected }` semantics are unchanged from plan.
- **Packet dispatch is keyed by `(PacketProtocol, opcode)`, not opcode alone.** Opcode `0x60` overloads between `OP_EDONKEYPROT` (`OP_ASKSHAREDFILESDIRANS`) and `OP_EMULEPROT` (`OP_QUEUERANKING`); same shape for any future extended opcode. `PeerPacket::Unknown` gains a `protocol: PacketProtocol` field; `NoticeEvent::UnknownPacket` gains the same field so replay tests and the inspector preserve the routing attribution.

### Non-goals (transfer scope)

- AICH negotiation, hash-set trees beyond `OP_HASHSETANSWER`.
- Secure user identification (SUI).
- Source exchange (`OP_REQUESTSOURCES` / `OP_ANSWERSOURCES`).
- `OP_OFFERFILES` (we never publish).
- Chat, friend, message opcodes.
- Compressed parts (`OP_COMPRESSEDPART` / `OP_COMPRESSEDPART_I64`).
- End-of-download credit exchange.
- Inbound peer listener.
- NAT traversal (UPnP, NAT-PMP, hole punching).
- Outbound `OP_CALLBACKREQUEST` (the handshake scope's non-goal still binds).
- Multi-peer driver, `PeerSwarm`, or any multi-connection orchestrator in `rmule-peer-net` (ADR-0026).
- Storage trait, `PartSink`, or filesystem sink in `rmule-peer-net` (ADR-0026).
- Hash verification inside `PeerSession` (ADR-0026).
- `OP_SENDINGPART` payload capture by default — ADR-0024 makes `ProtocolOnly` the capture default.
- `rmule-core` / `rmule-transfer` extraction. Multi-peer scheduling is the documented trigger.
- UDP peer surface in any form (`OP_QUEUEFULL`, file ping, reask, source exchange UDP variants).

### Live test policy (transfer scope)

Live integration test asserts only up through `HashSetReceived`. Slot grant is unbounded in eMule reality and not appropriate as a hard assertion. Richer live evidence is produced on demand by the `peer transfer capture` operator command and replayed in `peer_transfer_replay`. CI without `RMULE_LIVE_TRANSFER_PEER` + `RMULE_LIVE_TRANSFER_FILE` skips the live test.

## What rmule will need to add

- `crates/rmule-peer` (sans-I/O `PeerSession`, `PeerPacket` umbrella, `PeerHelloBody`, `PeerIdentity`, command/event vocabulary).
- `crates/rmule-peer-net` (Tokio `Connection<Peer>`, capture writer, error taxonomy).
- `PeerEndpoint` plus `PeerSource::as_peer_endpoint` in `rmule-primitives`.
- `Ed2kEvent::PeerCallbackRequested` in `rmule-ed2k`.
- `rmule-tools peer-packet inspect` plus the live `peer welcome capture --slice` command.
- (transfer scope) `ED2K_PART_SIZE` + `part_count(file_size)` in `rmule-primitives`; `PartIndex` + `PartBitmap` in `rmule-peer`; file-request / hash-set / slot / part packet model in `rmule-peer` (both `_I64` variants); expanded `PeerCommand` / `PeerEvent` / `PeerError` vocabulary; reusable + fully-interleaved `PeerSession` with single active slot context; `CaptureMode::ProtocolOnly` default in `rmule-peer-net`; `peer transfer capture` operator command + `download_one_part` integration example.
- (later work) `PeerIdentity` promoted to `rmule-primitives` when Kad consumes it; `MiscOptions1` / `MiscOptions2` typed capability bitset; inbound listener with NAT-traversal evidence; bandwidth policy boundary at the orchestrator level (ADR-0011); compressed-part decoders; multi-peer scheduling in `rmule-core` (ADR-0026 trigger); UDP peer surface.

## Sources

Cached:

- `docs/reference/amule-wiki/ed2k_protocol.wikitext` — short overview only.
- `docs/reference/emule-spec/emule_protocol_specification.pdf` section 4 ("Client to Client TCP Communication") — the primary structured peer-protocol reference. Section 6.5.4 documents `OP_QUEUERANKING`'s 10-byte trailing pad as "purpose unknown". Section 3 covers the relevant server-mediated callback handshake from the server-protocol side.

Link-only:

- aMule source (GPLv2): `src/ClientTCPSocket.cpp`, `src/UploadQueue.cpp`, `src/UploadClient.cpp`, `src/DownloadClient.cpp`, `src/PartFile.cpp`, `src/include/protocol/ed2k/Client2Client/TCP.h`, `src/include/protocol/ed2k/Client2Client/UDP.h`, `src/SafeFile.h`. Pinned commit SHA in `docs/protocol/source-map.md`.

## Open questions

- Mapping of compressed-part decode errors to the rest of the decode error taxonomy in `packet-framing.md`.
- ~~Whether to model upload-queue management as a protocol service or push it to the orchestrator boundary.~~ Resolved (ADR-0026 racing amendment): the sans-IO session surfaces queue rank as non-terminal events (`QueueRanked`/`QueueProgress`) and stays clock-free; the **orchestrator** owns the slot-wait budget (`CoreConfig::slot_wait_timeout`) and the multi-peer race that keeps a scarce part from stranding on a queued peer. No downloader-side keep-alive packet is sent — the protocol defines none in the transfer scope, so staying connected and racing across peers is the mechanism for surviving a busy uploader's queue.
- Where exactly part requests align to the 180 KiB AICH block boundary versus other choices.
- Whether `PeerIdentity` warrants promotion to `rmule-primitives` once Kad lookup arrives, or stays in `rmule-peer` until a third consumer appears.
- (candidates for later work) AICH tree negotiation; source exchange; UDP peer flows; multi-peer scheduling extraction trigger.
