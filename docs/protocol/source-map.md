# Protocol Source Map

rmule uses a hybrid compatibility source of truth: aMule behavior, eMule protocol references, and packet fixtures. This map tracks the sources used for protocol research and the confidence level for each source.

Many sources have a local cache entry under `docs/reference/<source-family>/`. The cache is gitignored bytes plus committed sidecar metadata; see ADR-0013, and `docs/reference/README.md` for the steps to fill the cache locally. URLs in this file are pinned to immutable revisions (commit SHA for source code, `?oldid=` for MediaWiki, snapshot URL for distros) so citations stay stable.

## Primary Sources

### eMule Reference Source

- URL: https://github.com/irwir/eMule/tree/13983526945d58b0bc1123619a795cf1e6b80aba
- Cache: `docs/reference/emule-source/eMule` (gitignored clone; sidecar committed). `kind = "git"`, pinned by commit SHA.
- Role: **the Reference Source of ADR-0082** — the normative eD2k/Kad implementation, read to specify behaviour. eMule 0.70b community edition, August 2024.
- Confidence: highest available for what eMule does; **never evidence** for a parity row per ADR-0045 — a constant read here still needs a capture.
- Notes: Strictly newer and more normative than aMule 2.3.3, which tracks eMule ~0.50a and is itself a port. Where the two disagree, or where aMule structurally cannot emit a shape, this is the tree that answers. GPL-2-**or-later** per its devteam file headers, so unlike aMule source it may be cached locally (ADR-0013 narrowed by ADR-0082) — but ADR-0004's no-porting rule still applies and is re-affirmed deliberately, not inherited.

### aMule Source

- URL: https://github.com/amule-project/amule/tree/377ec8d9d56618f1059d8705ae53a70fa4ffbe87
- Cache: not cached (GPLv2 — link-only per ADR-0013).
- Role: behavioral oracle for practical ED2K and Kad interoperability.
- Confidence: high for implemented behavior; still needs packet-level confirmation for rmule.
- Notes: aMule describes itself as a multi-platform eD2k/Kad client based on eMule. Reference reading only; rmule must not port GPLv2 source per ADR-0004.

### aMule Known File Hash Source

- URL: https://github.com/amule-project/amule/blob/377ec8d9d56618f1059d8705ae53a70fa4ffbe87/src/KnownFile.cpp
- Cache: not cached (GPLv2 — link-only per ADR-0013).
- Role: source-level evidence for ED2K part counts, part hash sets, and exact-part-size hash behavior.
- Confidence: high for current aMule behavior; reference only, not code to port.
- Notes: Confirms the special empty part hash at exact part-size boundaries and the ED2K hashset count rules. Summarized in `docs/reference/notes/ed2k-hash.md`.

### aMule Tag Source

- URL: https://github.com/amule-project/amule/blob/377ec8d9d56618f1059d8705ae53a70fa4ffbe87/src/Tag.cpp
- Cache: not cached (GPLv2 — link-only per ADR-0013).
- Role: source-level evidence for eD2k tag name encoding and supported tag value parsing.
- Confidence: high for current aMule behavior; reference only, not code to port.
- Notes: Supports the first, minimal tag codec fixtures. Summarized in `docs/reference/notes/tags.md`.

### aMule ED2K Protocol Wiki

- URL: https://wiki.amule.org/w/index.php?title=Ed2k_protocol&oldid=20544
- Cache: `docs/reference/amule-wiki/ed2k_protocol.meta.toml` (license: GFDL).
- Role: readable ED2K server protocol walkthrough and message format notes.
- Confidence: medium; the page says it may contain errors, so verify against source and fixtures.
- Notes: Useful for early login, tag, message header, and server interaction documentation. Summarized in `docs/reference/notes/ed2k-login.md`, `tags.md`, `packet-framing.md`.

### aMule Userhash Wiki

- URL: https://wiki.amule.org/w/index.php?title=Userhash&oldid=23716
- Cache: `docs/reference/amule-wiki/userhash.meta.toml` (license: GFDL).
- Role: terminology source for user hash as a client identity value reused across protocol flows.
- Confidence: medium for terminology; implementation behavior still needs packet and state-machine evidence.
- Notes: Supports modeling `UserHash` as protocol identity rather than application account identity. Summarized in `docs/reference/notes/user-hash.md`.

### aMule MD4 Hash Notes

- URL: https://wiki.amule.org/w/index.php?title=MD4_hash&oldid=13460
- Cache: `docs/reference/amule-wiki/md4_hash.meta.toml` (license: GFDL).
- Role: ED2K hash algorithm orientation, including the 9,728,000 byte part size.
- Confidence: medium; useful for algorithm shape, but exact behavior still needs fixtures.
- Notes: Use to guide hash compatibility fixtures, not as the only proof of implementation behavior. Summarized in `docs/reference/notes/ed2k-hash.md`.

### aMule ED2K Link Wiki

- URL: https://wiki.amule.org/w/index.php?title=Ed2k_link&oldid=28410
- Cache: `docs/reference/amule-wiki/ed2k_link.meta.toml` (license: GFDL).
- Role: ED2K file, server, server-list, part-hash-set, source, URL, and AICH root link syntax.
- Confidence: medium; useful for link grammar and examples, with real parser behavior proved by fixtures.
- Notes: Supports the first link parsing and canonical formatting scope. Summarized in `docs/reference/notes/ed2k-link.md`.

### eMule/eDonkey Protocol Specification

- URL: https://www.ramonmillan.com/documentos/bibliografia/eMuleProtocolSpecification.pdf
- Cache: `docs/reference/emule-spec/emule_protocol_specification.meta.toml` (license: unconfirmed, local-only per ADR-0013).
- Role: historical protocol reference for ED2K messages, tags, search, source lookup, and peer transfer messages.
- Confidence: medium; historical and incomplete in places, but valuable for packet field definitions.
- Notes: Authored by Yoram Kulbak and Danny Bickson, Hebrew University of Jerusalem, 17 January 2005. PDF carries no license notice; cached locally but must not be vendored or redistributed.

## Supporting Sources

### emule-qt (Stimulus Counterparty)

- URL: https://github.com/ModderMule/emule-qt/tree/73fff7146d2eec3e8426251ec4959238bae3479a
- Cache: `docs/reference/emule-qt/emule-qt` (gitignored clone; sidecar committed). `kind = "git"`, pinned by commit SHA.
- Role: **the Stimulus Counterparty of ADR-0082** — a headless `emulecored` daemon giving rmule a third body on the wire for rows blocked by a two-node artefact. Also carries two protocol specs of its own under `docs/protocol/`.
- Confidence: low as a behavioural authority — a 2026 rewrite, not a reference implementation. **Its bytes never score a parity row**; where a three-body setup unblocks a row, the proof is still the pinned counterparty's bytes.
- Notes: Read-for-facts only and, unlike the eMule Reference Source, **may not inform derived logic at all** — 672 of 677 classifiable files carry no licence header and the repo declares bare `GPL-2.0` with no "or later" grant. Its vendored `srchybrid/` is the eMule Reference Source and is pinned upstream instead; do not read it from this clone.

### eMule Kad Wiki

- URL: https://wiki.emule-web.de/index.php?title=Introduction_Kad&oldid=2662
- Cache: `docs/reference/emule-web-wiki/introduction_kad.meta.toml` (license: GFDL 1.2).
- Role: high-level Kad network orientation.
- Confidence: low to medium for implementation details; useful for terminology and scope.
- Notes: Kad implementation details must be verified against aMule source and fixtures. Indexed in `docs/reference/notes/kad.md`.

### ED2K URI Scheme Notes

- URL: https://en.wikipedia.org/w/index.php?title=Ed2k_URI_scheme&oldid=1353893233
- Cache: `docs/reference/wikipedia/ed2k_uri_scheme.meta.toml` (license: CC-BY-SA-4.0).
- Role: quick reference for ED2K file links and hash shape.
- Confidence: medium for orientation; verify exact behavior against protocol fixtures and code.
- Notes: Useful as a secondary source, especially for link grammar and examples.

### eMule Corruption Handling Help

- URL: https://www.emule-project.com/home/perl/help.cgi?l=1&rm=show_topic&topic_id=589 (retrieved 2026-05-17)
- Cache: not cached (proprietary site — link-only per ADR-0013).
- Role: File hash, part hash set, and AICH root terminology from the original eMule project.
- Confidence: medium; useful for terminology and relationships, with implementation behavior still fixture-gated.
- Notes: Supports the first implementation's distinction between file identity, part verification metadata, and AICH root metadata. Behaviour rewritten in `docs/reference/notes/aich.md`.

### AniDB ED2K Hash Notes

- URL: https://wiki.anidb.net/Ed2k-hash
- Cache: `docs/reference/anidb-wiki/ed2k_hash.meta.toml` (license: unconfirmed; fetch_status=manual because the site Cloudflare-gates scripted clients).
- Role: Documents the practical exact-part-size hash variant split across ED2K-compatible tools.
- Confidence: medium; useful for identifying compatibility forks, but rmule behavior must still be fixture-backed.
- Notes: Supports the decision to target eMule/aMule exact-multiple hash behavior. Manual browser save required to populate cache.

### rhash ED2K Implementation

- URL: https://github.com/rhash/RHash/blob/v1.3.8/librhash/ed2k.c
- Cache: `docs/reference/rhash/ed2k.c.meta.toml` (license: MIT-style, but porting forbidden per ADR-0004).
- Role: Independently documented eMule-compatible ED2K hashing behavior and exact-multiple note.
- Confidence: medium; source is permissively licensed, but rmule should use it only as reference material and not port code.
- Notes: Supports exact-part-size hash fixture expectations. Originally listed as a Debian-snapshot URL; sources.debian.org now requires JS PoW, so the GitHub raw mirror at the v1.3.8 tag is the durable fetch URL.

## Crate Candidates

### ed2k

- URL: https://crates.io/crates/ed2k
- Role: candidate implementation of the ED2K hash function.
- Confidence: medium for hash computation after fixture verification; the crate exposes multiple exact-boundary variants.
- Notes: rmule's eMule/aMule-compatible canonical hash should use `Ed2kRed`, not the crate default `Ed2k`/`Ed2kBlue`.

### Kademlia crates

- Examples: `kad`, `libp2p-kad`, `mainline` / `dht`, `magpie-bt-dht`, `kademlia-dht`, `tesseras-dht`, `rckad`, `kbucket`, `kademlia_routing_table`.
- Role: candidates for reusable concepts, dependency spikes, or internal components.
- Confidence: low for direct protocol reuse because eMule Kad compatibility is not established.
- Notes: Do not adopt as core Kad behavior without compatibility proof. Favor crates whose algorithmic surface can be adapted to eMule Kad wire packets, 128-bit Kad IDs, manual bootstrap nodes, and rmule's sans-I/O protocol/runtime split. The 2026-06-02 comparison in `docs/reference/notes/kad-crate-comparison.md` rejects `kad` adoption for now, keeps `libp2p-kad`, `mainline` / `dht`, and `magpie-bt-dht` as reference-only, and recommends internal rmule routing/lookup work unless another narrower crate is spiked. As of 2026-06-02 the internal path is taken: the `kad_adapter_spike` and its `kad` dependency are removed, and `rmule-kad` owns the plain `0xE4` Kad UDP envelope codec, the eight first-slice Kad2 opcode constants, an opaque `KadId`, deterministic in-memory contact state, and an evidence-gated source-result decoder boundary (packed `0xE5` is recognized as blocked, not inflated; source rows are not decoded until byte-order/identity/fixture evidence exists).

### Kad packet framing and source lookup

- URL: https://github.com/amule-project/amule/tree/377ec8d9d56618f1059d8705ae53a70fa4ffbe87/src/kademlia
- Cache: not cached (GPLv2 — link-only per ADR-0013).
- Role: primary behavioral evidence for eMule Kad UDP packet envelope, Kad2 opcode dispatch, source-lookup request/result shape, and source-result tag interpretation.
- Confidence: high for aMule behavior at the pinned commit; still needs rmule-owned packet fixtures before implementation.
- Notes: Summarized in `docs/reference/notes/kad-packet-framing.md` and `docs/reference/notes/kad-source-lookup.md`. Current evidence:
  - Kad protocol bytes: `0xE4` plain Kad and `0xE5` packed Kad from `src/include/protocol/Protocols.h:32-45`.
  - Kad UDP envelope: byte 0 protocol, byte 1 opcode, remaining bytes opcode payload from `src/ClientUDPSocket.cpp:88-118` and `src/kademlia/net/KademliaUDPListener.cpp:213-231`.
  - Kad2 source-lookup request opcode: `KADEMLIA2_SEARCH_SOURCE_REQ = 0x34` from `src/include/protocol/kad2/Client2Client/UDP.h:33-53`.
  - Kad2 source/search result opcode: `KADEMLIA2_SEARCH_RES = 0x3B` from `src/include/protocol/kad2/Client2Client/UDP.h:33-53`.
  - Source-lookup request payload: target, start position, file size from `src/kademlia/net/KademliaUDPListener.cpp:931-939`.
  - Source result payload: sender ID, target, result count, source ID plus tags from `src/kademlia/net/KademliaUDPListener.cpp:978-987` and `src/kademlia/kademlia/Indexed.cpp:815-858`.
  - Source-result tags: source type/IP/TCP port/UDP port and callback-related fields from `src/include/tags/FileTags.h:114-124` and `src/kademlia/kademlia/Search.cpp:870-927`.

## Open Research Gaps

- aMule-generated loopback login packet fixture and local fake-listener capture process.
- Current aMule source locations for hash, tag, packet, server, peer, and Kad behavior.
- eMule Kad message formats and routing-table semantics.
- Protocol obfuscation and secure identification references.
- Full AICH hash-tree verification scope beyond preserving AICH root metadata in the first implementation.

### Welcome-packet response fixtures

The welcome-packet work targeted the post-login server-protocol exchange. Wire layouts for the welcome-packet set were tightened against cached PDF and pinned aMule source in `docs/reference/notes/ed2k-welcome-packets.md`. Status per packet:

- `OP_REJECT` (`0x05`) — **cited wire layout**: zero payload. Implemented as a unit `Reject` packet (and unit `Ed2kEvent::LoginRejected`) per the cited sources. Open: capture a real-server fixture before promoting to a payload-bearing variant.
- `OP_GETSERVERLIST` (`0x14`) — **cited wire layout**: zero payload. No open gaps.
- `OP_SERVERLIST` (`0x32`) — **cited wire layout**: `u8` count + `count × (u32 ip + u16 port)`. No open gaps.
- `OP_SERVERSTATUS` (`0x34`) — **cited wire layout**: `u32 user_count + u32 file_count`. Open: aMule carries a `FIXME` about variable sizes; capture a current-day fixture to decide whether to keep rmule's strict 8-byte rule or extend.
- `OP_SERVERMESSAGE` (`0x38`) — **cited wire layout**: `u16 text_length + text bytes`. Open: confirm `text_length == size - 2` holds on the wire (aMule trusts `size`, not `text_length`).
- `OP_SERVERIDENT` (`0x41`) — **cited wire layout**: 16-byte hash + u32 IP + u16 port + u32 tag count + tags. Two typed tags (`ST_SERVERNAME 0x01`, `ST_DESCRIPTION 0x0B`). Open: confirm `ST_VERSION 0x91` presence on real servers before promoting it from `extra_tags` to typed `ServerIdentity::version`.

The welcome-packet work backed all six packets with handwritten fixtures and deliberately deferred a full aMule loopback capture.

### Search

The connected-server search slice is documented in `docs/reference/notes/ed2k-search.md`. Status:

- **TCP opcodes** — confirmed against `src/include/protocol/ed2k/Client2Server/TCP.h:34,47`: `OP_SEARCHREQUEST` is `0x16`; `OP_SEARCHRESULT` is `0x33`. This corrects the eMule PDF section 6.2.10 typo that labels the result opcode as `0x16`.
- **Request scope** — first slice uses the connected TCP server only. aMule's local eD2k path builds one `OP_SEARCHREQUEST` and sends it through `serverconnect->SendPacket(..., true)` (`SearchList.cpp:309-384`); UDP global search fanout (`SearchList.cpp:439-499`) is deliberately out of scope.
- **Query filters** — first slice exposes phrase, file type, min/max size, min availability, and extension. aMule's builder maps these to `FT_FILETYPE`, `FT_FILESIZE`, `FT_SOURCES`, and `FT_FILEFORMAT` constraints (`SearchList.cpp:677-792`).
- **Result rows** — count-prefixed TCP search results dispatch through `ServerSocket.cpp:356-368` and are read by `SearchList.cpp:541-548` as rows of file hash, client ID, TCP port, and descriptor tags.
- **Descriptor tags** — `FT_FILENAME`, `FT_FILESIZE`, `FT_FILETYPE`, `FT_FILEFORMAT`, `FT_SOURCES`, and `FT_FILESIZE_HI` are the first typed descriptor tags, sourced from `src/include/tags/FileTags.h:29-42`.
- **Bad result payloads** — aMule keeps the server socket alive after search-result processing errors (`ServerSocket.cpp:526-537`). rmule mirrors this as non-terminal `SearchResultSkipped` for framed `OP_SEARCHRESULT` payload projection failures.
- **Dedupe policy** — aMule groups duplicates by file hash plus size (`SearchList.cpp:587-608`). rmule keeps the same identity key and preserves first-arrival order, but leaves ranking and durable search history out of scope.

### Runtime

The live-socket work targeted the first live eD2k socket. Connection lifecycle, timeouts, welcome-burst arrival ordering, and disconnect causes are tightened against pinned aMule source in `docs/reference/notes/ed2k-runtime.md`. Status per behaviour:

- **Connection state machine** — confirmed against `ServerSocket.cpp:66,82-105,337,356-365` and `ServerConnect.cpp:48-128`. rmule's sans-I/O `Ed2kSession` collapses the larger aMule state set into the four states the protocol actually distinguishes (`BeforeStart`, `AwaitingIdChange`, `LoggedIn`, `Closed`).
- **Connect / login timeout** — confirmed: aMule uses one budget (`CONSERVTIMEOUT = 25000 ms`, `Constants.h:53`). rmule splits into `connect_timeout` (10 s default) and `login_timeout` (15 s default) per ADR-0023's typed `CloseReason::ConnectTimeout` / `CloseReason::LoginTimeout` distinction.
- **Disconnect causes** — confirmed: `OnConnect` error path, `OnClose`, `OnError`, `CheckForTimeout`, explicit `Disconnect`, and `OP_REJECT` payload (`ServerSocket.cpp:82-105,289-291,324-330,356-365`; `ServerConnect.cpp:341-469`).
- **Welcome-burst arrival ordering** — **no contract**; aMule dispatches each opcode independently with no enforced sequence (`ServerSocket.cpp:120-318`). rmule mirrors: `Ed2kSession` accepts any welcome opcode in any order while `LoggedIn`. One captured fixture pins an observed sequence as evidence.
- **Idle / keep-alive** — out of scope for the first live socket. Documented in `ed2k-runtime.md` for long-lived connections.
- **Captured fixtures** — produced by `rmule-ed2k-net`'s **Capture** writer (ADR-0022) and curated under `crates/rmule-ed2k/tests/fixtures/server/captured/`. The first captured welcome-burst fixture (`welcome-burst-2026-05-17/`, against public eD2k server 45.82.80.155:5687) is committed. It documents three protocol facts that the offline references could not pin down: (a) lugdunum servers push `OP_SERVERMESSAGE` *before* `OP_IDCHANGE`; (b) the login packet needs `CT_SERVER_FLAGS` (0x20) and `CT_EMULE_VERSION` (0xFB) capability tags on top of the earlier minimal login set or the server refuses to send `OP_IDCHANGE`; (c) the welcome burst can contain a zlib-compressed packet (protocol byte `0xD4`, magic `78 DA`) — preserved as `04_undecoded_tail.bin`; rmule's compressed-frame support inflates this frame into a logical `OP_SERVERMESSAGE` (see `### Compressed packet frames` below).

### Compressed packet frames

The captured `0xD4` welcome-burst tail promoted compressed frame handling from peer-transfer trivia to an eD2k server-protocol requirement. Status:

- **Protocol byte taxonomy** — confirmed against `src/include/protocol/Protocols.h:32-38`: `0xD4` is `OP_PACKEDPROT` for packed eD2k/eMule payloads; Kad has its own packed protocol byte (`0xE5`).
- **Compression boundary** — confirmed against `src/Packet.cpp:247-306`: packet packing zlib-compresses opcode-specific payload bytes, preserves the opcode in the frame header, and changes only the protocol byte.
- **Server-to-client** — confirmed against real capture plus `src/ServerSocket.cpp:592-608`: aMule unpacks inbound server TCP `OP_PACKEDPROT` before dispatching by opcode.
- **Captured welcome tail** — local zlib probe of `crates/rmule-ed2k/tests/fixtures/server/captured/welcome-burst-2026-05-17/04_undecoded_tail.bin` confirms the frame is opcode `0x38` (`OP_SERVERMESSAGE`) with compressed payload bytes inflating to an 875-byte server-message text payload. The next slice should update the replay oracle so the captured `s2c.bin` emits a second `ServerMessageReceived` event instead of terminal `ProtocolViolation`.
- **Inflated-size ceiling** — confirmed against `src/ServerSocket.cpp:592-608`: aMule caps server TCP unpacking at 250,000 bytes. rmule adopts that ceiling for inbound eD2k server compressed frames.
- **Inflation failure** — confirmed against `src/ServerSocket.cpp:596-602`: aMule logs failed server TCP decompression, counts overhead, and keeps the socket alive. rmule emits `Ed2kEvent::CompressedFrameSkipped { opcode, compressed_len, reason }` where `reason` is a typed `CompressedFrameSkipReason`.
- **Capture serialization** — `events.toml` records `CompressedFrameSkipped` with opcode, compressed length, typed reason label, and `limit` when the reason is `DecompressedSizeLimitExceeded`.
- **Client-to-server** — confirmed against eMule spec and `src/SharedFileList.cpp:740-854`: aMule compresses `OP_OFFERFILES` when the connected server advertises `SRV_TCPFLG_COMPRESSION`.
- **Rust dependency** — `flate2` is acceptable as a private `rmule-ed2k` implementation dependency because it supports zlib streams and defaults to a safe-Rust backend (`miniz_oxide`); public rmule APIs expose only rmule-owned event/reason types.
- **Next slice** — implement inbound eD2k server compressed frame decoding first. Outbound compression waits until rmule models offered-file publishing; peer compressed parts stay in the transfer protocol.
