# Kademlia (Kad)

**Status:** deferred
**Scope:** eMule's serverless distributed hash table, used for peer / file lookup when no eD2k server is involved.

Kad is the second major peer-discovery channel in the eMule network (alongside the eD2k server protocol). The first implementation phases did not touch Kad; this note indexes its research surface.

## What Kad is

- An eMule-specific Kademlia DHT — not directly interoperable with libp2p Kad or other Kademlia variants.
- Identifies nodes by a 128-bit Kad ID. References suggest a binding to the user's `UserHash` as part of secure identity, but rmule treats the exact derivation as unconfirmed until references or captures prove it.
- Uses its own UDP wire protocol with its own opcode space.
- Supports file search, source lookup, keyword search, and node lookup.

## Why deferred

- eMule Kad compatibility is not established for any existing Rust Kademlia crate. ADR (per `docs/protocol/source-map.md`) confirms this: "Do not adopt as core Kad behavior without compatibility proof."
- Kad is a state-heavy protocol service: routing table, bucket rebalancing, lookup state machines. Building it on top of an unproven foundation creates churn.
- The server protocol covered most of the early scope; deferring Kad let the server side reach maturity first.

## What rmule will need to add

- A new `rmule-kad` sans-I/O protocol crate (per ADR-0005 small-protocol-crate split).
- A new `rmule-kad-net` Tokio UDP runtime crate, mirroring the existing protocol/runtime split from ADR-0007.
- A Kademlia-style routing table with eMule's specific bucket parameters.
- One long-lived UDP socket per Kad protocol service; bootstrap, routing-table maintenance, and lookup traffic all feed the same state machine.
- A separate fixture set with packet captures from aMule's Kad path.
- First implementation slice is lookup/download consumption only; Kad publishing of shared files waits for a later serve-side advertising decision.
- Kad keyword/file search stays out of the first slice; it waits until routing and **Kad Source Lookup** are proven.
- A fixture-first compatibility path before live runtime integration: document Kad frame protocol bytes, compression behavior, bootstrap/node lookup packets, source lookup packets, and unknown-packet preservation, then prove packet codecs with precise handwritten fixtures or aMule Kad captures.

## Sources

Cached:

- `docs/reference/emule-web-wiki/introduction_kad.wikitext` — high-level orientation.

Link-only:

- aMule source (GPLv2): `src/kademlia/` directory. Pinned commit SHA in `docs/protocol/source-map.md`.
- emule-project Kad documentation (proprietary site).

## Open questions

- Confirm Kad opcode space and packet framing differences from the eD2k server protocol. Initial evidence is now in `docs/reference/notes/kad-packet-framing.md`; remaining gaps are byte-order and captured source-lookup fixtures, not the high-level Kad2 protocol byte/opcode split.
- Decide whether a Rust Kademlia crate can own any algorithmic Kad behavior without owning eMule Kad compatibility. Candidate classes found so far:
  - `kad` may fit an adapter spike because it separates generic DHT requests from communication mechanisms and encodings, but it is old / work-in-progress and needs proof against eMule Kad lookup flow.
  - `libp2p-kad` is libp2p-specific and should not own rmule Kad behavior unless a narrow reusable subcomponent is proven; its public model is built around libp2p `Behaviour`, `Swarm`, `PeerId`, `Multiaddr`, records, providers, and protocol streams rather than eMule Kad UDP packets.
  - `mainline`, `dht`, and `magpie-bt-dht` are BitTorrent Mainline DHT implementations; useful for concepts, not direct protocol reuse.
  - `kademlia-dht`, `tesseras-dht`, `rckad`, `kbucket`, and `kademlia_routing_table` need deeper review before dependency use; note especially license, maintenance, key-size, runtime, and protocol-coupling constraints.
  - A `kad` dependency spike must prove that rmule's **Kad ID** maps cleanly to the crate's ID trait, **Kad Bootstrap Node** maps without losing UDP endpoint data, lookup walks can emit abstract requests that rmule encodes as eMule Kad UDP packets, and source lookup results are not forced through the crate's generic store/value semantics. Adoption waits until a fixture-backed eMule Kad source lookup passes through the adapter, not merely until the type/API spike compiles.
- Identify the exact derivation of Kad ID from `UserHash`.
- Until the derivation is confirmed from references or captures, model `KadId` independently and require explicit local Kad identity in Kad tests/config.

## 2026-06-02 Kad packet/source-lookup evidence

- Kad uses UDP for source lookup and other DHT functions; it does not transfer file bytes. Cached orientation source: `docs/reference/emule-web-wiki/introduction_kad.wikitext`.
- Pinned aMule `src/include/protocol/Protocols.h:32-45` identifies plain Kad as protocol byte `0xE4` and packed Kad as `0xE5`.
- Pinned aMule `src/ClientUDPSocket.cpp:88-118` and `src/kademlia/net/KademliaUDPListener.cpp:213-231` show Kad dispatch reading the opcode from datagram byte 1 and treating bytes after that as opcode payload. This differs from rmule's eD2k TCP/server frame, which has a four-byte length field.
- Pinned aMule `src/include/protocol/kad2/Client2Client/UDP.h:33-53` identifies the Kad2 opcodes relevant to the first slice: bootstrap request/result, hello request/result, lookup request/result, source-lookup request `0x34`, and search/source result `0x3B`.
- Pinned aMule `src/kademlia/net/KademliaUDPListener.cpp:931-939` reads Kad2 source-lookup requests as target, start position, and file size. `src/kademlia/kademlia/Search.cpp:464-485` shows the sender building the same request for file source lookup.
- Pinned aMule `src/kademlia/net/KademliaUDPListener.cpp:978-987` and `src/kademlia/kademlia/Indexed.cpp:815-858` show Kad2 source results arriving as `KADEMLIA2_SEARCH_RES`: sender ID, target, result count, then source ID plus tags.
- Pinned aMule `src/include/tags/FileTags.h:114-124` and `src/kademlia/kademlia/Search.cpp:870-927` identify source-result tags used to recover source type, IP, TCP port, UDP port, buddy/callback fields, and encryption options. rmule's first slice accepts only direct-connectable High ID rows and keeps the rest as diagnostics.

## 2026-06-02 `kad` crate dependency metadata

Commands:

- `cargo search kad --limit 5`
- `cargo info kad`

Result:

- Crate: `kad`
- Version: `0.6.1`
- Summary: generic / futures-based Kademlia Distributed Hash Table implementation.
- License: `MIT / Apache-2.0`
- Rust version: not declared by `cargo info`.
- Documentation: <https://docs.rs/kad/0.6.1>
- Repository: <https://github.com/ryankurte/rust-kad>
- Initial status: acceptable license for a spike, but API fit remains unproven.

API-fit spike result:

- `KadId` conversion: raw 16-byte values can round-trip through a crate ID type (`[u8; 16]`), but the crate's blanket `DatabaseId` implementation treats byte slices as little-endian for `bits()`. For a network-order 128-bit ID, `[0x80, 0, ...]` reports 8 bits while `[0, ..., 0x01]` reports 121 bits. Because rmule has not yet proven eMule Kad byte order from fixtures, this fails the adoption gate.
- `Kad Bootstrap Node`: a known node ID plus rmule `KadNodeEndpoint` can be carried in `kad::common::Entry<[u8; 16], KadCrateNodeInfo>` without losing IPv4 UDP endpoint data.
- Abstract lookup requests: `kad::dht::Dht` can emit `Request::FindNode` work through a `futures` channel, so rmule could encode those requests as eMule Kad UDP packets outside the crate.
- Source result projection: a synthetic `Response::ValuesFound` can carry rmule-owned source values, but this still routes eMule Kad source results through the crate's generic value semantics. That is not enough for adoption without a fixture-backed eMule Kad transcript.
- Dependency graph: `cargo tree -p rmule-kad` shows `kad` brings old `futures 0.1`, `rand 0.5`, `structopt`, `clap 2`, and a broad async/dependency stack. This is acceptable for a temporary spike, but it is a maintenance risk for adoption.

Current gate result: reject adopting `kad` for now. It can remain a reference for abstract request emission, but adoption waits on byte-order proof and a fixture-backed eMule Kad source-lookup transcript.

See `docs/reference/notes/kad-crate-comparison.md` for the comparison against `libp2p-kad`, `mainline` / `dht`, `magpie-bt-dht`, and an internal rmule implementation.

## 2026-06-02 Internal slice: Kad ID stays opaque

The internal source-lookup slice models `KadId` as opaque 16-byte storage with no distance behavior. It adds no production XOR distance, bucket-index, nearest-contact ordering, or source-lookup key-ordering API, because eMule Kad byte order is still unproven.

The byte-order proof remains blocked and is now named as one canonical typed list in code (`rmule_kad::KadEvidence`). `KadId::DISTANCE_ORDER_BLOCKED_BY` lists the evidence that gates any distance/bucket-order API: exact Kad ID byte order, a reproducible routing comparison proving distance ordering, and reproducible eMule/aMule behavior for at least one lookup target. The same `KadEvidence` enum names the source-result row-decode gaps, so the missing evidence is recorded once instead of being scattered across tests, fixtures, and docs.

## 2026-06-02 Internal source-lookup slice landed

The first rmule-owned Kad building blocks are in `rmule-kad`:

- `kad_adapter_spike` was removed after the dependency decision; `kad` stays reference-only and the default build no longer pulls it (or `futures 0.1`, `rand 0.5`, `structopt`, `clap 2`).
- `rmule-kad` owns the Kad UDP envelope codec: byte 0 protocol, byte 1 opcode, rest payload. Plain `0xE4` round-trips via `decode_exact` / `KadEnvelope::encode`. It deliberately does not reuse `rmule_primitives::Packet` (which carries the eD2k four-byte length field).
- Packed `0xE5` Kad is recognized as a well-formed-but-blocked `KadDecoded::PackedBlocked { opcode, compressed_len }` value — not inflated, and not an error. Decode errors stay reserved for truncation and unsupported protocol bytes.
- First-slice Kad2 opcode constants are limited to the eight cited opcodes (bootstrap req/res, hello req/res, lookup-walk req/res, `KADEMLIA2_SEARCH_SOURCE_REQ` `0x34`, `KADEMLIA2_SEARCH_RES` `0x3B`).
- Deterministic in-memory contact state (`KadRoutingTable`, `KadContact`, `KadContactState`) and a lookup-walk skeleton exist for bookkeeping, but nearest-contact selection returns `KadRoutingSelectionError::DistanceEvidenceBlocked`.
- Source-result decoding stays evidence-gated: `decode_source_result` routes `KADEMLIA2_SEARCH_RES` but returns `KadSourceResultDecodeError::EvidenceBlocked` rather than parsing rows, and `KadSourceCandidate` is sealed so no `PeerSource` can be manufactured into a direct candidate without a proven decoder.
