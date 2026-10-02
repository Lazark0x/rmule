# Kad Crate Comparison

**Status:** dependency spike comparison, 2026-06-02
**Scope:** classify Kademlia-family crates for rmule's first Kad Source Lookup slice.

## Decision Summary

| Candidate | Classification | Reason |
| --- | --- | --- |
| `kad` | reject for adoption now; keep as reference | Abstract request emission works, but byte-order semantics and generic value projection fail the fixture-backed gate. |
| `libp2p-kad` | reference-only | Bound to libp2p identity, addressing, behavior, and provider/record model. |
| `mainline` / `dht` | reference-only | BitTorrent Mainline DHT, not eMule Kad UDP. |
| `magpie-bt-dht` | reference-only | BitTorrent BEP 5 implementation, not eMule Kad UDP. |
| internal rmule implementation | next main path unless another crate is specifically spiked | Keeps eMule Kad packet compatibility, byte order, source-result projection, and sans-I/O/runtime split under rmule control. |

## `kad`

Metadata from `cargo info kad`:

- Version: `0.6.1`
- License: `MIT / Apache-2.0`
- Documentation: <https://docs.rs/kad/0.6.1>
- Repository: <https://github.com/ryankurte/rust-kad>

Fit:

- Protocol coupling: generic Kademlia, not eMule Kad-specific.
- Key size and distance semantics: accepts `[u8; 16]` through a blanket byte-slice `DatabaseId` implementation, but `bits()` uses little-endian byte interpretation. The rmule spike recorded this as a byte-order failure (spike since removed; see git history); eMule Kad fixtures must prove the intended ordering before any distance API is added.
- Transport/runtime assumptions: emits abstract requests through `futures::channel::mpsc`; it does not own UDP sockets directly.
- Node endpoint model: generic `Entry<Id, Info>` can carry rmule `KadNodeEndpoint`.
- Lookup request/result model: emits `FindNode` and `FindValue`; source lookup must be squeezed through generic value lookup.
- Source lookup fit: fails adoption because no fixture-backed eMule Kad source lookup passes through the adapter, and result projection would be mediated by generic value semantics.
- License and maintenance risks: license is acceptable; dependency graph is broad and dated (`futures 0.1`, `rand 0.5`, `structopt`, `clap 2`).
- Classification: reject for adoption now; keep as reference for abstract request emission and lookup-walk structure.

## `libp2p-kad`

Metadata from `cargo info libp2p-kad`:

- Version: `0.48.0`
- License: `MIT`
- Rust version: `1.83.0`
- Documentation: <https://docs.rs/libp2p-kad/0.48.0>
- Repository: <https://github.com/libp2p/rust-libp2p>

Fit:

- Protocol coupling: libp2p Kademlia behavior, not eMule Kad UDP.
- Key size and distance semantics: built around libp2p peer identity/keying rather than rmule-owned 128-bit eMule Kad IDs.
- Transport/runtime assumptions: expects libp2p swarm/behavior integration and libp2p networking surfaces.
- Node endpoint model: libp2p addressing and peer model, not bare IPv4 UDP Kad node endpoints.
- Lookup request/result model: records/providers and libp2p query behavior, not eMule Kad source-result rows.
- Source lookup fit: not a main-path fit; only useful as a conceptual reference unless a narrow reusable subcomponent is separately proven.
- License and maintenance risks: mature active ecosystem, but adopting it would move rmule away from eMule Kad compatibility boundaries.
- Classification: reference-only.

## `mainline` / `dht`

Metadata from `cargo info mainline`:

- Version: `6.2.0`
- License: `MIT`
- Rust version: `1.85`
- Documentation: <https://docs.rs/mainline/6.2.0>
- Repository: <https://github.com/pubky/mainline>

Metadata from `cargo info dht`:

- Version: `6.4.0`
- License: `MIT`
- Rust version: not declared by `cargo info`
- Documentation: <https://docs.rs/dht/6.4.0>
- Repository: <https://github.com/nuhvi/mainline>

Fit:

- Protocol coupling: BitTorrent Mainline DHT.
- Key size and distance semantics: BitTorrent node/key model, not eMule Kad's 128-bit source-lookup target/result model.
- Transport/runtime assumptions: BitTorrent DHT node/runtime shape.
- Node endpoint model: BitTorrent DHT nodes, not rmule **Kad Bootstrap Node** semantics.
- Lookup request/result model: BEP 5/Mainline DHT queries and values, not eMule Kad source rows with source-type tags.
- Source lookup fit: not direct; useful for generic lookup and routing-table design ideas only.
- License and maintenance risks: license acceptable, but protocol mismatch is decisive.
- Classification: reference-only.

## `magpie-bt-dht`

Metadata from `cargo info magpie-bt-dht`:

- Version: `0.1.3`
- License: `Apache-2.0 OR MIT`
- Rust version: `1.94`
- Documentation: <https://docs.rs/magpie-bt-dht/0.1.3>
- Repository: <https://github.com/mlamp/magpie>

Fit:

- Protocol coupling: BitTorrent BEP 5 DHT for the magpie BitTorrent library.
- Key size and distance semantics: BitTorrent DHT, not eMule Kad.
- Transport/runtime assumptions: magpie/BitTorrent-oriented.
- Node endpoint model: BitTorrent DHT nodes, not manual/imported eMule Kad bootstrap nodes.
- Lookup request/result model: BEP 5, not `KADEMLIA2_SEARCH_SOURCE_REQ` / `KADEMLIA2_SEARCH_RES`.
- Source lookup fit: no direct eMule Kad source-lookup fit.
- License and maintenance risks: license acceptable; crate is young and protocol-coupled to BitTorrent.
- Classification: reference-only.

## Internal rmule Implementation

Fit:

- Protocol coupling: can target eMule Kad UDP directly.
- Key size and distance semantics: can stay blocked until byte order is fixture-proven, then encode that proof in rmule-owned tests.
- Transport/runtime assumptions: can preserve the planned split: `rmule-kad` sans-I/O and `rmule-kad-net` Tokio UDP runtime.
- Node endpoint model: can use rmule **KadNodeEndpoint** and **KadBootstrapNode** directly.
- Lookup request/result model: can model `KADEMLIA2_REQ`, `KADEMLIA2_RES`, `KADEMLIA2_SEARCH_SOURCE_REQ`, and `KADEMLIA2_SEARCH_RES` without generic record/value leakage.
- Source lookup fit: best fit after byte fixtures exist.
- License and maintenance risks: more implementation work, but avoids dependency mismatch and GPL porting.
- Classification: next main path unless a narrower crate spike proves better.

## Decision Matrix

The original gate evidence lived in `crates/rmule-kad/tests/kad_adapter_spike.rs`. That historical spike was removed once the reject decision held, so the citations below point at the removed spike (recoverable from git history) rather than live files.

| Gate | Evidence | Result |
| --- | --- | --- |
| `KadId` fit | byte-order test in the historical spike (removed); see git history; `docs/reference/notes/kad.md` API-fit section | fail |
| Bootstrap node fit | `kad_adapter_spike_preserves_bootstrap_udp_endpoint`, historical spike (removed); see git history | pass |
| Abstract lookup request fit | `kad_adapter_spike_emits_abstract_find_node_requests`, historical spike (removed); see git history | pass |
| Source result projection fit | `kad_adapter_spike_projects_rmule_source_values`, historical spike (removed); see git history; blocked fixture metadata | fail |
| Runtime split fit | spike emitted abstract requests and did not own UDP sockets | pass |
| License/dependency fit | `cargo info kad`; `cargo tree -p rmule-kad` | fail for adoption due to broad dated dependency graph |

Recommendation: `reject kad and implement routing/lookup internally`.

`kad` is not adopted as a dependency. The spike served its purpose and was removed (git history retains it); `kad` stays cited as reference-only. No ADR is created for this cleanup because the `kad` rejection is already recorded here and in `docs/reference/notes/kad.md`, and the fixture-backed eMule Kad transcript is still blocked.

## 2026-06-02 Internal Implementation Status

The internal rmule implementation is the chosen path and the first slice has landed in `rmule-kad`:

- `kad_adapter_spike` and the `kad` dependency are removed; the default `rmule-kad` build no longer pulls `kad`, `futures 0.1`, `rand 0.5`, `structopt`, or `clap 2`.
- `rmule-kad` owns the plain `0xE4` Kad UDP envelope codec; packed `0xE5` is recognized as a well-formed-but-blocked value, not inflated.
- Only the eight cited Kad2 opcodes are typed; `KadId` stays opaque with no distance API.
- The source-result decoder exists as an evidence-gated boundary that refuses to parse rows, and `KadSourceCandidate` is sealed so no caller can manufacture a direct High ID source.

`kad`, `libp2p-kad`, `mainline` / `dht`, and `magpie-bt-dht` remain reference-only.
