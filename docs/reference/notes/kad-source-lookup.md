# Kad Source Lookup

**Status:** transcript requirements for Kad dependency spike. As of 2026-06-19 `rmule-kad` is **frozen pending evidence** — see ADR-0069 and the closing "Frozen" section below.
**Scope:** fixture evidence needed before rmule can adopt any crate or implement Kad source lookup.

Kad Source Lookup asks the serverless Kad network for peers advertising a known **Source Lookup Target**. It is not user-facing search and it does not transfer file bytes.

## Transcript Definition

A Kad source-lookup transcript is the smallest evidence set that proves rmule can:

1. start from a local **Kad ID**, a known **Source Lookup Target**, and at least one known **Kad Bootstrap Node** or routing-table contact;
2. send or model lookup-walk requests to Kad contacts;
3. send or model a `KADEMLIA2_SEARCH_SOURCE_REQ` for the target;
4. receive a `KADEMLIA2_SEARCH_RES` containing source rows;
5. project only direct-connectable High ID rows into rmule-owned **Peer Source** output;
6. preserve unsupported rows as diagnostics.

## Request Requirements

Every promoted request fixture must identify:

- provenance: `handwritten`, `amule-generated`, or `captured`;
- protocol byte: expected `0xE4` for plain Kad or `0xE5` for packed Kad;
- opcode: expected `0x34` for `KADEMLIA2_SEARCH_SOURCE_REQ`;
- target key bytes and their byte-order source;
- start position and whether the high bit is set;
- file size and byte order;
- destination **Kad Node Endpoint**;
- destination **Kad ID**, if known;
- local **Kad ID** used for lookup state;
- whether UDP obfuscation/encryption was present outside the inner Kad packet.

The request transcript must also say whether the preceding lookup walk emitted `KADEMLIA2_REQ` / `KADEMLIA2_RES` packets, and if those packets are included in the fixture set or only cited as setup.

## Result Requirements

Every promoted result fixture must identify:

- protocol byte: expected `0xE4` for plain Kad or `0xE5` for packed Kad;
- opcode: expected `0x3B` for `KADEMLIA2_SEARCH_RES`;
- sender Kad ID;
- target key;
- result count;
- source ID for each row;
- tag list bytes for each row;
- decoded source tags, including source type, source IP, TCP source port, UDP source port, buddy/server callback fields, and encryption options when present;
- expected rmule projection for each row.

## Output Projection

First-slice rmule behavior is deliberately narrow:

- A result row may become **Peer Source** only when it represents a direct-connectable High ID source with an IPv4 address and TCP port.
- Low ID rows remain diagnostics.
- Firewalled, buddy, and callback-mediated rows remain diagnostics.
- Rows with missing IP, missing TCP port, unsupported source type, ambiguous identity, or unproven byte order remain diagnostics.
- Diagnostic rows must not fail the whole lookup when at least one usable High ID source is present.

## Fixture Metadata

Each fixture set must include adjacent metadata with:

- fixture name and status;
- provenance;
- reference citations;
- capture or generation command, if applicable;
- local Kad ID;
- source lookup target file hash and size;
- bootstrap node or routing contact used;
- packet byte order assumptions;
- compression state;
- expected decoded packet facts;
- expected rmule event/output facts;
- unsupported rows and diagnostic reasons.

## Adoption Rule

The `kad` crate, or any other dependency, cannot be adopted from API shape alone. Adoption requires a fixture-backed eMule Kad source-lookup request/result transcript to pass through the adapter and produce rmule-owned direct-connectable **Peer Source** output without hiding Kad result fields in generic DHT record/provider/value semantics.

## Open Questions

- Exact Kad ID derivation from **User Hash**.
- Exact source ID meaning for every source type.
- Captured High ID source result fixture.
- Packet-level evidence for packed Kad source lookup.

## 2026-06-02 Fixture Spike Status

`crates/rmule-kad/tests/fixtures/source_lookup/minimal.toml` records the first fixture gate as blocked.

Resolved enough to cite:

- plain Kad protocol byte `0xE4`;
- packed Kad protocol byte `0xE5`;
- Kad2 source-lookup request opcode `0x34`;
- Kad2 search/source result opcode `0x3B`;
- request payload shape: target key, start position, file size;
- result payload shape: sender ID, target key, result count, source ID plus tags.

Still missing before writing byte fixtures:

- exact Kad ID byte order for rmule fixtures;
- exact source IP tag byte order for Kad source result rows;
- source ID identity meaning for each source type;
- captured or independently handwritten High ID source result evidence;
- packed Kad source-lookup packet evidence.

Because these are unresolved, the internal source-lookup slice does not create `request_minimal.bin` or `result_high_id_minimal.bin`. The fixture test asserts the blocked metadata so the missing evidence remains visible in `cargo test -p rmule-kad`.

## 2026-06-02 Internal Slice: Opaque Kad ID and Typed Blocked Evidence

The internal source-lookup slice keeps `KadId` as opaque 16-byte storage. It adds **no** production XOR distance, bucket-index, nearest-contact, or source-lookup key-ordering API, because the eMule Kad byte order is still unproven.

The missing evidence is now one canonical typed list in code — `rmule_kad::KadEvidence` — instead of being re-spelled across tests, fixture metadata, and prose. `KadId::DISTANCE_ORDER_BLOCKED_BY` names the subset that gates any distance/bucket-order API:

- `KadEvidence::KadIdByteOrder` — exact Kad ID byte order for rmule fixtures;
- `KadEvidence::DistanceOrdering` — a captured or independently reproducible routing comparison that proves distance ordering;
- `KadEvidence::ReproducibleLookupTarget` — captured or independently reproducible eMule/aMule behavior for at least one lookup target.

Handwritten rmule distance unit examples may only be added once every named item is resolved from captures or independently reproducible references.

## 2026-06-02 Internal Slice: Codec and Decoder Boundary

The internal slice adds the rmule-owned building blocks around source lookup, but keeps row decoding blocked:

- `rmule-kad` owns the Kad UDP envelope codec. Plain `0xE4` datagrams round-trip; packed `0xE5` is recognized as a well-formed-but-blocked `KadDecoded::PackedBlocked` value (not inflated, not an error).
- The eight first-slice Kad2 opcodes are typed, including `KADEMLIA2_SEARCH_SOURCE_REQ` (`0x34`) and `KADEMLIA2_SEARCH_RES` (`0x3B`).
- `decode_source_result` routes a `KADEMLIA2_SEARCH_RES` envelope by opcode but returns `KadSourceResultDecodeError::EvidenceBlocked { missing }`, where `missing` is the canonical `SOURCE_RESULT_BLOCKED_BY` list: Kad ID byte order, source IP tag byte order, source ID meaning, and a High ID source-result fixture. It never parses source rows and never produces a `PeerSource`.
- `KadSourceCandidate` is sealed: `Direct(PeerSource)` has no public constructor (`from_peer_source` is removed), so no production helper can manufacture a direct High ID source. Diagnostics stay publicly constructible.

## 2026-06-02 Next Evidence Direction

The next Kad work item after the internal source-lookup slice is a **Local Interop Harness** evidence capture, not `rmule-kad-net` runtime implementation. The harness should add one private-network Kad capture command that runs real aMule/amuled instances with synthetic content, records passive UDP packet capture as the primary evidence, and keeps all full captures as gitignored **Interop Run Artifacts** until a human explicitly promotes minimal datagrams into **Compatibility Fixtures**.

Accepted boundaries:

- capture is private-network only: no public Kad bootstrap URLs, imported public `nodes.dat`, or external Kad peers;
- Phase 1 captures a two-aMule source lookup and targets `KadEvidence::HighIdSourceResultFixture`;
- Phase 2 is opt-in, uses a larger local topology with at least five aMule nodes, and targets `KadEvidence::DistanceOrdering`;
- observed Kad2 routing traffic (`KADEMLIA2_REQ` / `KADEMLIA2_RES`) is required for distance-ordering proof; aMule state/export data may only support endpoint and identity mapping;
- partial success is valid when remaining evidence gates stay explicitly blocked;
- promotion is manual: checked-in fixtures contain only minimal datagrams plus metadata, while full pcap/pcapng captures remain retained run artifacts.
- once a Phase 1 High ID source-result fixture is promoted, `rmule-kad` should narrowly unblock source-result decoding for the proven plain `0xE4` / `KADEMLIA2_SEARCH_RES` row shape and project only proven direct-connectable High ID rows into sealed `KadSourceCandidate` / **Peer Source** output.

Expected promoted fixture layout:

```text
crates/rmule-kad/tests/fixtures/source_lookup/captured/private-amule-kad-source-lookup-YYYYMMDD/
  request_0x34.bin
  result_0x3b_high_id.bin
  metadata.toml
  routing_request_0x21_*.bin        # Phase 2 only, if promoted
  routing_result_0x29_*.bin         # Phase 2 only, if promoted
```

The metadata must separate protocol facts from provenance facts. At minimum it records provenance (`captured`), capture command, rmule git SHA, retained artifact ID/path, harness-owned node roles, container IPs and ports at capture time, observed Kad IDs, **Source Lookup Target** facts, protocol byte/opcode/compression state, expected source-row projection or diagnostic reason, and an explicit statement that no public Kad bootstrap or external peers were used.

## Private Mesh Capture: Working Recipe and Partial Evidence

**Status: a private aMule Kad mesh now forms and emits genuine plain `0xE4`
datagrams. The `0x34` source request and `0x21`/`0x29` routing packets are
captured; the `0x3B` source result is not yet captured. The checked-in fixture
gate (`minimal.toml`) therefore stays blocked for the result, while
`KadEvidence::KadIdByteOrder` is now proven by the captured request.**

An earlier investigation concluded a private mesh "could not form"; that was
wrong — it was masked by several compounding issues, all since resolved.

### The recipe (verified against aMule 2.3.3)

A reproducible private mesh requires one source patch plus runtime config (see
`tools/interop-harness/images/amule-kad-patched/` and the `kad-node` entrypoint):

1. **`IsGoodIPPort` → `IsGoodIP(nIP, false)`** (single-line patch). Stock aMule
   hardcodes `filterLAN=true`, rejecting every RFC1918 Kad contact regardless of
   `FilterLanIPs`. `IsLanIP` is left intact so aMule's **LAN mode** activates
   (all-LAN routing table → non-firewalled "home LAN"), which is what makes
   nodes reach `Kad: Connected (ok)` and route. The patch relaxes a deployment
   guard only; no protocol/wire logic changes, so captured bytes are genuine.
2. **Bootstrap-edition `nodes.dat`** (version 3, edition 1; 25-byte contacts).
   aMule only sends `KADEMLIA2_BOOTSTRAP_REQ` for contacts in this list, not the
   normal routing-zone `nodes.dat`.
3. **Contact IP byte order**: file bytes are the reversed dotted octets
   (`172.18.0.2` → `02 00 12 ac`), confirmed by aMule logging the correct target
   IP. No public bootstrap URL or public `nodes.dat` is used.
4. **UDP obfuscation off** (`IsClientCryptLayerSupported/IsCryptLayerRequested/
   IsClientCryptLayerRequired = 0`) → packets are plain `0xE4`.
5. **Non-zero `MaxUpload`** → the upload-bandwidth throttler flushes queued Kad
   control packets (with `0` it starves the queue and nothing is sent).
6. **Capture on `-i eth0 -U`** (not `-i any`, which colima/lima does not deliver
   on), stopping the sidecar before reading the pcap.
7. **Source search trigger**: the requester only searches after the per-file
   `m_LastSearchTimeKad` allows — cancel + re-add the download to fire a fresh
   `CSearch::FILE` lookup while capturing.
8. **Publish enable**: the publisher only publishes its source after the initial
   `NODECOMPLETE` self-lookup completes (`SetPublish(true)`), ~4 min after it
   connects.

### Captured evidence (retained pcaps in `.scratch/evidence/`, not committed)

A live mesh reproducibly emits these genuine plain `0xE4` datagrams between
harness-owned private nodes:

- `KADEMLIA2_SEARCH_SOURCE_REQ` (`0x34`) for the synthetic file. The requester
  fans it to the α=3 closest nodes. Decoded payload:
  `e4 34 | b52d308e 5ca206b8 23fc8593 d26210f2 | 0000 | 0000 0100 0000 0000`.
  The target equals the file hash `8E302DB5B806A25C9385FC23F21062D2` **with each
  32-bit word byte-swapped** — this directly proves `KadEvidence::KadIdByteOrder`.
- `KADEMLIA2_REQ`/`KADEMLIA2_RES` (`0x21`/`0x29`) — the lookup-walk (routing
  evidence for Phase 2), plus `KADEMLIA2_HELLO_REQ`/`RES` (`0x11`/`0x19`) and
  `KADEMLIA2_PING`/`PONG` (`0x60`/`0x61`).

### What is still missing: the `0x3B` source result

`KADEMLIA2_SEARCH_RES` (`0x3B`) requires the DHT publish→store→retrieve to
complete: the publisher publishes its source (`KADEMLIA2_PUBLISH_SOURCE_REQ`,
`0x44`) to the nodes closest to the file hash, and the requester's search must
query a node that stored it. In a small controlled mesh (5 and 14 nodes both
tried) the publish set and the search set do not reliably overlap — a queried
routing node receives the `0x34` but never the `0x44`, so it has no source to
return. The publisher's own namespace could not be captured under colima to
steer this further. Capturing `0x3B` reliably needs a materially denser/converged
DHT or a different capture environment, not another single fix.

Consequence for the checked-in fixtures:

- `KadEvidence::KadIdByteOrder` is **proven** by the captured `0x34` request;
- `KadEvidence::HighIdSourceResultFixture` stays blocked (no `0x3B` captured), so
  `crates/rmule-kad` source-result projection stays blocked behind
  `SOURCE_RESULT_BLOCKED_BY` and no captured fixture is promoted yet;
- `KadEvidence::DistanceOrdering` (Phase 2) has captured `0x21`/`0x29` routing
  evidence but is not yet promoted to a paired transcript.

### Reproducing

```bash
docker build -t rmule/interop-amule:local tools/interop-harness/images/amule
docker build -t rmule/interop-amule-kad-patched:local \
  tools/interop-harness/images/amule-kad-patched
# then stand up publisher + routing + requester nodes on a private docker
# network, seed each from the publisher, and capture the requester's eth0 while
# cancel+re-adding the synthetic ED2K link (see the patched-image README).
```

## 2026-06-19 Documentation-Provenance `0x3B` Decoder Landed

The controlled-identity real capture (ADR-0043, plan Tasks 1–10) has not yet
produced a promoted `captured` `0x3B`. Per ADR-0043's explicit fallback,
`rmule-kad` now unblocks `decode_source_result` for the proven plain-`0xE4` /
`KADEMLIA2_SEARCH_RES` (`0x3B`) direct-High-ID row shape, backed by a
**handwritten `documentation`-provenance fixture** built strictly from the
documented eMule Kad2 layout — not from captured bytes.

### What decodes now

`decode_source_result` parses `[16B sender][16B target][2B count LE]` then per
row `[16B source ID][1B tag count][tags...]`. Source tags reuse the shared eD2k
tag codec (`rmule_primitives::Tag`, explicit form `[type][01 00][nameByte]
[value]`), dispatched on the single-byte tag name: `SOURCETYPE 0xFF`, `SOURCEIP
0xFE` (UINT32, host-order IP), `SOURCEPORT 0xFD` (UINT16 TCP), `SOURCEUPORT 0xFC`
(UINT16 UDP). Projection follows aMule `Search.cpp` source types: 1/4 →
direct; 3/5 → buddy callback; 6 → firewalled; 2/other → unsupported.
The large variants (4, 5) are what a publisher writes for a file strictly over
`OLD_MAX_FILE_SIZE` = 4 290 048 000 bytes (kno `Constants.h:89`,
`KnownFile.h:129`; eMuleAI `Opcodes.h:165`, `Search.cpp:885`, `:901`). That is
the whole number of `PARTSIZE` parts under `2^32`, not `u32::MAX`, and rmule's
publisher keys on the same constant. Readers treat 1/4 and 3/5 alike.

- A direct (type 1/4) row with a `SOURCEIP`, a non-zero `SOURCEPORT`, and a
  resulting `ClientId` that `is_high_id()` projects to a sealed
  `KadSourceCandidate::direct` **Peer Source**. eMule's `SOURCEIP` is the
  host-order `u32`; rmule's `ClientId` is the same value byte-swapped so
  `PeerSource::as_peer_endpoint` reconstructs `a.b.c.d`.
- A direct row whose IP resolves below the Low ID threshold → `LowId`;
  missing IP/port → `MissingEndpoint`; buddy/firewalled types → diagnostics;
  unknown type → `UnsupportedSourceType`. Packed `0xE5` stays `PackedBlocked`;
  a non-`0x3B` opcode is `NotASearchResult`; a malformed/truncated payload is a
  typed `MalformedPayload` error (no panic).

The committed fixture is
`crates/rmule-kad/tests/fixtures/source_lookup/documentation/0x3b-high-id-documented/`
(`result_0x3b_high_id.bin` + `metadata.toml`, `provenance = "documentation"`).
It carries one direct High ID row (IP `198.51.100.10:4662`, `SOURCEIP` wire
bytes `0A 64 33 C6`), one Low ID row, one buddy/firewalled row, one
missing-port row, and one deprecated-type row, so the test exercises projection
*and* every diagnostic branch. The fixture is hand-laid as explicit byte
literals (not encoder output) and the decoder is driven over the file.

### Provenance — honest status

- `KadEvidence::KadIdByteOrder` — **capture-proven** (the prior `0x34` capture).
- `KadEvidence::HighIdSourceResultFixture` — satisfied by the handwritten
  documentation fixture (ADR-0043 permits an independently handwritten example),
  so it is **removed** from `SOURCE_RESULT_BLOCKED_BY`.
- `KadEvidence::SourceIpTagByteOrder` and `KadEvidence::SourceIdMeaning` —
  **documentation-backed only**, from three agreeing clean-room sources
  (Wireshark `epan/dissectors/packet-edonkey.c`, the ETH Mysicka thesis,
  `a-pavlov/jed2k`) plus aMule `Search.cpp`. They are **not capture-proven**, so
  they **remain in `SOURCE_RESULT_BLOCKED_BY`** and are the upgrade target for
  the controlled-identity `0x3B` capture. No `KadEvidence` variant is deleted;
  the enum stays the canonical vocabulary.
- `KadId::DISTANCE_ORDER_BLOCKED_BY` stays **fully blocked** — distance ordering
  is separate Phase 2 evidence.

### jed2k framing cross-check (dev-only; bytes NOT committed)

As a local oracle, `a-pavlov/jed2k`'s public `kad2_search_res_0.dat` was fetched
to `/tmp`, prefixed with `0xE4 0x3B`, and run through rmule's parser. The
envelope + `[sender][target][count]` header parsed exactly: sender `1a6d37f5
4edb759d 9d89fec0 27524541`, target `ae4c36f5 090d15e8 4d0ba773 5864e3e7`,
count = 2. The per-row `[16B id][1B tag count][tag-LIST]` framing read correctly;
row 0's first five keyword tags decoded via the shared eD2k tag-prefix codec, and
the sixth uses UINT64 (`0x0A`), confirming these are **keyword** results whose
per-row value types exceed the source-tag subset (only the framing was under
test). **Framing: parsed correctly.** The public bytes were used only as a dev
cross-check and are **not committed** (private-only rule).

## 2026-06-19 Controlled-Identity Capture: Live-Debug Findings (`0x3B` still blocked)

An iterative live-Docker debugging pass (colima) corrected the diagnosis the
earlier handoff recorded and improved the harness, but **did not** capture a
`0x3B`: the publisher never advertises its source, so no node ever holds one to
return. `SourceIpTagByteOrder` and `SourceIdMeaning` therefore stay
documentation-backed in `SOURCE_RESULT_BLOCKED_BY`, and the committed
documentation fixture stands.

### Corrected diagnosis

- **`preferencesKad.dat` identity seeding is NOT the cause** (the handoff's prime
  suspect). A controlled bisection that disabled prefs seeding left the mesh
  equally silent. The seed writes the last-known-IP field as `0`, but a node that
  has never run also starts with IP `0`, so seeding changes nothing there.
- **The `KADEMLIA2_SEARCH_SOURCE_REQ` (`0x34`) does fire** — captured on the wire
  (`e4 34 | b52d308e 5ca206b8 23fc8593 d26210f2 | 0000 | 0000 0100 0000 0000` to
  the storer), correcting the handoff's "no `0x34` even on Cancel+re-Add". Two
  things gated it: aMule searches a download's Kad sources once and then blocks on
  the per-file `m_LastSearchTimeKad`, so the trigger must be **`Cancel` + re-`Add`**
  (a bare second `Add` is a no-op); and the requester needs the storer in its
  routing table, which the prior mutual-bootstrap topology did not reliably give.
  Firing is still timing-sensitive in this small mesh.
- **Seed byte order is verified**: the storer's on-wire Kad
  ID after `e4 09` is `b52d308e 5ca206b8 23fc8593 d26210f2`, exactly the
  byte-swapped file hash and exactly the `0x34` target. `storer_kad_id_for_file_hash`
  is correct; no change needed.

### Harness improvements made

- **Hub topology + storer-first start.** The storer (Kad ID = file-hash target) is
  the rendezvous hub: it bootstraps to nobody and is started first; the publisher
  and requester bootstrap only to it. This breaks the circular bootstrap of the
  prior mutual topology (where a node started before its peers were listening sat
  with an empty routing table forever). With it, the publisher reaches
  `Kad: Connected (ok)` — non-firewalled, the state a direct High ID source row
  needs — which the prior runs never achieved (firewall state remains somewhat
  fragile run-to-run).
- **`Cancel` + re-`Add` search trigger** (retried), replacing the single bare
  `Add`; the weak `rmule-kad-source-search-active` log signal is now best-effort
  (non-fatal) so the run still retains its pcap.
- Publish window default raised toward the documented ~4-minute source-publish
  delay.

### Remaining blocker: no source publish (`0x44`)

Across every configuration tried this session — 3-node seeded, hub topology, and
a 5-node `--routing-nodes 3` density mesh — the publisher **never emits a
`KADEMLIA2_PUBLISH_SOURCE_REQ` (`0x44`)** to the storer. Passive capture on the
storer (the rendezvous) shows only `HELLO`/`PING`/firewall-check traffic
(`0x11`/`0x19`/`0x60`/`0x61`/firewall opcodes) and no `0x21` lookup walk. With no
source stored on the storer, a `0x34` that reaches it returns nothing, so no
`0x3B` is produced. The leading hypothesis is that aMule only enables source
publishing after its initial `NODECOMPLETE` self-lookup completes, which does not
reliably happen in a mesh this small/quiescent — the same overlap wall the prior
session hit at 5 and 14 nodes. This is the "real capture proves unreproducible"
case ADR-0043 anticipated; the documentation-provenance fixture remains the
backing for the decoder.

### To get a real `0x3B` next

Make the publisher actually publish (`0x44`) before searching: confirm/await
`NODECOMPLETE` on the publisher (richer Kad debug or a denser, longer-converged
mesh), or drive publishing more directly, then fire the proven `Cancel` + re-`Add`
search once the storer holds the source. A different runtime than colima may also
deliver the periodic Kad maintenance/publish more faithfully.

## 2026-06-19 Frozen: `rmule-kad` parked pending evidence (ADR-0069)

The 2026-06-19 planning review chose the first **Application Front-End** (a headless
CLI driving an extended **Core Orchestrator**) as the next work over a Kad live
runtime. `rmule-kad` is **formally parked, not abandoned**: the sans-I/O crate
(envelope, `KadId`, routing table, lookup walk, bootstrap, documentation-provenance
source-result decode) stays compiled and tested, but **no `rmule-kad-net` is built**
until the wall above lifts — a genuine `0x44` publish landing a source on the storer
so a `0x34` yields a real `0x3B`, and, separately, the still-blocked distance
ordering (`KadId::DISTANCE_ORDER_BLOCKED_BY`). The **Source Discovery Policy** seam in
`rmule-core` already accommodates Kad as a second peer-discovery channel, so the first
front-end runs eD2k-only and Kad slots in later with zero redesign. See ADR-0069.

## 2026-07-07 Unfrozen: Kad resumes as a full node (ADR-0043)

The park is lifted. The 2026-07-07 review found the wall-breaker: the `0x44` gate sits
on aMule's *publisher* role, not its *storer* role — so once **rmule implements
publish**, the harness makes rmule the publisher (a **Kad Stimulus Node**, see
`crates/rmule-kad/CONTEXT.md`) against a real aMule storer. aMule parses, stores, and
re-serializes the entry; its `0x3B` answer is genuine real-client bytes, upgrading
`SourceIpTagByteOrder` and `SourceIdMeaning` to captured provenance. The denser-mesh /
NODECOMPLETE recipe below is superseded for that purpose (it remains valid background
on aMule publisher behavior).

Plan (ADR-0043): the first step unblocks `DISTANCE_ORDER_BLOCKED_BY` via a seeded-table
`KADEMLIA2_REQ`/`RES` discrimination capture (harness authors one aMule node's entire
routing table, stimulus targets chosen so the `0x29` answer discriminates XOR-ordering
hypotheses); a later step captures the genuine `0x3B`. Open question "exact Kad ID
derivation from **User Hash**" closes: **no derivation exists** — eMule's Kad ID is an
independent persisted random 128-bit identity.

## 2026-07-07 Distance ordering CAPTURE-PROVEN (ADR-0043)

`KadId::DISTANCE_ORDER_BLOCKED_BY` is now **empty**. A private aMule 2.3.3
`KADEMLIA2_RES` (`0x29`) ranked four discrimination contacts by aMule's own XOR
distance and returned them closest-first, confirming **`word_le_msw_first`**: four
32-bit words, most-significant word first, each little-endian on the wire — the unique
ordering consistent with the already-proven Kad ID byte order. Committed fixture:
`crates/rmule-kad/tests/fixtures/routing/captured/private-amule-kad-distance-20260707/`
(`request_0x21.bin`, `result_0x29.bin`, `metadata.toml`, provenance `captured`).
`rmule-kad` now ships `KadId::distance` / `KadDistance`, real
`KadRoutingTable::select_nearest`, and `KadLookupWalk::next_contact`; the blocked stubs
and `KadRoutingSelectionError` are deleted. `KadEvidence::DistanceOrdering` and
`ReproducibleLookupTarget` are resolved (the enum variants stay as canonical
vocabulary).

Two harness findings made the capture possible (both recorded in the fixture's
`provenance_disclosure`; neither changes aMule's distance computation, so the returned
*order* is genuine):

- **Routing-zone seed, not bootstrap edition.** `CRoutingZone::ReadFile` dispatches a
  version-3 **edition-1** `nodes.dat` (what `build_bootstrap_nodes_dat` writes) to
  `ReadBootstrapNodesDat` and returns *without adding any contact to the routing tree*
  — that format only feeds the bootstrap list. To make a seeded contact **queryable**
  (returnable in a `0x29`), the harness now writes a routing-zone **version-1**
  `nodes.dat` (`build_routing_zone_nodes_dat`) whose contacts load via `AddUnfiltered`.
  This likely explains part of the historical tiny-mesh capture difficulty.
- **Return-filter relaxation.** `CRoutingBin::GetClosestTo` filters returned contacts
  by `GetType() <= maxType && IsIPVerified()`. A tiny quiescent mesh never ages
  contacts to a good type nor completes IP verification, so aMule answers every
  `KADEMLIA2_REQ` with an empty (count=0) `0x29`. The patched image
  (`relax-kad-routing-return-filter.patch`) relaxes only that filter; the ordering
  (`ClientID ^ target`, sorted by `CUInt128`) is untouched. Same private-mesh-guard
  spirit as the existing `disable-lan-kad-filter.patch`.

Reproduce: `cargo run -p rmule-interop-harness -- kad-distance-ordering-capture` (builds
the mesh, fires the stimulus, auto-decodes the winning hypothesis to
`distance-verdict.txt`).

## 2026-07-07 The `0x3B` wall FELL: genuine source result captured (ADR-0043)

The controlled-identity `0x3B` capture the whole source-lookup slice was gated on is
**done**. rmule ran as a **Kad Stimulus Node** — publisher *and* requester — against one
real aMule **storer** in the private Docker mesh (`kad-source-capture` harness scenario):
rmule published a synthetic file's source (`0x44`), aMule accepted and acked it (`0x4B`),
rmule searched (`0x34`), and aMule answered with a genuine `KADEMLIA2_SEARCH_RES`
(`0x3B`). The wall-breaker (ADR-0043): the old silence sat on aMule's *publisher* gate
(its `NODECOMPLETE` self-lookup), not the *storer* path — so rmule doing the publishing
dissolves it. rmule's `0x44`/`0x34` are stimulus context; aMule's `0x3B` is
aMule-authored evidence (re-serialized from parsed tags, not a byte echo).

Fixture: `crates/rmule-kad/tests/fixtures/source_lookup/captured/private-amule-kad-source-result-20260707/`
(`request_0x34.bin`, `result_0x3b_high_id.bin`, `metadata.toml`, provenance `captured`).
`SOURCE_RESULT_BLOCKED_BY` is now **empty**; `KadEvidence::SourceIpTagByteOrder` and
`KadEvidence::SourceIdMeaning` are capture-proven (the enum variants stay as canonical
vocabulary). `crates/rmule-kad/tests/captured_source_result.rs` drives the genuine bytes
through `decode_source_result`.

### The firewall gate needed no new patch (capture-recipe finding)

aMule's `Process2PublishSourceRequest` silently drops a publish while it self-reports
UDP-firewalled (`IsFirewalledUDP(true)` → early return). This was the handoff's first suspect
for publish silence. It resolved with **no new patch**: `CUDPFirewallTester::IsFirewalledUDP`
returns `false` unconditionally when `CKademlia::IsRunningInLANMode()` (aMule
`UDPFirewallTester.cpp:58`), and the storer enters LAN mode because the mesh is all-RFC1918
and the entrypoint sets `FilterLanIPs 0` (`Kademlia.cpp:463` — routing table 1–256 nodes,
all LAN, re-checked every 10 s). The existing `disable-lan-kad-filter.patch` already
preserves `IsLanIP` precisely so LAN mode works. The stimulus node retries the publish on
an 8 s timer until it sees the `0x4B` (success-only opcodes never NAK), which covers the
~10–25 s the storer takes to reach LAN mode after boot.

### Capture facts (all cross-checked against the genuine bytes)

- **`SourceIpTagByteOrder` (capture-proven).** The `SOURCEIP` tag value is the host-order
  u32 `(a<<24)|(b<<16)|(c<<8)|d` of `a.b.c.d`, written little-endian — wire bytes `d c b a`.
  Decoding under exactly that order reconstructs the publisher's real mesh IP (172.30.0.9).
- **`SourceIdMeaning` (capture-proven).** The 16-byte per-row source ID equals the
  publisher **User Hash** word-swapped per 32-bit word (the Kad-key transform), **not** the
  publisher's Kad ID — confirming the identities are independent.
- **IP substitution (confirmed).** rmule's `0x44` carries no `SOURCEIP` (test-proven in
  `source_publisher`); the `SOURCEIP` in aMule's answer is aMule-authored from its observed
  publish sender. aMule's `Process2PublishSourceRequest` prepends
  `TAG_SOURCEIP = entry->m_uIP` (the observed sender) when it sees `TAG_SOURCETYPE`.
- **FILESIZE tag present (correction to the earlier handoff).** The handoff predicted the
  captured row would carry *no* FILESIZE tag. The capture corrects this: the row's tag list
  opens with a `FILESIZE` tag (name `0x02`, value = the file size) that aMule re-emits from
  the entry's `m_uSize` via `CEntry::WriteTagListInc` (aMule `Entry.cpp:153-155`). Tag order
  is `FILESIZE, SOURCEIP, SOURCETYPE, SOURCEPORT, SOURCEUPORT`. rmule's decoder ignores the
  unrecognized `0x02` name and still projects the direct source (regression-guarded).

Reproduce: `cargo run -p rmule-interop-harness -- kad-source-capture` (builds the mesh,
publishes + searches from the rmule stimulus node, writes `kad-source-capture-verdict.txt`
and the captured `0x3B` bytes for promotion).

## The firewalled publisher's own `0x44` (capture, 2026-09-22)

The rows above are a *storer's* answers. The publish that creates them was only
ever read out of the reference sources until flow M
(`kad-core-buddy --publish-source`) drew one from a firewalled stock aMule 2.3.3
holding rmule as its recruited buddy — run `1790097388`, promoted as
`crates/rmule-kad/tests/fixtures/buddy/captured/amule-233-publish-source-req-20260922`.
111 bytes: `[0xE4][0x44][fileKey 16][sourceID 16][tagCount 1][7 tags]`.

- **Tag order** — `SOURCETYPE(0xFF) UINT8`, `SERVERIP(0xFB) UINT32`,
  `SERVERPORT(0xFA) UINT16`, `BUDDYHASH(0xF8) STRING(32)`,
  `SOURCEPORT(0xFD) UINT16`, `FILESIZE(0x02) UINT32`, `ENCRYPTION(0xF3) UINT8`.
  `TAG_ENCRYPTION` rides last because `CSearch::StorePacket` appends it after
  the firewalled/direct branch. Four of the seven are `CTagVarInt`, so a
  narrower value narrows the tag.
- **`TAG_BUDDYHASH` is upper-case big-endian.** With the flow's Kad IDs pinned
  asymmetrically per 32-bit word, a buddy ID spelling
  `FFEEDDCCBBAA99887766554433221100` on the wire came out as
  `CCDDEEFF8899AABB4455667700112233` in the tag — `CUInt128::ToByteArray`, not
  `GetData()`. eMule 0.70b and eMuleAI write the other string (source reading;
  neither is on the bench), so the two families cannot address each other's
  buddies.
- **`TAG_SERVERIP` is not byte-swapped.** Its four value bytes read `a b c d`
  for `a.b.c.d` — the opposite of `SOURCEIP` above, which a storer synthesises
  in host order. A decoder that treats them alike gets one of them backwards.
- **No `TAG_SOURCEUPORT`, ever, from a stock publisher.**
  `CPrefs::m_useExternKadPort` starts `true` and the tag is written only under
  `!GetUseExternKadPort()`, so the storer indexes the port it observed — the
  only one a NAT in the path leaves correct.
- **No `TAG_SOURCEIP`**, for the reason the storer-side note already gives.

**The publish's fifth gate.** `CSharedFileList::Publish`'s four gates
(`IsConnected`, `GetCount`, buddy `Connected`, `GetPublish`) are not enough:
`CSearch::StorePacket` (`Search.cpp:456`) returns with **no log line** when the
candidate's distance to the file key exceeds `SEARCHTOLERANCE` (`0x01000000`)
and it is not a LAN IP. A swarm with no node near the file's own Kad location
therefore refuses every publish in silence — which is why the flow now pins one
placed member to `storer_kad_id_for_file_hash(<file hash>)`.
