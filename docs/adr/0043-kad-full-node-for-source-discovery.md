# Kad is a full Kad2 node for source discovery, with rmule as its own evidence stimulus

## Context

Kad is the server-less half of eD2k source discovery. Proving rmule's Kad against a
real client needs a genuine `KADEMLIA2_SEARCH_RES` (`0x3B`) carrying a source row, and
an aMule-only private mesh never produces one. aMule's *publisher* gates
`KADEMLIA2_PUBLISH_SOURCE_REQ` (`0x44`) on its `NODECOMPLETE` self-lookup, so in a small
mesh no publish is sent, no storer holds a source, and no search has anything to
return. Seeding node identities so publisher and requester converge on one storer does
not help, because the publish never leaves the publisher.

The gate sits on the publisher role, not the storer role. If rmule publishes to a real
aMule storer, aMule parses, stores and re-serializes the entry from its parsed tags, and
its `0x3B` answer is aMule-authored bytes. The re-encoding is not a byte echo, which
defeats the circularity trap. Building the feature is the research instrument. The
**Kad Stimulus Node** in `crates/rmule-kad/CONTEXT.md` records the rule: rmule may
provoke an exchange, the harness may arrange identities and topology, but only bytes a
real client emits are evidence, and rmule-authored bytes never prove a Kad Evidence
Gate.

The harness arranges identities by writing each aMule node's 23-byte
`preferencesKad.dat` (16-byte Kad ID at offset 6, read verbatim by `CPrefs::ReadFile`
when non-zero) and seeding its User Hash. aMule bypasses its `SEARCHTOLERANCE` distance
gate for LAN addresses (`distance > tolerance && !IsLanIP`), so steered routing works
on a private network. Distance ordering is proven the same way: the harness authors one
aMule node's entire routing table as a bootstrap-edition `nodes.dat`, so a stimulus
`KADEMLIA2_REQ` with adversarially chosen targets makes aMule's `0x29` answer
discriminate between XOR-ordering hypotheses against a fully known table.

The evidence lives in `crates/rmule-kad/tests/fixtures/routing/captured/` (distance
order) and `crates/rmule-kad/tests/fixtures/source_lookup/captured/` (genuine `0x3B`
source rows). The `0x3B` capture also settles that a source row's 16-byte ID is the
publisher's User Hash, word-swapped, and that the Kad ID and the User Hash are
independent identities.

aMule 2.3.3 is the interop oracle on purpose: its Kad is the ported eMule `CKademlia`
lineage, which is essentially the whole live network.

## Decision

rmule runs a **full Kad2 node** and uses it as a source-discovery channel.

**Roles.** The node implements all four Kad Node Roles: routing responder, requester,
publisher and storer. The storer is in scope so the deterministic tier can close
publish, store and search inside an rmule-only mesh. The other Kad layers are their
own decisions: the firewall self-check (ADR-0058), buddy and Low-ID connectivity
(ADR-0061), keywords (ADR-0062), notes (ADR-0063), liveness and flood protection
(ADR-0064), per-datagram obfuscation (ADR-0046), `nodes.dat` (ADR-0066) and the join
sequence (ADR-0067).

**A sans-I/O node with explicit time.** `rmule-kad`'s `KadNode` takes time as a
parameter and never reads a clock: `handle_datagram(now, from, bytes)`, `tick(now)` and
`next_wake()`. Per-lookup timeouts, bucket refresh, republish and expiry all hang off
that one explicit `now`. The small-timer hello pass runs every minute whether or not the
node has joined and reads a per-contact expiry, so a contact merged into a joined node
is greeted on the next pass that finds it at its bucket's front (aging rule in
ADR-0067).

**A thin runtime in `rmule-net`.** `rmule_net::kad` runs one task per node: a single
`select!` loop over transport receives, driver commands and the node's `next_wake()`
deadline. It maps real time onto the node's `KadInstant` scale, flushes outbound
datagrams, forwards events and taps every datagram into an optional capture directory
(ADR-0022). `spawn` binds a socket pair the node owns, for tools, the stimulus node and
the mesh sim; `spawn_over` rides the core's one client-UDP socket (ADR-0057). The
runtime is deliberately not a `DrivenSession`, whose contract is connection-shaped.

**The source row projection.** The **Kad Source Row Projection** carries the
publisher's User Hash, its connect-options byte, its Kad UDP endpoint and, for a
firewalled publisher, its serving buddy. A direct High-ID row is a candidate; a
type-3/5 row that names a usable buddy is a candidate through the callback route
(ADR-0061 pins the layout and its byte orders); any other row stays a diagnostic.

**Self-exclusion sits on the requester side.** aMule's responder
(`CKademliaUDPListener::ProcessKademlia2Request` → `CRoutingBin::GetClosestTo`) never
excludes the asker, so a lookup answer can name the requester itself. rmule's responder
(`KadRoutingTable::select_closest_servable`) matches that wire behaviour, and
`KadLookupWalk::add_candidate` drops any row whose ID equals the node's own before it
can take a walk slot.

**Core integration.** Kad is a Discovery Channel: `KadDiscoveryChannel` over the
`KadSourceChannel` seam feeds each active download's candidate pool beside the
server-UDP channel (ADR-0051), and `KadPublisher` publishes from Core's shared-file
registry. With Kad disabled, behaviour does not change. `EnableKad` starts the node,
the publisher and the ed2k→Kad handoff forwarder as one Kad Activity; `DisableKad` and
a pump death both run the same reclaim, which stops and joins all three, clears the
active flag and emits `CoreEvent::KadStopped` (lifecycle rule in ADR-0093).
`DumpDiagnostics` reports `kad_tasks_live`. The Kad identity, a random 128-bit ID
independent of User Hash, and the stable UDP port persist in the typed store
(ADR-0083).

## Consequences

- Testing has four tiers: sans-I/O unit and property tests; `KadMeshSim` in
  `rmule-testkit` (N nodes, virtual clock, in-memory routing, scripted loss and
  reorder) with a scriptable `FakeKadPeer` for adversarial datagrams; promoted fixtures;
  and opt-in private-mesh interop against aMule.
- Every interop proof asserts a bidirectional acceptance moment, such as aMule routing
  through rmule, acknowledging a publish or returning rmule's published source. The
  passive absence of an error does not count, because it looks the same as a malformed
  datagram silently dropped.
- Scored exit criteria are private-mesh and deterministic only. Joining public Kad is a
  manual, unscored smoke, and no public bytes are ever committed as evidence.
- `KadId::DISTANCE_ORDER_BLOCKED_BY` is empty: distance ordering is captured evidence.
- Kad source rows carry a User Hash and crypt options, so Kad is an obfuscate-dialable
  source channel (ADR-0042).
- A bootstrap answer's contact is probed at once, so bootstrap-dialing a helper toward
  the node it must be known by is the quickest way to seed a flow; the Seeded Bootstrap
  glossary entry in `crates/rmule-kad/CONTEXT.md` states the rule.

## Considered options

- **A lookup-only Kad client** with no publisher or storer. Rejected: it leaves nothing
  to capture the `0x3B` against, makes rmule a leech, and stops the deterministic tier
  from closing publish, store and search in-process.
- **Reusing `DrivenSession` for the Kad runtime.** Rejected: a connection-shaped
  contract (byte stream, startup deadline, close reason) contorts a connectionless node.
  The pattern (sans-I/O machine, thin driver, capture tap) is reused; the trait is not.
- **Driver-owned timers**, as the eD2k driver owns its startup deadline. Rejected: Kad
  has many timers, and an explicit `now` keeps the node deterministic and the mesh
  simulation trivial.
- **Natural convergence in a denser aMule mesh.** Rejected: non-deterministic, slow and
  environment-sensitive, and the publisher gate defeats it anyway.
- **A handwritten `0x3B`** from the documented layout (Wireshark `packet-edonkey.c`, the
  `jed2k` reimplementation). Rejected as proof: it asserts byte order and source-ID
  meaning instead of proving them.
- **Another implementation as oracle.** MLDonkey implements only Kad1/Overnet,
  jMule and xMule are dead, and eMule under Wine has no headless control. None improves
  on aMule.
- **A public-network join as a scored exit criterion.** Rejected: the public DHT is flaky
  in CI and public bytes are never evidence.
- **Excluding the asker on the responder side.** Rejected: aMule does not do it, so
  rmule's answer would differ on the wire for no interop gain.
