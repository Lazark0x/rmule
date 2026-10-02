# rmule-testkit

The dev-only home of every shared test counterparty and fixture in the
workspace (ADR-0040). Consumed exclusively as a `[dev-dependencies]` entry:
never published, never in a production dependency graph, and never wired into
the Local Interop Harness — the Compatibility Tier stays a separate tool
(ADR-0040).

Two rules govern what lands here. A fake is faithful to **behaviour**, not to
wire bytes; and a seam is added only when a test demands it, never
speculatively. A helper is hoisted into this crate when a **second** crate's
tests need it — until then it stays beside the tests that use it.

## Language

**Protocol Counterparty**:
A deterministic stand-in for the other side of a conversation — `FakeEd2kServer`,
`FakePeer`, `FakeServerUdp`, `FakeDialer`, `FakeBuddy`. It speaks enough of the
protocol to drive the code under test through a named situation, and no more.
_Avoid_: mock, stub, dummy (those name a technique; these are counterparties)

**Peer Script**:
The declarative program a `FakePeer` runs: the policies (`SlotPolicy`,
`ServePolicy`, `SourcesPolicy`, `HashSetPolicy`, `MultiPacketPolicy`) that
decide how it answers, plus the `PeerStats` a test asserts on afterwards. A
scripted peer is how adversarial paths are tested — refusals, stalls, malformed
answers — without a real peer to misbehave on cue.
_Avoid_: scenario config, mock setup

**Serving Core**:
A real `rmule-core` instance wired to loopback, used as the *honest*
counterparty. Both-fakes policy (ADR-0040): happy paths run against a
`ServingCore`, adversarial paths against a `FakePeer` — neither replaces the
other, because a fake proves nothing about the code it stands in for.
_Avoid_: integration server, test harness

**Kad Mesh Sim**:
The deterministic, explicit-time simulation that drives many `KadNode`s against
each other with no sockets: `FakeKadPeer` participants, a `LinkPolicy` that
decides which datagrams are delivered, dropped, or delayed, and a `TraceEntry`
log to assert the resulting conversation on. The sim lives here rather than in
`rmule-kad` because it is test scaffolding, not protocol.
_Avoid_: test network, mock swarm

**Fixture Vocabulary**:
A namespaced module of builders for one protocol area (`kad_mesh`, `kad_node`,
`kad_keyword`, `kad_source`, `peer_session`, `wire`). They stay behind their
module rather than being re-exported flat because their names — `node`, `key`,
`publish`, `ctx`, `A` — would collide at the crate root. A consumer picks: name
the few it wants, or glob one vocabulary in when that vocabulary is the whole
subject of the leg.
_Avoid_: helpers, utils, common (the shapes this crate exists to prevent)

**Fake Interfaces**:
A scripted **Interface Source** (ADR-0084): the set of addresses a test says
this host holds, and can change mid-run. The real enumeration answers whatever
machine the test runs on, which makes the two rules that read it — the
interface tier and the local-interface corroboration filter — untestable on CI;
this makes the set an input, so a renumber, an RFC 4941 rotation and a
dual-homed host are one call away.
_Avoid_: mock netif, address provider

**Tracing Guard**:
The per-test diagnostic subscriber install (`init_tracing`), returning a guard
that keeps the writer alive for the test's lifetime. One install per test, so
a failing test's own trace is what gets printed.
_Avoid_: logger, log setup

## Relationships

- Every crate that needs a counterparty declares `rmule-testkit` under
  `[dev-dependencies]`. Nothing depends on it at build time.
- The testkit depends on the protocol crates it fakes, so those crates cannot
  depend on it back — their own tests reach it only through `[dev-dependencies]`,
  which is not a cycle.
- The Compatibility Tier's live counterparties (real aMule, a real Lugdunum
  server) live in `tools/interop-harness`, not here. The two tiers never share
  a counterparty: one proves behaviour, the other proves bytes.
