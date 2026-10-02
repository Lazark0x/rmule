# Crate topology: sans-I/O protocol crates named after their wire conversation, one runtime crate rmule-net

## Context

rmule speaks three wire conversations: client↔server eD2k, client↔client eD2k, and Kad.
Each needs offline decoding (tools, fixtures, tests, ports without an async runtime) and
live I/O (sockets, drivers, timeouts, capture). Putting Tokio behind a `runtime` feature
in a protocol crate cfg-splits every test and consumer and drags Tokio into every
offline reuser's lockfile; putting it in unconditionally makes the offline-reuse
contract a lie.

A first answer gave each protocol a `-net` sibling crate on a shared driver-harness
crate. Those four runtime crates were small, never versioned apart, and every consumer
that needed one soon needed the others; the boundaries repeated manifest, glossary and
test-layout ceremony four times while expressing one fact: live I/O is separate from the
sans-I/O protocol libraries.

The peer-side protocol carries far more than file transfer — hello, file and status
requests, the slot queue, part exchange, AICH, chat, secure identification, compressed
parts — so a crate named after one feature inside it (`rmule-transfer`) misnames itself.

## Decision

**Protocol crates are sans-I/O and runtime-agnostic, and each is named after the wire
conversation it owns**, not after a feature inside it:

- `rmule-ed2k` — client↔server: packet decoders, umbrella enums, the sans-I/O
  `Ed2kSession` (ADR-0021), and the `Ed2kCommand` / `Ed2kEvent` contract.
- `rmule-peer` — client↔client: the peer state machine, packet umbrella and
  command/event vocabulary.
- `rmule-kad` — Kad: the explicit-time `KadNode` and its codecs.
- `rmule-primitives` — what all three share, including the session spine of ADR-0044.

None of them depends on Tokio.

**One runtime crate, `crates/rmule-net`, owns every socket**, one module per wire surface:

- `driver` — the generic Tokio harness (`DrivenSession`, `run_driver`,
  `spawn_connection`), the synthesized-`Disconnected` invariant of ADR-0044, the capture
  engine and the `CryptStream` obfuscation transport.
- `ed2k`, `peer` — the connection-shaped TCP runtimes, each re-exporting its surface
  under `rmule_net::<module>::…`. The `DrivenSession` adapters (`Ed2kDriven`,
  `PeerDriven`) stay private per module, keeping runtime adaptation out of the sans-I/O
  crates' vocabulary.
- `kad` — the connectionless UDP runtime, deliberately not a `DrivenSession`: that
  contract is connection-shaped and a Kad node is not (ADR-0043).
- `family`, `interfaces`, `portmap`, `natt` — the Family Pair of ADR-0085, the Interface
  Source of ADR-0084, the I/O half of port mapping (ADR-0086), and the NAT-T transport
  (ADR-0091).

Cross-peer orchestration — scheduling, part assembly, upload slots — lives in
`rmule-core` (ADR-0026); no separate transfer-orchestration crate exists.

**Placement:** `apps/` holds user-facing binaries (`rmule`, the terminal client, and
`rmule-cli`), `crates/` holds libraries, and `tools/` holds developer tools
(`rmule-tools`, `interop-harness`, `ed2ksrv-differ`). A one-shot harness binary becomes a
subcommand of `rmule-tools` (for example `kad join-node`), not a new tool.

## Consequences

- Offline reusers depend on a protocol crate and get no runtime; live consumers depend
  on `rmule-net` with one dependency line, one manifest and one `CONTEXT.md` organised by
  module.
- Touching one runtime module rebuilds the others and every `rmule-net` consumer. The
  runtimes change together in practice (harness contract changes always fan out), so the
  cost is minutes of incremental build.
- A new wire surface is a new module of `rmule-net` and, if it has a protocol of its own,
  a new sans-I/O crate named after the conversation.

## Considered options

- **A `runtime` feature in each protocol crate.** Rejected: Tokio behind a cfg in the
  offline codec crates makes the sans-I/O contract conditional.
- **One `-net` crate per protocol, plus a shared harness crate.** Rejected: the boundaries
  carried ceremony, not information; no consumer wanted exactly one of them, and the real
  seam lies between the protocol crates and the runtime, not between runtimes. A separate
  harness crate also forced `DrivenSession` to be public API across a crate boundary.
- **Merge the protocol runtimes but keep the harness as a leaf crate.** Rejected for the
  same reason: it has one consumer set.
- **Name the peer crate `rmule-transfer`.** Rejected: the conversation is far wider than
  transfer.
