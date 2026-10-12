# Context Map

This repo is split into multiple bounded contexts. Each has its own `CONTEXT.md` glossary. Global, cross-cutting language lives at `/CONTEXT.md`. All ADRs are global at `/docs/adr/`.

| Context              | Path                                      | Scope                                                  |
| -------------------- | ----------------------------------------- | ------------------------------------------------------ |
| Global               | `CONTEXT.md`                              | Cross-cutting terms used across all crates             |
| `rmule-primitives`   | `crates/rmule-primitives/CONTEXT.md`      | Shared wire values (no I/O): packets, tags, hashes, identities, endpoints, links, search and source rows, obfuscation and SUI key material, the sans-I/O session traits |
| `rmule-ed2k`         | `crates/rmule-ed2k/CONTEXT.md`            | ed2k protocol library: packets, codecs, login, hashing, sans-I/O session |
| `rmule-peer`         | `crates/rmule-peer/CONTEXT.md`            | eD2k peer protocol library: bidirectional sans-I/O peer session (requester + server capabilities), peer packets, hello body |
| `rmule-kad`          | `crates/rmule-kad/CONTEXT.md`             | Kad protocol library: packet envelopes, Kad identities, source-lookup evidence gates, private transcript fixtures, sans-I/O `KadNode` + k-bucket routing (the deterministic `KadMeshSim` that drives it lives in `rmule-testkit`) |
| `rmule-net`          | `crates/rmule-net/CONTEXT.md`             | Live network runtimes (ADR-0081): the shared generic Tokio driver harness + capture engine + crypt stream (`driver` module) and the live runtime layers for the eD2k server, eD2k peer, and Kad protocols (`ed2k`/`peer`/`kad` modules), each preserving its former crate's public surface |
| `rmule-winsock`      | `crates/rmule-winsock/CONTEXT.md`         | The Windows ICMP-reset switch on every unconnected UDP socket `rmule-net` binds: the one WinSock call no safe wrapper offers, and the workspace's only `unsafe` block |
| `rmule-bootstrap`    | `crates/rmule-bootstrap/CONTEXT.md`       | Zero-config bootstrap acquisition (ADR-0065): the `Fetcher` I/O seam, the server.met and command-only nodes.dat pipelines (parse-before-install, plan-not-effect), the first-run decision, the auto-update URL walk, and the feature-gated reqwest fetcher; pipelines-over-a-seam (decoders live in `rmule-ed2k`/`rmule-kad`) |
| `rmule-store`        | `crates/rmule-store/CONTEXT.md`           | Domain-free typed durable layer (ADR-0083): records and packed values, indexed tables as the only write path, the store and its schema, the version ladder |
| `rmule-core`         | `crates/rmule-core/CONTEXT.md`            | Core Orchestrator: activity-set actor, download scheduler, upload slot queue, shared-file registry, content store |
| `rmule-words`        | `crates/rmule-words/CONTEXT.md`           | The operator's words both front ends speak: sentences and clauses written from core's codes, one words module per domain, the units a sentence spells its data in |
| `rmule-testkit`      | `crates/rmule-testkit/CONTEXT.md`         | Dev-only Correctness-Tier scaffolding (ADR-0040): protocol counterparties, peer scripts, the serving core, the deterministic Kad mesh sim, per-protocol fixture vocabularies |
| `rmule-cli`          | `apps/rmule-cli/CONTEXT.md`               | Headless front-end: commands over the Core Orchestrator, the data directory, and the documented `kad join` exception |
| `rmule`              | `apps/rmule/CONTEXT.md`                   | Terminal front-end (ADR-0069): the pure UI state spine (edges vs levels, the data tick), view state, honest degrades and no-dead-UI, chrome and flashes, glyph goldens, greedy column widths |
| `interop-harness`    | `tools/interop-harness/CONTEXT.md`        | Live interop bench (ADR-0045): flows, counterparties and stimulus, the run dir, readiness gates, taps and capture sidecars, wire rows and verdicts, documented absences, the fake-public Kad swarm and seeded bootstraps, image recipes and the `RMULE_BENCH` tier |
| `rmule-tools`        | `tools/rmule-tools/CONTEXT.md`            | Protocol diagnostic and capture instrument: command families, operands, captures and slicing, probes and status pings, the Kad Stimulus Node |

> Every workspace member carries a `CONTEXT.md`; `scripts/guards.sh` enforces it. A new crate lands with its glossary and its row here in the same change.
