# Protocol crates stay runtime-free; Tokio drives networking, orchestration and apps

## Context

Hashes, links, identifiers, packet codecs, session state machines and fixtures are
reused by tests, tools and applications. Binding them to an async runtime would drag
that runtime into every consumer and make deterministic tests depend on it. Real
networking still needs sockets, timers, tasks, cancellation and backpressure, and Tokio
is the most mature Rust ecosystem for them.

## Decision

The protocol crates (`rmule-primitives`, `rmule-ed2k`, `rmule-peer`, `rmule-kad`)
and the runtime-free support crates (`rmule-store`, `rmule-bootstrap`) do not depend
on any async runtime. Tokio is used where I/O and tasks live: the runtime crate
`rmule-net` (ADR-0081), the orchestrating `rmule-core`, the test scaffolding in
`rmule-testkit`, the applications under `apps/`, the tools under `tools/`, and
dev-dependencies.

## Consequences

- `rmule-primitives` and the other protocol crates never depend on Tokio; their
  session logic is sans-I/O (ADR-0021, ADR-0044).
- Socket and stream adapters live in `rmule-net`, not in the protocol crates.
- Applications drive protocol work through command and event APIs (ADR-0011) rather
  than owning sockets.

## Considered options

- **Tokio throughout every crate.** Rejected: it couples codecs and state machines to
  one runtime and to real time.
- **Every crate runtime-generic.** Rejected: abstracting sockets and timers over all
  runtimes costs more than it returns for a client that ships on Tokio.
