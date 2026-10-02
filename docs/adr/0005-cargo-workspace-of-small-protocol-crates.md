# One Cargo workspace of small protocol crates and thin application crates

## Context

ADR-0001 puts protocol behaviour in libraries that every front-end consumes. Those
libraries cover separate concerns: shared primitives, eD2k server sessions, peer
transfer, Kad, networking runtime, bootstrap acquisition, storage, and orchestration.
Each moves at its own pace while sharing compatibility fixtures.

## Decision

rmule is one Cargo workspace with three areas:

- `crates/` holds small library crates, one concern each. `rmule-primitives` is the
  shared base; the protocol, runtime, storage and orchestration crates build on it.
  ADR-0081 fixes the crate topology and names.
- `apps/` holds thin application crates: `rmule` (the terminal client) and
  `rmule-cli`. They own no protocol behaviour.
- `tools/` holds developer and interop tooling: `rmule-tools`, `interop-harness` and
  `ed2ksrv-differ`.

## Consequences

- Crate boundaries are kept honest: shared primitives never accumulate app-specific
  behaviour.
- Protocol crates evolve independently while sharing compatibility fixtures.
- A new concern becomes a new crate when it has a boundary of its own, not a module
  bolted onto an application.

## Considered options

- **One large crate, split later.** Rejected: boundaries that are not enforced by the
  build erode before the split happens.
- **Application first, with protocol code as app internals.** Rejected by ADR-0001.
