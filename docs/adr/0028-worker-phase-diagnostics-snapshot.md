# Worker phase and diagnostics snapshot for hang investigation

## Context

Tracing (ADR-0027) attributes most failures to a span. It does not cover a Tokio
task parked on a channel receive or a lock for minutes: the last span says where a
worker is, not what it thinks it is doing. Multi-peer scheduling (ADR-0026) makes
this acute, because each download runs several peer workers that can stall
independently in different domain phases, and release builds without
`tokio_unstable` cannot ask a task what it is waiting on.

## Decision

`rmule-core` keeps a Worker Phase per peer worker, readable as part of a
point-in-time `DiagnosticsSnapshot`.

- `WorkerPhase` mixes connection facts and orchestration facts: `Idle`,
  `Connecting`, `HandshakingPeer`, `WaitingForSlot`, `RequestingHashSet`,
  `RequestingPart`, `ReceivingPart`, `VerifyingPart`, `Releasing` and `Retired`. It
  lives in `rmule-core` beside the scheduler, not in `rmule-net`, whose
  one-conversation surface has no words for orchestration (ADR-0026).
- Each slot has one `WorkerEntry`: its slot, the peer endpoint once known, the
  phase, the monotonic `Instant` it was entered, a transition count, and the peer's
  client software when identified. One writer per slot means no write contention.
- Every phase change goes through one helper, `enter_phase`, which emits the `DEBUG`
  trace event and updates the entry together, so trace and map never drift.
- State lives in `DiagnosticsState`, an `Arc<std::sync::Mutex<…>>` shared by `Core`
  and its tasks. A `std` mutex is right because every write is a point-in-time map
  update that never crosses an `.await`.
- Part counts are not mirrored. A download's row carries `parts: Vec<PartState>`,
  republished whole from the scheduler, and the verified, in-flight and missing
  counts are tallies of that vector (ADR-0079). `retired_peers` is a stored count
  because it is a peer fact, not a part fact.
- Two access shapes return the same value: the synchronous
  `Core::diagnostics_snapshot()`, a lock-and-clone for holders of a `Core`; and
  `CoreCommand::DumpDiagnostics`, answered by `CoreEvent::DiagnosticsSnapshot`, for
  consumers that hold only the command channel. The command reads state and
  schedules no work; it also fills the fields that only the actor can see, such as
  the Kad runtime's state.

## Consequences

- An operator or a failing test localises a stall to one worker, one phase and its
  age.
- The snapshot is the core's general read model: other decisions add their rows to
  the same shared state — transfer counters (ADR-0077), the server list (ADR-0080),
  port mappings, shared directories — and the sync accessor reports them without an
  actor round trip.
- A cross-process dump is not part of this decision; a separate daemon would add
  an adapter over `Core::diagnostics_snapshot`, not a second state store.

## Considered options

- **`tokio-console`.** Rejected as the primary mechanism: it needs
  `--cfg tokio_unstable` and a `console-subscriber` dependency, and shows channel and
  lock state rather than a domain phase.
- **A `watch` channel per worker.** Rejected: a dump needs an atomic cross-worker
  snapshot, which independent watches cannot give without extra coordination.
- **`DashMap`.** Rejected: an extra dependency for a map of a few dozen entries with
  one writer per key.
- **A `phase()` accessor on the `rmule-net` peer connection.** Rejected: the phases
  are orchestration language the runtime crate does not speak.
