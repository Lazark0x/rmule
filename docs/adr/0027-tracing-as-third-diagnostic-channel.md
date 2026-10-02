# Tracing as a third diagnostic channel

## Context

rmule already has two diagnostic surfaces. Typed events — core events, eD2k events,
peer events — describe domain facts for application consumers. Per-session capture
(ADR-0022, ADR-0024) records raw wire bytes as compatibility evidence. Neither
explains how Tokio tasks interact: hangs, decision audits across workers, and
failures whose first symptom is "nothing happened for four minutes". The glossary
keeps "log line" out of the event vocabulary on purpose, so growing events to fill
that gap would dilute the language the project guards.

## Decision

`tracing` spans and structured events are a third channel, the Diagnostic Trace,
for developer-facing cross-cutting observability. Domain events stay typed and
pure, captures stay byte-level, and traces stay for developers.

**Who emits.**

- Library crates emit; they never install a subscriber.
- The sans-I/O crates — `rmule-primitives`, `rmule-ed2k`, `rmule-peer`, `rmule-kad`
  and `rmule-store` — have no `tracing` dependency, so their determinism
  (ADR-0021, ADR-0025) holds without exception.
- The I/O and orchestration crates — `rmule-net`, `rmule-core` and
  `rmule-bootstrap` — and the binaries are instrumented.

**Spans** nest by domain ownership. `download { download_id }`, `search
{ search_id }` and `serve` are roots for the tasks `rmule-core` spawns;
`peer_worker { worker_slot }` and `source_lookup { server }` sit under a download;
`rmule-net` opens `ed2k_session { server }` and `peer_connection { peer }` inside
whatever parent the spawn site passes through `tracing::Instrument`. Fields carry
the typed identifiers core already has, not strings invented for logs.

**Levels.**

- `ERROR` only for a typed error that escaped the boundary meant to handle it.
- `WARN` for recoverable degradation: a retired peer, a skipped compressed frame, a
  rejected login.
- `INFO` once per state transition an operator would care about — download
  started, paused or completed; part assigned or verified; peer retired — and
  never inside a per-part, per-peer or per-packet loop.
- `DEBUG` mirrors each domain event a driver emits, plus scheduler assignment and
  release outcomes.
- `TRACE` for per-packet detail, which capture already owns and so rarely fires.
- Events carry structured fields, not formatted strings. A peer timeout the
  scheduler retries is never `ERROR`.

**Subscribers** are installed only in binaries and test helpers:

- `rmule-cli` and `rmule-tools` filter with `EnvFilter` from `RMULE_LOG` (default
  `info`) and write to stderr. `rmule-tools` also reads `RMULE_LOG_FORMAT`
  (`pretty` or `json`) and an optional `RMULE_LOG_FILE` that adds a daily-rotating,
  non-blocking file appender.
- `rmule` writes its Run Log, a bounded `rmule.log` in the data directory, with
  the same `RMULE_LOG` filter, since the alternate screen can carry no output.
- Tests install per test through `rmule_testkit::init_tracing()`, which uses
  cargo's per-test writer: passing tests stay silent and a failing test dumps its
  own trace.

No `tracing/max_level_*` feature is set; every callsite stays compiled and filtering
is at runtime.

## Consequences

- Domain event types carry no diagnostic fields; a new debugging need is answered
  with a span or a `DEBUG` event, never a wider event payload.
- A failing test carries enough span context to localise a hang without a re-run.
- A library crate that installs a subscriber is a review-blocking bug.
- No `tokio_unstable` build flag is required.

## Considered options

- **Grow the event vocabulary** with scheduler-progress, heartbeat and decision
  events. Rejected: it dilutes the domain language and forces consumers to handle
  noise they do not model.
- **Captures plus typed errors only.** Rejected: captures do not show which task is
  parked, and typed errors fire only on outcomes, not on hangs that never end.
- **The `log` facade.** Rejected: spans and structured fields are what make hang
  attribution work, and `log` has neither.
