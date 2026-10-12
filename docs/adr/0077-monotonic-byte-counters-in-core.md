# Transfer byte counters are monotonic facts in the core; rates are derived at the edge

## Context

A front end shows download and upload speeds, totals and estimates. The core can
answer with rates (it has the clock and the events) or with running totals that each
consumer differences itself. A rate is an opinion about a time window, and the core
cannot know which window a consumer wants: a 1 Hz gauge, a session summary and a
remote client want three different ones. A rate also cannot be checked against a
capture, where only byte counts exist. A total is reproducible and order-free: two
consumers polling at different cadences read the same number and are both right.

The diagnostics snapshot of ADR-0028 is the core's poll surface; ADR-0069 consumes it
on a 1 Hz tick.

## Decision

**The core publishes monotonic byte facts** — running totals of payload that crossed
the core's wire boundary — and derives nothing from a clock: no rates, moving averages,
windows or per-second fields, under any name. A consumer that wants a rate differences
two snapshots and smooths them itself.

**The surface is the existing `DiagnosticsSnapshot`**, one door rather than a parallel
statistics API:

- `DownloadDiagnostics::received_bytes` — payload this download has taken off the wire
  since its row opened.
- `DiagnosticsSnapshot::uploads: BTreeMap<PeerEndpoint, UploadDiagnostics>` — one row
  per peer holding an upload slot, with `peer`, `file_hash`, `started_at` and monotonic
  `bytes_sent`. Keyed by peer, as aMule's per-client `m_nTransferredUp`: a re-grant for
  another file keeps accumulating against the same peer.
- `DiagnosticsSnapshot::session: SessionCounters` — process-lifetime `down_bytes_total`
  and `up_bytes_total`.
- `DiagnosticsSnapshot::shared_files` — per shared file, aMule's `CFileStatistic`
  (`KnownFile.cpp:76-98`): upload requests, slots granted and bytes served, for this
  run and all time (`ShareTotals`).

**A storage reading on the same row is not a counter.** `DownloadDiagnostics::allocated_bytes`
(ADR-0111) is what the filesystem reserved for the `.part`, read after a write: it falls when a
gap is punched, may exceed the file's length, and is never a total or a rate. Facts only, no
ratio, kept in the shared `DiagnosticsState`.

**Rows are transient; totals are not.** A download row retires on teardown and an
upload row when its slot is released, but nothing subtracts from the session totals,
and a byte counted after its row is gone still lands there. A consumer polling more
slowly than transfers finish still sees every byte.

**Bytes are counted where the core hands payload to, or takes it from, the wire:**

- **Down** — in the download runner's worker-fact pump, on
  `PeerWorkerEvent::BlockReceived`, before the scheduling brain judges the block. A
  duplicate range or a block a later hash check discards still crossed the socket.
  `received_bytes` is a transfer fact; verified parts remain the progress fact.
- **Up** — in the serve enactor, when a `SendBlock` command is accepted by the peer's
  connection writer, the last core-owned step before the socket. A command dropped into
  a dead connection is never claimed. The upload row's lifetime follows the same
  enactor's `UploadSlotGranted` / `UploadSlotReleased` facts.

The sans-I/O `DownloadState` and `ServeState` brains stay clock-free and I/O-free; the
enactor is the only place that knows what happened.

**Payload, not octets.** eD2k framing, packet headers, obfuscation padding and
handshakes are outside the counters, and an inbound `OP_COMPRESSEDPART` counts its
inflated size. These are transfer measures, not bandwidth measures. A socket-level
octet counter, which a bandwidth limiter would need, belongs at the runtime boundary as
a sibling.

**The sync accessor and the actor echo agree.** The counters live in the shared
`DiagnosticsState` that `Core`, every download runner and the serve task hold, so
`Core::diagnostics_snapshot()` reports downloads, uploads, session totals and shared
files in full without an actor round trip, and `DumpDiagnostics` reports the same
values. `DiagnosticsSnapshot::kad` is the one field the sync accessor cannot fill,
because the Kad runtime lives with the actor; the exception is documented on the field.
New fields go behind the shared handle when they can, and document the exception when
they cannot.

**Durability.** Session totals and per-transfer rows reset with the process. The
per-file all-time figures are the stored Share Totals plus this run's: seeded from the
store once at start, and the files whose figures moved are flushed back periodically.

## Consequences

- Every consumer — the TUI, `rmule-cli`, any remote client — reads the same numbers and
  picks its own window; the TUI's speed meter and its 60 s ETA window are both edge
  derivations over `received_bytes`.
- Counters are poll-only levels. No `CoreEvent` is emitted per block, which would put
  wire-rate traffic on a deliberately low-frequency lifecycle channel.
- If two consumers duplicate the same differencing code, the fix is a shared helper on
  the consumer side, not a clock in the core.
- aMule's cumulative session totals across runs (`preferences.dat`) are not kept.
