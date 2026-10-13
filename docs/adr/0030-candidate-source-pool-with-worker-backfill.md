# Candidate-source pool with worker backfill and event-driven peer identification

## Context

A download caps its peer workers at `peer_concurrency_per_download` (ADR-0026), but
its source list is usually longer and full of dead or firewalled entries. If the
runner keeps only the first few sources and dials them in a blocking loop, two
things break: one dead entry in the first batch aborts the whole download while
other sources sit untried, and once the first workers are gone nothing replaces
them. Live runs showed exactly that — 14 to 46 usable sources, about six ever tried,
failure within twelve seconds — while a well-seeded file whose first peers all
happened to be live completed.

## Decision

The runner keeps every usable source as an ordered candidate pool and backfills
workers from it; a worker's identification is an event, not a blocking call.

- All usable sources go into the pool. The runner spawns workers from it to keep
  `peer_concurrency_per_download` in play — active, connecting and awaiting a
  callback together — at start and after every retirement.
- The pool grows while the download runs: server-UDP global sources (ADR-0051), Kad
  sources (ADR-0043), source exchange (ADR-0055), and Low-ID sources reached by
  callback (ADR-0039) all feed it.
- `PeerTransferService::start_peer_worker` returns before the handshake. The worker's
  own task dials and handshakes, then emits `PeerWorkerEvent::Connected` when the peer
  is usable, or `DialEnded` naming the cause followed by `Disconnected` (or
  `CryptIncompatible`) when it is not.
- Core assigns a worker its first part when its peer answers the file probe
  (`PartsAdvertised`, ADR-0112), never at spawn or on `Connected`, so neither a failed
  handshake nor a part the peer lacks strands a part. A failed handshake is an ordinary worker failure and
  takes the same retire-and-backfill path as a mid-download disconnect.
- The download fails with `NoUsableSources` only when the pool is empty and no worker
  is active, connecting or awaiting a callback.
- Timeouts stay where they were: the driver's hello timeout bounds a connecting
  worker, and the slot-wait timeout bounds a queued one (ADR-0026).
- On a run-ending stop — cancel, pause or failure — the runner tells each worker to
  shut down and waits until each has reported its terminal `Disconnected`, capped by
  `WORKER_SHUTDOWN_TIMEOUT` for one that never does. It does not wait for the event
  channel to close: the pool keeps a sender alive for backfilled workers, so the
  channel cannot close while the runner holds it.

## Consequences

- Any download with at least one live, granting peer among its sources completes,
  instead of depending on the first few entries being live.
- `peer_concurrency_per_download` stays the one concurrency knob and bounds socket
  use.
- In-process fakes return a worker at once and must emit `Connected` and then
  `PartsAdvertised` before a part is assigned, the same contract the runtime adapter keeps.

## Considered options

- **Skip a failed dial inline and dial a replacement in the same loop.** Rejected: a
  mid-run backfill would run a blocking handshake on the runner's event loop and
  stall every other worker for the replacement's hello timeout.
- **Connector tasks handing ready workers back on a second channel.** Rejected: it
  duplicates readiness bookkeeping beside the worker event stream the runner already
  consumes.
- **Dialling more connectors than the worker cap** to time out dead peers in
  parallel. Not adopted: backfill already makes dead-heavy source lists succeed, and
  over-dialling costs more sockets and a second tuning knob.
