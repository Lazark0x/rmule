# PeerSession is reusable and fully interleaved with a single active slot

## Context

eMule peers reuse connections: they probe several files over one TCP connection,
hold a queue position across files, and interleave probes for new files with an
in-flight slot wait. A session that lives for one transaction — hello, one file,
close — models none of that and pays a fresh hello and handshake for every extra
file against the same peer.

Slots are the constrained axis. `OP_QUEUERANKING` carries no file hash; a rank
applies to the most recent `OP_STARTUPLOADREQ`, so a second `OP_STARTUPLOADREQ` for
another file while a slot context is live is undefined on the wire. Multi-peer
scheduling (ADR-0026) also requests one `EMBLOCKSIZE` block at a time, and a busy
peer that must re-grant a slot per block drops us before a part finishes.

## Decision

`PeerSession` in `rmule-peer` is a reusable, fully interleaved state machine with
one active slot context per connection.

- After `ConnectionEvent::Identified` the session accepts commands for any file. Probes and
  hash-set requests for different files run concurrently, tracked in a per-file map
  keyed by file hash; their answers (`OP_REQFILENAMEANSWER`, `OP_FILEREQANSNOFIL`,
  `OP_FILESTATUS`, `OP_HASHSETANSWER`) carry the file hash and demultiplex
  unambiguously.
- A re-probe of a known file answers from the session's per-file state without a
  wire round-trip, and a hash set already received is not requested again.
- The slot ask (`AskSlot`, or a first `RequestParts` when none was sent) takes the slot
  context, which moves through queued, slotted and downloading. Once the slot is
  granted, `RequestParts` for the same file go straight out as `OP_REQUESTPARTS` over
  the held slot: one `OP_STARTUPLOADREQ` per file, across all its parts and blocks, as
  eMule does. A `RequestParts` before the grant waits for it, its ranges held.
- The session asks a part hash set only when told (`RequestHashSet`, once per file),
  and its slot ask waits on no answer: which link asks, and when, is the download's
  decision (ADR-0026, "One hash-set ask at a time").
- A slot ask for a different file while a slot is held is rejected at once with
  `PeerError::SlotBusy`. Probes and hash-set requests keep interleaving freely.
- The session never infers completion from byte counts. The slot ends on
  `RequesterCommand::ReleaseSlot` (the runtime worker decides the file is done),
  `CancelTransfer` (ADR-0056), or a terminal path: peer close, a mid-slot
  `OP_FILEREQANSNOFIL` (the peer lacks the file), or the driver-owned stale
  timeout. Each emits `SlotReleased` with a `SlotReleaseReason`, after which the
  next file may take the slot.
- `OP_OUTOFPARTREQS` is not terminal. On a granted slot it ends the transfer,
  not the flow: the flow is queued again on the same link and the session emits
  `Requeued`, as aMule turns `DS_DOWNLOADING` back into `DS_ONQUEUE`
  (`ClientTCPSocket.cpp:755-762`). The uploader sends it when our session is over
  and someone waits (`UploadQueue.cpp:549`, `UploadClient.cpp:597-600`), then
  queues us again and sends `OP_QUEUERANKING` on the same socket
  (`UploadClient.cpp:643-660`), which ranks the flow; a later
  `OP_ACCEPTUPLOADREQ` grants it again, and the next `RequestParts` waits for that
  grant as a first one does. While the flow is only queued, `OP_OUTOFPARTREQS`
  changes nothing.
- Timers stay in the driver (ADR-0021): it calls `signal_slot_stale()` and
  `signal_idle_close()` when its clocks fire.

## Consequences

- One connection serves a peer for its whole useful life, and probing many files
  costs one handshake.
- The worker, not the session, is the completion authority; it assembles bytes and
  releases the slot when it is finished with the peer (ADR-0026).
- Releasing per file rather than per part keeps re-grant churn away: a worker
  assigned parts one after another holds the slot throughout.
- The state machine is harder than a single transaction, but it matches the
  protocol's real concurrency model.
