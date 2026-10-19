# A peer is handed only a part it advertised: very rare first, then aMule's head and tail, then a streaming window, then rarest

## Context

`DownloadScheduler` (ADR-0026) hands a worker the lowest pending part and, when none is
pending, races the lowest in-flight part the worker is not on. It reads nothing from the
peer. The peer session reads the peer's `OP_FILESTATUS` into
`FileProbeStatus::Available { bitmap, complete }`, but the worker forwards only `complete`
(`PeerWorkerEvent::PartsAdvertised`, ADR-0108), and the first part is assigned on
`Connected` (ADR-0030), before the status is even asked for. A partial source is asked for
parts it does not hold, a file meant to be previewed fills from its lowest index only, and
a TCP status whose part count disagrees with the file size is taken as it comes.

Every `file:line` is stock aMule 2.3.3 (`4e8f2b3c`); kno's fork `ab483654` carries the same
rules at other lines. aMule facts are read, never ported (ADR-0004).

| Rule | aMule 2.3.3 | Here |
|---|---|---|
| status count | `0` is a complete source, every part (`DownloadClient.cpp:404-410`); any other count must be `size / PARTSIZE + 1` or it throws (`:417-425`) and the connection drops (`ClientTCPSocket.cpp:2018-2047`); only the file's real parts are read (`DownloadClient.cpp:426-449`) | §1 |
| a later status | rebuilds the source's status, its counts taken out and put back (`:400-401`, `:459`) | §2 |
| part frequency | per part, over every source whose status is known, connected or queued (`UpdatePartsFrequency`, `PartFile.cpp:3526`); a source leaves it only when it stops being the file's source (`DownloadClient.cpp:1558-1568`) | §2 |
| candidates | parts the source holds that the file still lacks (`PartFile.cpp:1910-1918`) | §4 |
| order | very rare — frequency at most `max(1, m × sources / 100)`, `m` 10, 5 above 200 sources, 2 above 800 — then preview, then rare, then common (`:1926-1939`, `:1985-2023`) | §4 |
| ties | `rand()` (`:2025-2054`) | §4 |
| preview parts | the first, the last, and the last-but-one when `last length + 1 < PARTSIZE / 3` (`:1958-1972`) | §5 |
| preview files | video and archive, behind the `PreviewPrio` preference, default off (`:1941-1945`, `Preferences.cpp:1088`) | §5 |
| previewable | video or audio with its first 256 KiB complete (`PartFile.cpp:3792-3800`) | §5, ADR-0114 |
| nothing needed | a TCP status holding nothing the file lacks sets `DS_NONEEDEDPARTS` (`DownloadClient.cpp:464-466`); no free block on a granted slot sends `OP_CANCELTRANSFER` and sets it too (`:641-667`); the source is kept across a disconnect (`BaseClient.cpp:1320-1329`), asked again over TCP after twice `FILEREASKTIME` (`PartFile.cpp:1436-1444`), and purged near the source limit, 40 s apart (`:1423-1434`) | §6 |

## Decision

### 1. A status is read once, into Advertised Parts

- One reader in `rmule-peer` turns a wire status into **Advertised Parts** over the file's
  real parts, `0..part_count(size)`: count `0` is every part; count `size / PARTSIZE + 1`
  gives its first `part_count(size)` bits, so the phantom part of an exact multiple is never
  read; any other count is refused. The wire count is one function,
  `ed2k_status_part_count`, in `rmule-primitives` beside `part_count`.
- A refused status on the TCP session closes the connection as a protocol violation, as
  aMule disconnects. On a `0x91` reask ack the whole reply is ignored, as today (ADR-0057).
- The worker forwards the probe's answer as `PeerWorkerEvent::PartsAdvertised { parts,
  complete }`: `parts` the Advertised Parts, or none when the peer answered
  `OP_FILEREQANSNOFIL`; `complete` is ADR-0108's bit, unchanged.
- rmule asks once per connection, so one answer per worker reaches core. A late status on a
  settled probe stays folded into the session's own record and is not raised again.

### 2. Advertised Parts ride the source's record; Part Frequency is the book's

| Set | Key | Owner | Lifetime |
|---|---|---|---|
| **Advertised Parts** | the source's Source Book record, inside one download | the Source Book, a record-tier attachment (ADR-0090) | written by every status the run reads from the source — its worker's probe answer, a `0x91` status — each replacing the last; gone with the record |
| **Part Frequency** | part index | the Source Book | derived, for the run |
| **Preview Band** | — | the scheduler | the run |
| **Streaming Window** | — | the scheduler | recomputed per assignment |

- Each download has its own book, so a status from a peer that holds two of our files feeds
  one download only (ADR-0107).
- `frequency[i]` equals the number of records whose Advertised Parts hold part `i` after
  every write, merge and removal, kept incrementally so an assignment costs the candidates,
  not records × parts. A merge keeps the kept record's Advertised Parts, or the folded
  record's when it has none, as it does a standing.
- Nothing is stored: Source Seeds (ADR-0109) do not carry it, and a restart's first probes
  write it again.

### 3. A worker's first part waits for its Advertised Parts

- After its connect-time `RequestFile` the worker reads the peer's answers — sources, a hash
  set, an AICH root, forwarded as they are while a part streams — until the probe is answered,
  bounded by `slot_wait_timeout` (ending `SlotTimeout`), then sends `PartsAdvertised`. The
  brain asks the worker's slot (or the hash set) on `PartsAdvertised`, never on
  `Connected`, and hands its first blocks at the grant (ADR-0026, "The slot ask").
- A handed block cannot be taken back: the worker asks the session for it at once. Assigning
  before the status would hand a partial source a part it lacks. aMule likewise chooses a part only once the
  status is known, and only on a granted slot.
- A worker that takes a grant its link already carries (an Awaited Grant, ADR-0107) sends no
  connect-time `RequestFile`: the Advertised Parts its record last heard — the probe before its
  hang-up, or a reask answer's status — are its probe's answer, as aMule's downloader asks blocks
  off the part status its client kept (`ClientTCPSocket.cpp:635-644`). A record that heard none is
  probed first, and the grant waits for that answer instead of a slot ask.
- An `OP_FILEREQANSNOFIL` answer ends the worker as it does today.
- A release hands the freed blocks only to a granted worker; a queued one is handed its
  blocks at its grant.

### 4. The rank

The candidates for worker `p` are the parts its Advertised Parts hold that still have an
unclaimed block (ADR-0117). The minimum of one tuple wins; `i` sits in every key, so no two
tie:

| Position | Component | `0` when |
|---|---|---|
| 1 | very rare | `frequency[i] ≤ max(1, m × n / 100)`, `n` the records holding Advertised Parts, `m` as aMule's |
| 2 | band | `i` is in the **Preview Band** |
| 3 | window | `i` is in the **Streaming Window** |
| 4 | key | `(0, i)` inside the window, `(frequency[i], i)` outside it |

- `n` counts the sources whose parts are known, where aMule's `GetSourceCount()` counts every
  source: the book also holds pooled sources nobody has asked yet. Below 20 the bound is 1,
  and very rare is a part only this source holds. Inside the very-rare zone aMule orders by
  frequency before preview; the tuple keeps the band ahead, the same order whenever the
  bound is 1.
- **The End Game** (ADR-0117) uses the same filter and the same tuple: with no unclaimed
  block left in a part its Advertised Parts hold, a worker's **Duplicate Set** is chosen by
  positions 1–3, then by expected arrival, latest first, so a very rare, band or window
  part still comes first, and the part index and offset break every tie.
- No randomness: the same inputs give the same part, so every decision sequence is
  assertable. aMule's completion criterion is not taken: a part whose workers left keeps its
  **Arrived Ranges** (ADR-0117), and its unclaimed blocks are handed whenever it is next
  chosen.
- Every download is filtered and ranked. Outside Streaming Priority the band and window are
  empty and the tuple is `(very rare, frequency, i)`; when every worker advertises every part,
  that is today's lowest-index order.
- Such a download now writes parts out of order; every write past the end punches the gap it
  leaves (ADR-0111).

### 5. Streaming Priority, Previewable, the band and the window

- **Previewable** is video ∪ audio, aMule's preview set; **Streaming Priority** is video ∪
  audio ∪ archive. Both are read off the stored **Download Metadata** name (ADR-0078) through
  `Ed2kFileClass` (aMule's table, `OtherFunctions.cpp:656-894`): the ASCII bytes after the
  last `.`, any case, the stem not empty. A CD image is not an archive
  (`OtherFunctions.cpp:125-138`). They are `DownloadMetadata::is_previewable()` and
  `is_streaming_priority()`: the class is the network's vocabulary in `rmule-primitives`; the
  two sets are rmule's preview and scheduling policy and live in core. No rename exists, so
  each is constant for the run.
- rmule adds audio to aMule's video and archive so every Previewable download is fetched
  head first for the Preview action (ADR-0114), and keeps the band on with no switch where
  aMule's `PreviewPrio` defaults off. Both are local policy, invisible on the wire.
- **Preview Band**: part `0`, the last part, and the last-but-one when the last part's length
  plus one is below `PARTSIZE / 3` (so at most 3,242,664 bytes) — aMule's set exactly. One part
  gives `{0}`, two give `{0, 1}`; empty outside Streaming Priority. A member that verifies
  leaves candidacy, with no latch. The tail is fetched early but never gates readiness:
  ADR-0114 reads part `0`.
- **Streaming Window**: `[anchor, anchor + N)`, `anchor` the lowest unverified part, `N`
  `CoreConfig::streaming_window_parts`, default `8`, `0` for none; empty outside Streaming
  Priority. It slides as the anchor verifies; a resumed run anchors at its lowest unverified
  part, since the scheduler seeds only the missing ones.
- `N` is an engineering knob: no operator chooses a look-ahead, so it sits in `CoreConfig`
  beside the Connection Budget's knobs (ADR-0069, ADR-0116), not in Core Settings and never per
  download. aMule has no window, so its default is not aMule's. The default `8` is measured: against stock aMule 2.3.3 seeds (three partial
  seeds, one worker each, no source leaving), the verified prefix reached half the file about
  30 s sooner at `8` than at `4` (≈189 s against ≈219 s) and the time-averaged out-of-order
  lag fell from 13.0 to 11.2 MB, while `2`, narrower than the workers, lagged 40 % more than
  `4`; the whole file's time is set by the seeds and does not move with `N`. Two seeds cannot
  separate `N` — every part's frequency is 1 or 2, and the window's order and the outside's
  agree — so the bench takes three. What a wide window costs when a source leaves (the rare
  parts it defers behind the window) is not measured.

### 6. A source that holds nothing we need

- When a worker's Advertised Parts hold no part the file lacks — aMule's `bPartsNeeded`
  false, the one predicate the `0x91` path already reads — the worker is retired
  **`NoNeededParts`**. It ends with `OP_CANCELTRANSFER` when it holds a granted slot
  (ADR-0056). Its record keeps its queue standing, or earns one at rank 0, with the
  no-needed-parts mark, and waits in the RemoteQueued stage: no UDP ping, a TCP full ask at
  twice `FILEREASKTIME` (43.3 minutes), and a purge 40 s after the last one once the file
  nears its source limit (ADR-0057). It is not spent and not distrusted (ADR-0090): a source
  with nothing we need is alive and honest. The retirement says why; no queue rank is
  reported for it.
- A worker whose Advertised Parts hold a part the file lacks asks its slot at its probe
  answer even when every such part is in flight elsewhere (ADR-0026): its blocks are chosen
  at the grant. Granted with none it may be handed once its pipeline has drained — every block
  claimed, and no Duplicate Set for it (ADR-0117) — it gives the slot back with `OP_CANCELTRANSFER` and is
  retired **`NoFreePart`**, its record waiting in the RemoteQueued stage on the ordinary
  cadence (ADR-0056, ADR-0057): it still holds a part we lack.
- A worker slot is never held by a source that holds nothing we need, nor a granted slot by
  a worker with no part to work.

## Consequences

- Scheduling stays sans-I/O and assertable; decision-sequence tests gain the probe answer
  between `Connected` and the first assignment, and in-process fakes send it.
- A partial source is asked only for parts it holds; a previewed file grows its head, its
  index and the parts from its lowest unverified one first, every source that holds them
  sharing their blocks.
- The wire changes in one place: a TCP status with a wrong part count now ends the
  connection, as it does in aMule. rmule asks nothing new; it only stops dropping what it
  already read.

## Considered options

- **Availability per worker, held by Download State.** Rejected: a second per-source table
  beside the Source Book, and a frequency over the live workers alone that knows nothing of the queued sources aMule counts.
- **An unknown status read as every part, the first part on `Connected`.** Rejected: the
  first part is chosen blind and the worker cannot give it back.
- **A later status merged into the last, add-only.** Rejected: aMule rebuilds it, and a
  source that dropped a part stops advertising it.
- **The head and tail above everything.** Rejected: a part only this source holds cannot be
  had elsewhere; aMule ranks it first.
- **aMule's random tie-break.** Rejected: decisions must repeat for the same inputs.
- **A last-`K`-parts tail.** Rejected: megabytes no container index needs; aMule's two-part
  rule covers an index spilling over a short final part.
- **The window as a Core Setting.** Rejected: nothing in it is the operator's choice; the
  bench, not the operator, tunes it.
