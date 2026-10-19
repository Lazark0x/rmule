# A download's progress is one positional part-state vector; every count is derived from it

## Context

The download scheduler of ADR-0026 knows each part by index: a part is pending, racing,
or gone (completion is by absence). A diagnostics row that publishes only how many
parts sit in each bucket can say "4 of 10 parts" but never which four, so the chunk map
every eD2k client draws, "is the tail still missing" and "which region are these peers
racing" are unanswerable from the surface. Stored counts beside the scheduler's maps are
also a second copy of a fact the scheduler holds, kept in step by nothing but care.

## Decision

**A download's progress is one published fact: `parts`, a positional
`Vec<PartState>` indexed by part number**, on `DownloadDiagnostics` (ADR-0028). Every
count a consumer reads is derived from it.

```rust
pub enum PartState { Verified, InFlight, Missing }

pub struct DownloadDiagnostics {
    // …
    pub parts: Vec<PartState>,
}
```

- **`parts[i]` is part `i`** for every `i` in `0..part_count(file_size)`. The vector
  spans the whole file for the row's whole life; it is never a shrinking "remaining"
  list.
- **Three states, because the scheduler partitions into exactly three:** a block of it
  claimed by a worker, or its bytes being verified → `InFlight` (ADR-0117); unverified and
  none of that → `Missing`; verified → `Verified`. No `Requested`,
  `Corrupt` or `Paused`: the scheduler does not distinguish them, and a state no writer
  can populate makes a surface lie.
- **Empty means unknown, not zero.** A row opens with every part `Missing` (ADR-0094),
  so a row core holds is never empty; a consumer with no row for a download yet renders
  "no map yet".
- **One source.** `DownloadScheduler::part_states()` walks `0..total_parts` once over the
  missing parts, their claims and the parts being verified, all of which it owns; it is the
  only place a part's status is decided. The runner
  republishes the whole vector, never patching an index, whenever the scheduler settles
  (`refresh_parts`, inside the drain).
- **Counts are readings, not fields.** `part_counts()` returns
  `PartCounts { verified, in_flight, missing }` in one pass, and `verified_parts()` and
  its siblings are named accessors over that tally. `PartCounts::total()` equals
  `parts.len()` by construction. The scheduler keeps no separate counting path.
- **A level on the shared state.** `parts` rides the shared `DiagnosticsState`, like the
  counters of ADR-0077, so the sync `Core::diagnostics_snapshot()` and the
  `DumpDiagnostics` echo report the same value. The whole map is republished, so a slow
  or late poller sees a correct current picture without replaying a diff. The
  `PartVerified` events stay the edge surface, and both agree because they come from the
  same scheduler transition.
- **Consumer-agnostic.** The surface says where each part stands, not how to draw it.
  Bucketing into a bar, which state wins a mixed bucket, colours and glyphs belong to
  whoever renders. The core ships no bar, percentage or bucket rule — the discipline
  ADR-0077 applies to rates.

## Consequences

- A percentage consumer and a positional consumer read the same partition of the same
  file; no count can disagree with the map, because no count is stored.
- A tally costs `O(parts)` instead of a field read: about 11k entries for a 100 GB file,
  polled at about 1 Hz (ADR-0069).
- No block-level map: aMule tracks in-progress ranges inside a part, and a finer map
  would be a second, differently shaped fact.
- No per-part peer attribution: which peer races part 7 is worker state
  (`WorkerPhase::ReceivingPart`), published per slot, and joining it is the consumer's
  job.
- No history: a part that failed verification and re-pended reads `Missing` again;
  retry history belongs to the event stream.
