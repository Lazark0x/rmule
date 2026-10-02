# A download's name and exact size are one stored core fact, reported on both core surfaces

## Context

A download is created from an `Ed2kFileLink`, which carries the file's name and its
exact byte size. If the core keeps neither as a fact of its own, every consumer
re-derives them: a name from the canonical link (a string kept to rebuild hash
authority, not for reading), and a size as `part_count × ED2K_PART_SIZE`, which is
wrong before the hash set arrives and rounded up after it.

Names on the eD2k network are routinely Windows-1252 or mojibake. ADR-0019 keeps text
wire-faithful, so storing a name as decoded text would force the core to invent an
encoding.

## Decision

**The name and the exact size are one recorded fact, `DownloadMetadata`**, persisted
with the download row at creation, replayed on recovery, and reported on both core
surfaces.

```rust
pub struct DownloadMetadata {
    pub name: Ed2kText,
    pub size: u64,
    pub origin: DownloadMetadataOrigin,
}
```

- **The name keeps the wire's bytes** in the stored row. Rendering projects it with
  `Ed2kText::to_display_string` at the edge, where lossiness is a display choice rather
  than a stored one.
- **The size is the link's declared byte count**, exact, never derived from the part
  count. The download row holds one `DownloadMetadata`, and the record's size reads
  through it, so the size cannot be stored twice and drift.
- **Provenance** (`DownloadMetadataOrigin`):
  - `Link` — recorded at creation from the caller's `Ed2kFileLink`;
  - `RecoveredLink` — re-parsed from the row's own canonical link rather than recorded
    at creation;
  - `Unknown` — no name is known (a link that no longer parses, or a record synthesized
    without one, such as `InMemoryDownloadStore::start_download`, which is handed a hash
    and a size). The size is still exact.
- **No search-result origin.** A search result reaches the core only after the caller
  renders it into an `Ed2kFileLink`, the same value a pasted link produces. Recording
  "search" would persist a caller's claim the core cannot check; the core carries facts
  and the edges derive. A UI-origin fact, if ever wanted, belongs to the caller's state.

**Surfaces.**

- **Edge.** `DownloadEvent::DownloadQueued` and `DownloadEvent::DownloadRecovered` both
  carry `metadata`, and `DownloadRecovered` also carries `file_hash`. A consumer folding
  events learns the file's identity in the message that creates its row, with no
  snapshot join. This matters most on recovery: a recovered download has no live task
  and so no diagnostics row until it resumes.
- **Level.** `DownloadDiagnostics::metadata` (ADR-0028) carries the same value for
  every download with a live task. The row opens from the stored record at start and at
  resume, so the snapshot and the event stream cannot disagree.
- Both surfaces read the metadata back from the durable record, not from the command's
  copy of the link: what a consumer sees is what a restart replays.

## Consequences

- Front ends show real names and exact sizes with no derivation, and any later consumer
  reads the same two surfaces with no core change.
- A snapshot grows by one name per live download per tick, which is noise at 1 Hz.
- Still absent: renaming a download, peer-reported names (`OP_REQFILENAMEANSWER`,
  aMule's most-voted name), and a name on `ServeEvent::FileShared`, which stays
  hash-only. A peer-reported name would be a new origin and join the enum when it is
  actually driven.
