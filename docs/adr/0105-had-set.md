# The Had Set remembers content that left the disk, by hash, and a move never passes through it

## Context

The Had mark (ADR-0100) says a file was shared and has since left the disk, so the operator
does not fetch again what they deleted. Its record must outlive the registry row, and a
file moved between paths must not look like one that left.

aMule citations are to 2.3.3 unless they say kno's fork; read, never ported (ADR-0082).

## Decision

- **Key and row:** the content hash, with the size, the name the file last had, and when rmule
  noticed it left; no path. A mark matches on hash and size. Stored in `had_file`.
- **Which exits join:** a file under a shared directory found gone at start or while running; an
  `UnshareFile` whose file is already gone; a row outside every shared directory found gone. Not an
  `UnshareFile` of a file still on disk, and not a changed file. A row counts as gone only when its
  folder is still there: an unmounted volume is not a deletion.
- **One step:** a gone row is removed and its hash joins in one transaction, only if the row still
  names the path found gone. Every share removes its hash from the set in the transaction that
  writes the row. No action clears the set otherwise.
- **A move never passes through the set:** before a gone row leaves, the scan looks for its
  content elsewhere — a spare copy (ADR-0104), or a **candidate** of its size settling or
  awaiting its hash. While a candidate exists the row is held and withheld; the hold ends when the
  candidate hashes, when no candidate of its size remains, or 30 s after the row was found gone,
  whichever is first (in the start pass, until the pass's own files are hashed). One case is not
  covered: the new path's event arriving after the old path was examined with no candidate; the
  hash joins and leaves again once the new path is hashed.
- `DumpFileHistory` carries the set beside the registry and the cancelled downloads. A history part
  whose read fails is named (`FileHistory::unread`) and holds nothing; the front end keeps the last
  answer for that part and says the marks may be out of date.

## Consequences

- A deleted shared file is remembered by content, with no path kept.
- An unmounted volume is not a deletion, and a moved file is not Had.
