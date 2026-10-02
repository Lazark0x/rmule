# The scan hashes one file at a time and trusts a stored hash on its path, size and time

## Context

Everything under a shared directory is hashed before it is offered (ADR-0101). Hashing tens
of gigabytes on every start is not affordable; a stat per file is. Transfers read the same
disk the hashing does, and rmule's own part files sit in the download directory beside
finished files.

aMule citations are to 2.3.3 unless they say kno's fork; read, never ported (ADR-0082).

## Decision

- **One activity per scanned directory** in the actor's ledger (ADR-0093): a blocking-pool worker,
  its stop flag (checked between reads, so a file in hand is abandoned within one buffer), its
  progress cell and the consent reply half. A pass, then a watch of that directory. A start for a
  directory already scanned is a no-op, unless it is unwatched, in which case it runs a fresh pass.
  A single worker over the whole list was rejected: each directory's watch is its own wait, outage
  and re-establishment.
- **Hashing is one file at a time across every directory:** a worker takes a turn before each read
  and gives it back after, waiting in short steps so a stop is seen within a quarter second. Transfers
  keep the disk; parallel hashing was rejected for that reason.
- **The Hash Trust Rule.** A stored hash is trusted while the file's path, size and modification
  time match its row, so a restart is one `stat` per file. The blind spot — an in-place edit that
  restores the modification time — is accepted; a spot-check of the file's ends was rejected for
  its cost on every start. A changed file is dropped and hashed as new, and its old hash does not
  become Had.
- **What the scan knows without reading** comes from one **Known** view the actor answers in
  channel order: the registry rows, the spare copies (ADR-0104), and the part files the
  download rows name.
- **Which rows the scan owns:** every registry row under its directory, whatever its source. A file
  it hashes enters as `ShareSource::DownloadDirectory`. When content it hashes is already shared
  from another path still on disk, the first path in wins and the new path is recorded as a spare
  copy.
- **Part files are known by their download rows**, not by a suffix: the part path of a queued,
  active, paused or failed download is skipped silently. A part path named by a cancelled or
  completed download with a file still on it is rmule's own partial work and is skipped and
  reported once per scan (`ScanEvent::LeftoverParts`), never deleted. A file merely ending `.part`
  that no row names is shared like any other.
- **A file that moves while it is hashed** is not shared and settles again.
- **A subfolder that cannot be listed hides nothing:** gone, its rows are gone; refused for another
  error, each row and spare under it is looked at by its own path, and an unreadable look withholds
  the row, never Had. Only the scanned directory itself refusing its listing ends the pass
  (`Unlistable`). An entry removed between the listing and the look was never listed.
- **Progress** is the entry's diagnostics level.

## Consequences

- A restart over thousands of files and tens of gigabytes costs one `stat` per file.
- An in-place edit that restores the modification time is not noticed: the accepted blind
  spot of the trust rule.

## Considered options

- **Parallel hashing.** Rejected: transfers keep the disk.
- **Skipping every name ending `.part`.** Rejected: a file that merely ends `.part` was put in a
  shared directory by the operator; rmule's own part files are known by the rows that name them.
