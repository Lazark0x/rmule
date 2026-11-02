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
  download rows name. A pass reads it once its listing is done, and every watch round reads it
  again, so a path a download names before its file lands there is known by the time the scan
  judges that file.
- **A file past eD2k's limit is refused before it is read.** Past `MAX_ED2K_FILE_SIZE`, 256 GiB,
  no server, peer or Kad node can be told what the file is, so the scan rules on its stamp, hashes
  nothing and says once which file and why (`ScanEvent::FileRefused`), as stock's hasher skips one
  (`ThreadTasks.cpp:98` at 3.1.0). A row stored before the rule is withheld by the Registry Check
  (ADR-0106). A `PartHashSet` exists only up to the limit, so an answer's `u16` count cannot
  overflow whatever a store holds.
- **A scan's writes land in commits of many.** A hashed file is two registry writes, its row and
  its identity, a carried file is one, its moved row or its Spare Copy, and a commit is an fsync,
  so the actor gathers them and commits up to 256 at once,
  a quarter second after the first at most, on the blocking pool. Any other message from a worker
  lands the batch first, so the Known view still answers in channel order, and a stop lands it too.
  Every commit stays durable, and a file is offered and told of only behind its commit, so a kill
  or a power cut costs the open batch a second hash and claims nothing. The per-file commit was
  rejected because it held the actor for 52 s of a first scan of 10,000 files; a commit that is
  not durable was rejected because the next open rolls it back after a kill.
- **Which rows the scan owns:** every registry row under its directory, whatever its source. A file
  it hashes enters as `ShareSource::DownloadDirectory`. When content it hashes is already shared
  from another path still on disk, the first path in wins and the new path is recorded as a spare
  copy.
- **Part files are known by their download rows**, not by a suffix: the part path of a queued,
  active, completing, paused or failed download is skipped silently. A part path named by a
  cancelled or completed download with a file still on it is rmule's own partial work and is
  skipped and reported once per scan (`ScanEvent::LeftoverParts`), never deleted. A file merely
  ending `.part` that no row names is shared like any other. A download placed in the Temp
  Directory (ADR-0115) has no part file under a shared directory, so the rule covers older rows,
  whose part lies beside its final path, and a `Completing` row's destination: a completing
  download's files are the download's until its registry row is written (ADR-0113).
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
