# A download's state is durable: a process ending changes neither the operator's word nor its verified parts

## Context

A download's store row says what the operator last wanted of it, and its verified parts say
what it holds; neither may change because a process ended. A quit and a crash end a process
alike, and the operator may delete or damage a part file between runs or under a running
download. The download's lifecycle is an activity in the actor's ledger (ADR-0093).

aMule references are to 2.3.3 (`4e8f2b3c`); read, never ported (ADR-0082).

## Decision

The Download Set is the downloads with a run. **Quit rewrites nothing:** it aborts each run,
and the row keeps the operator's last word. A crash leaves the same rows and gets the same
attach. aMule likewise persists only a part file's paused bit (`PartFile.cpp:1059`,
`:655-657`), and a file loaded without it is processed like any running file
(`PartFile.cpp:872`, `906`).

| Operator's word | Store lifecycle | Has a run | At attach |
|---|---|---|---|
| Downloading / Waiting | `Active` | yes, or queued to start | started again by core, paced |
| Waiting (never started) | `Queued` | no | started by core, paced |
| Paused | `Paused` | no | reported, not started |
| Failed | `Failed` | no | reported, not started |
| Completed | `Completed` | no | listed until cleared; the file is in the Shared File Registry |
| Cancelled | `Cancelled` | no | not reported |

**Attach.**

- Core starts restored downloads; front ends send nothing. The store's restart read writes
  nothing and returns every row that still holds its file's place.
- A run presents the node's credentials (nickname, TCP port, protocol version), composed from
  its Core Settings (ADR-0069). A front end that wants its downloads restored says so once
  (`CoreBuilder::restore_at_attach`). A core built without it (a one-shot tool) reports its
  `Active` rows and starts none.
- Restored downloads start one per `CoreConfig::download_restore_pace` (1 s), in store order.
- A download waiting its turn is still the operator's: pause, cancel and resume reach it; a
  cancel of a download with no run cancels it.
- Every resume re-hashes the verified parts against the `.part` file (below). A missing file
  with parts recorded fails the download with `StorageIntegrityFailed(PartFileMissing)`, as
  aMule refuses to load such a part file (`PartFile.cpp:867-869`).

**The part picture is the download's, not its run's.** At attach core opens a resting
diagnostics row for every restored download, `parts` built from the verified-part records over
`part_count(size)`. A run's end (pause, failure, completion) puts its row to rest instead of
removing it: in-flight parts become `Missing`, worker rows and source count clear. A resume opens
on the resting row; only a cancel removes it. A run with no resting row opens one with every part
`Missing`, since the size is known from the start. The Transfers bar keeps ADR-0079's glyphs, and
a bucket reads held only when every part in it is held.

**Failed.** A failed download keeps its row, `.part` file and verified parts, so it still holds
the file's place; the store refuses a second live row for the file. Re-adding the file restarts
the same download in place (`Failed` → `Active`), and Transfers offers the same action as
**Restart**. Its Known-File Mark is **Failed** (ADR-0100). Why it failed is durable: the row
keeps the `DownloadFailure` as a code with the `Failed` lifecycle, set by one write and cleared
by every other lifecycle, and attach reports it on `DownloadRecovered`. A storage-integrity
failure keeps its fault as codes and data (an unreadable part file keeps the OS error number,
never its message). A row failed before the store carried a reason says "reason not recorded".

**Damaged parts are repaired, not condemned.**

- A part that fails its re-hash (`PartFault::HashMismatch` with both hashes, or
  `PartFault::Short`) has its verified-part record dropped in the same revalidation, so the run
  fetches it again; `DamagedPartsDropped` names each part and fault, logged once at `warn`.
- The download fails only when nothing can be trusted or written: parts recorded and the part
  file missing (`PartFileMissing`) or unreadable (`PartFileUnreadable`), or no recorded part
  holds (`NoPartHolds`). A download with no part recorded starts as a new one.
- **Restart is one action, and rmule picks.** When the part file still backs what was recorded,
  or nothing was recorded, the run continues. When the part file is gone or no recorded part
  matches it, it starts over: the recorded parts and any peer-supplied provisional hash set are
  discarded, the `.part` the row names is removed, and the run starts from nothing, keeping the
  download's id, file, name, size, final path and place. An unreadable part file does not start
  over: its disk or permissions may return. `DownloadRestarted` says `Continued` or `StartedOver`
  and what it cost. Only the operator's Restart starts over; attach and a paused download's
  Resume still fail, so a download the operator meant to drop by deleting its part file does not
  come back on its own. A Restart that fails again leaves the row as it was and says why.

**The run holds its part file.** It opens the file once — creating it for a download with no
part recorded — and writes every part through that handle, never re-opening by path. Before each
verified part is written, before finalize, when it leaves a wait, and every second while it waits
(`WAITING_PART_FILE_CHECK`), it compares the path's device and inode with the handle's and the
handle's length with the end of the highest recorded part (one `stat` and one `fstat`); a removed
file's handle stays writable on macOS and Linux, so an error is never the signal.

- **Gone or replaced:** the run stops writing, reports `PartFileLost` (`Gone`, `Replaced`) with
  the parts and bytes to fetch again, drops the verified-part records, and fails with
  `PartFileMissing`. It does not recreate the file: the delete was the operator's.
- **Truncated:** the parts past the end are dropped (`PartFileLost`, `Truncated`) and the run goes
  on fetching them.
- **A whole-file hash failing at finalize** re-checks every recorded part, drops those that fail,
  and goes on; when no part can be named, every recorded part is dropped.

Who may touch a live part file: only its run's held handle writes it; finalize renames the run's
own `.part` after the run releases its handle; cancel unlinks the row's `.part` only after the run
is joined; a starting-over Restart unlinks only for a `Failed` row with no run; clearing completed
downloads, the directory scan and its watch, the rename carry, spare copies, the Registry Check,
the Had Set and serve reads never open a file under the download directory for writing.
`ContentFileStore::write_verified_part` writes by path and is called only by tests and tools.
rmule's other file writes (`clients.met`, `nodes.dat`, the Run Log, capture taps) land in the
data directory or a capture directory.

**Clearing a completed download.** A completed download stays in Transfers until the operator
clears it, across restarts: attach reports every completed record, so the list shows exactly what
"Clear completed" removes. aMule keeps completed files listed only for the run
(`DownloadListCtrl.cpp:1151-1164`, `DownloadQueue.cpp:919-949`); rmule differs so that no record
a clear removes is hidden. Clearing removes the record (row, verified parts, provisional hashes,
distrusted peers, in one transaction), its resting diagnostics row and its Transfers row
(`DownloadCleared`), and never the file, its registry entry, its share totals or the Had Set.
Only a completed download is cleared (`DownloadNotCompleted` otherwise; a run still in the set
has not been shared yet). Commands: `ClearDownload`, `ClearCompletedDownloads`. In the TUI, a
completed row's menu offers **Clear from list**, and `C` in Transfers clears every completed
download after one confirm.

## Consequences

- A download the operator left running restarts running; one they paused stays paused; a crash
  and a quit look the same.

## Considered options

- **Folding `Active` rows to `Paused` at attach.** Rejected: it stored a running download as one
  the operator paused.
- **Separate Restart and Start-over menu items.** Rejected: the operator had to ask what the
  difference was; what is on disk decides.
- **Recreating a part file deleted under a run.** Rejected: it hid the operator's delete and wrote
  holes over verified parts.
