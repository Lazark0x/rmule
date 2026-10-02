# The watch: one notify stream per shared directory, coalesced and waiting for stillness

## Context

Between passes a shared directory changes under rmule: files are added, edited, renamed and
deleted, and a file being written is not yet the file it will be. A pass reads each file's
stamp (ADR-0102); something has to say which paths to look at again, without keeping an
idle disk awake.

aMule citations are to 2.3.3 unless they say kno's fork; read, never ported (ADR-0082).

## Decision

- **`notify` 8.2** (CC0-1.0): one FSEvents stream over the tree on macOS, one inotify watch per
  directory on Linux. `notify-debouncer-full` was rejected (its own wall-clock timer thread makes
  stillness untestable without sleeping, and its rename stitching buys nothing), and so was polling
  (a `stat` per file per interval for ever keeps an idle disk awake).
- **An event says only that something at a path moved.** The path is queued and looked at as it is
  now — a file is stamped, a directory walked, an absent path means its rows are gone — through the
  same plan the pass uses. A queue overflow (`IN_Q_OVERFLOW`, `MustScanSubDirs`, flagged `Rescan`)
  queues the whole directory. `Access` events are dropped. Paths with a skipped component are
  dropped at the queue.
- **Coalescing:** queued paths are examined once no event has arrived for one second, or five
  seconds after the first; a path under another queued path is dropped.
- **Stillness:** a file the plan would hash settles; five seconds later it is stamped again and
  queued for hashing only if unchanged. Time comes from the watch seam, the only place anything
  waits, so tests move time without sleeping. A file that never holds still is never hashed and
  shows in the settling count.
- **A file the watch cannot read** is not shared, and the operator is told once per file with the
  OS error (`ScanEvent::FileNotHashed`); its next change notice tries it again.
- **The inotify limit** (`fs.inotify.max_user_watches`) is named, with the sysctl that raises it,
  when `notify` reports `MaxFilesWatch`.
- **Lifetime:** the watch starts on the worker after the first pass reports `Finished`
  (`ScanPhase::StartingWatch`, then `Watching { settling }` or `Unwatched` with its reason). Its
  first round examines the whole directory. It is dropped when the stop flag rises.
- **Degrade and re-establishment.** An error naming a path other than the root drops only that path,
  which is examined at once and stays unwatched until the watch is next established
  (`ScanEvent::PathUnwatched`). An error about the watch, or the backend channel closing, drops the
  watch and re-establishes it after 1 s, 5 s, 30 s, 2 minutes and 10 minutes
  (`ScanEvent::WatchInterrupted`, `ScanPhase::Rewatching`, `WatchRestored`); the first round of the new
  watch examines the whole directory. If every attempt fails, the activity ends *unwatched*
  (`ScanEvent::WatchUnavailable`). A watch that starts and never delivers cannot be told from a quiet
  directory.

## Consequences

- A change under a shared directory reaches the registry within seconds, and an idle disk
  stays idle: nothing polls.
- A network mount whose watch reports nothing is a known disagreement with the disk.
