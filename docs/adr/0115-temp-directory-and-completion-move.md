# Part files live in a Temp Directory apart from finished files; completion moves the file into the download directory, waits while a program holds it, and copies only across volumes

## Context

A download's `.part` is its final path with `.part` appended, in the download directory
(`DownloadPaths::from_final_path`), and finalize renames it in place. The download directory is
entry 0 of the Shared Directory List (ADR-0101): everything under it is offered, so the scan has to
recognise rmule's own unfinished work by the rows that name it (ADR-0102), and partial work fills
the disk that holds finished, shared files. A file already at the final path fails the download
(`FinalPathTaken`). On Windows a rename is refused while another program holds the file open
without delete sharing, so a player previewing the `.part` (ADR-0114) when it completes fails the
download as `CompletedFileNotMoved`. A crash between the rename and the row's `Completed` leaves an
`Active` row whose part file is gone.

aMule keeps part files in a Temp directory (`/eMule/TempDir`, default `Temp` in its config
directory, `Preferences.cpp:1068`) and finished files in an Incoming directory
(`Preferences.cpp:1081`). At completion it picks a free name by a numbered postfix
(`ThreadTasks.cpp:455-465`), renames, and when the rename fails copies to the final name and
removes the part (`ThreadTasks.cpp:467-474`); the copy writes the final name directly and is not
synced. Its background tasks run one at a time (`ThreadScheduler.h:50-58`).

aMule citations are to 2.3.3; read, never ported (ADR-0082).

## Decision

**A new download's part file lives in the Temp Directory; completion moves it into the download
directory by a rename, waits while another program holds it, and copies only when the two lie on
different volumes. The part file is deleted only after the finished file is in place.**

### The Temp Directory

- **A Core Setting** beside the download directory (ADR-0069): `CoreSettings::temp_dir`, set by
  `Setting::TempDir`. Unset, it is `Temp` in the data directory the front end hands core
  (ADR-0076). The set makes it when it is missing. A core given neither (a test, a tool) places a
  part file beside its final path, as before.
- **Placement.** `place_download` chooses both paths at once: the final path in the download
  directory and the part path `<temp dir>/<final file name>.part`, under one free-name rule — the
  numbered `stem (n).ext` is taken until neither the final path nor the part path exists. Both are
  stored on the row, as today. Changing either setting moves nothing: running, paused and recovered
  downloads keep the paths their rows hold.
- **Refused at the set**, nothing stored, as `SettingRefusal::TempDirRefused(DirectoryRefusal)`:
  the download directory itself; a directory inside any shared directory, the download directory
  included, or holding one; the home directory itself; a filesystem root or mount point; a path not
  valid UTF-8 or not absolute; a path that is not a directory or cannot be made. Inside the data
  directory is allowed; the default lies there.
- **Symmetric.** A shared-directory add, and a download directory set, that is the Temp Directory
  or holds it is refused (`DirectoryRefusal::HoldsTempDirectory`), and so is one inside it
  (`DirectoryRefusal::InsideTempDirectory`): the Temp Directory and the Shared Directory List
  never overlap, either way, so no part file of a new download lies under a shared directory and
  nothing is shared from among them. The guard is judged again wherever ADR-0101 judges the
  others again, and when the Temp Directory moves on a running core: an entry refused for the old
  one is scanned once it passes, and an add still waiting on its confirm that the new one
  overlaps is refused, its scan stopped and nothing stored.
- **Older rows.** A row whose part file lies beside its final path keeps working, and its move is a
  rename within that directory. Those rows are now the only reason the scan skips part files by the
  rows that name them (ADR-0102).

### Completing

`DownloadLifecycle::Completing` means every part is verified and the file hash checked, and the
finished file is not yet in place. It is durable, appended as the enum's last variant. It follows
`Active`; it leaves to `Completed`, to `Active` (the bytes changed under a copy: repaired as a
finalize mismatch is, ADR-0094), to `Failed`, to `Paused` or to `Cancelled`. Attach treats a
`Completing` row as live: its run starts and goes straight to the move. A Pause or a Cancel stops a
move whose file is not yet in place: a partial copy is deleted and the part file is untouched. A
Pause leaves the download `Paused` like any other, its Served Download handed back to the actor and
still offered from the part file (ADR-0113), and a Resume moves again from the check. Once the
finished file is in place the download completes, and a Pause or Cancel that arrives then is
refused (`CoreCommandRejectReason::DownloadCompleting`).

### The move

The move is the run's last step (ADR-0093), on the blocking pool, after the scheduling brain's
last decision; Download State holds no clock and takes no part.

1. **Check.** The run hashes the part file, as today; a mismatch repairs (ADR-0094).
2. **Name.** The destination is the row's final path or, when a file stands there, the first free
   `stem (n).ext` beside it. The run stores `Completing` and the destination in one write before
   anything moves. A file at the row's final path of the file's size that hashes to the file hash
   (one read, before the check) is the download's own — a past move landed it and a Pause or a
   stop came before its row was written — so the run takes step 6 there, numbering nothing past it;
   a file of another size or hash is someone else's and is left as it is.
3. **Rename.** The run renames the part file onto the destination.
4. **In use.** When the OS refuses the rename because another program holds the file (Windows
   `ERROR_SHARING_VIOLATION` 32 or `ERROR_LOCK_VIOLATION` 33), the download stays `Completing`
   with the step `WaitingForRelease`, and the run retries on a backoff of 1 s doubling to 30 s,
   answering its stop between attempts. It completes on its own when the player closes. Nothing is
   copied.
5. **Across volumes.** When the rename is refused as crossing devices (`ErrorKind::CrossesDevices`:
   `EXDEV`, Windows `ERROR_NOT_SAME_DEVICE`), the run makes the **Completion Copy**. It waits for
   the core's one copy turn (`QueuedForCopy`), so copies run one at a time, as aMule's tasks do.
   It copies the part file to `.<destination name>.completing` beside the destination
   (`Copying`); the dot prefix keeps the scan and its watch off it (ADR-0101). It hashes the bytes
   it reads, and a hash that differs discards the copy and repairs. It `fsync`s the copy and
   renames it onto the destination (a name taken meanwhile takes the next free name, stored
   first), and syncs the directory where the platform allows it.
6. **In place.** The finished file is now at the destination. The run, which holds the download's
   Served Download lease (ADR-0113), points the entry's bytes path at the destination, with the
   identity of the file now there, at the swap itself, and reports the final file in place to the
   actor with the path it chose, `(n)` included. In that one step the actor writes the
   file's registry row from the download record — hash, size, part hash set and the file's
   modification time, nothing read (`SharedFileEntry::from_completed_download`) — and ends the
   Served Download, then fires the share trigger. A download of one part has no Served Download
   and takes the same step without it. A row the registry cannot write leaves the Served
   Download with the run, still offered from the finished file, and the run, its step
   `WaitingForStore`, reports again on the backoff of step 4 until the row is written.
7. **Done.** The run deletes the part file — a delete refused because the file is in use waits as
   in step 4 — then stores `Completed` (a store that refuses the write is retried the same way,
   `WaitingForStore`) and sends `DownloadCompleted { final_path }`, which names where the file
   landed.

Any other refusal fails the download with the part file untouched and every verified part kept:
a rename as `CompletedFileNotMoved { os_code }`, a copy as `CompletionCopyFailed { os_code }` (a
full disk, an I/O error), with its partial copy deleted. Restart (ADR-0094) continues: the run finds
every part verified and moves again. `FinalPathTaken` is no longer produced; rows that hold it still
decode and read as before.

### Invariants

- The part file is deleted only after the finished file is in place, its directory synced and its
  registry row written.
- At every instant the verified bytes are at the path the Served Download names: the part file
  until the swap, the finished file from then on.
- Every move starts from a stored `Completing` row that names its destination, so the one file
  rmule may have put at that name is known.
- No half-copied file ever carries the finished name, and the scan never hashes a completing
  download's files: the copy's dot-prefixed name is one the scan and its watch skip (ADR-0101),
  and a `Completing` row's destination is, like its part file, a path the scan knows as the
  download's own (ADR-0102) and skips while the row is `Completing`. By the time the row leaves
  that state the registry entry exists, and the scan trusts it on its path, size and time.

A `Completing` row at attach is resolved by what is on disk:

| Part file | Destination | The run |
|---|---|---|
| there | absent | moves again; a leftover `.completing` copy is deleted |
| there | there | the destination is rmule's when the registry holds the file at it, or when it hashes to the file hash (step 2's one read): the run takes step 6 if the row is missing, then step 7; otherwise it takes the next free name and moves again. A Pause during that read leaves the row `Paused` naming the destination, and the resumed move reads it again |
| gone | there | completes: the part file goes only after the destination and its row are in place |
| gone | absent | fails as `PartFileMissing` |

### What the operator reads

Core carries the lifecycle, the step and the bytes copied; the sentences live in the download words
of `rmule-words`. `DownloadEvent::Completing { download_id, to, step }` is sent when a step that
waits or copies begins (`QueuedForCopy`, `Copying`, `WaitingForRelease`), and
`DownloadDiagnostics::completion` holds the step and the bytes copied as a level. A store that
cannot record the finished file is `WaitingForStore`, told the same way. The TUI's status
reads Completing, with "waiting for the file to be released" while a program holds it and the
bytes copied while it copies; the CLI prints each step's sentence. Until its registry row is
written, a Completing download's Known-File Mark is an active download's (ADR-0100).

## Consequences

- No part file of a new download lies under a shared directory, so none is scanned or watched,
  and partial work no longer fills the download directory's disk; a running download's verified
  parts are offered as ADR-0113 says, from the Temp Directory.
- With the default, part files sit on the data directory's volume. A download directory on another
  disk makes every completion a copy, at most one at a time, with its file's size written twice
  until the part is deleted.
- A file previewed on Windows when its last part lands completes when the player closes, instead of
  failing.
- A taken final name no longer stops a finished download.

## Considered options

- **Part files beside their final paths**, today's layout. Rejected: everything under the download
  directory is offered, so rmule's unfinished work lay where the network is answered from, and
  filled that disk.
- **Copying straight to the finished name**, aMule's copy. Rejected: a crash or a full disk leaves a
  short file under the finished name, which the scan would hash and offer.
- **Copying when the file is in use.** Rejected: the player still holds the part file, so its
  delete would wait anyway, and a copy of gigabytes is the wrong price for waiting out a player.
- **Failing on a taken final name.** Rejected: aMule numbers the name, and a finished download should
  not wait on one.
- **The operating system's temporary directory as the default.** Rejected: it is cleared at reboot
  on common systems, and a part file is days of work.
