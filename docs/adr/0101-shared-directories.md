# Shared directories are the only way rmule shares: whole, recursive, guarded and confirmed

## Context

Sharing a directory recursively, within seconds, is a disclosure: every file's name and hash
reaches the servers rmule connects to and Kad. A listed directory can also vanish for a
while — a volume unplugged — and come back.

aMule shares its Incoming directory, each category's and the operator's list, merged and
made unique (`SharedFileList.cpp:340-351`), hashed in the background (`:352-356`), and drops
a listed directory that does not exist when it reloads (`Preferences.cpp:1783-1795`). aMule
citations are to 2.3.3 unless they say kno's fork; read, never ported (ADR-0082).

## Decision

**The operator shares whole directories, never a lone file.** Everything under a shared
directory is hashed and enters the Shared File Registry, so Have is registry membership and
needs no store of its own.

- **The Shared Directory List** is ordered. Entry 0 is the download directory: it follows
  `Preference::DownloadDir`, carried in `ScanCommand::Start` (core never reads the preference),
  is never stored as a row, and cannot be removed. Every other entry is one the operator added,
  keyed by its canonical path (`fs::canonicalize`), stored in `shared_directory`, and living
  from the operator's yes to their remove — across restarts, its directory going missing, and
  the download directory moving. A path that is not valid UTF-8 is refused.
- **Always recursive.** Dot-prefixed files and directories, symlinks under the directory, and
  rmule's own part files are skipped; no exclusion list. The directory itself may be named
  through a symlink, the one link followed, and keeps the name the operator gave it, so
  repointing the link never renames a row.
- **Covered.** Scans never overlap: the outermost entries are scanned, and an entry under
  another is *covered*, shown as such, its files the parent's. An entry that stops being covered
  is scanned again, reading nothing the trust rule vouches for.
- **Guards**, checked at the add on the canonical path, each refusal a code with its reason
  (`ScanEvent::DirectoryRefused`):

  | Refused | Why |
  |---|---|
  | not a directory, or cannot be looked at | nothing to scan |
  | not valid UTF-8 | the key is the path's text |
  | the home directory itself | a home holds keys, mail and documents |
  | a filesystem root or mount point | a whole volume |
  | rmule's data directory, anything inside it, or a directory holding it | the store, the identity keys and the credit file |
  | already in the list | nothing to add |
  | inside a listed directory, the download directory included | already shared |

  The home and data directories are handed to core by the front end at build time. A parent of
  an added entry is not refused: it replaces the entry after the confirm names it.

- **States**, one diagnostics level per list entry in list order:

  | State | Its files |
  |---|---|
  | asking (added, awaiting the confirm) | not offered; nothing hashed |
  | scanning (*done / total*, the file in hand) | trusted rows offered; new files as each is hashed |
  | watched | offered |
  | not watched (the watch could not start, or was lost for good) | offered; later changes unnoticed until the next start |
  | missing (since when rmule noticed) | Withheld (`folder missing`), never Had |
  | covered | the parent's |
  | declined (the download directory's guard answered no) | not offered |

- **Add** (`ScanCommand::AddSharedDirectory`): the scan walks and plans, then always asks
  (`ScanEvent::ConsentRequested`) with the files and bytes it would offer, those already hashed,
  and the entries it would replace — the scan's own count, so the number confirmed is the number
  offered. The confirm says every file's name and hash will be offered to the servers rmule
  connects to and published on Kad. A yes stores the entry, retires the replaced entries' scans
  and releases the pass; a no stores nothing and records no answer.
- **Remove** (`ScanCommand::RemoveSharedDirectory`), after a confirm naming the count: the scan is
  retired, the entry deleted, and every registry row under it and no other entry leaves the
  registry in one transaction — not into the Had Set (ADR-0105), since the file is still on disk
  — unless a spare copy (ADR-0104) under another shared directory takes it. Each leaving row
  takes the path every leaving row takes (ADR-0106): dropped from the serve snapshot and the next
  announce, its Kad republish withdrawn, its queued and slot-holding peers told
  `OP_FILEREQANSNOFIL` and released (`ScanEvent::DirectoryRemoved`). The rows taken and the spare
  copies under the directory are kept as **Set-Aside Rows** (`set_aside_row`: path, size,
  modification time, identity, content hash and part hash set), which share nothing; a later pass
  that finds a path with the same stamp takes the entry from it instead of reading, so adding the
  directory back reads nothing.
- **Missing.** A listed directory not there is *missing*; its rows are Withheld, the entry stays,
  and the scan looks once a minute. When it returns, a fresh pass re-validates every row without
  reading and the Registry Check (ADR-0106) looks again at once (`ScanEvent::DirectoryMissing`,
  `DirectoryReturned`).
- **The download directory moves:** its old scan is retired and a new one starts; rows under the
  old directory that no entry covers become the Registry Check's.
- **`UnshareFile`** stops offering one file; the next start of its directory offers it again.
  Moving the file out is how the operator stops offering it for good. Rows shared explicitly
  before directories were the only way stay in the registry, outside every directory, the
  Registry Check's.

**The disclosure guard.** Beyond every added directory's confirm, the download directory's first
share is guarded: with no answer on record the scan plans, and if it would hash any file it raises
`ConsentRequested` and waits; nothing is hashed, shared or unshared until `ScanCommand::Answer`. A
no ends the scan and a declined directory is not scanned at later starts; a plan that hashes
nothing records a silent yes. Choosing a directory in Settings warns that everything under it will
be offered, and confirming is a yes (sent before `Start`, so the operator is asked once).

## Consequences

- Nothing under a directory is offered before the operator's yes to it.
- A deleted folder looks like an unmounted volume and stays withheld until unshared.
- What is shared, and when, is ground any partial-sharing design inherits rather than decides again.

## Considered options

- **Sharing lone files** (`ShareFile` and its own hashing activity). Rejected: every shared file
  goes through one mechanism, the shared directory's walk, watch, trust rule and guards.
- **Top-level sharing only, as aMule.** Rejected: operators sort into folders.
- **Dropping a missing listed directory, as aMule.** Rejected: a disk unplugged for a month is still
  the operator's.
