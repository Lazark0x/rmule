# A download offers its verified parts from the first one, running or paused: the download's own, never a registry row

## Context

aMule shares a part file the moment one part verifies while it holds the file's whole part hash
set (`PartFile.cpp:3080-3085`, and on a recovered part `:3112-3117`); its shared list holds only
files with a whole set (`SharedFileList.cpp:488-490`), a pause leaves that list alone
(`PartFile.cpp:2411-2453`), and a reload shares every ready part file, paused or not
(`SharedFileList.cpp:327-336`, `PartFile.cpp:3927-3934`). Before that moment a file in its
download queue larger than one part still answers a name, status or hash-set ask
(`ClientTCPSocket.cpp:441-448`, `:503-529`, `UploadClient.cpp:676-698`), and the asker is added as
a source (`ClientTCPSocket.cpp:449-455`, `:1094-1096`); only the slot ask needs the shared list
(`:607-617`).

rmule offers only Shared File Registry rows (ADR-0031): the serve snapshot is the offered rows
(`serve/runner.rs:586`), and a download joins the registry when it completes
(`registry.rs:128`). Yet the download already tells its peers which parts it holds
(`DownloadState::our_part_status`, `download/state.rs:607`), so the same node says "parts 0 and 7"
in its name ask and "no such file" when that peer asks back.

The registry is the shared directories' (ADR-0101): the scan rules every row under its directory,
treats a row whose file it skipped as gone (`directory_scan/plan.rs:173-179`, `:203-204`), and
trusts a row on its path, size and time (ADR-0102) — all of which a part file changes on every
write. Part files live in the Temp Directory, never under a shared directory, and a finished file
reaches the download directory by the completion move (ADR-0115). Any number of downloads run
side by side, at most one per file (ADR-0107). A running download holds its part file and checks
it before every part (ADR-0094); a paused one has no run, and nothing holds its file.

aMule citations are to 2.3.3 unless they say kno's fork; read, never ported (ADR-0082).

## Decision

**A download larger than one part, queued, running or paused, is a Served Download: Serve State
answers a peer's probes for it. It is offered — a Partial Share — once it holds one part verified
against the whole part hash set, and it stays offered while paused, every read checked against its
part file's identity. After a restart a paused download is offered once its parts are re-read. A
Served Download belongs to its download and is never a Shared File Registry row; completion writes
the file's one registry row, from the record, without reading the file.**

### The sets and who writes them

| Set | Key | Holds | Writer | Lifetime |
| --- | --- | --- | --- | --- |
| **Served Downloads** | file hash | size, name, the part and final paths and which holds the bytes now, the part hash set once whole, the **Verified Range**, the **Part File Identity**, the source-exchange pool, an inbox for sightings | one at a time, by a lease: the run while it runs, then ADR-0115's completion move; the core actor while the download is queued or paused | from the row being queued, active, completing or paused to its cancel or failure; at completion, until the actor has written the registry row |
| **Held back** | file hash | — | the core actor | while the download's destination lies under a refused entry (ADR-0101) |

1. **Membership** is the download rows that are queued, active, completing (ADR-0115) or paused and
   larger than one part (aMule's `GetFileSize() > PARTSIZE`, `ClientTCPSocket.cpp:445`). A failed
   row is not: its part file is in doubt, and aMule's reload shares only a ready part file
   (`SharedFileList.cpp:331`). The store admits one live download per file, so the file hash keys
   the entry and two downloads never share one. A file of one part has no part hash set and its
   part verifies only at completion; it is shared by completion alone.
2. **The Verified Range** is the parts whose recorded part hash (`VerifiedPartRecord`,
   `durable.rs:165`) equals the whole set's hash at that index — the only bytes the serve side reads
   from a part file. The run writes it in the arm that hands a persist result to the download brain,
   before any decision that result returns is enacted, so no name ask, reask or status rmule sends
   names a part the serve side lacks. A part written while no set was held is checked by its recorded
   hash when the set arrives, without a read: a match joins the range, a mismatch is a part proven bad
   and is fetched again. While the download is queued or paused nothing writes the file, so nothing
   adds to the range; it is emptied when a read finds the file changed, and set by the Offer Check
   after a restart. Whenever the download is offered, the status it advertises and its Verified Range
   are one set, spelt by one function (`PartBitmap::downloader`, `rmule-peer/src/file.rs:118`).
3. **Offered** while the Verified Range holds a part, the set is whole
   (`PartHashSet::expected_hash_count`, `rmule-primitives/src/hash.rs:347`; from the link or a peer's
   proven set) and the file is not held back. No threshold and no knob. When the registry offers the
   same content whole, the whole row is served and announced, and the Partial Share is not.
4. **Pause keeps the offer, as aMule's does.** Waiters and slot holders keep their standing. Cancel
   and failure end the Served Download: its waiters and slot holders are told `OP_FILEREQANSNOFIL` and
   released, as for any file that leaves the offer (ADR-0106). Quit ends it with the process.
5. **One trigger.** Whatever changes what is offered — a Served Download becoming offered, held
   back, released, emptied or ending — reaches the actor, which fires its one share trigger; the serve
   announce and the Kad publisher re-read the share set from it. Serve State reads each entry's
   Verified Range, paths and identity afresh before every peer input and reask ping, as it reads its
   own position (`serve/runner.rs:292-301`); membership changes only at a trigger, so a refresh never
   drops a file between two.

### A paused download

- **Its owner is the core actor.** At pause the run ends and hands its lease back to the actor with
  the Part File Identity read from its Held Part File handle as it lets go: the file key
  (`FileKey::of_open`, `file_key.rs:50`, `:89` — device and inode on Unix, volume serial number and
  file index on Windows), the length and the modification time. From then on the actor writes the
  entry: it holds it back or releases it, empties it, ends it at cancel, and hands the lease to the
  run a Resume starts. Serve State answers its probes and serves its parts exactly as for a running
  download; no ask reads the store.
- **Every read is checked** against the identity (§"Reading a part file"); a paused file that changed
  is never served, and its offer ends until the operator resumes it, when the run's own check
  decides (ADR-0094).
- **After a restart: the Offer Check.** A queued or paused download is not offered at attach. It is a
  Served Download with an empty Verified Range — probes answered, nothing held — until the actor's
  **Offer Check** has re-read every recorded part and hashed it against its record: Resume's own check
  (`DownloadRepository::revalidate`, `store/download.rs:546`; `revalidate_verified_parts`,
  `content.rs:163`), with Resume's effect. A part that no longer holds loses its record and is said
  (`DamagedPartsDropped`); a part file gone or unreadable leaves the download paused and unoffered,
  and its Resume says why. The check records the identity from the handle it read through; the parts
  that held become the Verified Range, and the download is offered if rule 3 holds. It runs on the
  blocking pool once the Registry Check's start look is done, one download at a time, taking the
  hashing turn the scans share (ADR-0102), so it never reads beside a scan's hashing. A Resume while
  the check waits or runs stops it, and the run's own revalidation takes over. Each check the actor
  applies is said once, whatever it found, as `ServeEvent::OfferChecked` with the bytes its walk read
  and how long the read took once it held the turn (the Run Log's `serve.offer_checked`). An active
  download restarted at attach is checked by that same revalidation before its run starts
  (ADR-0094).
- **A Pause during the completion move** stops a move whose final file is not yet in place
  (ADR-0115): any partial copy is deleted, the part file is untouched, and the download is paused
  as any other, its lease with the actor and its offer kept from the part file. A Resume moves
  again. Once the final file is in place a Pause or a Cancel is refused, and the actor's completion
  step ends the Served Download.
- **Its cost** is one read and hash of every verified byte of every queued or paused download larger
  than one part, once per start, behind the scans; one with no verified part costs nothing. Until its
  turn comes such a download answers probes and offers nothing. A paused download needs no check
  while the process that paused it runs: nothing wrote the file, and its reads are checked.
- **The identity is in memory only**, since every start re-reads the parts it vouches for.

### What each ask is answered

| Ask | Registry row, offered | Served Download, not offered | Partial Share | aMule |
| --- | --- | --- | --- | --- |
| name ask, bundle | name; moves the Asked File | name, status from the Verified Range; moves no standing; the asker becomes a candidate | as a row; the asker becomes a candidate | `ClientTCPSocket.cpp:441-455`, `:1061-1096` |
| status ask | count `0` | the Verified Range | the Verified Range | `ClientTCPSocket.cpp:503-529` |
| hash-set ask | the stored set | the set once whole, else `OP_FILEREQANSNOFIL` | the set | `UploadClient.cpp:676-698` |
| slot ask | queued | silence | queued | `ClientTCPSocket.cpp:607-617` |
| block request | read | — | read inside the Verified Range only | `UploadClient.cpp:227-231` |
| UDP reask | count `0` | — | the Verified Range | `ClientUDPSocket.cpp:215-219` |
| AICH asks | the tree | nothing | nothing | `DownloadClient.cpp:1657-1661`, `ClientTCPSocket.cpp:1613-1619` |
| source exchange | the engaged pool (ADR-0055) | — | the download's pool | `PartFile.cpp:2596-2605` |

- **A candidate.** An asker of a running Served Download is handed to its run as a sighting, admitted
  under the run's source cap as aMule admits it under its own (`ClientTCPSocket.cpp:452-454`). A
  queued or paused download has no run to take one, and its asker is not kept. A probe of a download
  not yet offered moves no waiter, because no slot can be granted for it.
- **The candidate is the client that asked.** aMule adds the asking client itself, link and all
  (`DownloadQueue.cpp:707-760`). The sighting names the asker at its link's address with its
  hello's listen port, whatever ID the hello claims (`BaseClient.cpp:661`, `:678-680`), and while the
  link it asked on lives the run's worker rides that link instead of dialing (ADR-0107, "One peer,
  one link"); a second link would make aMule drop the first and end our upload to it.
- **A whole bitmap is count `0` on the wire** (`rmule-peer/src/session/serve.rs:96-107`), so a
  Partial Share whose every part verified answers as a complete file does. The UDP reask answer takes
  the served file's status the same way; it no longer assumes every file is whole.
- **AICH is never answered for a part file.** aMule's set for one is complete only once the whole
  file is hashed at completion (`ThreadTasks.cpp:186`).
- **Source exchange** answers from the download's own pool, as ADR-0055 already rules for a file in
  progress: the sources it downloads from or waits at that are not queue-full
  (`PartFile.cpp:2601`), with a known part status. A source holding no part we need is not
  waiting (aMule's `DS_NONEEDEDPARTS` is no queue state). The run keeps the pool in its entry from
  its **Source Book** (ADR-0090), after its first fill and on each one-second sample tick; a paused
  download has no source in those states, so its answer is empty and sends nothing.

### Reading a part file

- **The guard.** Before a read is decided, every sub-range of a block request left after the ranges
  already served must lie inside the Verified Range. One that does not ends the peer's slot with
  nothing read and nothing sent: aMule throws on an incomplete block (`UploadClient.cpp:227-231`) and
  its handler only takes the client out of the upload queue (`:270-282`, `UploadQueue.cpp:522-546`).
- **The identity.** The read opens the path, reads the opened handle's key, length and modification
  time, compares them with the entry's Part File Identity, and only then reads, through that handle.
  The key is always compared; the length and time only while no run writes the file. A mismatch, or
  an identity that cannot be read, sends nothing; the Partial Share stops being served at once, as for
  a failed read, and the entry's Verified Range is emptied — whoever holds it, until a holder records
  the identity of the file it reads — so the download answers probes and offers nothing. A running
  download's run meets the same change at its own next check and fails as ADR-0094 says.
- **Which path.** The entry names the path that holds the bytes: the part file until the completion
  move puts the final file in place, then the final path, with the identity of the file now holding
  them (a rename keeps the key, a copy has a new one). ADR-0115 deletes the part file only after the
  final file is in place, so at every instant one of the two holds the verified bytes and a copy in
  progress keeps serving from the part file. A read that finds its path gone tries the other once.
- **A failed read** of both paths stops serving the Partial Share at once: its waiters and slot
  holders are told `OP_FILEREQANSNOFIL` and released, and its Verified Range is emptied as for a
  changed file, so no later trigger offers it again until a holder reads the file. It has no registry
  row, so the Registry Check never looks at it (ADR-0106).
- **Nothing is suspended across the move.** rmule opens the file per read (`content/checked.rs`); aMule
  suspends uploads around completion only to close its one permanent handle (`PartFile.cpp:2186-2192`,
  `:2152`).

### Completion: one row, one writer at every instant, no read

| When | The file's registry row | The Served Download |
| --- | --- | --- |
| before the final file is in place | none (or a whole copy's, which wins) | the run, then the completion move, writes it |
| when ADR-0115 puts the final file in place | the actor writes it | the actor ends it, in the same step, before the trigger |
| after | the download directory's scan rules it (ADR-0102), or the Registry Check outside every scan | gone |

- The actor writes the row as `ShareSource::CompletedDownload` at the final path the completion move
  chose, with the record's hash, size and whole set and the final file's modification time
  (`SharedFileEntry::from_completed_download`, `registry.rs:67`) — nothing is read. A destination
  under a refused entry is written withheld (`registry.rs:163-167`). Through that step the hash is in
  the share set as one or the other, so no waiter or slot holder hears that the file left.
- The scan then trusts the row on its path, size and time. ADR-0115 keeps a completing download's
  files out of the scan until the actor has written the row, so no pass reads the file first.
- A part file was never a row: a cancelled download's part never joins the Had Set (ADR-0105), and
  its search mark is Cancelled (ADR-0100). The scan's rule that skips the part paths download rows
  name (ADR-0102) now matters only for downloads made before the Temp Directory, whose part sits
  beside the final file.

### Announce and Kad

- **The announce** lists the offered rows and the Partial Shares; a Partial Share is
  `FileCompleteness::Incomplete` (`rmule-ed2k/src/offer_files.rs:36`), which a server granting
  `SRV_TCPFLG_COMPRESSION` reads as `0xFCFCFCFC:0xFCFC` beside `0xFBFBFBFB:0xFBFB` for a whole file;
  any other server gets our ID and port while it is High (`offer_files.rs:296-314`,
  `KnownFile.cpp:1097-1115`). The Announce Policy withholds Partial Shares with every other share
  (ADR-0099). No advertised capability changes (ADR-0047).
- **Kad sources** are published for every offered file, Partial Shares included, as aMule's source
  loop takes every shared file (`SharedFileList.cpp:835-856`), and withdrawn when one ends.
  **Kad keywords** are published from registry rows alone, so a part file never reaches them, as
  aMule's keyword loop skips part files (`SharedFileList.cpp:807-809`).
- `UnshareFile` names registry rows; a Partial Share has none. As in aMule, which shares every ready
  part file (`SharedFileList.cpp:327`), a download's offer stops only when the download is cancelled
  or fails.

### What the operator sees

Core says `ServeEvent::PartialOffered { file_hash }` when a download begins to offer its parts and
`ServeEvent::PartialWithdrawn { file_hash, cause }` when it stops, `cause` a code — completed (the
row's `FileShared` is said just before it), ended (the download's own event says why), held back,
changed (a read found the part file not the one it named), unreadable. The sentences are written in `rmule-words`. Shared
Files lists each Partial Share under the download's name and size with the State `partial`, ranked
after offered; a download whose Offer Check has not passed is not listed, since it offers nothing.
The upload-peers pane names a partial upload's file from it.

## Consequences

- A peer never hears from rmule about a part the serve side would refuse it.
- Several downloads offer side by side; no entry is shaped for one download (ADR-0107).
- No part file meets the trust rule, the Registry Check, the Had Set or the scan.
- A paused download keeps offering what it verified, and a byte of a part file changed while paused
  is never sent.
- Every start re-reads the verified parts of every paused download before offering them, behind the
  scans; until then they answer probes only.
- The operator stops a download's offer only by cancelling it, as in aMule.
- Completion costs no read of the finished file.

## Considered options

- **A Partial row in the Shared File Registry** (`ShareSource::PartialDownload`). Rejected: the scan
  rules a row it skipped gone, into the Had Set (`directory_scan/plan.rs:173-179`, `:203-204`); a part
  file's size and time move under the trust rule with every write; a row keyed by hash overwrites a
  whole copy's row; and the row restates the download's record, so one fact would have two writers.
- **One active download, a single serve-side slot.** Rejected: any number of downloads run at once
  (ADR-0107).
- **Pushing each verified part to the serve task as a command.** Rejected: it crosses tasks, and
  nothing orders it before the reask that names the part; a level the serve task reads at its next
  decision is ordered by construction.
- **Ending the offer at pause.** Rejected: aMule keeps a paused part file shared
  (`PartFile.cpp:2411-2453`, `SharedFileList.cpp:327-336`), and a verified part is as good paused as
  running; the identity checked on every read stands in for the run that no longer holds the file.
- **Trusting a paused part file after a restart on an identity stored at pause.** Rejected: rmule
  never trusts a part file across a start without re-reading it — Resume re-reads every recorded part
  (ADR-0094) — and aMule bans a client it finds sending corrupt data (`CorruptionBlackBox.cpp:217`).
- **Disconnecting on a request outside the Verified Range.** Rejected: aMule ends the slot and keeps
  the link (`UploadQueue.cpp:522-546`).
