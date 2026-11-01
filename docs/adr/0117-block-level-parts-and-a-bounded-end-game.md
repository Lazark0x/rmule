# A part's blocks are shared by every worker that holds it, and its last blocks are asked twice, at most three at a time

## Context

ADR-0029 assembled each part as one contiguous prefix. A worker streamed its part from the
prefix end to the part's end, and a part had one worker unless a second raced it (ADR-0026,
"Bounded racing"). The bench measured what follows.

- **The tail is the slowest worker's whole part.** With one part per worker, the last parts
  belong to the slowest granted sources, and the fast ones give their slots back
  (`NoFreePart`), each a lost wait at a stock uploader (ADR-0116). Six stock seeds capped at
  200, 200, 100, 100, 25 and 25 KiB/s finished in 384 s against an ideal of 219 s, 1.75×. The
  Tail Race cut four seeds at 200, 200, 200 and 25 KiB/s to 193.3 s against 182.4 s, but it
  raced the rest of a part: 4,945,920 bytes crossed twice.
- **A file of P parts uses at most P sources without racing.** A one-part file transfers from
  one source plus its racers.
- **The grid is already gone.** A block that repeats a range the uploader holds as asked is
  asked a byte shorter (ADR-0107, the link's **Asked Ranges**), so blocks leave the 180 KiB
  grid. A prefix cannot hold a hole: a lost block cost the whole slot (ADR-0029).

Stock aMule never had a prefix. Its downloader splits a chunk into blocks across its sources.

| Step | Stock 2.3.3 |
|---|---|
| A block | at most `BLOCKSIZE` (184,320), on the part's grid, clipped to the gap it fills (`GetNextEmptyBlockInPart`, `PartFile.cpp:1246-1311`, the grid at `:1283`) |
| One block, one source | a block overlapping any block asked of any source is skipped (`IsAlreadyRequested`, `:1233-1244`, checked at `:1291`); no end game, no overlapping request |
| Sources per chunk | several; the rank prefers a chunk nobody is downloading, then spreads sources over the rest (`:1842-1843`) |
| Blocks per source | all inside one chunk; a source keeps drawing from its last chunk until it is all asked (`:1829-1831`, `:1886-1893`) |
| Refill | `SendBlockRequests` keeps `m_MaxBlockRequests` pending and refills after each block (`DownloadClient.cpp:589-641`) |
| No free block | `OP_CANCELTRANSFER` to itself, `DS_NONEEDEDPARTS`, or to a slower source when `DropSlowSources` is set (off by default, `Preferences.cpp:1246`) (`DownloadClient.cpp:644-695`) |
| A chunk arriving twice | dropped when every byte of it is already written (`PartFile.cpp:2894-2899`), or when it touches a hashed chunk (`:2905`) |
| A lost block | freed for other sources; the slot is kept (`RemoveBlockFromList`, `DownloadClient.cpp:985`) |

amule-kno cancels the slower source wholesale once four parts or fewer are left
(`DownloadClient.cpp:662-676`, `PartFile.cpp:4903-4930`). eMule-Qt lets every source ask the
same blocks once the file's gaps total three `EMBLOCKSIZE` or less (`src/core/files/PartFile.cpp:629-646`,
`ENDGAME_BLOCK_THRESHOLD`, `PartFile.h:211`).

**The uploader sees only ranges.** A stock uploader queues a request only for a client in its
upload slots (`UploadClient.cpp:495-500`). It drops a range equal to one it holds or has sent
(`:503-521`). It ends the session on a range over three `EMBLOCKSIZE`, or one not complete on its
side (`:219-230`). It checks no alignment and no part boundary between two ranges, so an off-grid
block, two parts in one pipeline and a duplicate are each an ordinary request to it.

## Decision

**A part's missing blocks are handed to every granted worker that advertised it, one worker per
block. Once a worker has no unclaimed block left, it may be handed at most three blocks that a
slower worker is fetching. The first byte to arrive at an offset is kept, in the `.part`, and a checkpoint keeps the ranges.**

### 1. Assembly state: the Arrived Ranges

- **Per in-flight part, the Arrived Ranges.** A sorted set of disjoint byte ranges, in the file's
  offsets as every other range is, exact to the byte. A merge passes on only the bytes not yet
  arrived. Every later copy of an arrived byte is dropped, from whatever worker, so an off-grid
  block, a block split across two workers and a duplicate all merge the same way.
- **The bytes go to the `.part`** at their own offsets, through the Write Cache (§4).
- **A cell** is 180 KiB of the part's `EMBLOCKSIZE` grid. **Each cell records its writers**: every
  worker that wrote a byte into it. This is the AICH provenance of ADR-0038. It is exact even when
  a cell holds two workers' bytes.
- **A part is complete when its Arrived Ranges cover it.** The Persist Lane then reads it back from
  the file and verifies it by MD4 against the authority in force, unchanged (ADR-0026, ADR-0027).
  A cell hash a failure or a refetch's verdict needs is read from the file on the same lane.
- **What one bad source costs.**
  - With a **Trusted AICH Root**, the recovery data names the corrupt cells. Only those cells'
    bytes leave the Arrived Ranges, and they are fetched again by whoever has room. The workers
    that wrote into a corrupt cell are retired. A cell's sole writer is distrusted (ADR-0090).
    Honest workers keep their slots and their blocks.
  - Without a root, the part's MD4 says only that some cell is corrupt. The refetch attributes
    it, cell by cell, as aMule's corruption black box does with the ranges each IP sent
    (`TransferredData`, `PartFile.cpp:2918`; `VerifiedData`, `:3075`, `:3102`, `:3412-3415`).
    The rules are below. The same path takes a part whose recovery answer is empty, malformed,
    or names no cell (ADR-0038).

#### A part that fails with no root

- **Nobody is retired who cannot be named.** The part's bytes are dropped and its blocks are
  handed again to whoever has room. Workers that shared the part keep their slots.
- **Kept across the refetch: the Failed Cells.** For each cell of the failed attempt, the SHA-1
  of its bytes (its AICH block hash) and its writers, each with the User Hash its hello named.
  A part keeps one attempt, the latest. That is at most 53 hashes of 20 bytes plus one
  attempt's writers per part. It lives in memory for the run and goes when the part verifies, or
  when the run ends: it is evidence, and a run that starts without it costs a repeated failure its
  verdict, never a byte.
  aMule keeps the same evidence as per-IP ranges until they verify
  (`CorruptionBlackBox.cpp:78-112`).
- **A refetched cell is asked of someone else.** A worker is handed the blocks of cells it did
  not write first, so a refetched cell comes from another writer whenever one holding the part
  has room. Without that, a writer that refetched its own bad cell would prove nothing.
- **What a refetched cell's new bytes prove.** When the part next completes, each cell is
  compared with its Failed Cell.
  - **The part verifies.** A cell whose hash differs held corrupt bytes, exactly as a root would
    have named it. Its old writers are retired, and its sole old writer is distrusted. A cell
    that matches clears its writers. aMule's black box gives the same verdict only through AICH
    (`:3412-3415`); on a plain MD4 pass it credits every old range as good (`:3075`).
  - **The part fails again.** A cell whose bytes match the old copy, sent by writers disjoint
    from the old ones, is **corroborated**: two senders agree, so both copies are taken as good.
    A cell whose bytes differ is **disputed**: one of its two copies is corrupt.
- **Who is named.** An attempt's **suspects** are the writers of its cells that were not
  corroborated.
  - **A first failure** names a writer only when one worker wrote the whole part. It is retired
    and distrusted (ADR-0090). Otherwise nobody is retired.
  - **A repeated failure** names every writer that could have sent the bad bytes of both
    attempts: a suspect of both that wrote a copy of every disputed cell. With one bad sender,
    that is the sender: its corrupt copies are never corroborated, and every disputed cell holds
    one of them. Every named writer is retired. Several named writers cannot be told apart by
    the evidence, so retiring them all bounds the refetches. A repeated failure that names
    nobody (two senders lied, one in each attempt) retires nobody.
  - Then the attempt becomes the part's Failed Cells.
- **Who is distrusted.** Only a proven sender (ADR-0090): the sole writer of a whole failed
  attempt, a writer that alone sent both differing copies of one cell, and the sole old writer
  of a cell the verified part disproves. A writer named only by elimination is retired, not
  distrusted, until the part's verified bytes prove it. aMule bans only past 32 % proven-corrupt
  bytes (`CorruptionBlackBox.cpp:38`, `:191-225`), and without AICH it proves none.
- **While a recovery ask is out, the part is verifying.** None of its blocks is handed until
  the answer comes. The asked worker's end stands for an empty answer.

### 2. Assignment: Claimed Blocks

- **A worker is handed blocks, not a part.** A **Claimed Block** is a block handed to one worker to
  ask, until its bytes arrive. Blocks are cut from a part's unarrived, unclaimed bytes on the
  part's `EMBLOCKSIZE` grid, as aMule cuts them, so they are off the grid exactly where the gaps
  are. A block never crosses a part's end.
- **At most one claim per block.** No block is handed to two workers outside the End Game (§3).
- **The worker sets the count.** A worker reports how many blocks its **Request Depth** has room
  for once it has asked every block it holds (`BlocksWanted`). A handout never exceeds that room.
  At the grant the brain hands three, the most the first request may carry (ADR-0029, "One request
  before the grant"). The depth stays the link's measure.
- **The rank chooses the part at every handout.** The candidates are the parts the worker's
  **Advertised Parts** hold that still have an unclaimed block. The minimum of ADR-0112 §4's tuple
  wins: very rare, then the **Preview Band**, then the **Streaming Window**, then rarest, then the
  index. A handout fills the room from the first-ranked part, then the next.
  - Workers therefore join one part. Outside Streaming Priority, with every part advertised,
    they fill part 0's blocks before part 1's. A part verifies as soon as its blocks are claimed
    and arrive, and the Streaming Window fills in its order across every source that holds it.
  - No worker is bound to a part. aMule keeps a source on its last chunk (`PartFile.cpp:1886-1893`).
    rmule's rank is deterministic, so a worker stays on its part unless a better-ranked part gains
    an unclaimed block, for example a window part a dropped worker freed.
- **A claim ends when its range has arrived**, whoever delivered it. A worker's end, a
  requeue (`OP_OUTOFPARTREQS`) and a lost block (`BlockLost`) free its claims, and the next
  worker with room takes them.
- **A lost block no longer ends the stream.** A compressed block the session could not use is
  reported lost and freed. The worker keeps its slot, as aMule keeps its link (`RemoveBlockFromList`,
  `DownloadClient.cpp:985`). If the block comes back to the same worker, it is asked a byte shorter,
  around the link's Asked Ranges (ADR-0107).
- **A granted worker gives its slot back** (`NoFreePart`, ADR-0056) only when two things hold:
  its pipeline has drained, and neither an unclaimed block nor a Duplicate Set is left for it. A
  worker whose Advertised Parts hold nothing we lack is retired `NoNeededParts`, as before
  (ADR-0112 §6).

### 3. The End Game

- **When it starts.** It is a worker's state, not the download's. It starts when a granted
  worker has room and no part it advertised holds an unclaimed block. At the file's end every
  worker reaches it, as with libtorrent's strict end game, which asks a block twice only once
  every block is asked.
- **A Duplicate Set** is at most three blocks, at most 3 × `EMBLOCKSIZE` bytes, each of which:
  - is claimed by exactly one other worker, in a part the worker advertised;
  - has a holder whose **Delivery Rate** is below the worker's. An unmeasured holder counts as
    zero, and an unmeasured worker duplicates nothing.

  The blocks are chosen by the rank's first three positions (very rare, band, window), then by
  expected arrival, latest first, then by part and offset. A block's expected arrival is its
  holder's claimed, unarrived bytes up to and including that block, over the holder's rate. Of
  each block only what has not arrived is asked again.
- **The bounds.** A block is asked of at most two workers. A worker holds at most one unsettled
  Duplicate Set; it may be handed another once every block of the set has arrived. Each set
  therefore wastes at most 3 × `EMBLOCKSIZE`: the copy that arrives second.
- **On arrival.** The eD2k protocol has no per-block cancel: `OP_CANCELTRANSFER` ends the whole
  slot (ADR-0056). The losing copy is not cancelled. It drains through its worker's pipeline,
  counts against that worker's depth, and is dropped on merge. It is still credited to its
  uploader, which sent it (ADR-0041). The slower uploader keeps its slot, and once its pipeline
  has drained with nothing left for it, it gives the slot back like any other.
- **The Tail Race is subsumed.** Its two guards carry over: the duplicating worker must be
  measured faster than the holder, and the expected finish is ranked latest first after the rank's
  first three positions. Its unit shrinks from the rest of a part to at most three blocks. The
  backup race goes too. A worker that has not delivered a part now shares the part's unclaimed
  blocks instead of streaming the part a second time.

### 4. Persistence: the bytes in the `.part`, the ranges in a checkpoint

- **What is on disk.** Every byte the lane wrote lies in the `.part` at its own offset (ADR-0111).
  The store's verified parts are unchanged (ADR-0079), and the **Arrived Checkpoint** is one
  `download.arrived_part` row per part in flight: its Arrived Ranges, its writers and the User Hash
  each hello named. Claimed Blocks stay in memory: a run hands blocks again.
- **The Write Cache** is the node's bound on bytes between the brain and the disk: 64 MiB,
  counted at arrival and returned when the write ends, over every run. One run may hold 16 MiB of
  it, so a volume that stalls costs its own runs, not the node's. A run writes its bytes in order of
  offset, joined where they touch, once it holds 1 MiB, each second, and before a part's check, a
  checkpoint or a run's end. A run past its share, or short of the cache, holds its drain until
  its lane or the node gives bytes back: the workers wait on the brain and the sockets on the
  workers. A stop lets the drain through over the cap, so a stalled volume never stands between a
  run and its end.
- **Everything of a run's disk goes through its Persist Lane, in order:** writes, part checks,
  checkpoints and recovery checks, one at a time. A part's check is queued behind its last bytes,
  and a checkpoint behind every byte it claims, by that order alone. The first write the volume
  refuses ends the lane: nothing behind it runs, so nothing claims what it did not write, and the run
  ends as a Volume Stop (ADR-0094), disk full and a write error alike, as a code.
- **The checkpoint.** Every 30 seconds with bytes written, every 256 MiB, and at a run's end, the
  lane syncs the `.part`'s data and only then commits the rows of the parts that moved, at the
  store's own durability. So a checkpoint claims only bytes already on the disk. A row of a part
  with a verified record is never written, and `record_verified_part` removes the part's row in its
  own transaction.
- **What it promises.**

| The run ended by | What a claimed byte is | What is lost |
|---|---|---|
| Pause, Stop, Quit, a Volume Stop's pause once its lane stands | synced before the last commit | nothing the brain merged |
| kill -9, a panic, a rebuild of the core | on the file, as the kernel holds it | bytes since the last checkpoint: 30 s or 256 MiB of them per download, and a part that had not committed. They count as absent and are fetched over themselves |
| A power cut | synced before the commit that claims it | the same, and whatever the writeback window held of verified parts: their records are re-hashed at the run's start (ADR-0094) |
| A foreign write or a bad disk | whatever the file holds | the part's check fails, and the part refetches as any bad part does |

- **Nothing reads the file to learn what arrived.** A byte no row claims counts as absent, whatever
  the file holds there. A run cuts every claim to the length of the file it holds, so a file cut
  short costs what it cost and no read at a part's end meets the end of the file. A part file gone
  or replaced takes its rows with it (ADR-0094). A Restart that starts over, a cancel and a clear
  remove them with the rest of the record.
- **Provenance survives a restart.** The row carries each cell's writers, so a resumed part is an
  assembly like any other: a failure names the same writers, the sole writer of a corrupt cell is
  distrusted by the User Hash it wrote under, and a writer no longer connected retires nobody.
  The alternative, a resumed cell with unknown writers, would make "one worker wrote the whole part"
  false on a part with a past, and every rule of §1 would grow a case for it.
- **A part the checkpoint covers** verifies as its run starts, before any worker: a part that stood
  on the lane or awaited a recovery answer as the run ended. A recovery ask that was out is not
  remembered: the check fails again and asks again.
- **The serve side and Preview are unchanged in what they trust.** The serve side reads only the
  Verified Range (ADR-0113). A player reads the file as it stands (ADR-0114). The Allocated Bytes
  bound counts bytes written (ADR-0111).
- **Why the rank breaks ties by arrived bytes.** Outside the Streaming Window, of two parts equally
  rare, the one with more bytes is chosen (ADR-0112 §4), so a part a source stranded finishes
  before a new one opens. Disk, not heap, pays for a part left open now, so this is a tie-break and
  no more: a rarer part still goes first.

### 5. The worker's side

- **`RequestBlocks { blocks, handout }`** replaces `RequestPart { plan, resume_offset }`. Each
  block is a part index and an absolute range inside that part, and `handout` numbers the handout
  on that worker from 1. The worker queues them behind what it holds, and consecutive blocks of
  one part form a run.
- **The worker asks its runs in order**, in steps of at most `EMBLOCKSIZE`, three ranges per
  `OP_REQUESTPARTS`, up to its Request Depth (ADR-0029, "Request pipeline"). A step that repeats
  an Asked Range is shortened by a byte. The run continues from the shortened end, so no byte of
  a run is skipped.
- **`BlocksWanted { room, drained, handout }`**: everything handed has been asked, and the depth
  has room. `drained` says nothing asked is still to arrive, and `handout` names the last handout
  the worker took. A worker sends it once for each room it reaches, and again once it drains. The
  brain answers each want once, with blocks or not at all. A want left unanswered is answered when
  blocks free up. A drained want that nothing can answer gives the slot back. A want that names an
  earlier handout than the last one sent was sent before that handout reached the worker; it says
  nothing of those blocks, so it is set aside, and the worker speaks again once it takes them.
- **`BlockLost { start, end }`** replaces giving the slot back on a lost block.
- **An AICH recovery ask (ADR-0038) leaves at once, while blocks stream.** Its answer is forwarded
  when it comes, and an empty answer stands in at the slot budget or the link's end. A worker no
  longer reaches a drain at a part's end, so the ask cannot wait for one. While the ask is out the
  worker keeps reading its link as between handouts: a rank, the grant, `OP_OUTOFPARTREQS` and the
  peer's end reach the download at once, and a shutdown ends the wait. One ask is out per link; a
  second waits for the first to settle.
- **`PartStreamed` goes.** The next handout reaches the worker before its pipeline drains, so a
  part boundary costs no round trip (ADR-0029, "A part boundary drains it").
- **`BlockReceived` is unchanged.** It still names the part and the absolute offset.

### What the operator reads

- **A part's state** (ADR-0079): `InFlight` while any block of it is claimed or it is being
  verified, `Missing` otherwise until it verifies.
- **`ReceivingPart { part_index, bytes_received }`**: the bytes of that part this worker
  delivered, the field's own definition. The prefix that ADR-0029 wrote there counted every
  worker's bytes, which overstates a shared part's per-source rate.
- **`PartAssigned`** is said when a worker is first handed blocks of a part it held none of, so
  several workers can be assigned one part. **`PartReleased`** is said when a worker's end or
  requeue frees its claims in a part.
- **`EndGameBlocks { peer, part_index, blocks, bytes }`** is said when a Duplicate Set is handed.
  Its sentence is written in `rmule-words`, and the run log writes it as
  `download.end_game_blocks`.
- **`PartCorrupt { part_index, writers, named }`** is said when a part fails its check with no
  root to name its corrupt cells (§1): how many sources wrote it, and how many of them the failure
  named. Its sentence is written in `rmule-words`, and the run log writes it as
  `download.part_corrupt`. Each named writer still working is retired, said as `PeerRetired`.

## Consequences

- A granted worker has work until no unclaimed block it can fetch is left and no slower worker
  holds a block it could duplicate. Fast uploaders keep their slots to the file's end.
- A file of P parts can use every granted source. A one-part file shares its 53 blocks.
- The tail is the slowest worker's last few blocks, not its part, and the End Game duplicates
  those blocks. Duplicate bytes are at most 3 × `EMBLOCKSIZE` per Duplicate Set, against the rest
  of a part per Tail Race.
- A part boundary no longer drains the pipeline.
- Without an AICH root, a failed shared part retires nobody it cannot name. With one bad sender
  among three or more writers, a refetch that fails again usually names it alone. Two writers
  alone on a part dispute each other's cells, so a repeated failure usually retires both.
- Assignment, the End Game, the merge and the rebuild are pure bookkeeping. They are asserted with
  decision sequences and deterministic fake workers, without sockets.
- **The bench leg.** The flow is `peer-streaming-window` with `--seed complete` and
  `--streaming-window 0`. The after rows are:
  - six seeds capped at 200, 200, 100, 100, 25 and 25 KiB/s (archived 384 s against 219 s);
  - the Tail Race run's four seeds at 200, 200, 200 and 25 KiB/s (archived 193.3 s against
    182.4 s, 4,945,920 bytes twice);
  - a one-part file from six seeds.

  The claims, each read off the tap and the run log:
  - `tail_over_ideal` falls on the six-seed caps;
  - no seed is retired `no_free_part` before the last part's blocks are all claimed;
  - two or more seeds ask blocks of the same part;
  - every `download.end_game_blocks` carries at most three blocks and 552,960 bytes;
  - the bytes asked of two links are at most the sum of the `end_game_blocks` bytes.

## Considered options

- **Keep the prefix and let a part-delivering worker race the slowest part.** This was the
  research's interim. Rejected: each racer duplicates up to the rest of a part, and a file of P
  parts still uses at most P sources.
- **eMule-Qt's file-wide threshold**: duplicates only once the file's gaps total three blocks
  or less. Rejected: with a Request Depth of 3–24 per link, the slowest worker's in-flight blocks
  usually exceed three, so the End Game would start after the tail has already formed.
- **amule-kno's swap**: cancel the slower source near completion. Rejected: a cancelled slot is
  a lost wait at a stock uploader, and duplicating at most three blocks costs less than the slot.
- **Unbounded duplicates**, BitTorrent's end game. Rejected: without a per-block cancel, every
  duplicate's losing copy crosses the wire in full.
- **Arrived blocks in memory for the run.** Rejected: a part held 9.5 MiB of heap with no node-wide
  cap, and workers do not stay on one part: a source that leaves strands its part, and at twenty
  workers simulated parts ran at two to three times the sources. Each Pause and restart then
  fetched it all again. Libtorrent and aMule keep this state on disk.
- **A checkpoint per block.** Rejected: a sync and a commit per block spend the disk on a promise a
  Pause gets for free and a kill loses little of.
- **A checkpoint committed before its sync.** Rejected: a power cut would leave claims over bytes
  never written, and each would fail its part and name an innocent writer.
- **Dropping the provenance of resumed bytes.** Rejected (§4).
- **The Write Cache's cap per run.** Rejected as the whole rule: 500 transfers across many
  downloads add up to no bound at all. Kept as the share.
- **Rebuilding the ranges from the `.part`'s allocation** (the Hole Probe's reading). Rejected:
  allocation is page-grained, absent on a `HoleLess` disk, and blind to off-grid blocks.
- **A worker bound to its part**, as aMule does. Not taken: the deterministic rank keeps a worker
  on its part anyway, and binding it would delay a Streaming Window part freed behind it.
- **Retire every writer of a part that fails with no root** (ADR-0029's earlier rule). Rejected
  (§1): with blocks shared, one bad sender costs up to six honest workers their slots.
- **aMule's black box as it is**: per-IP ranges, banned past 32 % corrupt. Not taken alone:
  without AICH it marks no range bad, and on an MD4 pass it credits every old range as good
  (`PartFile.cpp:3075`), so a poisoner sharing parts with honest sources is never banned. The
  Failed Cells keep its per-sender evidence and judge it by the refetch instead.
- **Refetch a failed part from one worker.** Rejected: its MD4 would name the writer at once, but
  on a one-part file every other worker would give its slot back.
- **Keep every failed attempt of a part.** Not taken: the latest is enough to name a single bad
  sender, and one attempt bounds the evidence at 53 hashes per part.
