# Core-owned part assembly across peers, and the request pipeline

## Context

Core hands peers the blocks of ED2K parts and counts only a verified, complete part as
durable progress (ADR-0026). A worker asks for `EMBLOCKSIZE` blocks, a few asked ahead
("Request pipeline" below). If each worker kept its own bytes, a peer that
dropped mid-part would take them with it and the next peer would restart at block 0.
Busy peers do exactly
that: they grant a few blocks and drop. A live server-sourced part raced by seven
such peers never finished, because every racer restarted from zero.

## Decision

Part assembly lives in `rmule-core`, in one shared buffer per in-flight part.

- `PartAssembly` holds, per in-flight part, its **Arrived Ranges** — the exact byte
  ranges that have arrived — and their bytes, the set of contributing peers, and the
  writers of each `EMBLOCKSIZE` cell (ADR-0117).
- Workers are block askers. `PeerWorkerCommand::RequestBlocks` hands a worker the
  blocks to ask (ADR-0117), and the worker reports each arrival as
  `PeerWorkerEvent::BlockReceived { part_index, offset, bytes }`. It neither keeps
  bytes nor decides completion.
- Core merges each arrival into the part's Arrived Ranges, writing only the bytes not
  yet arrived: a later copy of an arrived byte, a duplicate's or a drained block's, is
  dropped. When the ranges cover the part, core verifies the MD4 part hash, persists
  the part, and frees the buffer.
- Several workers share a part's blocks, and the End Game asks its last blocks twice
  (ADR-0117). A worker's end frees the blocks it was asked and keeps every byte that
  arrived, so a mid-part drop never resets progress.
- Assembly is in memory and per session. Pause, cancel and restart discard partial
  parts. A part's bytes live in 180 KiB cells, each allocated at its first byte, so a
  part holds about what has arrived and at most `ED2K_PART_SIZE`. Workers join the
  first-ranked part with an unclaimed block (ADR-0117), so the parts holding bytes are
  fewer than the transferring sources: twenty transfers hold at most 20 parts, about
  186 MB, per download.
- **Request pipeline.** A worker keeps its link busy by keeping blocks asked ahead of
  the bytes, as stock 2.3.3 keeps `STANDARD_BLOCKS_REQUEST` (3) blocks pending
  (`updownclient.h:102`, `DownloadClient.cpp:619-641`) and amule-kno sizes the
  pending count to the bandwidth-delay product (amule-kno `DownloadClient.cpp:613-630`).
  An uploader reads a block only once its request is queued and then sleeps between
  sends (`UploadClient.cpp:189-197`), so one block in flight leaves the link idle at
  every block.
  - **A block is one range** of at most `EMBLOCKSIZE` inside one part, asked in the
    order the blocks were handed (ADR-0117). No range exceeds three blocks: a stock
    uploader ends the session on one (`UploadClient.cpp:221-224`).
  - **The Request Depth** — how many blocks are asked and not yet arrived — is
    `3 + ⌊2 × rate × rtt / EMBLOCKSIZE⌋`, held between 3 and 24. `rate` is the link's
    delivery rate (bytes over windows of at least one second, smoothed by a quarter
    per window); `rtt` the least time from a request to its block's first byte. With no
    sample yet it is 3. At 24 a link has at most 24 × 184,320 B (about 4.4 MB) asked.
  - **Refill before the link drains.** At every arrival the worker asks the shortfall
    to its depth at once, up to three new blocks per `OP_REQUESTPARTS`, from the blocks
    it was handed; with none left it says how many more fit (`BlocksWanted`, ADR-0117).
    A block is asked once: a stock uploader drops a range it already holds or has sent,
    whatever its file, until it takes the client out of its upload slots
    (`UploadClient.cpp:503-521`, `UploadQueue.cpp:540-541`). The link's **Asked
    Ranges** — every range it asked since then, kept across a hand-over to another file
    (ADR-0107) — reach the worker at each grant, and a block whose range is one of them
    is asked a byte shorter, its run going on from the shortened end.
  - **One request before the grant.** A stream's first `OP_REQUESTPARTS` carries at
    most three blocks, and a second goes out only after the stream's first byte: the
    session holds a single request until `OP_ACCEPTUPLOADREQ` (ADR-0025), and a stock
    uploader drops a request from a client outside its upload slots
    (`UploadClient.cpp:497-501`).
  - **Arrivals are credited by offset** to the asked block they fall in. Bytes inside no
    asked block are dropped.
  - **A lost block is freed.** A compressed block the session cannot use will not arrive
    in this slot: it failed to inflate, or the session refused it because its declared
    size or the count of blocks mid-accumulation passed a ceiling. A stock uploader drops
    an ask for a block it has already sent, for the life of the slot (aMule
    `UploadClient.cpp:503-511`, cleared at slot end, `UploadQueue.cpp:541`; eMuleAI
    `UploadClient.cpp:768-775` outside its NAT-traversal recovery), so aMule's own re-ask
    after an inflate failure (`DownloadClient.cpp:985-998`, asked again at `:721` and
    `:772`) never lands. The worker reports the block lost (`BlockLost`, ADR-0117); it
    stops counting against the depth, core frees it for another worker, and the slot is
    kept, as aMule keeps its link and frees the lost block for other sources
    (`RemoveBlockFromList`, `:985`). A compressed block still mid-accumulation goes with
    its slot, and a chunk that arrives outside the granted slot opens nothing, as aMule
    drops its pending zlib streams when it leaves `DS_DOWNLOADING` and reads no block
    outside it (`DownloadClient.cpp:541-543`, `:836-838`). A block cut short in one slot
    therefore never corrupts the same block asked in the next.
  - **The pipeline is the link's.** `OP_OUTOFPARTREQS` empties it: the uploader dropped
    every queued block, and core frees every block the worker held.
  - **No part boundary drains it.** The next handout reaches the worker while its blocks
    are still asked, so the pipeline runs from one part into the next without a round
    trip (ADR-0117).
- **On a failed part hash:** with a trusted AICH root, core drops only the corrupt
  cells' bytes and retires the workers that wrote into them (ADR-0038, ADR-0117).
  Without one, nothing attributes the bad block, so core retires every contributor to
  that attempt, discards the buffer, and the part's blocks are handed again to the
  surviving workers. Retirement is per download; if it exhausts the swarm, the download
  fails.

## Consequences

- Scarce parts finish across many short-lived grants.
- End-game duplicates pull at most three blocks twice per Duplicate Set (ADR-0117).
- Without AICH, the retire-all path removes a persistent poisoner at the cost of
  retiring honest co-contributors for that download.
- Assembly behaviour — off-grid and duplicated arrivals merged, bytes kept across a
  drop, retirement on failure, buffers freed on success and failure — is asserted with
  deterministic fake workers, without sockets.
- A link no longer idles between blocks: a fast uploader's measured 18–58% idle share
  with one block in flight is what the depth buys back. The depth rule is a pure
  function of instants handed in, asserted without sockets.

## Considered options

- **Each worker keeps its own bytes; seed a reassigned peer with the furthest.**
  Rejected: while workers download concurrently each still restarts at 0, so the
  common scarce-part case stays unsolved.
- **Durable block-level progress across restarts.** Rejected: it needs sub-part rows
  and `.part` revalidation, and unverified bytes on disk are risky to trust on resume;
  the gain, mid-part resume after a restart, is smaller than the cost.
- **Write blocks to `.part` at once, track ranges in memory.** Rejected: restart must
  treat those bytes as absent anyway, so it pays the write complexity for nothing.
- **Retire only the last contributor, or keep per-block provenance with staged
  re-verification.** Rejected: the first lets an early-block poisoner escape and can
  loop on the same bad peer; the second reinvents AICH badly.
- **One block in flight.** Rejected: every block waits out the uploader's wake after
  its request lands, so a fast link idles for a large share of each block.
- **aMule's fixed three.** Rejected as the rule, kept as the floor: three blocks cover a
  slow slot, but not a fast one behind a long round trip.
- **A time budget of queued data** (libtorrent's request queue time). Not taken: the
  bandwidth-delay product with amule-kno's headroom and bounds is the same idea in the
  counterparty's own terms, and the cap of 24 already covers a default socket
  buffer's worth.
