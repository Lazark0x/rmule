# Block-level cross-peer part assembly with a core-owned prefix buffer

## Context

Core assigns ED2K parts to peers and counts only a verified, complete part as
durable progress (ADR-0026). A worker requests a part in `EMBLOCKSIZE` blocks, a few
asked ahead ("Request pipeline" below). If each worker kept its own bytes, a peer that
dropped mid-part would take them with it and the next peer would restart at block 0.
Busy peers do exactly
that: they grant a few blocks and drop. A live server-sourced part raced by seven
such peers never finished, because every racer restarted from zero.

## Decision

Part assembly lives in `rmule-core`, in one shared buffer per in-flight part.

- `PartAssembly` holds, per in-flight part, the received bytes, the set of
  contributing peers, and the contributor of each `EMBLOCKSIZE` block.
- A worker fetches blocks strictly in order, so a partial part is always a
  contiguous prefix. The assembly state is a length plus bytes, not a block bitmap.
- Workers are block streamers. `PeerWorkerCommand::RequestPart` carries a
  `resume_offset` — the part's current prefix end — and the worker reports each block
  as `PeerWorkerEvent::BlockReceived { part_index, offset, bytes }`. It neither keeps
  bytes nor decides completion.
- Core merges each block: a chunk that covers the prefix end extends it, a chunk
  wholly behind it (a lockstep racer's duplicate) is dropped, and a chunk that would
  leave a gap is dropped. When the prefix reaches the part's length, core verifies the
  MD4 part hash, persists the part, and frees the buffer.
- Racing (ADR-0026) is unchanged at the scheduler: every assignment, fresh or
  reassigned, starts at the shared prefix end, and `release_for_retry` keeps the
  buffer across the hop. A mid-part drop never resets progress while any contributor
  survives.
- Assembly is in memory and per session. Pause, cancel and restart discard partial
  parts. Memory is bounded by the parts in flight × `ED2K_PART_SIZE`: one buffer per part
  in flight, however many peers race it, and at most one part in flight per
  transferring source (ADR-0116), so twenty transfers hold at most 20 parts, about
  186 MB, per download. A buffer grows with what has arrived, so a part still filling
  holds only its prefix.
- **Request pipeline.** A worker keeps its link busy by keeping blocks asked ahead of
  the bytes, as stock 2.3.3 keeps `STANDARD_BLOCKS_REQUEST` (3) blocks pending
  (`updownclient.h:102`, `DownloadClient.cpp:619-641`) and amule-kno sizes the
  pending count to the bandwidth-delay product (amule-kno `DownloadClient.cpp:613-630`).
  An uploader reads a block only once its request is queued and then sleeps between
  sends (`UploadClient.cpp:189-197`), so one block in flight leaves the link idle at
  every block.
  - **A block is one range** of at most `EMBLOCKSIZE` inside the worker's part, the
    blocks consecutive from its resume offset. No range exceeds three blocks: a stock
    uploader ends the session on one (`UploadClient.cpp:221-224`).
  - **The Request Depth** — how many blocks are asked and not yet arrived — is
    `3 + ⌊2 × rate × rtt / EMBLOCKSIZE⌋`, held between 3 and 24. `rate` is the link's
    delivery rate (bytes over windows of at least one second, smoothed by a quarter
    per window); `rtt` the least time from a request to its block's first byte. With no
    sample yet it is 3. At 24 a link has at most 24 × 184,320 B (about 4.4 MB) asked.
  - **Refill before the link drains.** At every arrival the worker asks the shortfall
    to its depth at once, up to three new blocks per `OP_REQUESTPARTS`. A block is asked
    once: a stock uploader drops a range it already holds or has sent
    (`UploadClient.cpp:503-521`).
  - **One request before the grant.** A stream's first `OP_REQUESTPARTS` carries at
    most three blocks, and a second goes out only after the stream's first byte: the
    session holds a single request until `OP_ACCEPTUPLOADREQ` (ADR-0025), and a stock
    uploader drops a request from a client outside its upload slots
    (`UploadClient.cpp:497-501`).
  - **Arrivals are credited by offset** to the asked block they fall in; the uploader
    serves its queue in order (`UploadClient.cpp:197`), so blocks still complete in
    order and the prefix stays contiguous. Bytes inside no asked block are dropped. A
    stream ends when every block of its range has arrived.
  - **A lost block ends the stream.** A compressed block the session cannot use leaves a
    hole the prefix cannot pass: it failed to inflate, or the session refused it because its
    declared size or the count of blocks mid-accumulation passed a ceiling. This slot cannot
    fill that hole. A stock uploader drops an ask for a block it has already sent, for the
    life of the slot (aMule `UploadClient.cpp:503-511`, cleared at slot end,
    `UploadQueue.cpp:541`; eMuleAI `UploadClient.cpp:768-775` outside its NAT-traversal
    recovery). aMule's own re-ask after an inflate failure (`DownloadClient.cpp:985-998`,
    asked again at `:721` and `:772`) therefore never lands. aMule keeps the link anyway,
    because its part file takes the blocks past the hole and frees the lost one for other
    sources (`RemoveBlockFromList`, `:985`). rmule's prefix drops the bytes past a hole, so
    the worker gives the slot back with `OP_CANCELTRANSFER` at once and reports the link
    ended, and the part returns to the download with its prefix. A lost block of an earlier
    part that is still draining only stops counting against the depth. A compressed block
    still mid-accumulation goes with its slot, and a chunk that arrives outside the granted
    slot opens nothing, as aMule drops its pending zlib streams when it leaves
    `DS_DOWNLOADING` and reads no block outside it (`DownloadClient.cpp:541-543`,
    `:836-838`). A block cut short in one slot therefore never corrupts the same block asked
    in the next.
  - **The pipeline is the link's.** `OP_OUTOFPARTREQS` empties it: the uploader dropped
    every queued block. A worker handed a new part stops asking for its old one at
    once; the old blocks already asked still arrive, count against the depth while they
    drain, and are dropped — at most one depth of bytes per reassignment.
  - **A part boundary drains it.** A worker is handed its next part only after its
    range has streamed (ADR-0026), so each part starts on an empty pipeline: one round
    trip per part. Block-level assignment across parts would remove it.
- **On a failed part hash:** with a trusted AICH root, core repairs the part block by
  block and retires only the peer that delivered a corrupt block (ADR-0038). Without
  one, nothing attributes the bad block, so core retires every contributor to that
  attempt, discards the buffer, and refetches the part from its start with the
  surviving peers. Retirement is per download; if it exhausts the swarm, the download
  fails.

## Consequences

- Scarce parts finish across many short-lived grants.
- Lockstep racers still pull redundant bytes for the same blocks.
- Without AICH, the retire-all path removes a persistent poisoner at the cost of
  retiring honest co-contributors for that download.
- Assembly behaviour — prefix growth across a drop, resume offsets, retirement on
  failure, buffers freed on success and failure — is asserted with deterministic fake
  workers, without sockets.
- A link no longer idles between blocks: a fast uploader's measured 18–58% idle share
  with one block in flight is what the depth buys back. The depth rule is a pure
  function of instants handed in, asserted without sockets.

## Considered options

- **Seed only a reassigned peer with the furthest prefix.** Rejected: while racers
  download concurrently each still restarts at 0, so the common scarce-part case
  stays unsolved.
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
