# Core owns download orchestration: per-peer connections, multi-peer scheduling, verification and storage

## Context

A real eD2k download is a swarm: parts come from many peers in parallel, each peer
queues us for a slot on its own terms, and the bytes must be verified against a
part hash set before they count. That work spans many wire conversations — source
lookup, one connection per peer, part planning across peers, verification, and
writes to disk.

Each runtime connection in `rmule-net` is one conversation with one counterparty
(ADR-0021, ADR-0025). Putting a swarm, peer choice, verification or storage inside
the runtime or protocol crates would fuse transport to orchestration and settle
storage and trust policy where no other consumer can see it.

Busy peers make the scheduling hard. A peer may queue a downloader for an
open-ended wait and grant a slot late or never. On a file with one or two parts, a
rule that each part goes to exactly one peer leaves every other peer idle, and an
idle queued peer is dropped by the uploader within tens of seconds — so when the
one assigned peer stalls, no backup is left.

## Decision

`rmule-core` is the Core Orchestrator, and it owns download orchestration end to
end.

**Boundary.**

- A `rmule-net` peer `Connection` carries one conversation with one peer, inbound or
  outbound. `rmule-net` has no swarm, no peer selection, no storage and no store
  dependency.
- `PeerSession` hashes nothing and writes nothing. Part bytes leave it as
  `RequesterEvent::PartReceived` and a peer's hash set as `RequesterEvent::HashSetReceived`;
  the serve side is the mirror image, with core reading shared bytes and pushing
  them down (ADR-0031).
- Core accepts an eD2k file link, drives source discovery, runs one peer worker per
  chosen source over its own connection, verifies, and writes through the
  core-owned storage layer (ADR-0083).

**Scheduling.** The per-download brain is `DownloadState`, a sans-I/O state machine
that returns ordered `Decision`s for an async runner to enact; the part bookkeeping
is `DownloadScheduler`.

- **Time is an argument.** Every entry that can move a clock takes `now: Instant`, as
  the serving brain's do. One `on_tick(now)` runs the reask sweep (ADR-0057), turns the
  spent period and expires the callback roads' deadlines (ADR-0090), and `next_wake()`
  names the earliest instant anything falls due, so the runner sleeps until then. The
  brain reads no clock and holds no timer, so receiving time keeps it sans-I/O.

- A download has no worker cap: asking is paced by the node's **Connection Budget**
  and every grant transfers (ADR-0116).
- **The slot ask.** A worker whose Advertised Parts hold a part we lack asks its
  uploader for a slot (`OP_STARTUPLOADREQ`) at its probe answer, whether or not a part
  is free, as aMule sends it to every source whose status names a needed part (stock
  2.3.3 `DownloadClient.cpp:466-483`). Its part is chosen at the grant, never at the
  ask, as aMule chooses blocks only on a granted slot (`ClientTCPSocket.cpp:640-643`):
  a queued worker holds no part, so no part waits behind an uploader's queue, and a
  released or refetched part goes to the next grant.
- A worker holds at most one part at a time and keeps its connection and its granted
  slot across assignments. An assignment — at the grant, and after each part it
  streams — takes the first-ranked pending part the peer advertised (ADR-0112); outside
  Streaming Priority, with every part advertised, that is the lowest index. A granted
  worker with no part it can be handed gives the slot back (ADR-0056).
- **Bounded racing.** When no pending part it advertised remains, a granted peer races
  an in-flight part instead of giving its slot back, by one of two rules:
  - A **backup** peer — one that has not yet delivered a verified part in this
    download — joins the first-ranked in-flight part it advertised (ADR-0112), so a
    busy primary's part has a second source.
  - A peer that has delivered a part runs a **Tail Race**: it joins an in-flight part
    it advertised and is not on, held by exactly one racer whose **Delivery Rate** is
    below its own (a racer not yet measured counts as zero). Among those parts the rank
    of ADR-0112 §4 chooses, with its fourth position read as the expected finish — the
    bytes past the part's assembled prefix over that racer's rate — latest first. A tail
    race never makes a part's third racer, and it is run only by a peer measured faster
    than the one it races, so its duplicate bytes are at most the rest of one part per
    in-flight part. With no such part it gives its slot back (ADR-0056).
  - A **Delivery Rate** is what core measures of each worker from its block arrivals
    at the instants it is handed: bytes over windows of at least one second, smoothed
    by a quarter per window, kept for the worker's life. It is scheduling input only,
    never a published figure (ADR-0077).
  - The first verified copy wins. Every racer is cleared at once and handed its next
    part or gives its slot back; a loser handed a part stops its old stream at once
    (ADR-0029 "Request pipeline"), and a block that arrives for a part already
    assembled or verified is dropped without opening a buffer. A loser's later
    failure is a no-op.
- **One hash-set ask at a time, with a deadline.** While the download holds no whole
  part hash set — no link `p=`, no proven peer set yet, a file of more than one hash —
  one worker at a time asks for it (`OP_HASHSETREQUEST`): the first whose probe answer
  names a part we lack. Its slot ask waits on the answer, as aMule's asker waits in
  `DS_REQHASHSET` (`DownloadClient.cpp:467-483`, `:571-586`); every other worker asks
  its slot at once. The ask passes to the next transferring worker whose parts
  name a part we lack — with none, to the next probe answer, so a worker that hangs up
  at its rank never holds it (ADR-0116) — when its worker ends before an answer or answers with a set that is not the file's (aMule
  `SetHashSetNeeded(true)`, `BaseClient.cpp:1305-1306`, `DownloadClient.cpp:583`), and
  at the **Hash-Set Deadline**, 20 s after the ask, when its worker asks its slot
  regardless: half aMule's 40 s idle close (`CONNECTION_TIMEOUT`, `Constants.h:34`), so
  the slot ask still reaches an uploader that never answers the set and the source is
  kept on its queue (ADR-0090). A worker the deadline passed is not asked again while
  it lives. A held set asks nothing; a link already holding it never waits for its own
  answer.
- Racers share the part's bytes: every assignment starts at the part's assembled
  prefix, block by block (ADR-0029).
- The candidate pool grows during the download and backfills retired workers
  (ADR-0030, ADR-0055).
- A disconnect, slot refusal or transfer failure releases the worker's part for
  reassignment. A failed part verification retires its contributors (ADR-0029)
  unless AICH recovery can name the bad blocks (ADR-0038).
- `CoreConfig::slot_wait_timeout` (default 180 s) bounds how long a worker waits for
  the answer to its slot ask: from its probe answer, or from its flow's return to the
  queue, with no part streaming. A rank answers it, and a worker that is not granted
  hangs up at its rank, its record keeping the standing (ADR-0116, the **Queued
  Hang-Up**). The timer is the runtime's; the session stays clock-free. Queue state
  reaches the operator as `DownloadEvent::PeerQueued { rank }`, `PeerSlotGranted` and
  `PeerSlotTimeout`. The downloader sends no keep-alive: the eD2k peer protocol defines
  none, so a download holds its place in a busy uploader's queue by the reask
  (ADR-0057), not by a connection.

**Verification.** Trust is download-wide, ranked by `VerificationAuthority`:

- `LinkPartHashSet` — the link's `p=` hash set — is final when present.
- Otherwise the first peer hash set — asked of one link at a time, above — becomes
  `PeerHashSet`, persisted with the download as the provisional authority; parts verify against it and the whole-file
  hash at finalize confirms it.
- A peer hash set whose MD4 is not the file hash is refused, and its sender is
  retired and distrusted. A proven peer set that disagrees with the link's set
  fails the download with `HashSetMismatch`, since the link itself is then wrong.
- With neither, `FileHashOnly` defers all verification to the finished file.

**Persistence and lifecycle.**

- Each verified part is persisted at once, as a `Decision::PersistPart` round-trip
  through the store, so a restart resumes rather than refetches.
- Pause stops new assignments, shuts workers down within a bound, and keeps
  verified progress. Cancel stops the run, deletes the `.part` content file, and
  leaves the download row in the terminal `Cancelled` state.

## Consequences

- Transport stays one-conversation-per-connection; the conversation graph, trust
  and disk policy live in one place that sees every peer.
- Scheduler behaviour — the slot ask, the hash-set ask and its deadline, assignment,
  racing, release, retirement, backfill, persistence, pause, cancel, source exhaustion,
  the reask cadence and every callback deadline — is asserted on `DownloadState`'s decisions without sockets, driven by the
  instants a test hands in.
- Racing spends some redundant bandwidth on scarce parts in exchange for a live
  backup when a busy peer stalls. The Tail Race spends at most the rest of a part per
  in-flight part to stop the slowest granted source from setting the download's end,
  and keeps a fast granted slot working instead of handing it back to a stock
  uploader that would queue us again.

## Considered options

- **A one-shot `download_file` helper.** Rejected: it bypasses the layered
  command/event architecture (ADR-0011) and cannot be paused, cancelled or observed.
- **A swarm, peer selection or storage in `rmule-net`.** Rejected: it collapses
  transport into orchestration and fixes storage policy below the only layer that
  sees every download.
- **A separate `rmule-transfer` crate or a `rmule-core-net` split.** Rejected: the
  orchestrator is one crate over the shared runtime (ADR-0081); a second split adds
  a boundary with no second consumer.
- **Strictly one peer per part.** Rejected: on few-part files it leaves backup peers
  idle until busy uploaders drop them.
- **A finished peer gives its slot back.** Rejected: the download's last parts then
  ride on its slowest sources while its fastest hand back slots they waited a queue
  for. aMule 2.3.3 swaps a slower source out only behind the default-off
  `DropSlowSources` (`DownloadClient.cpp:645-675`); amule-kno takes the same
  steal at the end game, four parts or fewer left (amule-kno `DownloadClient.cpp:666-674`).
- **Cancelling the slower source instead of racing it** (aMule's swap). Rejected: it
  throws away the slower source's slot and its assembled share for a guess at
  speed; the race keeps both and lets the first verified copy decide.
