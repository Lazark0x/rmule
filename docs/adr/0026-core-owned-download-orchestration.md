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

- `CoreConfig::peer_concurrency_per_download` (default 2; `0` reads as 1) caps a
  download's workers — active, connecting, and waiting on a callback together.
- A worker holds at most one part at a time and keeps its connection across
  assignments. A fresh assignment takes the first-ranked pending part the peer
  advertised (ADR-0112); outside Streaming Priority, with every part advertised, that
  is the lowest index.
- **Bounded racing.** When no pending part remains, a backup peer — one that has not
  yet delivered a verified part in this download — joins the first-ranked in-flight
  part it advertised (ADR-0112), so
  several peers can sit queued on the same scarce part. The first verified copy
  wins and the losing racers are cleared; a loser's later failure is a no-op. A
  peer that has already delivered a part idles instead of racing a healthy peer, so
  racing engages only on few-part files.
- Racers share the part's bytes: every assignment starts at the part's assembled
  prefix, block by block (ADR-0029).
- The candidate pool grows during the download and backfills retired workers
  (ADR-0030, ADR-0055).
- A disconnect, slot refusal or transfer failure releases the worker's part for
  reassignment. A failed part verification retires its contributors (ADR-0029)
  unless AICH recovery can name the bad blocks (ADR-0038).
- `CoreConfig::slot_wait_timeout` (default 180 s) bounds how long a worker waits for
  a slot grant. The timer is the runtime's; the session stays clock-free. Queue
  state reaches the operator as `DownloadEvent::PeerQueued { rank }`,
  `PeerSlotGranted` and `PeerSlotTimeout`. The downloader sends no keep-alive: the
  eD2k peer protocol defines none, so staying connected and racing across peers is
  how a download survives a busy uploader's queue.

**Verification.** Trust is download-wide, ranked by `VerificationAuthority`:

- `LinkPartHashSet` — the link's `p=` hash set — is final when present.
- Otherwise the first peer hash set becomes `PeerHashSet`, persisted with the
  download as the provisional authority; parts verify against it and the whole-file
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
- Scheduler behaviour — assignment, racing, release, retirement, backfill,
  persistence, pause, cancel, source exhaustion, the reask cadence and every callback
  deadline — is asserted on `DownloadState`'s decisions without sockets, driven by the
  instants a test hands in.
- Racing spends some redundant bandwidth on scarce parts in exchange for a live
  backup when a busy peer stalls.

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
