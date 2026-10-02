# Block-level cross-peer part assembly with a core-owned prefix buffer

## Context

Core assigns ED2K parts to peers and counts only a verified, complete part as
durable progress (ADR-0026). A worker requests a part one `EMBLOCKSIZE` block at a
time. If each worker kept its own bytes, a peer that dropped mid-part would take
them with it and the next peer would restart at block 0. Busy peers do exactly
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
  parts. Memory is bounded by `peer_concurrency_per_download × ED2K_PART_SIZE`: one
  buffer per part in flight, however many peers race it.
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
