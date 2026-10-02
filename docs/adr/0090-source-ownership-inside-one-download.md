# A download holds each source under one owner, spends a failed endpoint, and never re-pools bad data

## Context

A download reaches a source through several roads — the High-ID pool, its workers, Low-ID
queues and their callbacks (ADR-0039, ADR-0061), a rung-0 IPv6 dial (ADR-0087), the
Remote-Queued Pool (ADR-0057) — and sights the same source again through a server answer,
source exchange (ADR-0055), Kad or a link. A dual-stack source is one source with two
addresses (ADR-0087). Without one stated owner per source, one peer is dialed twice into
two worker slots, a dead endpoint is redialed at once, and a sender of bad data is pooled
again.

## Decision

A source is reached by keys, and each set a download holds is stated once:

| Set | Held by | Keyed by | Lifetime |
|---|---|---|---|
| High-ID pool | the brain | endpoint | until dialed (`pool_high_id`, a dual-stack fall, `readd_source` → `fill`) |
| Workers | the brain; the runner's per-worker channel mirrors it (`WorkerChannels`) | endpoint | one TCP session (`spawn_worker`, an adopted callback → `release`) |
| Low-ID queues | the brain | `CallbackKey` (server, low id) | until a road opens |
| Roads in flight (`pending_callbacks`, `direct_ipv6_dials`) | the brain | `CallbackKey` / rung-0 endpoint | one callback, punch or rung-0 dial |
| Remote-Queued Pool | the runner holds clock and contact; the brain holds membership (`remote_queued`) | endpoint | until granted, dropped (`0x92`) or re-asked by TCP |

Attachments ride one owner's key and are never a second owner: `dual_stack_fallbacks`,
`peer_crypts` / `hello_crypts` (ADR-0049), `peer_user_hashes`. Blocks stop a source from being pooled:
`SpentEndpoints` (below), and the **distrusted peers** — keyed by User Hash, durable as a
child table of the download's record (ADR-0083), never expiring in the download's life.

**A failed dial spends its endpoint for a re-ask period.** Every endpoint the download
dials — single-address, either dual-stack half, or a Low-ID candidate's rung-0 half — is
**spent** when its dial ends short of a handshake, and is neither pooled nor kept as a
fallback for one to two `FILEREASKTIME` periods (21.7–43.3 minutes): `SpentEndpoints` is two
generations turned once a period, so the brain stays clock-free. That brackets aMule's
30/45-minute dead-source block (`DeadSourceList.cpp:34`). A retirement after the handshake
never spends — the peer is alive — and a `CryptIncompatible` refusal dialed nothing.

Invariants every transition keeps:

1. **One owner.** A source is held by at most one owner at a time. The brain's `holds()`
   reads the Remote-Queued Pool's membership, so a sighting of a remote-queued source attaches
   its other half to the standing and pools nothing.
2. **Merge, never duplicate.** A sighting of a held source merges its facts into the owner's
   record; `pool_high_id` is the one pooling seam, including for `0x9E` sources.
3. **One failed dial per endpoint per re-ask period**, whichever road dialed it.
4. **Bad data is not re-pooled.** A proven sender of bad data for this file — an
   AICH-attributed block, a part's sole contributor, or the sender of a part hash set that is
   not the file's own — is distrusted, consulted at every pooling seam and at the hello (a
   source reached without its hash is retired as `Distrusted`, its endpoint unspent). A
   retire-all's several contributors are never distrusted. Distrust follows the peer across
   addresses and stays apart from the IP-keyed, core-wide `BanStore` (ADR-0064).

aMule's counterparts: one `CUpDownClient` per peer and one pooling seam,
`CDownloadQueue::CheckAndAddSource` (`src/DownloadQueue.cpp:687-745`); dead endpoints in
`CDeadSourceList` (`src/DeadSourceList.cpp:34-35`, `:88`, `:112`); a corrupt sender banned by IP
for two hours (`CorruptionBlackBox.cpp:39`, `:216-236`).

The worker lifecycle keeps the invariants:

- `release` emits one `EndWorker` per released worker, whatever the reason, enacted as
  `Shutdown { cancel: false }`, as aMule drops a client it gives up on
  (`ClientTCPSocket.cpp:2037-2047`). `WorkerChannels` drops the channel there, and each worker's
  facts carry a minted `WorkerId`, so a released worker's late fact never retires a live
  re-spawn at the same endpoint.
- The worker's block loop reads its command channel between blocks, ahead of the peer's
  events, so a shutdown mid-part stops the stream at once.
- **A part hash set is proven on arrival**: it must carry the count the file size implies and
  its MD4 over the part hashes must equal the file hash, as aMule's `LoadHashsetFromFile(..,
  checkhash = true)` (`KnownFile.cpp:521-543`, `:787-799`) run from `ProcessHashSet`
  (`DownloadClient.cpp:571-586`). A set that fails is refused and its sender retired as
  `VerificationAuthorityMismatch` and distrusted. A link's `p=` set that is not the file's own
  is dropped (aMule loads it with `checkhash` and only logs a failure, `PartFile.cpp:248-251`),
  and a persisted provisional set is re-proven at resume.
- **A sub-part file is checked on arrival** against the file hash, its one part hash
  (`PartFile.cpp:2338-2343`): corrupt bytes retire and distrust their sole sender and release
  the part, rather than failing the download at finalize.

## Consequences

- A called-back Low-ID source between its callback and its next re-ask has no owner by its
  `CallbackKey`: when its worker ends without a queue rank only a fresh sighting brings it back,
  and with a rank the Remote-Queued Pool's TCP full ask dials it as if it were a High ID. The
  model's answer — keeping the candidate record beside the adopted worker and returning it to
  its Low-ID queue — is three transitions and is not built.

## Considered options

- **Spend a failed endpoint for the run.** Rejected: a source momentarily down never returns;
  one to two re-ask periods brackets aMule's dead-source block.
