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

A download holds its sources in one **Source Book**: one record per source, however many
roads reached it and channels sighted it. A record is known by its aliases — up to two
endpoints, a `CallbackKey` (server, low id) and a User Hash — and one index points each
alias at its record. Each record carries exactly one stage, so one owner holds it by
construction:

| Stage | Held by | Keyed by | Lifetime |
|---|---|---|---|
| Pooled: High ID | the Source Book's High-ID lane | endpoint | until dialed (a sighting, a dual-stack fall, a TCP full ask → `next_dial`) |
| Pooled: Low ID, connected server then global | the Source Book's two Low-ID lanes | `CallbackKey` | until a road opens |
| Dialing (a High-ID half, a rung-0 IPv6 half, an adopted callback) | the Source Book; the runner's per-worker channel mirrors it (`WorkerChannels`) | endpoint | until its handshake completes or its dial ends |
| Worker | the Source Book; the runner's per-worker channel mirrors it | endpoint | one TCP session (→ `release`) |
| CallbackPending | the Source Book; the record holds the road and its deadlines | `CallbackKey` | one callback, punch or traversal |
| RemoteQueued | the Source Book; the record's standing holds rank, UDP contact and reask clock | endpoint, and a called-back source's `CallbackKey` | until granted, dropped (`0x92`) or re-asked by TCP |

Every channel's sighting arrives as one **Source Sighting** through the book's one entry,
which merges a held source rather than pooling it twice. Slots in use are read off the
stages; the next dial is the book's to pick, in lane order — High ID, then Low ID on the
connected server, then Low ID global — under the Low-ID admission rule (ADR-0091).

**Attachments** ride a record and are never a second owner, in two tiers stated once:

- **Record tier**, gone with the record: its endpoints (a dual-stack source's other half),
  its Low-ID Candidate Record, its queue standing, its ask facts (ADR-0108), its seed
  origin (ADR-0109), its Advertised Parts (ADR-0112), and the crypt side, User Hash and UDP contact its hello stated
  (ADR-0049, ADR-0057) — the last three pruned at the worker's end besides.
- **Run tier**, the book's own tables for the run: the crypt side a record stated, by
  endpoint (`0x44`, source exchange, a Kad row's `TAG_ENCRYPTION`), the buddy a hello
  named, by User Hash, and the ask facts a name kept when its record stopped answering to
  it (ADR-0108), until a client-list cleanup finds no record answering to the name. Each is
  folded into a record sighted later.

**Queue standing is an attachment**, not a set: the rank a worker learned, the source's
UDP contact, the reask clock with its one-ping latch, and the queue-full and
no-needed-parts marks (ADR-0057). It rides the record from Worker to RemoteQueued and
back, so a queued source still ending its worker is one record, counted once. A rank on a
live worker earns or refreshes it, and so do Advertised Parts holding no part we lack
(rank 0, ADR-0112); a worker that hangs up, times out its slot wait, is refused for parts
or is retired `NoNeededParts` keeps it, and its record waits in the RemoteQueued stage; a grant, a
transfer, a `0x92` or any other retirement ends it. The reask sweep runs inside the brain's
tick. Its TCP full ask is aMule's `AskForDownload` (`DownloadClient.cpp:139-160`): the
record leaves RemoteQueued for its road — a High ID dialed at its endpoint, a called-back
source, which kept its `CallbackKey`, by the road a fresh Low-ID candidate takes (rung 0, a
callback, its buddy or a punch, as `TryToConnect` does, `BaseClient.cpp:1395`) — and the
connection that answers is the same record, which its next rank puts back in the standing. A full ask that reaches
nobody drops the source as any failed dial or lapsed road does, as aMule deletes a
`DS_CONNECTING` or `DS_WAITCALLBACK` source (`BaseClient.cpp:1341-1347`).

**Blocks** stop a source from being pooled, live in the book and outlive its records:
the **IP filter** and **address family** (the intake gate, below), `SpentEndpoints`
(below), and the **distrusted peers** — keyed by User Hash, seeded at the book's
construction from the download's record, where each new one is persisted as a child table
(ADR-0083), never expiring in the download's life. The book hands a new distrust back as an
outcome for the brain to persist.

**The intake gate** is the first two blocks, applied inside the book's one entry to every
sighting from every channel. Each is judged per half: a filtered half is dropped while its
sibling half survives, a dual-stack source whose client id is refused stays on its IPv6
half, and a source whose only address is a family this node holds no address to dial from
is blocked. The caller lends the book the filter's current view and our Dial Position for
the one call, so a filter reload applies from the next sighting and sources already pooled
stay as they are. The book answers a block with its reason — filtered, family
unreachable, spent or distrusted.

**Two records merge only on wire proof**: a dual-stack pairing names both endpoints, a
Low-ID candidate names its rung-0 IPv6 half, or an adopted callback's inbound endpoint joins
its `CallbackKey`. A matching User Hash is a fact on the record and never merges two —
eMule's weak-key clones and shared hashes make it no identity. When the proof joins two
held records, the higher stage keeps the record — Worker > Dialing > CallbackPending >
RemoteQueued > Pooled — and the other's aliases and attachments fold into it. When both are
live, the newer one ends with `EndWorker` and its endpoint is not spent: the peer is alive.

**A failed dial spends its endpoint for a re-ask period.** Every endpoint the download
dials — single-address, either dual-stack half, or a Low-ID candidate's rung-0 half — is
**spent** when its dial ends short of a handshake, and is neither pooled nor kept as a
fallback for one to two `FILEREASKTIME` periods (21.7–43.3 minutes): `SpentEndpoints` is two
generations the book turns once a period at the brain's tick, so no endpoint carries a clock. That brackets aMule's
30/45-minute dead-source block (`DeadSourceList.cpp:34`). A retirement after the handshake
never spends — the peer is alive — and a `CryptIncompatible` refusal dialed nothing.

Invariants every transition keeps:

1. **One owner.** A source is held by at most one owner at a time: its record's one stage.
   A sighting of a remote-queued source attaches its other half to the record and pools
   nothing.
2. **Merge, never duplicate.** A sighting of a held source merges its facts into the owner's
   record; the book's one sighting entry is the one pooling seam, including for `0x9E`
   sources.
3. **One failed dial per endpoint per re-ask period**, whichever road dialed it.
4. **Bad data is not re-pooled.** A proven sender of bad data for this file — an
   AICH-attributed block, a part's sole contributor, or the sender of a part hash set that is
   not the file's own — is distrusted, consulted at the sighting entry and at the hello (a
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
- A called-back Low-ID source keeps its record, `CallbackKey` included, beside its adopted
  worker: when the worker ends without a queue rank, the record returns to its Low-ID lane;
  with one, it waits in the RemoteQueued stage, its key kept for the TCP full ask.
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

- A called-back Low-ID source whose worker ends without a queue rank goes back to its
  Low-ID lane by its `CallbackKey`, and its next road is a callback again. With a rank, it
  is pinged at the address it called in from (ADR-0057), and its TCP full ask, on silence,
  is a callback road too, never a dial at the endpoint it called in from.
- Time reaches the book as the brain's `now`: the reask sweep, the spent period and the
  callback roads' deadlines all turn on the brain's tick, and none needs a runner-side
  timer.

## Considered options

- **Spend a failed endpoint for the run.** Rejected: a source momentarily down never returns;
  one to two re-ask periods brackets aMule's dead-source block.
- **Merge two records on a matching User Hash.** Rejected: eMule's weak-key clones and peers
  sharing a hash would fold two peers into one record and drop one of them.
