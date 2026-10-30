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
| RemoteQueued | the Source Book; the record's standing holds rank, UDP contact and reask clock | endpoint, and a called-back source's `CallbackKey` | until granted, spent by a `0x92`, or re-asked by TCP |

Every channel's sighting arrives as one **Source Sighting** through the book's one entry,
which merges a held source rather than pooling it twice, and takes none while it holds 300
records, aMule's `MaxSourcesPerFile` (ADR-0116's Source Limit), a record waiting on another
download's Queue Standing not among them (below). The connections a download
holds are read off the stages — Dialing, Worker and CallbackPending — for the node's
Connection Ceiling, and a source's **Source Activity** with them (ADR-0116); the next dial is
the book's to pick, once the Connection Budget admits it, in lane order — High ID, then Low ID on the
connected server, then Low ID global — under the Low-ID admission rule (ADR-0091).

**A Low-ID Candidate Record is keyed by its namespace, its id and the port that tells two
apart**, as aMule's `CClientList::FindMatchingClient` tells Low IDs apart (stock 2.3.3
`ClientList.cpp:264-297`): a server-assigned id by the server that assigned it (aMule's
ID and server), a Kad row by the address its publisher was observed at and its Kad UDP
port (aMule's IP and Kad port). Two publishers behind one address are two records. A
sighting under a held key merges into that record, newer non-`None` winning and a silent
channel withdrawing nothing. A sighting naming another User Hash than the record's is
**another owner** of the key — the server gave the id to someone else, or the address and
port now front another peer — and it **replaces** the candidate whole: nothing the older
owner's channels stated, its buddy, Kad UDP endpoint, IPv6 half, crypt side or NAT-T and
callback bits, carries over, and an IPv6 half no live worker dials leaves the record.

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
back, so a queued source still ending its worker is one record, counted once.

**How a worker ends, and what its record keeps.** A worker's `OP_STARTUPLOADREQ` (`0x54`)
puts its source on the uploader's queue, as aMule's `SendStartupLoadReq` sets
`DS_ONQUEUE` before the packet leaves (stock 2.3.3 `DownloadClient.cpp:163-169`): the
record earns a standing then, **without a rank** until a `0x60` ranks it, its clock dated
at the ask. A rank on a live worker ranks or refreshes it, and so do Advertised Parts
holding no part we lack (rank 0, ADR-0112). A grant or a transfer ends it — the source is
live, not queued. How the worker ends decides the rest:

| The worker ends by | Its standing | Its record | Spent |
|---|---|---|---|
| a dial that ends short of a handshake | ends | a High ID falls to its other half once, a rung-0 half to the candidate's callback roads, an adopted callback back to its Low-ID lane; anything else leaves | the endpoint it dialed |
| the link it waited on ending before its turn, a waiting **Link Rider** (ADR-0107 invariant 9) | earned without a rank, waiting on the peer's Queue Standing, its clock the peer's last ask, as aMule's A4AF file keeps the client (`BaseClient.cpp:1322-1328`) | waits in RemoteQueued | no |
| the peer hanging up, or the link failing | kept; a worker transferring on a granted slot earns one without a rank, dated at its last ask, as aMule turns `DS_DOWNLOADING` into `DS_ONQUEUE` at a disconnect and keeps the client (`BaseClient.cpp:1283-1284`, `:1322-1330`), its reask due a period after that ask (`DownloadClient.cpp:156`, `PartFile.cpp:1449-1483`) | waits in RemoteQueued when it holds a standing; else a called-back source returns to its Low-ID lane and any other leaves | no |
| its slot wait timing out | kept; a granted slot that delivered no byte for the slot budget is given back with `0x56` and earns one without a rank, dated at its last ask, as aMule's `DOWNLOADTIMEOUT` cancels and turns `DS_DOWNLOADING` into `DS_ONQUEUE` (`DownloadClient.cpp:1188-1196`, ADR-0056) | as a hang-up | no |
| a rank while its slot is not granted, at an uploader that notices our close: the **Queued Hang-Up** (ADR-0116); elsewhere the worker holds its link, and the uploader's close ends it as a hang-up | kept, ranked | waits in RemoteQueued | no |
| `OP_OUTOFPARTREQS` (`0x57`) on a granted slot | the worker does not end: its flow is queued again on the same link, as aMule turns `DS_DOWNLOADING` back into `DS_ONQUEUE` (`ClientTCPSocket.cpp:755-762`); the part it held is released for retry (ADR-0026) and a standing is earned without a rank, which the `0x60` that follows ranks (ADR-0057) | stays Worker | no |
| `OP_OUTOFPARTREQS` while only queued | ignored, as aMule acts on it only while downloading | stays Worker | no |
| Advertised Parts holding no part we lack | kept, or earned at rank 0, with the no-needed-parts mark: asked again at twice the period, over TCP | waits in RemoteQueued | no |
| a granted slot it has no part to work, given back with `0x56` (`NoFreePart`) | earned, on the ordinary cadence (ADR-0057) | waits in RemoteQueued | no |
| the peer saying it lacks the file (`0x48`, at the probe or mid-slot) | ends | leaves the book, whichever road reached it — a called-back source does not return to its lane | every Ask Name its record holds, below |
| bad data it alone sent, or a part hash set not the file's own | ends | leaves | no: distrusted (invariant 4) |
| bad bytes a failed part's refetch names it for by elimination (ADR-0117 §1) | ends | leaves | no |
| a hello naming a distrusted User Hash | ends | leaves | no |
| crypt stances that cannot meet | (it dialed nothing) | leaves | no |
| giving way in a merge | folds into the keeper's | folded into the keeper | no |

In the RemoteQueued stage a `0x92` answer to a reask spends the record as a `0x48` does.
The reask sweep runs inside the brain's
tick. Its TCP full ask is aMule's `AskForDownload` (`DownloadClient.cpp:139-160`): the
record leaves RemoteQueued for its road — a High ID dialed at its endpoint, a called-back
source, which kept its `CallbackKey`, by the road a fresh Low-ID candidate takes (rung 0, a
callback, its buddy or a punch, as `TryToConnect` does, `BaseClient.cpp:1395`) — and the
connection that answers is the same record, which its next rank puts back in the standing. A full ask that reaches
nobody drops the source as any failed dial or lapsed road does, as aMule deletes a
`DS_CONNECTING` or `DS_WAITCALLBACK` source (`BaseClient.cpp:1341-1347`).

**Blocks** stop a source from being pooled, live in the book and outlive its records:
**ourselves**, the **IP filter** and **address family** (the intake gate, below), the spent
names (below), and the **distrusted peers** — keyed by User Hash, seeded at the book's
construction from the download's record, where each new one is persisted as a child table
(ADR-0083), never expiring in the download's life. The book hands a new distrust back as an
outcome for the brain to persist. A record the store cannot read ends the start as a store
failure: a run that began without it would forget every distrust the download earned. A
write the store refuses ends the run the same way, and the run never goes on believing the
peer persisted.

**The intake gate** is the first three blocks, applied inside the book's one entry to every
sighting from every channel. A sighting that names us is refused whole, below; the filter and
the family are each judged per half: a filtered half is dropped while its
sibling half survives, a dual-stack source whose client id is refused stays on its IPv6
half, and a source whose only address is a family this node holds no address to dial from
is blocked. The caller lends the book the filter's current view, our Dial Position and our
**Own Position** for the one call, so a filter reload or a new login applies from the next
sighting and sources already pooled stay as they are. The book answers a block with its
reason — ourselves, filtered, family unreachable, spent or distrusted.

**A sighting that names us is refused whole**, on every channel, as aMule's `CanAddSource`
(`PartFile.cpp:1575-1625`) reads a server answer, a link and a source exchange, its
`CheckAndAddSource` (`DownloadQueue.cpp:612-619`) every source that reaches a file, and its
Kad intake its own row (`DownloadQueue.cpp:1569`). The **Own Position** is what those rules
read of us, taken per batch from the one owner of each fact: our User Hash, the live session's
id and server, the address **Address Learning** holds, and the serve listener's port. One half
naming us proves the pair ours, so its sibling is not kept.

| The sighting names | aMule | rmule |
|---|---|---|
| our User Hash | `CheckAndAddSource`, `DownloadQueue.cpp:612-619` | refused, whatever its address |
| our Low ID on our server, while we hold a Low ID | `PartFile.cpp:1596-1598` | refused; the same id in another server's namespace is another peer |
| our public address at any port, while we hold a Low ID | `PartFile.cpp:1599-1601` | refused |
| our High ID at our port | `PartFile.cpp:1603-1605` | refused |
| our address at our port, from Kad and from an open Kad | `DownloadQueue.cpp:1569`, `PartFile.cpp:1609-1615` | refused on every channel: Address Learning holds one address, and nobody else answers at our port there |
| a Kad callback row at our address and port | `DownloadQueue.cpp:1569` reads every row type | refused |
| our Known IPv6 at our port | none: kno has no such rule | refused: rmule writes that half into its own hello and rows (ADR-0087) |
| a Low ID while we are firewalled | `PartFile.cpp:1619-1624` drops it | departs: pooled, for the punch roads aMule lacks (ADR-0091); the Low-to-Low purge lets it go at the threshold |

Any other address at our IP, while we hold a High ID, is a peer behind our NAT, and stays a
source.

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
fallback for one to two `FILEREASKTIME` periods (21.7–43.3 minutes): the spent names are two
generations the book turns once a period at the brain's tick, so no name carries a clock. That brackets aMule's
30/45-minute dead-source block (`DeadSourceList.cpp:34`). A retirement after the handshake
never spends — the peer is alive — and a `CryptIncompatible` refusal dialed nothing, with
one exception.

**A source that says it lacks the file is spent for this download.** A TCP
`OP_FILEREQANSNOFIL` (`0x48`) — at the probe, mid-slot, or on a called-back link — or a
UDP `OP_FILENOTFOUND` (`0x92`) to a reask spends the record under every **Ask Name** it
holds (ADR-0108): its endpoints, its Low-ID key, and the User Hashes it knows. Its
standing ends and it leaves the book; a sighting under any of those names is refused,
`spent`, for the same one to two periods. It is not distrusted: it sent nothing bad.
aMule dead-lists such a source by its ID, its TCP or Kad port and, for a Low ID, its
server (`DeadSourceList.cpp:63-75`, `AddDeadSource` at `ClientTCPSocket.cpp:541-563` and
`DownloadClient.cpp:1228-1238`), and every sighting road checks the list
(`DownloadQueue.cpp:627`); its per-file block lasts 45 or 60 minutes
(`DeadSourceList.cpp:34-35`), which rmule's one clock for every spent name shortens to the
re-ask brackets. The block is this download's alone: the same peer stays a source of
another download (ADR-0107), and aMule's swap of such a source to another file
(`SwapToAnotherFile(true, true, true, NULL)`, `ClientTCPSocket.cpp:555-561`) is the peer's
Queue Standing passing on as the record leaves.

### Sources shared between downloads

aMule holds a peer as one client: `m_reqfile` names the file it asks for, `m_A4AF_list` the
other files that sighted it (`DownloadQueue.cpp:678`, `:745`, `DownloadClient.cpp:496-507`).
A source of that client holding nothing the file needs is offered to one of the others before
it is let go (`PartFile.cpp:1423-1437`). rmule holds such a peer as one record in each download's
book, and **no record ever crosses a book**: its stage, blocks, ask facts and Advertised Parts are
that download's, and each run owns its book alone. What the downloads share is the peer's one
**Queue Standing** (ADR-0107), the holder of which is `m_reqfile` and every other record of which
is an A4AF entry.

| Set | Key | Owner | Lifetime |
|---|---|---|---|
| **Places** | each Ask Name of a record holding a standing (ADR-0107) | the run, republished after every step | from its record earning a standing to the standing's end |
| **Pooled Places** | each Ask Name of a record in a lane | the run, republished after every step | while the record waits in its lane |

A **Source Handover** is the standing passing from a record holding no part we lack to another
download's record of the peer. **Nothing moves and nobody sends anything.** Each run reads its
own role off the **Queue Standings** (`role`, a pure function of what every run published), under
a lock held for one read or one publication, never over a book and never across an await. Both
sides of a handover so read one answer, each in its own step, and neither run touches the other's
book, wakes it or waits for it. A run that stops withdraws its places, which is aMule's refusal
of a stopped or finished target (`IsValidSwapTarget`, `DownloadClient.cpp:1546-1551`).

1. **Who may take.** A download holding a record of the peer that may need a part, in a lane or
   in the RemoteQueued stage, as aMule's target is a file that sighted the client and whose
   `NeededParts` stands, which it does from the sighting (`DownloadClient.cpp:501`). A download
   that never sighted the peer is offered nothing: it may not hold that file.
2. **What a Pooled Place outranks.** Only a place holding no part we lack. Against a place that
   may need a part, or another Pooled Place, it changes nothing, so two downloads that have not
   asked yet still meet on the Peer Link (ADR-0107 invariants 7 and 8) rather than on a standing
   neither holds.
3. **The taker asks by TCP, on the peer's clock.** A fill that reaches its record while the
   giver's place stands and the peer's last slot ask named the giver's file parks it in the
   RemoteQueued stage, no rank and no contact, its clock at the peer's last ask, and its TCP full
   ask falls due a period after that, as aMule's swap
   leaves `DS_NONE` and only `AskForDownload` serves it, at the last ask plus `FILEREASKTIME`
   (`DownloadClient.cpp:1498`, `PartFile.cpp:1472-1483`). The full ask stamps the record's own
   ask, as `AskForDownload` stamps the client's (`DownloadClient.cpp:156`), so the fill that
   follows dials it rather than parking it again.
4. **The giver keeps its record.** At the purge tick, spaced from the file's one purge clock as
   a no-needed-parts purge is and restarting it, whatever the file's source count, the book notes
   the record whose role reads as waiting: its rank is cleared and the handover reported, once
   (`PartFile.cpp:1424-1432`, `DownloadClient.cpp:1498-1502`). The record stays, as the A4AF entry
   aMule keeps (`DownloadClient.cpp:1483-1491`): no purge takes it, as aMule's purges walk `m_SrcList`
   and not the A4AF list, and neither the Source Limit, the purge threshold nor the source-ask
   counts read it (`GetSourceCount`, `PartFile.h:144`). Its Advertised Parts stay too, for a grant
   that reaches it; aMule's `ResetFileStatusInfo` says nothing on the wire.
5. **With nobody to take it**, a no-needed-parts source stays the holder, is asked at twice the
   period, and is let go at the threshold, as aMule's failed swap is (`PartFile.cpp:1426-1432`).
6. **A handover ends when the taker's place does.** The giver's next sweep reads the standing back
   and it asks by TCP on the peer's clock, counted again, as aMule's stopping file swaps its
   sources on, needed parts or not (`PartFile.cpp:2206`).

Two downloads never dial one peer over this: the giver asks nothing once it reads as waiting, the
taker's dial is the full ask, and the Peer Link look-up (ADR-0107 invariant 7) is the floor under a
step that read the role just before the other published. aMule's 15-minute suspension of the file
a client left (`PURGESOURCESWAPSTOP`, `DownloadClient.cpp:1529`) has no counterpart: it stops a
swap back, and a record marked as holding nothing we need loses the mark only on an answer, which
only the holder is given, so a handover cannot swing back. rmule's downloads carry no priority
(ADR-0107); among several takers the rank rule picks, the slot ask read last, then the download
added first. The operator's and EC's swap commands (`GuiEvents.cpp:631`, `:646`,
`ExternalConn.cpp:1490`) and A4AF-auto (`PartFile.cpp:1490-1502`) have no counterpart.

Invariants every transition keeps:

1. **One owner.** A source is held by at most one owner at a time: its record's one stage.
   A sighting of a remote-queued source attaches its other half to the record and pools
   nothing.
2. **Merge, never duplicate.** A sighting of a held source merges its facts into the owner's
   record; the book's one sighting entry is the one pooling seam, including for `0x9E`
   sources.
3. **One failed dial per endpoint per re-ask period**, whichever road dialed it.
4. **Bad data is not re-pooled.** A proven sender of bad data for this file — an
   AICH-attributed block, a failed part's sole contributor, the sole sender of two differing
   copies of one cell, the sole old writer of a cell a verified refetch disproves (ADR-0117
   §1), or the sender of a part hash set that is not the file's own — is distrusted,
   consulted at the sighting entry and at the hello (a source reached without its hash is
   retired as `Distrusted`, its endpoint unspent). Its User Hash is the one the hello named
   when it wrote, so a sender proven after its worker ended is distrusted too. Writers a
   failure names only by elimination are retired and never distrusted. Distrust follows the
   peer across addresses and stays apart from the IP-keyed, core-wide `BanStore` (ADR-0064).
5. **A handover moves no record.** A peer shared by two downloads is one record in each book,
   each with its one owner; only the Queue Standing's holder passes between them, and a run reads
   and writes its own book alone.

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
  worker: when the worker ends without a queue standing, the record returns to its Low-ID
  lane; with one, it waits in the RemoteQueued stage, its key kept for the TCP full ask. A
  called-back source that said it lacks the file does neither: it is spent and leaves.
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

- A called-back Low-ID source whose worker ends without a queue standing goes back to its
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
- **Keep the older owner of a Low-ID key, as aMule keeps the client it already knows**
  (`CheckAndAddSource` drops the newcomer, `DownloadQueue.cpp:672`). Rejected: a server
  reassigns a freed low id and a NAT reuses a port, so the newer sighting names who answers
  at the key now; a callback asked under the older owner's facts reaches the newer owner
  with the wrong crypt side and buddy.
- **One source record shared by the Download Set.** It would give a peer aMule's one object, at
  the cost of a lock over every sighting and a record whose blocks, ask facts and Advertised Parts
  are per download anyway. Rejected: the only per-peer fact the wire needs is the standing, which
  already has its registry.
- **A handover as a message between runs, offer then accept.** Rejected: it needs the taker's run
  awake to answer, a timeout for one that stops, and a third state in which two runs each think
  the other asks. A published place has none of these: a stopped run's places are simply gone.
- **Moving the record into the taker's book.** Rejected: the record's facts are about the giver's
  file, and the taker that sighted the peer holds a record of its own.
- **Waiting for the taker's fill to reveal it, with no Pooled Places.** Rejected: a fill the
  Connection Budget refuses reaches no record, so a saturated node would keep asking a source for
  a file that needs nothing while another download that wants it sits in a lane, and would let the
  giver's record go at the threshold.
- **Keep a source that lacks the file, asking it again each period.** Rejected: it said it
  holds nothing of this file; asking spends ask budget and a slot on every cycle, and aMule
  dead-lists it.
