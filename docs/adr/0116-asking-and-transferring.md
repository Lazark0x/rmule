# A download asks for queue places under one Connection Budget and transfers from every slot it is granted

## Context

A download capped its workers at `peer_concurrency_per_download` (ADR-0026, ADR-0030), and the cap
counted asking and transferring together. A worker whose slot ask was answered with a rank held its
slot until the uploader closed the idle link, about 40 s (`CONNECTION_TIMEOUT`, `Constants.h:34`).
At a cap of 2 a download asked about three new sources a minute and never transferred from more than
two; raised to 20 as a stopgap, the cap still let twenty queued workers block a twenty-first that an
uploader would have granted. Measured against stock amuled seeds, 2 → 6 workers gave 3.02× the
throughput, and the transfer side scaled linearly.

Stock aMule has no per-file worker count. It asks every source whose reask time has come
(`PartFile.cpp:1474-1478`) unless `TooManySockets` holds (`DownloadClient.cpp:139-160`,
`BaseClient.cpp:1398`): more than `MaxConnections` sockets open, or more than `MaxConPerFive` new
ones since the last 5-second turn (`ListenSocket.cpp:193-201`, counter `:121-130`, turned by
`amule.cpp:1230-1232`). Defaults: 300 sources per file, 500 connections, 20 per 5 s
(`Preferences.cpp:1027-1029`, `:1493-1510`). A file holding 300 sources takes no more from any
channel (`DownloadQueue.cpp:1556`, `ClientTCPSocket.cpp:452`, `:1095`, `PartFile.cpp:1677`,
`:2814`). Every source that grants transfers.

An uploader scores a waiter by waiting time × credit ratio × file priority (`UploadClient.cpp:106-141`).
Waiting time survives disconnect and reasks (`UploadQueue.cpp:405-431`) and is purged an hour after the
last one (`MAX_PURGEQUEUETIME`, `Constants.h:68`). A High-ID waiter is dialed back on promotion
(`UploadQueue.cpp:206-210`), which ADR-0107's Awaited Grant takes. A Low-ID waiter at the top is only
marked, and its slot opens at its next connection (`UploadQueue.cpp:136-138`, `:405-425`). A slot ask or
UDP reask less than `MIN_REQUESTTIME` (590 s, `Constants.h:67`) after the last adds 3 to the client's
aggressiveness, and 10 bans it (`UploadClient.cpp:795-822`, called at `ClientTCPSocket.cpp:601` and
`ClientUDPSocket.cpp:194`).

aMule references are to 2.3.3 (`4e8f2b3c`) unless kno or eMuleAI is named; read, never ported (ADR-0082).

## Decision

**A download runs two activities on its sources.**

- **Asking**: a road opened to a source — a dial, a rung-0 dial, a callback or a punch — its hello,
  file request, probe and slot ask, until the answer. A rank ends it: the worker hangs up at once (the
  **Queued Hang-Up**) and its record waits in the RemoteQueued stage holding its standing, its place
  kept by the reask (ADR-0057). A grant turns it into a transfer. Any other end is the record's, as
  ADR-0090's table says.
- **Transferring**: a worker holding a granted slot, whether the grant answered its own slot ask or came
  unasked on a link (the Awaited Grant, ADR-0107). Every grant transfers. No count per download bounds
  it; only bandwidth and the Connection Ceiling do, and a grant never waits for either: its link is
  open already.

**Source Activity.** Each source is in one of five states, read off its record's stage (ADR-0090) and
its worker's slot ask (ADR-0026):

| State | Stages | Holds a connection | Ends |
|---|---|---|---|
| pooled | Pooled | no | when a fill takes it |
| asking | Dialing, CallbackPending, a Worker whose slot is not granted | yes (a callback holds its road) | at the answer or the record's end |
| queued | RemoteQueued: holding the peer's Queue Standing, or waiting on another download's (ADR-0107) | no | at a grant on a link, a call to the standing holder's link, a TCP full ask (back to asking), a `0x92`, a purge |
| transferring | a Worker whose slot is granted | yes | at the worker's end; a `0x57` makes it asking again until its rank |
| retired | none: the record left the book or is spent | no | — |

The operator reads the asking, queued and transferring counts of every running download
(`DownloadDiagnostics::source_activity`, worded in `rmule-words`).

**The Connection Budget** paces asking. It is the node's, shared by every run of the Download Set:

| Key | Bound | Default | aMule |
|---|---|---|---|
| **Dial Window** — the node, one fixed 5-second window at a time | new connections a fill opens: each dial, rung-0 dial, callback ask or punch, and each TCP full ask's road | 20 | `MaxConPerFive` (`Preferences.cpp:1029`), the counter turned every 5 s |
| **Connection Ceiling** — the node, summed over the downloads | connections the downloads hold: every source asking or transferring, a callback road in flight included | 500 | `MaxConnections` (`Preferences.cpp:1028`, `:1493-1500` for a descriptor limit above 520 or unknown) |
| **Source Limit** — one download | sources its Source Book holds | 300 | `MaxSourcesPerFile` (`Preferences.cpp:1027`; `DownloadQueue.cpp:1556`) |

`CoreConfig::peer_connections` carries the first two; the Source Limit is aMule's default and no knob.

**The Ceiling under the descriptor limit.** Each binary, once at its start, raises the process's soft
open-descriptor limit toward its hard limit and reads the limit then in force (`rmule-os`, ADR-0111).
On macOS the soft limit goes no higher than `OPEN_MAX` (10240), above which the kernel refuses it; a
refused raise keeps the limit as it was. Windows states no such limit. The Ceiling the binary hands the
core is the configured one (the operator's, else 500), held under the room the limit leaves by the
reserve of aMule's `GetRecommendedMaxConnections` (`Preferences.cpp:1493-1509`):

| The limit | The room it leaves |
|---|---|
| unknown | no bound |
| under 20 | the limit |
| 20 to 256 | the limit less 10 |
| above 256 | the limit less 20 |

aMule's 500 for a limit above 520 or unknown is its default `MaxConnections`, which the user may set
higher; in rmule it is the default Ceiling, and an operator's larger Ceiling stands wherever the room
holds it.

A Ceiling lowered so is said to the operator once, with the limit that lowered it. aMule raises its
soft limit to the hard one the same way at start (`UnlimitResource`, `amule.cpp:126-134`, `:144`,
`:210`) but reads a limit only on Windows, where it is the TCP connection count
(`PlatformSpecific.h:52-56`, `PlatformSpecific.cpp:118-148`); rmule applies the same arms to the
descriptor limit, the one that bounds its sockets.

Invariants every transition keeps:

1. **A grant is never admitted.** A grant on a live worker, an Awaited Grant on a link nobody rides, and
   a waiter called to its standing holder's link (ADR-0107) take a slot whatever the Dial Window and the
   Ceiling read. None opens a connection.
2. **No road opens without the budget.** A fill asks the Dial Window and the Ceiling before it takes a
   record from its lane. A refused fill takes nothing; the brain names a wake at the window's turn and
   fills again then, as aMule re-reads `TooManySockets` on its process loop. A token admitted for a fill
   that found nothing to dial is given back.
3. **A ranked worker without a grant hangs up.** Its record keeps the standing the rank earned
   (ADR-0057) and holds no connection: its link closes with it unless another download rides or
   waits on it, or the peer pulls on our serve side over it (ADR-0107 invariant 9), so the FIN
   leaves well before the uploader's 40 s silent-link close (`ClientTCPSocket.cpp:201-229`). The
   uploader keeps the client on its waiting queue and promotes it by dial-back, or at its next
   connection when rmule is Low ID (`UploadQueue.cpp:136-138`, `:206-217`). The download's one
   hash-set ask is made only of a transferring worker, at its grant, so no hang-up drops a hash set
   in flight and no `0x51` waits on a link the uploader ranks (ADR-0026).
4. **A queued source is asked again only by its reask.** Its next slot ask comes with the TCP full ask
   at the reask period, never sooner than aMule's 590 s. A peer queued for several downloads is asked
   once per cycle, by the download holding its Queue Standing; the others wait on it and ask nothing
   (ADR-0107 invariants 12-14).
5. **The Ceiling counts what the stages hold.** Each run republishes its count, read off its Source
   Book, after every step; a run's end withdraws it. Nothing is incremented and decremented by hand.
6. **A file holds at most 300 sources.** A sighting from any channel is not taken while the book holds
   300 records, as aMule's every intake reads `GetMaxSourcePerFile` (a prober's sighting was the only
   one held to it before).

Departures from aMule, settled: rmule counts only the connections its downloads open, where aMule
counts every socket it creates, accepted ones too (`ClientTCPSocket.cpp:154`) — so the serve side's
dial-back to a waiter it promoted (ADR-0057) takes no token and no place under the Ceiling, as
aMule's `TryToConnect(true)` skips `TooManySockets` for it (`BaseClient.cpp:1398`) — and rmule has
no spike modifier shrinking the window (`ListenSocket.cpp:225-238`). Downloads take tokens first
come, as aMule asks in download-queue order; no share is reserved per download.

**The reask cadence.**

| rmule's reach | The UDP ping | The TCP full ask | aMule |
|---|---|---|---|
| High ID (Self Reach not firewalled) | at 1280 s | at 1300 s | `FILEREASKTIME` 1 300 000 ms (`Constants.h:35`), ping at −20 s and ask at the period (`PartFile.cpp:1463`, `:1477`) |
| Low ID (Self Reach firewalled) | none direct; through the source's buddy at 880 s (ADR-0057) | at **900 s** | kno's `SourceReaskMinutes` floor of 15 (kno `Preferences.cpp:1168`, `:1774-1777`); eMuleAI's `FILEREASKTIME` of 15 min (eMuleAI `Opcodes.h:122`) |
| either, no needed parts | none | at 2600 s | `FILEREASKTIME*2` (`PartFile.cpp:1440`) |

A Low-ID downloader's slot opens only at its next connection, and a firewalled rmule sends no direct
ping (`DownloadClient.cpp:1269`), so its TCP full ask is its only road to a slot that comes its way.
900 s cuts the wait at the top of a queue by about a third and stays above aMule's 590 s. A High-ID
rmule keeps 1300 s: its promotion reaches it by dial-back, so an earlier ask buys no score. A
no-needed-parts source asks for parts, not a slot, and keeps twice the ordinary period. The period is
read at each sweep from the reach then in force, so a standing dated under one reach falls due by the
other's period once the reach moves. The cycle is the peer's: only the download holding a peer's Queue
Standing re-asks it, and a download the standing passes to asks first by TCP, a period after the
standing's last ask (ADR-0107).

**The upload preference.** A waiter in our upload queue whose link's address and hello's User Hash
both name a source one of our downloads stands queued at — a record in the RemoteQueued stage holding
a standing, or an asking worker whose slot ask is out — has its score multiplied by the **Reciprocity
Factor**, 18/7: aMule's Very High over Normal upload priority (1.8 / 0.7, `UploadClient.cpp:117-137`).
What we upload to it raises our credit there (`ClientCredits.cpp:139-161`), and our wait there with it.
The downloads publish these **Held Places** after every step; the serve side reads them with the
credit modifiers at every rank.

The factor stays inside the rules a stock downloader waiting at rmule relies on:

- its score still grows with its waiting time, which survives its reasks and disconnects (ADR-0057);
- its credit counts as aMule's does (ADR-0041), and the factor composes with it as a file priority does;
- the per-address cap (ADR-0088), the Low-ID abuse guard and the purge are unchanged;
- every rank it is told is its place by the score in force;
- the factor is bounded: a waiter it favours passes another only while its score is within 18/7 of
  that waiter's, the spread aMule lets an operator give one file over another;
- a User Hash alone earns nothing: the link's address must be the source's too.

## Consequences

- Fifty sources are asked in about 12.5 s at the default window, against about 17 minutes at a cap of
  2; every source that grants transfers. A queued source holds no socket, so open connections stay near
  the transfers plus the asks in flight; a dead dial ends within the peer connect and hello timeouts
  (10 s, 15 s).
- Assembly memory is bounded by the parts holding arrived bytes, fewer than the transferring sources
  since workers share the first-ranked part, each holding about what has arrived (ADR-0029, ADR-0117).
- The Sources pane's slot rows grow with the sources asking and transferring at once; a freed row
  number is reused first, so the rows stay as many as the most held at once.
- A process started at 256 descriptors — the macOS shell default — raises them to 10240 and keeps the
  Ceiling at 500; one whose raise is refused at 256 holds a Ceiling of 246, and the operator is told.
  The Dial Window keeps the asks in flight near 100 at worst. The Ceiling counts only
  the downloads' connections, so the serve side's and the server session's sockets ride in the 20 or
  10 descriptors the arms leave.
- A Low-ID rmule asks each queued peer about 44% more often (1300 / 900), each ask still 310 s clear
  of the aggressive-request floor, and once per cycle however many downloads queue there.
- Measured against stock aMule 2.3.3 (2026-10-19). In a six-sharer fan-out with four sharers
  queueing us, throughput went from 217.2 to 219.4 KiB/s with the split, because the queued sharers
  granted by dial-back in both builds. A Low-ID rmule's TCP ask came 900.0 s after its rank, and its
  first part 901 s after the uploader freed a slot, against 1300 s before. Once rmule had given a
  credit-honouring uploader 32 MiB, that uploader promoted rmule ahead of two clients that had
  queued before it.
- Not yet measured: the connections that closing a link at the Queued Hang-Up saves, and the
  Reciprocity Factor's choice at rmule's own upload slots.

## Considered options

- **Raising the per-download cap.** Rejected as the rule, kept until this ADR as the stopgap: a cap
  counts queued workers as transfers, so a download's twenty-first grant still waits behind twenty
  ranks.
- **A share of the Dial Window per download.** Rejected: aMule reserves none, and a share wastes the
  tokens of downloads with nothing to dial.
- **Staying connected after a rank until the uploader closes the link.** Rejected: it holds a connection
  for 40 s per queued source to catch a promotion the dial-back (High ID) or the next connection
  (Low ID) delivers anyway.
- **Reasking every source at 900 s.** Rejected for a High-ID rmule: faster reasks buy it no score, and
  each costs a connection or a datagram.
- **Granting the next slot outright to a peer we queue at.** Rejected: it is aMule's friend slot
  (`UploadClient.cpp:93-95`) given without the operator's word, and it would let such a peer pass any
  waiter however long it had waited.
