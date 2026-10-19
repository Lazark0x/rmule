# One peer, several downloads: one link and one queue standing per peer, and every claim and answer keyed to the download it serves

## Context

rmule holds any number of downloads side by side (the **Download Set**, keyed by
`DownloadId`). Structures that a peer or the core keys must therefore not be shaped for one
download: source lookups must not take turns on one lock, a reask reply (`0x91` / `0x92` /
`0x93`) carries no file hash and must not feed one standing into two downloads, and two
downloads waiting on the same Low-ID peer must not overwrite each other's callback or tunnel
claim.

aMule has one `CUpDownClient` per peer with one requested file (`m_reqfile`) and an A4AF
list of the other files the peer also has (`DownloadClient.cpp:496-517`); every question it
asks a peer is for `m_reqfile` alone. rmule runs one worker per (peer, download): two
downloads of files one peer holds are two conversations, carried on the peer's one link and its
one place in the peer's queue. That is the departure every rule below is measured against.

Every `file:line` is stock aMule 2.3.3 (`4e8f2b3c`), the counterparty the bench runs; the
same rules in kno's Fork Pin `ab483654` are mapped in "Citations in two trees". aMule facts
are read, never ported (ADR-0004). Evidence: the stock aMule `0x91` reply to rmule's `0x90`
at `crates/rmule-peer/tests/fixtures/peer_udp_reask/captured/amule-233-reask-ack-to-rmule-20261001/`
— the sharer's complete-source status ahead of rank 1, from the endpoint rmule pinged.

## Decision

### The sets and their keys

| Set | Key | Owner | Lifetime |
|---|---|---|---|
| **Source Asks** on a Server Session | file hash | the session multiplexer | from the `OP_GETSOURCES` send to the `OP_FOUNDSOURCES` carrying that hash, or the session's end |
| **Source Ask Budget** | Session Generation | the core, shared by the Download Set | reset by every new session (ADR-0097) |
| **Reask Routes**: installs | `DownloadId` | each run, by lease | the run |
| **Reask Routes**: pings in flight | the peer's client-UDP endpoint → one `DownloadId` | the run that sent the `0x90` | until its reply, the 20 s UDP lead, or the run's end |
| **Pending Callbacks** | `(server, low_id)` → an ordered list, one entry per download | each run | registration to adoption, lapse or the run's end |
| **Pending Tunnel Claims** | target User Hash → an ordered list, one entry per download | each run | registration to adoption, retract or the run's end |
| **Source Ask Clock** (ADR-0108) | the peer's **Ask Names** — endpoint, `(server, low_id)`, User Hash — inside one download | the run | stamps: the run; a name bound to a connection's endpoint: that worker |
| **Source Seeds** (ADR-0109) | `(DownloadId, peer endpoint)`, in rank order | the Durable Store, written by the core actor from the run's ranking | from a write to the next write, 24 h, or the row's completion, cancel or clear |
| **Served Downloads** (ADR-0113) | file hash | the download's activity, by lease: the run, then its completion move, and the core actor while the download is queued or paused; the actor ends it | from the row being queued to its cancel or failure, or at completion until the registry row is written |

Invariants every transition keeps:

1. **One wire ask per file hash per session.** A second lookup for a hash already asked on the
   live session joins the first and is answered by the same `OP_FOUNDSOURCES`; an ask whose
   every waiter has gone is asked again. Lookups for different hashes run side by side.
2. **The answer is attributed by the hash it carries**, never by order: `OP_FOUNDSOURCES` names
   its file (`ServerSocket.cpp:452-460`).
3. **The budget keeps rmule inside aMule's envelope.** aMule packs at most 15 `OP_GETSOURCES`
   per frame and sends the next frame no sooner than `15 × (16 + 4)` s = 300 s later
   (`DownloadQueue.cpp:1044`, `:1127`), starting over at a new server
   (`ResetLocalServerRequests`, `DownloadQueue.cpp:1011-1016`). rmule sends each ask at once while
   fewer than 15 went out in the last 300 s on this session; past that an ask waits for the
   window, its stop still reaches it, and its lookup bound runs from the moment the budget admits
   it.
4. **A reask reply goes to the download whose ping it answers, or to nobody.** At most one `0x90`
   is in flight per peer client-UDP endpoint; a download whose peer has another download's ping in
   flight defers to the next sweep, and the one that loses the 20 s window rides its TCP full ask.
   A reply matching no ping in flight is dropped and counted per session. Only a peer's standing
   holder pings it (invariant 12); this rule holds any ping that slips past that, one sent as the
   standing passed between two runs' sweeps among them.
5. **One connection answers one claim.** A callback or a punch opens one connection, and the
   oldest claim on that key takes it; the others stay pending to their own deadlines. A traversal
   retirement reaches every claimant of its target. Only a claim's owner retracts it.
6. **A source ask is sent only when aMule's gate would send it**, keyed per (peer, download), with
   a per-download file clock (ADR-0108).

### Source lookups on one Server Session (ADR-0032)

| Rule | aMule | rmule |
|---|---|---|
| asks for different files ride one link together | `DownloadQueue.cpp:1044-1124` (up to 15 per frame) | sent at once, side by side |
| the answer is routed by the file hash it carries | `ServerSocket.cpp:452-460` | the multiplexer's `pending`, keyed by hash |
| at most 15 asks, then 300 s | `DownloadQueue.cpp:1044`, `:1127` | rolling 15 per 300 s per Session Generation |
| a new server starts the spacing over | `DownloadQueue.cpp:1011-1016` | the budget resets on a new generation |
| a second ask for the same file | never queued twice (`SetLocalSrcRequestQueued`) | joins the ask in flight |

### Reask replies (ADR-0057)

| Rule | aMule | rmule |
|---|---|---|
| a reply is matched to a client by IP and UDP port | `ClientUDPSocket.cpp:243-275` → `GetDownloadClientByIP_UDP` (`DownloadQueue.cpp:835-849`) | matched to the ping in flight to that endpoint, in either family |
| the reply answers the client's one requested file | `UDPReaskACK` / `UDPReaskFNF` act on `m_reqfile` (`DownloadClient.cpp:1220-1247`) | the reply reaches only the download that sent the ping |
| only the requested file is pinged | `UDPReaskForDownload` sends `m_reqfile`'s hash (`DownloadClient.cpp:1249-1323`) | one ping in flight per endpoint; a second download defers |
| the uploader answers only for the client's current upload file | `ClientUDPSocket.cpp:196` | a ping for the other file draws no reply and ends at the 20 s lead |
| a file the peer also has waits on A4AF and is swapped to over TCP | `SwapToAnotherFile` (`DownloadClient.cpp:1411-1520`) | the download waits on the peer's Queue Standing and asks first by TCP when the standing passes to it ("One peer, one queue standing") |

The pool decodes a `0x91` by the UDP version both sides stated: aMule writes the status when the
*pinger* advertised UDP v4 (`ClientUDPSocket.cpp:213-221`), so rmule reads its own version from the
registry value its hello's nibble states whenever a client-UDP socket is bound. Every reply a
download takes and cannot use says why (`runt`, `unexpected_opcode`, `no_pooled_source`,
`misframed`) and is counted on its diagnostics row.

### Callbacks and tunnel claims (ADR-0039, ADR-0091)

| Rule | aMule | rmule |
|---|---|---|
| one peer is one client object | a new source merges into the known client (`DownloadQueue.cpp:610-704`, `ClientList.cpp:253-347`) | one worker per (peer, download), the workers of one peer riding one Peer Link |
| a second connect to a connected client opens nothing | `TryToConnect` on a live socket only calls `ConnectionEstablished` (`BaseClient.cpp:1489-1496`) | a download that reaches the peer's Peer Link asks no callback; a claim filed before the link came up waits for a later connection or lapses at its deadline |
| the connection serves the requested file | `m_reqfile` | the oldest claim on the key takes it |
| the other file learns over that connection by swap | `SwapToAnotherFile` | the other download waits on the adopted link and takes it when the first one's worker ends |

An adopted connection is a Peer Link like any other, so a second download of the peer rides it in
turn rather than holding a second connection; the cost is the second claim's own deadline, bounded
and visible.

### One peer, one link (the Peer Link)

aMule holds one client per peer and that client one socket: every download of the peer asks over
it, one file at a time, and the other files wait on the client's A4AF list. rmule holds the same
shape as a **Peer Link** — every live, identified link to a peer, whoever dialed it, and every
dial rmule has in flight to one — and the downloads that ride it, one at a time.

| Set | Key | Owner | Lifetime |
|---|---|---|---|
| **Peer Links** | each **Ask Name** the link proves: its dial endpoint (the link's own address with the hello's listen port; for a link rmule dialed, also where it dialed), `(server, low_id)` when the hello names a Low ID and its server, and the hello's User Hash; a **Dial in Flight**, before its hello, under where it dials and the User Hash the dialing source's record knows | the link's driver — the accept road's or the dialing worker's router, and before the socket the dialing worker — by filing | a link rmule dials: from the dial, as a Dial in Flight, refiled under its hello's names at the hello; an accepted link: from the hello (an adopted callback: from the adoption); to the link's end or the dial's failure; a newer link filed under a name takes that name |
| **Link Riders** | one Peer Link: one rider, then the waiters in arrival order | the link's driver | a rider from its turn to its worker's end; a waiter from its join to its turn, its run's stop, or the link's end |
| **Awaited Grants** | each Ask Name of a source whose record waits in the RemoteQueued stage (ADR-0057): its dial endpoint and the User Hash its record knows — a record's statement, or the hello its standing kept past the worker (ADR-0049); several downloads under one name, the peer's standing holder first, then in the order they filed | the download's run, held to its Source Book's RemoteQueued stage and its standing's holder after every brain step | from the record entering the stage to its leaving it, or the run's end |

Invariants every transition keeps:

7. **A download never dials a peer it reaches a Peer Link of**, a Dial in Flight among them. Before
   a dial or a callback ask it looks the link up under the source's names — a dial under the dial
   endpoint and the User Hash its record knows, a callback under its `(server, low_id)` — and rides
   or waits on what it finds. The look-up and a dial's filing are one step, so of two downloads
   that start together one dials and the other finds its dial.
8. **One download rides a link at a time**, as aMule's client has one `m_reqfile`. Another download
   of the peer waits on the link, not on a second socket, and the oldest waiter still running takes
   the link the moment the rider's worker ends.
9. **The link lives while any half holds it**: its serve side, its rider or a waiter (ADR-0031). Its
   end hands every waiter back to its download, which dials as before.
10. **A name is filed only from what the link proves or the node accepts**: the socket's address
    (never an IPv4 claim on an IPv6 link), the hello's `(server, low_id)` and User Hash, and a Low
    ID an `OP_CHANGE_CLIENT_ID` moves only under a server the node's list holds. A hash another
    client claims falsely is caught by the identified-client rule below.
11. **A Dial in Flight is a link not yet up.** The download that dials it rides it from the dial;
    another download that finds it waits on it, is told it waits once the socket is up, and takes
    its turn on the link after the hello. A dial that fails — refused, timed out, reset, closed
    before the hello — retires the dialing download and every waiter with the dial's one cause, as
    aMule's one client in `DS_CONNECTING` is a dead source deleted from every file's source and
    A4AF lists (`BaseClient.cpp:1340-1346`, `:419`, `DownloadQueue.cpp:763-786`). A dial refused
    before any socket — by the IP filter, a ban or the outbound crypt rule (ADR-0049) — is no Dial
    in Flight and files nothing: each download meets those gates with what its own record knows.

| Rule | aMule | rmule |
|---|---|---|
| a client is found by its address and port, then by `(low_id, server)`, then by its hash | `FindMatchingClient` (`ClientList.cpp:253-347`) | a Peer Link is filed under each name; a download looks up every name its source has |
| a download from a connected client asks over its socket | `TryToConnect` on a live socket only calls `ConnectionEstablished` (`BaseClient.cpp:1489-1496`), which sends the file request (`:1692-1698`) | the download rides the link: its requests go out on it and the link's requester events come back to it; nothing is dialed |
| another file of a connected client waits on the client | `AddRequestForAnotherFile` (`DownloadClient.cpp:496-507`) | the download waits on the link (a **Link Rider** waiting); nothing is dialed |
| a client being connected to is the client every file of it asks | one `CUpDownClient`, found by address and port while `DS_CONNECTING` (`DownloadQueue.cpp:610-704`, `ClientList.cpp:253-347`) | the Dial in Flight is filed at the dial; another download of the peer waits on it and dials nothing |
| a client whose connect fails is a dead source for every file | `DS_CONNECTING` on disconnect: `AddDeadSource` and delete (`BaseClient.cpp:1340-1346`), which removes it from every file and A4AF list (`:419`, `DownloadQueue.cpp:763-786`) | the dial's cause retires every download waiting on it, as it retires the one that dialed |
| a downloading source is never swapped away | `SwapToAnotherFile` refuses `DS_DOWNLOADING` (`DownloadClient.cpp:1411-1421`) | the rider keeps the link until its worker ends |
| the client swaps when its file is gone, needs nothing, or stops | `ClientTCPSocket.cpp:555-561`, `PartFile.cpp:1423-1426`, `:2203-2206` | each of these ends the rider's worker, and the oldest waiter takes the link |
| an A4AF-auto file pulls a queued client every 15 min | `PartFile.cpp:1490-1502` | departs: rmule has no A4AF-auto preference; a rider waiting in the peer's queue holds the link until its rank, at which it hangs up (ADR-0116) |
| the uploader grants at once a client asking another file while it downloads | `UploadQueue.cpp:486-493` | a waiter that takes the link from a rider that released its slot silently asks and is granted on that slot |
| a Low-ID client is found by `(low_id, server)` | `ClientList.cpp:265-300` | a callback source whose `(server, low_id)` names a link rides it, and no callback is asked: the peer's `TryToConnect` would open nothing, so the callback would lapse |
| an IPv6 client's address is its socket's | `SetAddress(m_socket->GetPeerAddress())` (kno `BaseClient.cpp:812-813`) | on an IPv6 link the peer is a source at the link's address with its listen port (`PeerIdentity::source_coordinate`); the hello's IPv4 claim names nothing |
| a client met inbound is dialed where its socket came from | `BaseClient.cpp:661`, `:678-680`, `:1620` | the link is filed under that address, the one its sighting names |
| a second link from the same address and port replaces the first | the old socket is dropped (`ClientList.cpp:400-403`), and what it carried ends | not opened by a download; a newer accepted link takes the filing |
| a second link under an identified, connected client's hash from elsewhere is a thief | the newcomer is banned, "Userhash invalid" (`ClientList.cpp:384-392`) | the serve side bans the newcomer's address and closes its link; a client identified is one whose Secure User Identification the credit ledger bound (ADR-0041) |
| two queued clients under one hash | the unidentified one leaves the queue, and an unidentified asker gets no answer (`UploadQueue.cpp:432-458`) | at a slot ask, a waiter under the asker's hash on another link that is not identified leaves the wait list; an asker not identified is answered nothing and not queued |
| a Low-ID client's pending grant follows it to its next connection | `m_bAddNextConnect` (`UploadQueue.cpp:410-425`) | a pending dial-back grant (ADR-0057) moves with the waiter's place onto the link its hello came back on |
| a Low ID in `OP_CHANGE_CLIENT_ID` is taken only from a known server | `ClientTCPSocket.cpp:773-787` | the session holds the claim; core takes it only for a server in its server list, with that server's port |
| an uploader promotes a waiter by dialing it, or on the link it holds | `AddUpNextClient` (`UploadQueue.cpp:206-217`), `OP_ACCEPTUPLOADREQ` on connect (`BaseClient.cpp:1707-1716`) | a link nobody rides that reads an unasked grant hands it to the **Awaited Grant** of the peer's standing holder under its names, else the oldest; that download rides the link and asks, and is granted at once (`UploadQueue.cpp:486-493`); a peer back from a new address is found by its User Hash (`ClientList.cpp:253-347`) |
| the downloader takes a grant for its queued file at once, and cancels one it does not want | `DS_ONQUEUE` → `DS_DOWNLOADING`, else `OP_CANCELTRANSFER` once (`ClientTCPSocket.cpp:635-659`) | the Awaited Grant's worker opens on the link with no admission by the Connection Budget (ADR-0116); with none the link gives the grant back with `0x56` (ADR-0056) |

The swap rule, settled: a waiter takes the link when the rider's worker ends, for whatever reason it
ends — the peer lacks the file, has nothing the download needs, ranked it without a grant
(ADR-0116), its slot wait ran out, the run stopped, paused, finished or was cancelled. A waiter whose run stops leaves the line without a turn.
The rider's teardown (`OP_CANCELTRANSFER` or the silent release, ADR-0056) goes out before the next
rider's file request, so the peer reads the hand-over as aMule's `SetUploadFileID` switch.

What the uploader reads, settled: the next rider's file request is the one any new source gets —
`OP_REQUESTFILENAME`, `OP_SETREQFILEID` for a file of more than one part, then `OP_STARTUPLOADREQ`
on the probe's answer. aMule takes the first two as a file switch, `SetUploadFileID` re-targeting
the client (`ClientTCPSocket.cpp:487-530`), and answers the ask by the client's upload state, not by
the file (`:592-616`, `UploadQueue.cpp:395-519`):

| The rider ended | The client at aMule | The next rider's ask |
|---|---|---|
| holding a slot, released silently (its last part streamed, the download finished) | still uploading | granted at once, `OP_ACCEPTUPLOADREQ` (`UploadQueue.cpp:486-493`) |
| holding a slot, with `OP_CANCELTRANSFER` (cancel, pause, nothing to work, ADR-0056) | out of the upload list and not queued (`ClientTCPSocket.cpp:673-680`) | a fresh admission: granted at once only when a slot is free and nobody waits, else queued with its wait from zero (`UploadQueue.cpp:500-518`) |
| waiting in the queue | on the queue, its wait kept | answered with its rank (`UploadQueue.cpp:402-430`), the wait per client, not per file |

The next rider asks the same way in all three and reads what comes back, a grant or a rank, as any
worker does; nothing is skipped. The third row is the one place a hand-over asks the peer twice in
a cycle, and "One peer, one queue standing" says when it happens.

A grant nobody asked for on the link, settled: aMule grants a waiter it promotes on the link it
holds or on one it dials to it, and the `0x55` names no file. A link a download rides leaves it to
the rider, whose own ask is about to be granted. A link nobody rides offers it to the **Awaited
Grants** under its names, the peer's standing holder first, then oldest first: the download that takes it opens the record's worker on that link at
once, with no admission by the Connection Budget (ADR-0116), and the worker rides the link as any rider does, asking
for its file. With no Awaited Grant to take it, the link gives the slot back with `0x56` (ADR-0056).

A download that rides or waits on a link is told so, and the operator sees it: a Run Log record
(`download.link_shared`, the turn `waiting` or `riding`) and the Sources pane's mark on the slot. A
grant taken this way is a Run Log record of its own (`download.slot_offered`).

A Low-ID peer's callback claims are unchanged (ADR-0039): one connection answers the oldest claim.
A second download whose claim the connection did not take rides the link at its next candidate turn,
and its claim lapses at its own deadline.

### One peer, one queue standing

aMule's uploader holds one queue entry per client whatever file it asks for: a client already
queued is answered with its rank (`AddClientToQueue`, `UploadQueue.cpp:395-430`), and a request
for another file re-targets the entry (`SetUploadFileID`, `ClientTCPSocket.cpp:462`, `:521`,
`:613`). A UDP reask is answered only for the file the entry holds (`ClientUDPSocket.cpp:196-228`).
Every slot ask and every reask, answered or not, is scored (`CheckForAggressive`,
`UploadClient.cpp:795-825`, called at `ClientTCPSocket.cpp:601` and `ClientUDPSocket.cpp:194`):
one under `MIN_REQUESTTIME` (590 s) after the last adds 3, a polite one takes 1 off, and 10 bans.
aMule's downloader asks a client for one file and reasks it on the client's one clock
(`m_dwLastAskedTime`, `DownloadClient.cpp:156`, `:1225`). Two downloads each keeping a place of
their own and reasking on their own clocks net about 2 points a cycle: a ban in about four. rmule
holds aMule's shape as a **Queue Standing**: one per peer across the Download Set, naming one file.

| Set | Key | Owner | Lifetime |
|---|---|---|---|
| **Queue Standings** | each Ask Name (ADR-0108) of a record holding a standing: the endpoint it stands at and the User Hash its record knows; per name, a **stamp** — the peer's last ask and the download whose slot ask it last read | the core, shared by the Download Set; each run republishes its places after every step and stamps each ping and TCP full ask its sweep sends | a place: from its record earning a standing (a slot ask, ADR-0057) to the standing's end; a stamp: until no place carries its name and two reask periods have passed |

Invariants every transition keeps:

12. **A peer is asked once per cycle.** Its standing is held by one download: the one whose slot
    ask the peer read last, a download that may need a part of the peer before one holding no part
    we need. Only the holder's record re-asks — the ping naming its file, or the TCP full ask — on
    its own clock (ADR-0116).
13. **A waiter asks nothing.** Every other download with a record at the peer waits on the
    standing, as aMule's A4AF file waits on its client: no ping, no TCP full ask and no first ask.
    A fill that takes a pooled record of a peer standing in another download's standing dials
    nothing; the record waits in the RemoteQueued stage, holding no rank and no contact of its own.
14. **The standing's clock is the peer's.** Each ping and TCP full ask a sweep sends stamps the
    peer, and so does each slot ask a record earns its standing by. A download the standing passes
    to pings nothing — the peer holds the other file — and its TCP full ask falls due a period after
    the last stamp, never sooner. A waiter's own clock follows the stamps, so it wakes when the
    standing would next be asked.

| Rule | aMule | rmule |
|---|---|---|
| one queue entry per client | `AddClientToQueue` (`UploadQueue.cpp:395-430`) | one Queue Standing per peer, found under any Ask Name a place carries |
| the entry names one file | `SetUploadFileID` at each file request (`ClientTCPSocket.cpp:462`, `:521`, `:613`) | the holder is the download whose slot ask the peer read last |
| the client is reasked once a cycle, for its requested file | `UDPReaskForDownload` sends `m_reqfile` (`DownloadClient.cpp:1249-1323`) on the client's clock (`PartFile.cpp:1449-1483`) | the holder's record re-asks; every other download's record waits |
| another file of a queued client waits on the client | `AddRequestForAnotherFile` (`DownloadClient.cpp:496-507`) | a pooled record of a peer standing elsewhere waits on that standing and is not dialed |
| a source holding nothing we need, or not the file, swaps to an A4AF file | `PartFile.cpp:1423-1426`, `ClientTCPSocket.cpp:555-561`, `PartFile.cpp:2203-2206` | a holder holding no part we need yields to a waiter that may need one; a holder whose standing ends — a `0x92`, the TCP no-file answer, a purge, a failed road, its run's stop, pause or end — leaves it to the next waiter |
| a swapped client asks by TCP on the client's clock | `SwapToAnotherFile` leaves `DS_NONE` (`DownloadClient.cpp:1499`), which only the TCP ask serves, at the last ask plus `FILEREASKTIME` (`PartFile.cpp:1472-1483`) | the new holder's first re-ask is the TCP full ask, a period after the standing's last stamp |
| a promoted client takes the grant for its requested file | `OP_ACCEPTUPLOADREQ` names no file; `DS_ONQUEUE` becomes `DS_DOWNLOADING` for `m_reqfile` (`ClientTCPSocket.cpp:635-645`) | an unasked grant goes to the holder's Awaited Grant first |
| the A4AF files take the socket after the transfer | `SwapToAnotherFile` over the client's one socket, granted at once while it uploads (`UploadQueue.cpp:486-493`) | a grant on the standing calls every waiter to the holder's link |

Which file the standing names, settled: the holder's — the file of the download whose slot ask the
peer read last, which is the file aMule's entry holds and so the one file a ping is answered for. A
slot ask, first or a TCP full ask's, earns the standing for its download, and the downloads it
passes over wait. aMule ranks A4AF files by download priority when it swaps; rmule's downloads
carry none, so the next holder is the download added first, one that may need a part before one
that needs none.

How a grant hands over, settled: a grant the holder takes — unasked on a link nobody rides, or on
its own ask — transfers the holder's file. The holder's run then calls every Awaited Grant filed
under the peer's names: the waiters, whose records still wait in the RemoteQueued stage. Each opens
its record's worker on the holder's link at once, unadmitted by the Connection Budget as a grant is
(ADR-0116), and waits there as a Link Rider. When the holder's worker ends, the swap rule hands the
link to the oldest waiter: after a silent release its ask is granted at once
(`UploadQueue.cpp:486-493`), after a cancel it is admitted afresh, and a rank makes it the holder.
A waiter whose call comes after the link ended dials, as any download does that finds no link.
rmule has no A4AF-auto preference, so nothing else swaps a standing.

Two downloads that reach a peer before either stands, departs: the second waits on the first's
link (invariant 8) and, when the first hangs up at its rank, takes its turn and asks — the swap
table's third row. The peer reads two asks seconds apart once, 3 points; the standing then asks
once per cycle and each polite ask takes one off, so no ban follows. A called waiter whose holder
ends ranked rather than released (`OP_OUTOFPARTREQS` and then a rank) costs the same once, and so
does a Low-ID source a fill reaches by a callback road: its record has no address to wait at
until the peer connects, and the connection that answers asks.

### Citations in two trees

Every citation here and in ADR-0108 is checked against stock 2.3.3 and kno's fork. Twenty
rows carry the same code in both (the fork only widens tick counts to 64 bits). Three differ; the
rows of "One peer, one queue standing" are read in 2.3.3 alone:

| Rule | kno `ab483654` | 2.3.3 `4e8f2b3c` | What rmule follows |
|---|---|---|---|
| a reask reply is matched to its client | `DownloadQueue.cpp:951-973` (`CNetworkAddress`, either family) | `DownloadQueue.cpp:835-849` (32-bit IPv4) | the ping in flight's endpoint in either family: 2.3.3 for IPv4, the fork's reading for IPv6 (ADR-0087) |
| the uploader answers only for the current upload file | `ClientUDPSocket.cpp:997` (drops a banned client first) | `ClientUDPSocket.cpp:196` | the same rule |
| one peer is one client object | `ServerSocket.cpp:582-605` | `ServerSocket.cpp:570-591` | that is `OP_CALLBACKREQUESTED`; the rule followed is `DownloadQueue.cpp:610-704`, `ClientList.cpp:253-347` and `BaseClient.cpp:1489-1496` |

## Consequences

- A download added while another looks up sources asks at once; the lookup bound is its own.
- A peer queued for two of our files holds one standing and is re-asked once per cycle, for the file
  it holds; the other download waits on it and takes the link by the swap rule once the standing is
  granted. Each re-ask costs the peer one datagram or one connection, not one per download.
- Two downloads falling back on the same Low-ID peer no longer strand each other.
- **Two downloads of one peer share one link.** A stock aMule 2.3.3 answers a second hello from the
  same client by closing the first socket silently (`AttachToAlreadyKnown`, `ClientList.cpp:386-403`),
  which left the first download with no usable source; the second download now waits on the first's
  link instead, so the peer meets one connection, re-targeted between files as aMule re-targets
  its own.
- **Two downloads that start together dial once.** The first dial is filed before its socket, so
  the second, finding it, waits instead of racing a second hello that would make aMule close the
  first socket; a dial that fails costs both downloads the source at once, as aMule loses its one
  client.
- A download waiting on a link holds a worker slot of its own download while it waits, as aMule's
  A4AF source counts among the file's sources; it dials nothing and asks the peer nothing.
- The links rmule dials are filed too, so a download of a peer another download dialed rides that
  link; a Low-ID asker's link is found by its callback name, an IPv6 asker's by its own address.
- An asker downloading from us is asked for our download over its own link, so our upload to it
  survives our download from it.
- The reask attribution is proven against fakes and the captured `0x91`; a bench topology with a
  queuing stock sharer is what would prove it live.

## Considered options

- **Copying a reask reply to every download.** Rejected: a peer queued for two files fed one standing
  into both.
- **One pending entry per callback or tunnel key.** Rejected: two downloads waiting on one Low-ID peer
  overwrote each other.
