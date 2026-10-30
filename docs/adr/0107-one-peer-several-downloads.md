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
and visible. Its serve half holds the peer as the accept side read it, as any inbound link's does:
aMule takes a callback socket at its `OP_HELLO` like every socket a client opens
(`ClientTCPSocket.cpp:391`). The serve side so reads the adopted link's hello before anything the
peer asks over it, and a slot ask there is scored by that hello's User Hash and credit, and meets
the bans and the two-clients rule under that hash, as on any inbound link.

### One peer, one link (the Peer Link)

aMule holds one client per peer and that client one socket: every download of the peer asks over
it, one file at a time, and the other files wait on the client's A4AF list. rmule holds the same
shape as a **Peer Link** — every live, identified link to a peer, whoever dialed it, and every
dial rmule has in flight to one — and the downloads that ride it, one at a time.

| Set | Key | Owner | Lifetime |
|---|---|---|---|
| **Peer Links** | each **Ask Name** the link proves: its dial endpoint (the link's own address with the hello's listen port; for a link rmule dialed, also where it dialed), `(server, low_id)` when the hello names a Low ID and its server, and the hello's User Hash; a **Dial in Flight**, before its hello, under where it dials and the User Hash the dialing source's record knows | the link's driver — the accept road's, the dialing worker's or the serve side's dial-back's router, and before the socket the dialing worker or the dial-back — by filing | a link rmule dials: from the dial, as a Dial in Flight, refiled under its hello's names at the hello; an accepted link: from the hello it answers, an adopted callback's among them; to the link's end or the dial's failure. A link filed later under a name takes that name, a User Hash only from a link at the same address or one not yet answered ("One client on two addresses") — a dial is filed at the dial, an accepted link at its hello — and a refiling, a dial's hello or a revised identity, never takes back a name a link filed later holds; a name a link gives up, at its end or at a revision, goes back to the newest live link that proves it; a Dial in Flight whose hello has not gone out is unfiled the moment an accepted link of its peer takes one of its names; and an accepted link is not filed while a dial's hello is out unanswered under one of its names (invariant 7) |
| **Link Riders** | one Peer Link: one rider, then the waiters in arrival order | the link's driver | a rider from its turn to its worker's end; a waiter from its join to its turn, its run's stop, or the link's end |
| **Awaited Grants** | each Ask Name of a source whose record waits in the RemoteQueued stage (ADR-0057): its dial endpoint and the User Hash its record knows — a record's statement, or the hello its standing kept past the worker (ADR-0049); several downloads under one name, the peer's standing holder first, then in the order they filed | the download's run, held to its Source Book's RemoteQueued stage and its standing's holder after every brain step | from the record entering the stage to its leaving it, or the run's end |

Invariants every transition keeps:

7. **A download never dials a peer it reaches a Peer Link of**, a Dial in Flight among them. Before
   a dial or a callback ask it looks the link up under the source's names — a dial under the dial
   endpoint and the User Hash its record knows, a callback under its `(server, low_id)` — and rides
   or waits on what it finds. The look-up and a dial's filing are one step, so of two downloads
   that start together one dials and the other finds its dial. The serve side's dial-back to a
   promoted waiter (ADR-0057) meets the same look-up and files its dial the same way.

   **Two links of one peer.** The far end holds one client and that client one socket, and which
   of two links lives is its choice: rmule reads that choice and never makes it. aMule attaches a
   socket to a client it knows at the `OP_HELLO` of a socket the peer opened
   (`ClientTCPSocket.cpp:391`), deleting the one the client held, connecting or connected
   (`ClientList.cpp:400-403`). The deleted socket is unlinked first, so `Disconnected` does not run
   and the client keeps its download state (`ClientTCPSocket.cpp:278-288`). The hello answer on a
   socket it dialed only finishes that client's own socket. A client with a live socket and no
   address, having read no hello yet (`m_dwUserIP` stays 0 until one is, `BaseClient.cpp:239`,
   `:661`), is the exception: the found client's address differs from the sender's, so the attach
   is refused (`ClientList.cpp:388-397`), the hello makes a second client with no file, that client
   answers it, and the first waits on its own socket. So **an answer on rmule's dial says nothing
   alone**; the close of the far end's own socket is what tells the two ends apart. Three of its
   states decide a crossing:
   `DS_CONNECTING` asks at whichever link's hellos finish first (`BaseClient.cpp:1692-1698`);
   `DS_CONNECTED` has asked, so a link attached later is asked nothing and a grant on it is dropped
   (`ClientTCPSocket.cpp:640-645`); and a link closing under either is a dead source, the client
   leaving the download (`BaseClient.cpp:1289-1293`, `:1340-1346`). So the one wrong move is to let
   the far end finish its hellos on a link it is about to replace, or to close that link under it.

   Traced for a waiter W whose own link L meets rmule's dial D, its hello out (the same for a seed
   S and a download's dial):

   | Order at W | W's client | Answer L, close L (refuted) | Close L unanswered | Answer L, keep both | Hold L's answer (the rule) |
   |---|---|---|---|---|---|
   | reads D's hello, no L hello sent | on D: asks from `DS_CONNECTING`, waits a grant from `DS_ONQUEUE` | transfer | transfer | transfer | transfer |
   | L's hello sent, reads D's hello, then what rmule did on L | L deleted unread, on D, as above | transfer | transfer | transfer | transfer |
   | L's hello sent, reads rmule's answer on L, then D's hello | `DS_CONNECTED`, file ask on L; L deleted; asks nothing on D, grant dropped | **0 parts** (bench) | | **0 parts** | cannot happen |
   | L's hello sent, reads L's close, then D's hello | `DS_CONNECTING` closes: dead source; D's hello makes a client with no file | | **0 parts**, grant answered `OP_CANCELTRANSFER` | | cannot happen |
   | L's hello sent, D ends unread | stays on L | **dead source** | **dead source** | transfer | L answered at D's end: transfer |
   | L's hello sent, W's client has no address (a first contact), reads D's hello | stays on L, `DS_CONNECTING`; a second client with no file answers D; a grant on D is answered `OP_CANCELTRANSFER` (`ClientTCPSocket.cpp:639-653`) | **0 parts**, dead source | **0 parts**, dead source (bench, closing L at D's answer) | transfer, two links | L answered at the close bound, D let go, the grant on L: transfer |

   **The hello of a link the peer opened is answered only when no dial of rmule's to that peer has
   its hello out unanswered.** Only that rule ends in a transfer in every order: it leaves W in
   `DS_CONNECTING`, which asks on whichever link it keeps. Each row of the table below is the one
   rule at one stage of the dial; the decision and the filing are one step under the Peer Links'
   lock, taken as the session reads the hello, so no dial's hello can go out behind an answer. It
   cannot wait for the serve loop: a server's port test is answered before that loop runs.

   | Stage of rmule's dial when the peer's hello is read | Which link lives | The peer's hello | Downloads | Grant or slot |
   |---|---|---|---|---|
   | before its hello: connect or crypt handshake running, or up with the hello not yet claimed under the lock | L; D is never heard | answered at once | a download's dial closes, retiring nobody; its download then its waiters ride or wait on L, each new rider asking afresh | a dial-back closes unheard and is unfiled; its pending grant moves onto L, `OP_ACCEPTUPLOADREQ` going there at once (`ClientTCPSocket.cpp:328`, `BaseClient.cpp:1707-1716`) |
   | hello out, unanswered | the far end's: see below | **held**, unanswered and unfiled; nothing of it reaches the serve side | the rider stays on D, and D keeps every name | the pending grant stays on D |
   | answered, with a hello held on it | the far end's: L's close says | still held, for the close bound; closed, answered on D | the rider hears nothing of the answer until the verdict | no grant on D before the verdict |
   | answered, alive | D, unless it turns out dead | answered at once and filed: W closed L already, or holds L because D is dead with its FIN on the way, and an unread answer harms neither | the rider stays on D; L holds the names until it closes, and they come back | stay on D; **rmule closes neither link**, the far end closes one, and the standing follows (last row) |
   | dead at the far end (below) | L | answered at once and filed | D closes now, whatever rides it: the rider and the waiters leave as at any link's end, and each rides or waits on L at its next turn | move onto L as from a link that ended; `serve.dead_dial_let_go` |
   | any live link, when a link of the same client carrying its slot ends | the one left | | | the slot moves there and is granted there; the blocks last asked on the ended link are read again for it |

   A held hello settles at the first of:
   - L's close, D answered or not: the far end attached D. L ends unanswered, the serve side never
     having heard of it (`serve.crossed_dial_kept`), and D goes on: its rider hears the answer and
     the grant goes on it. Stock aMule's FIN on L leaves before its answer on D: `Safe_Delete` runs
     at the attach, ahead of `SendHelloAnswer` (`ClientList.cpp:400-403`, `ClientTCPSocket.cpp:391`,
     `:406`). **The hello held on L is answered on D**, once, ahead of anything else on it: the
     client W attached still has the answer to the hello it sent on L pending, an `OP_HELLO` not
     ending that wait (`BaseClient.cpp:466`, `:744`), and it drops a link that answers it before
     the answer comes (`ClientTCPSocket.cpp:1205-1208`, bench: `OP_MULTIPACKETANSWER` drew a reset
     4 ms later). A second `OP_HELLOANSWER` is nothing to a far end not waiting for one.
   - The **close bound**, 3 s after D's answer with L still open: the far end refused the attach
     and its real client waits on L. L is answered and filed (`serve.crossed_dial_refused`), and D
     yields to L as a dial yields before its hello: it closes retiring nobody, its rider and
     waiters move onto L, and the pending grant moves there. The bound is no aMule timer: it
     only has to outlast a FIN retransmitted on a live path, the one thing that can part the close
     from the answer, and a far end that kept D would lose it by a wrong reading, while a far end
     that refused loses 3 s of a first contact. L's 40 s clock has room for it behind the longest
     hold.
   - D's end: L is answered, filed, and takes the pending grant as above. A dial-back ending with a
     hello held on it does not end the grant.
   - The bound: D's hello went unread that long while L stood open, so the far end is on L. D closes
     and L is answered, as at D's end. The bound keeps inside W's 40 s clock on L
     (`ClientTCPSocket.cpp:201-229`, restarted as W's hello went out, `:1870-1886`) with room for
     the answer to arrive, and it is the only thing that settles two rmules crossing, since each
     holds the other's hello: it is **20 s when rmule's User Hash is the lower of the two, 10 s
     otherwise**, so the higher hash gives its dial up first, the lower reads that close on its held
     hello or within the close bound of its own dial's answer, and neither waits on the other.

   `serve.crossed_hello_held` records the hold. A download's dial given up at the bound ends as a
   dial closed before its hello, and a dial-back so given up leaves the grant to L.

   The hold starts at L's hello. A first contact's answer on D overtaking the hello L sent before
   it, on two streams of one path, finds nothing held: L is answered at once, and a grant on D is
   given back with `OP_CANCELTRANSFER`, the slot released and W's ask on L answered as a fresh one.
   No hold can stage that order, and no draw has landed it.

   **A dial's hello wait.** A dial waits for the peer's hello as long as aMule's socket lets one
   (`CONNECTION_TIMEOUT`, 40 s, `Constants.h:34`, `EMSocket.cpp:61`), the connect of a callback
   dial-back likewise: both were 15 s, which ended a dial with a hold of 20 s still running, and a
   dial-back's grant and the waiter's place with it, where aMule still waits. The holds above end
   a crossed dial sooner, so no crossing reaches it.

   **Which link rmule keeps past the crossing.** A name a link gives up — at its end, or at a
   revision that no longer proves it — goes back to the newest live link that proves it, so a
   dialed link whose names the peer's link took is filed again when that link ends. Where the two
   links' names do not meet, so nothing held the hello (a seed whose listen port the source record
   does not name, a multi-homed peer), the far end may still replace a link carrying a slot with
   rmule's dial. Its client stays `DS_DOWNLOADING` with its pending blocks (no `Disconnected`, above):
   a grant on the dial is dropped (`ClientTCPSocket.cpp:640-645`), but it takes `OP_SENDINGPART` for
   those blocks (`DownloadClient.cpp:836`, `ClientTCPSocket.cpp:713-720`), asks on at their end, and
   only gives up after 100 s without a block (`DownloadClient.cpp:1189-1197`). So the slot's move
   reads the blocks its last ask named again on the link it moved to, since each `OP_REQUESTPARTS`
   names every block aMule has pending.

   An uploader dialing a waiter it promoted grants at its `ConnectionEstablished`
   (`BaseClient.cpp:1707-1716`), so a link that overtook a download's dial may carry an unasked
   grant before the moving download has joined it. Until every download moving over from the dials
   it overtook has joined, the link holds itself up for them, as for its waiters (invariant 9), and
   holds that grant — offers it to no Awaited Grant and gives nothing back: a download then riding
   it leaves the grant to its own ask, which the
   uploader, uploading to the client already, grants at once (`UploadQueue.cpp:486-493`), and with
   none riding the grant goes as any unasked grant does. A rank the peer's link carries answers only
   an ask made on it: the moved download's ask is answered by the client's standing at the
   uploader, its rank with the wait kept (`UploadQueue.cpp:402-430`). On a dial whose hello went
   out, the far side grants at rmule's hello on that dial (`ClientTCPSocket.cpp:417`), to the
   dial's rider.

   **A link rmule dialed, already dead at the far end.** A link rmule dialed counts as dead at the
   far end once rmule has read a reset or a FIN on it — its session ended, whether or not the serve
   side has heard of the end yet — or once nothing has crossed it either way for longer than
   aMule's socket timeout: the far side's timer restarts at every packet it sends or receives
   (`ClientTCPSocket.cpp:1886-1895`, `:2059-2080`) and closes the socket 40 s after the last
   (`CONNECTION_TIMEOUT`, `:201-229`, `EMSocket.cpp:61`). aMule adds 15 minutes to that for a buddy
   (`:206-218`), and `FarEnd` never needs it: the far end is read only on a download's dial and a
   dial-back, and neither is ever a buddy link. The slot holds the link the firewalled peer opened
   to rmule, and a firewalled rmule's own dial to its buddy belongs to its firewalled front and is
   no Peer Link (ADR-0061).
8. **One download rides a link at a time**, as aMule's client has one `m_reqfile`. Another download
   of the peer waits on the link, not on a second socket, and the oldest waiter still running takes
   the link the moment the rider's worker ends.
9. **The link lives while any half holds it**: its rider, a waiter, its serve side while it serves
   once the peer has asked it anything over the link — or from the dial, on a link the serve side
   dialed to grant a slot on (ADR-0057) — and the buddy slot while the link is the held
   buddy link (ADR-0031, ADR-0061). A link its last rider leaves with no other half holding it closes
   then: a rider's Queued Hang-Up (ADR-0116), made only at an uploader that notices our close,
   sends the FIN well inside the uploader's 40 s silent-link close (`ClientTCPSocket.cpp:201-229`).
   Its end hands every waiter back to its download, and the source stands: the record waits in the
   RemoteQueued stage on the peer's Queue Standing, its clock the peer's last ask, and is asked at
   the reask like the rider's — the link's end dials nothing. aMule keeps one client for both
   files: a downloading client goes back on queue at the disconnect and is kept
   (`BaseClient.cpp:1283-1284`, `:1322-1328`), its other file holding it as an A4AF source that
   nothing dials before the reask. Where the rider was still asking, aMule's client is a dead
   source for every file (`BaseClient.cpp:1289-1292`); rmule's waiter departs and waits for the
   reask too, so one refused dial never fails its download. A link its last rider leaves with an unasked grant still
   standing — the rider ended before its own ask — gives that grant back with `0x56` before it
   stays up or closes (ADR-0056 item 3).
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
    A dial the peer's own link overtook before its hello went out has not failed, and retires
    nobody (invariant 7).

| Rule | aMule | rmule |
|---|---|---|
| a client is found by its address and port, then by `(low_id, server)`, then by its hash | `FindMatchingClient` (`ClientList.cpp:253-347`) | a Peer Link is filed under each name; a download looks up every name its source has |
| a download from a connected client asks over its socket | `TryToConnect` on a live socket only calls `ConnectionEstablished` (`BaseClient.cpp:1489-1496`), which sends the file request (`:1692-1698`) | the download rides the link: its requests go out on it and the link's requester events come back to it; nothing is dialed |
| another file of a connected client waits on the client | `AddRequestForAnotherFile` (`DownloadClient.cpp:496-507`) | the download waits on the link (a **Link Rider** waiting); nothing is dialed |
| a client being connected to is the client every file of it asks | one `CUpDownClient`, found by address and port while `DS_CONNECTING` (`DownloadQueue.cpp:610-704`, `ClientList.cpp:253-347`) | the Dial in Flight is filed at the dial; another download of the peer waits on it and dials nothing |
| a connecting socket gives way to the one the client opens | the `OP_HELLO` of the client's own socket deletes the one it was connecting (`ClientList.cpp:400-403`), and `ConnectionEstablished` sends the file request on the new one (`BaseClient.cpp:1692-1698`); a client with a live socket and no address refuses the attach, and a second client answers (`ClientList.cpp:388-397`) | a dial whose hello has not gone out yields to the peer's accepted link: a download's closes, retiring nobody, and its downloads ride or wait on that link; a dial-back closes and hands its grant to that link. With the dial's hello out the peer's hello is held unanswered until the far end shows which it keeps, by closing that link or, answering the dial, leaving it open past the close bound; the dial then yields the same way (invariant 7) |
| a client whose connect fails is a dead source for every file | `DS_CONNECTING` on disconnect: `AddDeadSource` and delete (`BaseClient.cpp:1340-1346`), which removes it from every file and A4AF list (`:419`, `DownloadQueue.cpp:763-786`) | the dial's cause retires every download waiting on it, as it retires the one that dialed |
| a downloading source is never swapped away | `SwapToAnotherFile` refuses `DS_DOWNLOADING` (`DownloadClient.cpp:1411-1421`) | the rider keeps the link until its worker ends |
| the client swaps when its file is gone, needs nothing, or stops | `ClientTCPSocket.cpp:555-561`, `PartFile.cpp:1423-1426`, `:2203-2206` | each of these ends the rider's worker, and the oldest waiter takes the link |
| an A4AF-auto file pulls a queued client every 15 min | `PartFile.cpp:1490-1502` | departs: rmule has no A4AF-auto preference; a rider waiting in the peer's queue holds the link until its rank, at which it hangs up (ADR-0116) |
| the uploader grants at once a client asking another file while it downloads | `UploadQueue.cpp:486-493` | a waiter that takes the link from a rider that released its slot silently asks and is granted on that slot |
| a Low-ID client is found by `(low_id, server)` | `ClientList.cpp:265-300` | a callback source whose `(server, low_id)` names a link rides it, and no callback is asked: the peer's `TryToConnect` would open nothing, so the callback would lapse |
| an IPv6 client's address is its socket's | `SetAddress(m_socket->GetPeerAddress())` (kno `BaseClient.cpp:812-813`) | on an IPv6 link the peer is a source at the link's address with its listen port (`PeerIdentity::source_coordinate`); the hello's IPv4 claim names nothing |
| a client met inbound is dialed where its socket came from | `BaseClient.cpp:661`, `:678-680`, `:1620` | the link is filed under that address, the one its sighting names |
| a second link from the same address and port replaces the first | the old socket is dropped (`ClientList.cpp:400-403`), and what it carried ends | not opened by a download; a newer accepted link takes the filing |
| a second link under an identified, connected client's hash from elsewhere is a thief | the newcomer is banned, "Userhash invalid", at the `OP_HELLO` of a socket the peer opened (`ClientList.cpp:384-392`, `ClientTCPSocket.cpp:391`) | the serve side bans the newcomer's address and closes its link where both addresses are IPv4 and the peer opened the link; a client identified is one whose Secure User Identification the credit ledger bound (ADR-0041). Everywhere else, "One client on two addresses" below |
| two queued clients under one hash | the unidentified one leaves the queue, and an unidentified asker gets no answer (`UploadQueue.cpp:432-458`) | at a slot ask, a waiter under the asker's hash on another link that is not identified leaves the wait list; an asker not identified is answered nothing and not queued |
| a client promoted while unconnected is granted on whichever link its hellos finish first | `US_CONNECTING` answered at `ConnectionEstablished` (`BaseClient.cpp:1707-1716`; `ClientTCPSocket.cpp:328`, `:417`) | a pending dial-back grant (ADR-0057) moves with the waiter's place onto the link its hello came back on, and `OP_ACCEPTUPLOADREQ` goes on it at once; a hello that crosses the dial's is held until the far end shows which link it kept, so the grant goes on that one, and never on the dial before that (invariant 7) |
| a Low-ID client marked for its next connection takes its slot there | `m_bAddNextConnect` (`UploadQueue.cpp:410-425`) | its slot ask on the link it came back on is granted, under the budget or one over it (ADR-0057) |
| a Low ID in `OP_CHANGE_CLIENT_ID` is taken only from a known server | `ClientTCPSocket.cpp:773-787` | the session holds the claim; core takes it only for a server in its server list, with that server's port |
| an uploader promotes a waiter by dialing it, or on the link it holds | `AddUpNextClient` (`UploadQueue.cpp:206-217`), `OP_ACCEPTUPLOADREQ` on connect (`BaseClient.cpp:1707-1716`) | a link nobody rides that reads an unasked grant hands it to the **Awaited Grant** of the peer's standing holder under its names, else the oldest; that download rides the link and takes the grant, asking nothing first; a peer back from a new address is found by its User Hash (`ClientList.cpp:253-347`) |
| the downloader takes a grant for its queued file at once, and cancels one it does not want | `DS_ONQUEUE` → `DS_DOWNLOADING` and its block requests, no file request on the uploader's dial-back (`BaseClient.cpp:1692-1706`), else `OP_CANCELTRANSFER` once (`ClientTCPSocket.cpp:635-659`) | the Awaited Grant's worker opens on the link with no admission by the Connection Budget (ADR-0116) and asks its blocks, no file request and no slot ask first; with none the link gives the grant back with `0x56` (ADR-0056) |
| a client keeps its other file's place when its link drops | `DS_DOWNLOADING` → `DS_ONQUEUE` at the disconnect, the client kept and its A4AF file holding it (`BaseClient.cpp:1283-1284`, `:1322-1328`) | a waiter the link's end hands back stands on the peer's Queue Standing and waits for the reask (invariant 9) |

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
| holding a slot, released silently (its last part streamed, the download finished) | still uploading, its done blocks kept (`SetUploadFileID`, `UploadClient.cpp:464-492`) | granted at once, `OP_ACCEPTUPLOADREQ` (`UploadQueue.cpp:486-493`); a block whose range repeats one the link asked is dropped, whatever its file (`UploadClient.cpp:503-521`), so the rider asks around the link's **Asked Ranges** |
| holding a slot, with `OP_CANCELTRANSFER` (cancel, pause, nothing to work, ADR-0056) | out of the upload list and not queued (`ClientTCPSocket.cpp:673-680`) | a fresh admission: granted at once only when a slot is free and nobody waits, else queued with its wait from zero (`UploadQueue.cpp:500-518`) |
| waiting in the queue | on the queue, its wait kept | answered with its rank (`UploadQueue.cpp:402-430`), the wait per client, not per file |

The next rider asks the same way in all three and reads what comes back, a grant or a rank, as any
worker does; nothing is skipped. The third row is the one place a hand-over asks the peer twice in
a cycle, and "One peer, one queue standing" says when it happens. A file the link already probed
for an earlier worker — the same download's next worker on a link that stayed up, or at a TCP
full ask — is probed again and its answer read afresh, as on a new link: a
one-part file's probe settles on the name answer alone (aMule asks no `OP_SETREQFILEID` for it,
`DownloadClient.cpp:241`), so no status is waited for.

A grant nobody asked for on the link, settled: aMule grants a waiter it promotes on the link it
holds or on one it dials to it, and the `0x55` names no file. A link a download rides leaves it to
the rider, whose own ask is about to be granted. A link nobody rides offers it to the **Awaited
Grants** under its names, the peer's standing holder first, then oldest first: the download that takes it opens the record's worker on that link at
once, with no admission by the Connection Budget (ADR-0116), and the worker rides the link and
takes the grant as its own: no file request and no slot ask go first. aMule's downloader sends
neither on an uploader's dial-back while it waits on queue (`BaseClient.cpp:1692-1706`) and
answers `OP_ACCEPTUPLOADREQ` with its block requests (`ClientTCPSocket.cpp:635-644`); a slot ask
there is scored like any other (`CheckForAggressive`, `UploadClient.cpp:795-825`, from
`ClientTCPSocket.cpp:601`), 3 points for a slot already held, and a hand-over that follows asks
again. The worker's blocks come off the Advertised Parts its record last heard — the probe before
its hang-up, or a reask answer's status — as aMule's come off the part status its client kept;
a record that heard none is probed first, a file request aMule does not score, and handed its
blocks at the answer (ADR-0112). The uploader serves the file each block request names
(`UploadClient.cpp:198`), so the grant serves the file of the download that takes it. With no Awaited Grant to take it, the link gives the slot back with `0x56` (ADR-0056).
A link is left with nobody riding it only while another half holds it (invariant 9): the peer's
pull on our serve side, or the held buddy link. A worker that hung up at its rank on a link nothing
else held closed that link — only where the uploader notices our close (ADR-0116 item 3) — so the
uploader promotes it by dialing it: `AddUpNextClient` finds the client unconnected
(`UploadQueue.cpp:206-210`), and the grant comes on that new link, nobody riding it. Where the
uploader misses our close the ranked worker holds its link, and the grant comes on it to the
rider's own ask; a grant written on a link we had closed is lost at the uploader, which drops the
upload at our reset (`BaseClient.cpp:1278-1281`).

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
| **Queue Standings** | each Ask Name (ADR-0108) of a record holding a standing: the endpoint it stands at and the User Hash its record knows; per name, a **stamp** — the peer's last ask and the download whose slot ask it last read | the core, shared by the Download Set; each run republishes its places after every step and stamps each ping and TCP full ask its sweep sends | a place: from its record earning a standing (a slot ask, ADR-0057) to the standing's end; a Pooled Place, the same names of a record still in a lane (ADR-0090): while it waits there; a stamp: until no place carries its name and two reask periods have passed |

Invariants every transition keeps:

12. **A peer is asked once per cycle.** Its standing is held by one download: the one whose slot
    ask the peer read last, a download that may need a part of the peer before one holding no part
    we need. Only the holder's record re-asks — the ping naming its file, or the TCP full ask — on
    its own clock (ADR-0116).
13. **A waiter asks nothing.** Every other download with a record at the peer waits on the
    standing, as aMule's A4AF file waits on its client: no ping, no TCP full ask and no first ask.
    A fill that takes a pooled record of a peer standing in another download's standing dials
    nothing; the record waits in the RemoteQueued stage, or the Held Road stage for a Low-ID record
    with no address to stand at, holding no rank and no contact of its own, and so does one that
    takes the standing from a place holding no part we need (ADR-0090, "Sources shared between
    downloads"), whose ask falls due by invariant 14. A pooled record the standing has passed to
    since the last ask rides a link if one stands, and dials nothing (ADR-0090).
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
| a source holding nothing we need, or not the file, swaps to an A4AF file | `PartFile.cpp:1423-1426`, `ClientTCPSocket.cpp:555-561`, `PartFile.cpp:2203-2206` | a holder holding no part we need yields to a waiter, or a download holding the peer in a lane, that may need one (a **Source Handover**, ADR-0090); a holder whose standing ends — a `0x92`, the TCP no-file answer, a purge, a failed road, its run's stop, pause or end — leaves it to the next waiter |
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
The grant after a silent release keeps the slot, and with it what the uploader remembers of the
client: `AddReqBlock` drops a requested block whose start and end equal one in its done list or
its pending queue, comparing offsets alone, not the file (stock 2.3.3 `UploadClient.cpp:503-521`,
kno `:367-386`, 3.1.0 the same). `SetUploadFileID` re-targets the client and keeps the list
(`:464-492`). Only `RemoveFromUploadQueue` clears it (`UploadQueue.cpp:540-541`): an
`OP_CANCELTRANSFER` runs it (`ClientTCPSocket.cpp:673-680`), an upload session's end runs it
before its `OP_OUTOFPARTREQS` (`UploadClient.cpp:598-600`), and so does a disconnect
(`BaseClient.cpp:1278-1281`). Neither list is capped or trimmed. Every file's blocks lie on one
grid from each part's start, so the next rider would ask ranges the uploader already holds, be
served nothing, and idle to the 40 s close. The link therefore keeps its **Asked Ranges**: every
range its `OP_REQUESTPARTS` carried since the uploader last cleared that list, forgotten at a
`0x56` we send, a `0x57` we read and the link's close. Each grant hands them to the rider's
worker, which never asks one of them: a block whose range is one is asked a byte shorter, which
moves every later block of its run off the old grid (ADR-0117). eMuleAI keys the same drop by the file
too (`UploadClient.cpp:79-86`, `:769-770`), so a switch collides nowhere there, and asking
around the Asked Ranges costs it nothing.
A waiter whose call comes after the link ended dials, as any download does that finds no link.
rmule has no A4AF-auto preference, so nothing else swaps a standing.

Two downloads that reach a peer before either stands, departs where the uploader notices our close:
the second waits on the first's link (invariant 8) and, when the first hangs up at its rank, takes
its turn and asks — the swap table's third row. Where the uploader misses our close the first
holds the link at its rank (ADR-0116 item 3), and the second waits on it to the grant or the
link's end, asking nothing. The peer reads two asks seconds apart once, 3 points; the standing then asks
once per cycle and each polite ask takes one off, so no ban follows. A called waiter whose holder
ends ranked rather than released (`OP_OUTOFPARTREQS` and then a rank) costs the same once. A
Low-ID source a fill reaches by a callback road waits on the standing too, in the Held Road stage
(ADR-0090), so no callback asks the peer ahead of the clock.

### One client on two addresses

aMule's rule rests on one premise: a client has one address, so the same hash from a second one
while the first is connected is a second party. That holds for IPv4 alone. A dual-stack client
holds an address in each family and may dial us on both, and an IPv6 host holds several addresses
at once. Run `1793356626` shows the cost: emule-qt dialed over IPv6, then over IPv4 51 ms later,
and rmule banned that client's own IPv4 for two hours at the hello. The references carry the
premise unchanged. aMule's rule never meets two families. kno compares `CNetworkAddress`es and
would ban the second family (`ClientList.cpp:483-494`, read, not run). emule-qt escapes it by
accident, and only when the known client is on IPv6: `toNetworkUint32` is `0` there, so the state
reads `IdBadGuy`, not `Identified` (`ClientList.cpp:120-122`, `Address.cpp:78-83`, read, not run).
rmule parts from all three: **an address is proof of a second party only between two IPv4
addresses.**

**What proves two links one client.** Two links under one User Hash are one client when either
holds:

- **Both links proved the key** the ledger binds to that hash (ADR-0041). This proves it in any
  family.
- **The other link's own hello names this address, on the same listen port**, and the two are not
  both IPv4: the High ID that link's hello claims is the IPv4 this link came from, or the
  `CT_MOD_IP_V6` it carries is the IPv6 this one came from. TCP makes the address unforgeable, and
  the words are those of the client already held.

The newcomer's own hello proves nothing: a thief copies a claim as easily as a hash.

| A same-hash link from a different address | Held link verified | Held link unverified |
|---|---|---|
| both IPv4 | **banned at its hello**, as aMule does. A link rmule dialed is no newcomer and is never banned: aMule's rule runs at the `OP_HELLO` of a socket the peer opened, and the hello answer on one it dialed does not reach it (`ClientTCPSocket.cpp:391`) | no ban; at a slot ask the ones not identified leave the wait list (`UploadQueue.cpp:432-458`) |
| not both IPv4, proved one client | **the client's second link**: its hello, name and status asks are answered; its slot ask is answered with the rank the client holds, 1 while it holds a slot, and earns no second standing and no second slot | the same |
| not both IPv4, not proved | **an unproved link**: no ban; its hello, name and status asks are answered as a stranger's are; its slot ask is answered nothing and earns no standing | the same, and nobody leaves the wait list |

The standing stays on the link that earned it and keeps its file. Neither link is closed: which
one lives is the far end's choice (invariant 7), and a far end holding two client objects reads a
close as a dead source. When the standing's link ends, a slot moves to a proved second link, a
pending dial-back grant is handed to one, and a place waits for the next link that asks, as a
standing whose link has ended moves to any link. While the standing's link lives an unproved link
inherits nothing, and a verified client's slot or dial-back grant never reaches one.

**A reask from the other address.** aMule's waiter has one address, so a `0x90` is matched by it
(`ClientUDPSocket.cpp:196-228`). A waiter on a link of one family may ping from the other, or from
a second IPv6 address. The queue matches the datagram's own address first, as ever, and then a
waiter whose standing link's hello names that address, on the client-UDP port the same hello
advertised, and the two are not both IPv4. The second proof above carries over, and the port
stands in for the listen port. A datagram is not a TCP link: its source can be forged, but a
forged ping only refreshes the waiter it names and reads the rank the client holds, which a
forged ping from the waiter's own address does today.

**A download's look-up.** A link from another address takes no User Hash from a live link that
holds it, as aMule's client stays on the socket it holds and the newcomer attaches to nothing
(`ClientList.cpp:384-398`): a download looking a peer up by hash finds the link the hash was
first filed for, whatever the serve side later rules on the newcomer, which this step cannot
read. A dial not yet answered holds nothing yet, so a newcomer still takes the name from it and
overtakes it. The newcomer keeps the name among those it proves: when the link holding it ends,
the name passes as any name does. It rides nothing until then, unless a download finds it under
its own address.

**A ban is earned by proof, never by sight.** The first sight of a second address says nothing
about who owns it. The rule reaches a ban in only two ways: both addresses are IPv4, or the
newcomer's session proved a *different* key under the hash while the verified client is linked.
One client holds one key, so an honest dual-stack client can meet neither. A failed signature is
not that proof, since V2's signed bytes carry an address either side can have wrong, and it bans
nobody. A real thief on another family or a second IPv6 address gets a hello answered and nothing
else: no place, no slot, no bytes, no credit, and no eviction of the client it copied. If it proves
its own key it is banned. If it shares the client's public IPv4 and listen port, the client's own
naming passes it as a second link, where it reads a rank and holds nothing until the client's link
ends. That is the cost taken: a thief behind the client's own address is missed, and an honest
client is not banned.

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

- **Giving the slot back with `0x56` before every hand-over to another file.** It would clear the
  uploader's done list, and the next rider would be admitted afresh (the swap table's second
  row): queued whenever anyone waits, its wait from zero. Rejected: the slot is the point of the
  one-link grant, and asking around the Asked Ranges is wire-legal — the uploader serves any
  other range.

- **Copying a reask reply to every download.** Rejected: a peer queued for two files fed one standing
  into both.
- **One pending entry per callback or tunnel key.** Rejected: two downloads waiting on one Low-ID peer
  overwrote each other.
