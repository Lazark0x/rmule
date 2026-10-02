# One peer, several downloads: every per-peer set is keyed so two downloads never share a standing, a claim or an answer

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
downloads of files one peer holds are two conversations. That is the departure every rule
below is measured against.

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
   A reply matching no ping in flight is dropped and counted per session.
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
| a file the peer also has waits on A4AF and is swapped to over TCP | `SwapToAnotherFile` (`DownloadClient.cpp:1411-1520`) | departs: each download holds its own standing and reasks over its own TCP full ask |

The pool decodes a `0x91` by the UDP version both sides stated: aMule writes the status when the
*pinger* advertised UDP v4 (`ClientUDPSocket.cpp:213-221`), so rmule reads its own version from the
registry value its hello's nibble states whenever a client-UDP socket is bound. Every reply a
download takes and cannot use says why (`runt`, `unexpected_opcode`, `no_pooled_source`,
`misframed`) and is counted on its diagnostics row.

### Callbacks and tunnel claims (ADR-0039, ADR-0091)

| Rule | aMule | rmule |
|---|---|---|
| one peer is one client object | a new source merges into the known client (`DownloadQueue.cpp:610-704`, `ClientList.cpp:253-347`) | one worker per (peer, download) |
| a second connect to a connected client opens nothing | `TryToConnect` on a live socket only calls `ConnectionEstablished` (`BaseClient.cpp:1489-1496`) | the second download's claim waits for a later connection or lapses at its deadline |
| the connection serves the requested file | `m_reqfile` | the oldest claim on the key takes it |
| the other file learns over that connection by swap | `SwapToAnotherFile` | departs: the other download reaches the peer on its next candidate turn |

Handing one adopted connection to two downloads would need one worker serving two files — aMule's
A4AF — which rmule does not have; the cost is one lapsed callback deadline for the second download,
bounded and visible.

### Citations in two trees

Every citation here and in ADR-0108 is checked against stock 2.3.3 and kno's fork. Twenty
rows carry the same code in both (the fork only widens tick counts to 64 bits). Three differ:

| Rule | kno `ab483654` | 2.3.3 `4e8f2b3c` | What rmule follows |
|---|---|---|---|
| a reask reply is matched to its client | `DownloadQueue.cpp:951-973` (`CNetworkAddress`, either family) | `DownloadQueue.cpp:835-849` (32-bit IPv4) | the ping in flight's endpoint in either family: 2.3.3 for IPv4, the fork's reading for IPv6 (ADR-0087) |
| the uploader answers only for the current upload file | `ClientUDPSocket.cpp:997` (drops a banned client first) | `ClientUDPSocket.cpp:196` | the same rule |
| one peer is one client object | `ServerSocket.cpp:582-605` | `ServerSocket.cpp:570-591` | that is `OP_CALLBACKREQUESTED`; the rule followed is `DownloadQueue.cpp:610-704`, `ClientList.cpp:253-347` and `BaseClient.cpp:1489-1496` |

## Consequences

- A download added while another looks up sources asks at once; the lookup bound is its own.
- A peer queued for two of our files holds two honest standings, or one standing and one TCP reask,
  never one standing read twice.
- Two downloads falling back on the same Low-ID peer no longer strand each other.
- **Two downloads dial one High-ID peer twice.** A stock aMule 2.3.3 answers the second hello from the
  same client and closes the first socket silently (`AttachToAlreadyKnown`, `ClientList.cpp:386-403`),
  which can leave the first download with no usable source. The remedy is aMule's model — one connection
  per peer that several downloads ride, re-targeted between files — which rmule does not have.
- The reask attribution is proven against fakes and the captured `0x91`; a bench topology with a
  queuing stock sharer is what would prove it live.

## Considered options

- **Copying a reask reply to every download.** Rejected: a peer queued for two files fed one standing
  into both.
- **One pending entry per callback or tunnel key.** Rejected: two downloads waiting on one Low-ID peer
  overwrote each other.
