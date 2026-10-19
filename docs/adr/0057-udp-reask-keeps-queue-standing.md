# Queue standing survives disconnect, kept by a UDP reask over one shared client-UDP socket

## Context

aMule's counterparties expect a queue lifecycle where a downloader asks, learns its
rank, hangs up, and keeps its place with a reask heartbeat of about 21.7 minutes: one
UDP datagram instead of a TCP session
([PartFile.cpp#L1462](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/PartFile.cpp#L1462)).
The source-reask quartet is `OP_REASKFILEPING` (`0x90`), `OP_REASKACK` (`0x91`),
`OP_FILENOTFOUND` (`0x92`) and `OP_QUEUEFULL` (`0x93`). Holding a TCP connection open to
wait burns a counterparty socket and loses the standing on disconnect.

A client-UDP frame is `[protocol][opcode][payload]`, no length prefix, at least 2 bytes
([ClientUDPSocket.cpp#L80](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientUDPSocket.cpp#L80)),
demuxed on its first byte
([ClientUDPSocket.cpp#L92](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientUDPSocket.cpp#L92)).
An eMule-family client runs Kad and client-UDP on one socket. Two sockets would also
mean two NAT mappings, so the mapping a serving buddy observed while rmule recruited it
over Kad would differ from the one a NAT-T Tunnel rides, and an endpoint hint naming
rmule would name the wrong hole (ADR-0091).

## Decision

**rmule adopts aMule's disconnect-and-reask queue standing on both sides**, carried by
one shared client-UDP socket and a peer-UDP engine that answers and emits the reask
quartet as aMule does.

### One client-UDP socket

- One `ClientUdpSocket` **Family Pair** (ADR-0085), bound once at core start on
  the configured `CoreSettings::udp_port` (`0` is legal for tests), carries everything a
  counterparty sends to rmule's advertised UDP endpoint: the reask surface, NAT-T and Kad.
- After the receive transform (ADR-0046) the front demuxes: `0xC5` to the peer-UDP
  engine; `0xE4`, and `0xE5` after zlib inflate, to the running Kad node's inlet; and
  every leading byte no protocol claims, once the peer-UDP dual-path receive has missed,
  also to the Kad node. An obfuscated Kad datagram opens with a random marker, and only
  the node's Kad-ID and receiver-verify key families can tell it from noise. The peer-UDP
  key is tried first and cannot mis-accept one, because a decrypt is admitted by the
  magic value, not a marker or length, the order aMule's
  `CEncryptedDatagramSocket::DecryptReceivedClient` uses.
- Kad is IPv4-only (ADR-0087): a declared Kad datagram on the IPv6 half is dropped and
  counted; an unclaimed byte there is simply dropped.
- The accepted set is disjoint from the server-UDP socket's `0xE3` (ADR-0051); each
  socket rejects the other's traffic.
- `rmule_net::kad` runs one driver loop over two transports: `spawn` binds its own pair
  (tools, the Kad Stimulus Node, the mesh sim), `spawn_over` rides the core's socket
  (ADR-0043).
- **The Kad inlet** is a shared slot the node fills on start and clears when its pump
  ends, because the socket outlives every Kad runtime on it. With no node running, a Kad
  datagram is dropped at trace level and counted as nothing. The inlet is fed with
  `try_send` over a deep queue and never awaited, so it cannot back-pressure a socket that
  every reask, NAT-T frame and Kad datagram shares.
- UDP version nibble **4** (aMule's own) and the UDP port tags come from the registry
  (ADR-0047).

**Bind failures are stated, and the socket stays down until restart.**

- A total bind failure logs the `io::Error` once, sets
  `DiagnosticsSnapshot::client_udp_bind_failure` (`ClientUdpBindFailure { port, kind }`,
  never cleared), fires `CoreEvent::ClientUdpBindFailed { port, kind }` once, and makes a
  later `EnableKad` refuse with `KadUnavailableReason::UdpUnbound { port, kind }`. When
  every family refuses, the joined error carries a real `ErrorKind`: the shared one when
  the families agree, else the IPv4 half's, where an operator's port conflict lands.
- A one-family refusal still brings the pair up on the other family. When IPv4 is the
  missing half, it costs Kad, the NAT-T punch path and the IPv4 UDP advert, so it is a
  **Half-Bound Pair** with its own row (`half_bound_pairs`), its own start event
  (`CoreEvent::SocketBoundWithoutFamily`) and its own `EnableKad` refusal
  (`KadUnavailableReason::UdpFamilyMissing`).
- A receive error budget (`rmule_net::family::ReceiveErrorBudget`) ends the front when it
  is exhausted, rather than hot-spinning; Kad, reask and NAT-T go dark together.
- There is no re-bind. The front and the first port-mapping set are assembled once around
  the bound socket at actor start, and the conditions that cause a failure (a second
  instance, a stale hold after a crash) clear with a process restart.

### Downloader: queue standing on the source's record, and a reask cycle

A worker's `OP_STARTUPLOADREQ` earns the source's **Source Book** record its queue standing,
without a rank until a `0x60` ranks it (ADR-0090, "How a worker ends, and what its record
keeps"). A worker without a grant ends at its rank (the **Queued Hang-Up**, ADR-0116), and
any worker that ends holding a standing moves its record to the RemoteQueued stage, the
standing riding the record: the rank, the UDP contact its hello stated, the reask clock
and the one-ping latch, held without a socket. The download's brain runs the cycle on its tick (ADR-0026). Per pooled source, on
aMule's `FILEREASKTIME` of 1 300 000 ms
([Constants.h#L35](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/include/protocol/ed2k/Constants.h#L35)),
900 s while rmule is firewalled (the **Low-ID Reask**, ADR-0116):

- **UDP first.** At `FILEREASKTIME` − 20 s, send `0x90 <hash16>` plus version-gated extras
  (UDP version above 3: our part status; above 2: the complete-source count), as aMule
  does
  ([DownloadClient.cpp#L1249](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/DownloadClient.cpp#L1249)).
  Gates: the socket is up, the source's UDP port is known, rmule is reachable (Self
  Reach's `!firewalled()`: a server High ID or Kad open, aMule's `!IsFirewalled()`), the
  source is not connected, and the TCP ask is preferred when a source-exchange ask is due
  (ADR-0055), because a TCP session carries value a datagram cannot. A called-back Low-ID
  source is pinged like any other, at the address its connection came from and the port
  its hello advertised: aMule has no `HasLowID` gate here and sends to `GetConnectIP()`
  (stock 2.3.3 `DownloadClient.cpp:1269-1296`). Its answer refreshes the clock, so its
  callback road is taken again only on silence.
- **Through the buddy.** When the direct ping's gate fails because we are firewalled, a
  Low-ID source whose record names its buddy's ID and endpoint (a Kad source row,
  ADR-0061) is reasked through that buddy instead:
  `0x94 <buddy id 16><hash16>` with the same version-gated extras, plain, to the buddy's
  UDP endpoint (stock 2.3.3 `DownloadClient.cpp:1297-1318`). The buddy relays it as
  `0x9A` and the source answers from its own client-UDP endpoint, so the reply is matched
  there as a `0x90`'s is, and the same one-in-flight latch holds it. Neither our
  reachability nor a due source ask holds this road: aMule gates only the direct branch on
  them (`:1269-1273`). A source whose contact is unknown is not reasked through its buddy:
  its UDP version, which frames the extras, and the endpoint its answer would be matched
  at both ride the contact (aMule sends the datagram and then cannot match the answer,
  `DownloadQueue.cpp:835-849`).
- **Connected, or nothing.** Neither the ping nor the TCP full ask leaves while rmule is
  connected to no network — no server login and no Kad node that has heard a contact,
  aMule's `IsConnected()` (stock 2.3.3 `PartFile.cpp:1460`, `:1475`). A standing that
  falls due offline waits, and is asked the moment a Callback Capability sample connects
  us again.
- **One ping in flight per peer client-UDP endpoint**, remembered with the download that
  sent it; the reply goes to that download alone, and a reply matching no ping in flight
  is dropped (ADR-0107).
- **Replies:** `0x91` records the rank, clears queue-full and refreshes the ask clock
  ([DownloadClient.cpp#L1220](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/DownloadClient.cpp#L1220));
  its UDPv4 part status is read as a TCP one is (stock 2.3.3 `ClientUDPSocket.cpp:259`):
  holding no part we lack makes the source no-needed-parts, and a status counting other
  than the file's parts throws in aMule before the rank is read, so rmule ignores that
  whole reply (`DownloadClient.cpp:416-424`, `:487-491`);
  `0x93` sets queue-full and rank 0 and refreshes the clock; `0x92` spends the source for
  this download under every name its record holds, as aMule dead-lists and removes it
  ([DownloadClient.cpp#L1228](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/DownloadClient.cpp#L1228);
  ADR-0090).
- **Queue full:** aMule neither lengthens a queue-full source's reask nor ranks it lower
  for a slot; it is one of the sources let go to make room.
- **Purges:** once the file holds 80 % of aMule's default `MaxSourcesPerFile` (300), one
  source goes at a time, on one clock per file (`lastpurgetime`, the run's start counting
  as the last): a Low ID no road reaches 30 s after the last purge, a no-needed-parts
  source 40 s after, a queue-full source 60 s after (stock 2.3.3 `PartFile.cpp:1406-1456`,
  `:3644`). The Source Book takes the oldest record whose kind's spacing has passed, only
  ever a record no worker holds; a Low ID counts as unreachable only while we are
  connected, since aMule reaches `DS_LOWTOLOWIP` only by asking. aMule first offers a
  no-needed-parts source to another download (`SwapToAnotherFile`); rmule's downloads
  share no source, so none takes it over. The brain reports each as `SourcePurged`, with
  its reason.
- **Silence:** the TCP full ask fires at `FILEREASKTIME` (900 s while we are firewalled,
  ADR-0116, whose road is the only one that opens a Low-ID downloader's slot)
  ([PartFile.cpp#L1476](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/PartFile.cpp#L1476))
  and resets the one-in-flight latch, so a lost datagram costs 20 seconds, never the
  standing. It reaches a High ID at its endpoint and a called-back Low ID by its callback
  road, the one a fresh Low-ID candidate takes (ADR-0090).
- **A grant by dial-back is taken.** An uploader promotes a waiter it is not connected to by
  dialing its listen port and sending `OP_ACCEPTUPLOADREQ` once the hellos are done
  (`UploadQueue.cpp:206-210`, `BaseClient.cpp:1707-1716`), and a waiter it is connected to on
  that link (`UploadQueue.cpp:211-217`). Either way the `0x55` lands on a link no download of
  ours rides: the record waits in RemoteQueued with no worker. aMule's downloader holds the
  client `DS_ONQUEUE` and takes the grant at once (`ClientTCPSocket.cpp:635-645`). rmule's
  link hands the unasked grant to the download standing at its peer (ADR-0107, the
  Awaited Grants), whose brain opens the record's worker on that link at once, with no
  admission by the Connection Budget (ADR-0116): a granted slot is a transfer, not a dial. The worker asks as
  any rider does — the file request, then `OP_STARTUPLOADREQ` on the probe's answer — and
  the uploader, uploading to the client already, grants it at once (`UploadQueue.cpp:486-493`),
  well inside the 40 s it keeps an idle link (`CONNECTION_TIMEOUT`, `Constants.h:34`). A
  dropped grant costs the standing: the uploader times the link out, takes the client out of
  its upload list without queueing it again (`BaseClient.cpp:1278-1281`,
  `UploadQueue.cpp:522-546`), and the next ask starts the wait from zero (`:501`). An
  unasked grant no download stands for is given back with `0x56` (ADR-0056).
- **A held window looks again a second later.** While the ping is due but cannot leave —
  we are unreachable, a source ask is due, or another download's ping holds the endpoint
  (ADR-0107) — the brain names a wake one second on, as aMule's once-a-second `Process`
  re-reads its gate.
- **Back on queue:** an `OP_OUTOFPARTREQS` (`0x57`) on a granted slot keeps the worker on
  its link, its flow queued again (ADR-0025): the part it held is released for retry, its
  record earns a standing without a rank, and the `OP_QUEUERANKING` that follows ranks it.
  The source holds parts we lack, so a standing it leaves with reasks on the ordinary
  cadence above, never the no-needed-parts one; a `0x57` while only queued changes
  nothing.
- **A granted slot given back:** a worker granted a slot it has no part to work gives it
  back with `0x56` (ADR-0056), retired `NoFreePart`, and its record waits in RemoteQueued
  with a standing without a rank, its clock dated at the give-back, on the ordinary
  cadence: it holds a part we lack, only none is free now. aMule marks such a source
  `DS_NONEEDEDPARTS` (`DownloadClient.cpp:667`) and asks it at twice the period; rmule
  keeps the ordinary period, since a part frees as soon as a racer verifies or fails.
- **No needed parts:** such a source reasks at twice the period, then forces a TCP
  recheck
  ([PartFile.cpp#L1439](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/PartFile.cpp#L1439)).
  A worker whose Advertised Parts hold no part we lack enters this cadence too,
  its record keeping or earning a rank-0 standing with the mark (ADR-0112).

### Uploader: standing that survives disconnect

- A waiting entry survives disconnect and dies only when its reask heartbeat stops (purged
  after an hour,
  [UploadQueue.cpp#L86](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/UploadQueue.cpp#L86),
  `MAX_PURGEQUEUETIME`) or its file stops being shared. An inbound `0x90`, matched by IP
  and UDP port, refreshes that clock
  ([ClientUDPSocket.cpp#L171](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientUDPSocket.cpp#L171)).
- **Replies, as aMule sends them:** a known waiter with a matching hash gets `0x91` with
  its rank (plus our part status for a UDPv4 peer); an unshared hash gets `0x92`; an
  unknown pinger when `waiting + 50 > queue size` gets `0x93`, always plain because there
  is no identity to key crypt on. A hash mismatch, an unknown pinger with room, and one IP
  using several UDP ports are dropped silently: the silence forces the peer to a TCP full
  ask, which repairs the mismatch. `0x91` and `0x92` are encrypted when the sender's hash
  is known (ADR-0046). The full rule set is in ADR-0055's surface table.
- **A waiter on a new link keeps its place.** The place belongs to the client, not to the
  link it asked on: aMule attaches a new socket to the client it already knows
  (`ClientList.cpp:371-412`) and a client already queued keeps its place
  (`UploadQueue.cpp:395-431`). So the hello of a new link that names a waiter's User Hash
  moves that waiter's entry — its place, its wait, its file — onto the new link when the
  link it waited on has ended, or comes from the same address and listen port, which is
  closed for the new one (`:400-403`); a live link from anywhere else keeps its client.
  `ServeEvent::WaiterRelinked` carries every row and mark keyed by the old link to the
  new one, and the new link's slot ask is answered at the place it kept. A pending
  dial-back grant moves the same way, and `OP_ACCEPTUPLOADREQ` goes on the new link at
  once: aMule grants a client it promoted unconnected (`US_CONNECTING`) on whichever link
  its hellos finish first, inbound or dialed (`ClientTCPSocket.cpp:328`, `:417`,
  `BaseClient.cpp:1707-1716`).
- **Promotion reaches the waiter.** Every freed slot promotes the best waiter rmule can
  reach, and the grant goes out as aMule's `AddUpNextClient` sends it
  (`UploadQueue.cpp:202-222`):

  | Rule | aMule | rmule |
  |---|---|---|
  | who is promoted | the best-scored waiter that is connected or holds a High ID; a Low-ID waiter not connected and scored above it is marked for its next connection (`m_bAddNextConnect`, `UploadQueue.cpp:126-149`); with none, the slot stays free | the best-scored waiter that is linked, or whose hello names an endpoint a dial reaches: a High ID at the address its link came from, or an IPv6 (`PeerIdentity::source_coordinate`); a waiter that hung up under a Low ID and ranks above it is marked for its next connection and passed over; with none, the slot stays free until a waiter asks from a link, as `Process` fills a free slot within its next second (`UploadQueue.cpp:255-258`) |
  | a promoted waiter with a link | `OP_ACCEPTUPLOADREQ` on its socket (`:211-217`) | the grant goes on its link: the one it waits on, or any live link whose hello names its User Hash, its place moving there |
  | one with none | the slot is taken at once in `US_CONNECTING` and the client dialed (`:206-210`, `:222`) | the slot is held as a **pending dial-back grant** and the waiter dialed at that endpoint, under ADR-0049's outbound rule toward the crypt stance and the User Hash its hello named |
  | the dial and the budget | `TryToConnect(true)` skips `TooManySockets` (`BaseClient.cpp:1398`) | no Dial Window token and no place under the Ceiling: the Connection Budget paces the roads downloads open (ADR-0116), and a grant is never admitted |
  | the dial's gates | the IP filter and the ban list refuse it before any socket (`BaseClient.cpp:1427`, `:1437`) | the same two gates, before any socket |
  | one peer, one link | one client, one socket | the dial is filed as a Dial in Flight under the waiter's endpoint and User Hash; a link or dial already filed under one of them is not dialed around (ADR-0107 invariant 7), and the grant goes on it once its hello reaches the serve side |
  | after the hellos | `ConnectionEstablished` in `US_CONNECTING` sends `OP_ACCEPTUPLOADREQ` (`BaseClient.cpp:1707-1716`) | the pending grant moves onto the dialed link and `OP_ACCEPTUPLOADREQ` goes on it; the link is a Peer Link like any served one, filed under its hello's names and where it was dialed, so a download of ours rides it, and the serve side holds it from the dial (ADR-0107 invariant 9) |
  | the dial fails | `US_CONNECTING` on disconnect makes the client a dead source and deletes it (`BaseClient.cpp:1333-1337`), out of the upload and the waiting lists (`:413-417`); the next `Process` fills the slot (`UploadQueue.cpp:255-258`) | the pending grant ends and the waiter's place with it, so its next ask queues it at the tail with its wait from zero (`UploadQueue.cpp:501`); the slot promotes the next waiter at once |
  | the dialed hello names another client | the client takes the new hash (`BaseClient.cpp:475`) and is granted | departs: the grant is the waiter's, so it fails as a failed dial, and the link is left to whatever else holds it |
  | a Low-ID waiter marked for its next connection | its slot ask on that connection takes a slot while the upload list is under the slot count, or one over it when the last slot went to a High ID; the turn passes to a Low ID again only after a High ID's (`UploadQueue.cpp:410-425`, `:147`) | the same: its slot ask on the link it came back on is granted under the budget, or one over it when the last promotion went to a waiter rmule could reach |

  A pending dial-back grant whose client never links is reclaimed by the purge after
  `MAX_PURGEQUEUETIME`: the net under a link found filed whose hello never reaches the
  serve side. The operator reads each step in the Run Log: `serve.upload_dial_back` when
  rmule dials, `serve.upload_dial_back_failed` with its cause when the waiter's grant ends
  unsent, and `serve.upload_slot_granted` with its road — on the link the peer holds, on
  the link rmule dialed, on the link it came back on while its grant was held, or at its
  next connection after a Low-ID mark.

All four opcodes map onto existing core meanings (rank, queue full, dead source); the
UDP forms are transport variants. The reask codecs and every reply and parse rule live in
`rmule_peer`'s sans-I/O peer-UDP module: the Reask Responder answers a ping once core has
resolved the pinger against its queue, and the Reask Requester frames the ping and reads
the reply. The socket and its demux stay in core. On the downloader side the brain holds
the standing in its Source Book, builds each ping and parses each reply through the
Requester, because the source's UDP version is on the record; the runner installs the
download's reply sink on the socket, sends what the brain hands it, and sleeps until the
brain's next wake. The purge clock and dial-back promotion belong to serve state.

## Consequences

- The deterministic tier covers the demux table (accept `0xC5`, `0xE4`, `0xE5`; drop
  `0xE3`, `0xD4` and junk; the 2-byte minimum), the reask codecs across UDP versions, the
  uploader reply matrix, the purge clock and heartbeat, dial-back promotion, and the
  downloader cycle (UDP-first timing, latch, TCP fallback, the no-needed-parts doubling,
  the source-exchange preference) as the brain's decisions at the instants a test hands
  it.
- Captures live in `crates/rmule-peer/tests/fixtures/peer_udp_reask/captured/`: aMule's
  replies to rmule's pings, plain and encrypted, and aMule's own ping to rmule as an
  uploader. `0x92` is provoked by unsharing mid-queue and `0x93` by a queue-size
  preference below 51. The reask through the buddy is captured too: a firewalled aMule
  queued rmule while rmule stood on a server High ID, the server went away, and rmule's
  `0x94` reached the buddy, crossed the held link as `0x9A`, and drew the aMule's `0x91`.
- A buddy recruited over Kad now observes the same mapping a Tunnel rides, so an endpoint
  hint naming rmule is right (ADR-0091).
- One socket failing takes the reask surface, NAT-T and Kad down together, which is why
  each failure has a named fact.

## Considered options

- **Consume only, waiting connected.** Rejected: it burns a counterparty socket for the
  whole wait and forfeits earned queue standing.
- **A separate UDP port for reasks, or for Kad.** Rejected: counterparties send to the one
  advertised endpoint, and a second socket means a second NAT mapping.
- **Always replying, skipping aMule's silent drops.** Rejected: the silences force the TCP
  fallback that repairs state mismatches.
- **Periodic re-bind after a bind failure.** Rejected: it would re-run the whole front
  assembly against a running actor, for conditions a restart already clears.
- **Reading `OP_OUTOFPARTREQS` as "no needed parts", or as a refused slot that ends the
  worker.** Rejected: aMule's uploader sends it when our session's 10 MB or hour is up
  while someone waits (`UploadQueue.cpp:549`), then queues us again and ranks us on the
  same socket; nothing in it says the source holds nothing we lack, and ending the link
  throws away the rank that follows.
