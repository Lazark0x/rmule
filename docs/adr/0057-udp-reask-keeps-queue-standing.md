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

After a rank arrives, the worker disconnects and the source's **Source Book** record moves
to its RemoteQueued stage, its queue standing riding the record (ADR-0090): the rank, the
UDP contact its hello stated, the reask clock and the one-ping latch, held without a
socket. The download's brain runs the cycle on its tick (ADR-0026). Per pooled source, on
aMule's `FILEREASKTIME` of 1 300 000 ms
([Constants.h#L35](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/include/protocol/ed2k/Constants.h#L35)):

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
  `0x93` sets queue-full and rank 0 and refreshes the clock; `0x92` drops the source as dead
  ([DownloadClient.cpp#L1228](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/DownloadClient.cpp#L1228)).
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
- **Silence:** the TCP full ask fires at `FILEREASKTIME`
  ([PartFile.cpp#L1476](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/PartFile.cpp#L1476))
  and resets the one-in-flight latch, so a lost datagram costs 20 seconds, never the
  standing. It reaches a High ID at its endpoint and a called-back Low ID by its callback
  road, the one a fresh Low-ID candidate takes (ADR-0090).
- **A held window looks again a second later.** While the ping is due but cannot leave —
  we are unreachable, a source ask is due, or another download's ping holds the endpoint
  (ADR-0107) — the brain names a wake one second on, as aMule's once-a-second `Process`
  re-reads its gate.
- **No needed parts:** such a source reasks at twice the period, then forces a TCP
  recheck
  ([PartFile.cpp#L1439](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/PartFile.cpp#L1439)).
  A slotless standby worker (ADR-0056) that loses its connection degrades into this
  cadence. A worker whose Advertised Parts hold no part we lack enters this cadence too,
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
  (`ClientList.cpp:370-412`) and a client already queued keeps its place
  (`UploadQueue.cpp:395-431`). So the hello of a new link that names a waiter's User Hash
  moves that waiter's entry — its place, its wait, its file — onto the new link when the
  link it waited on has ended, or comes from the same address and listen port, which is
  closed for the new one (`:395-401`); a live link from anywhere else keeps its client.
  `ServeEvent::WaiterRelinked` carries every row and mark keyed by the old link to the
  new one, and the new link's slot ask is answered at the place it kept. A pending
  dial-back grant does not move yet: it is reclaimed by the purge.
- **Promotion dials back.** Promoting a disconnected waiter dials its TCP endpoint and
  sends `OP_ACCEPTUPLOADREQ` on connect
  ([UploadQueue.cpp#L169](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/UploadQueue.cpp#L169)),
  a serve-side outbound dial (`ServeDecision::DialBackGrant`) over the dialed-serve seam
  of ADR-0031. A Low-ID waiter cannot be dialed directly.

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
  preference below 51.
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
