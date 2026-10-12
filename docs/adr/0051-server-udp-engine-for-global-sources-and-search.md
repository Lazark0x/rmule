# One server-UDP engine serves global sources and global search

## Context

Besides the connected server's TCP lookup and peer source exchange, eMule asks every
server in its list over UDP, without logging in: `OP_GLOBGETSOURCES` (`0x9A`) answered
by `OP_GLOBFOUNDSOURCES` (`0x9B`) for sources, and `OP_GLOBSEARCHREQ` (`0x98`),
`OP_GLOBSEARCHREQ2` (`0x92`) or `OP_GLOBSEARCHREQ3` (`0x90`) answered by
`OP_GLOBSEARCHRES` (`0x99`) for search. This is the breadth path: more sources and
results, from more servers, without N logins. aMule runs it all through one
`ServerUDPSocket`.

Wire facts that shape it:

- A server's client-facing UDP port is its **TCP port + 4** (aMule `ServerUDPSocket.cpp`
  sends to `GetPort() + 4` and reads an answer's source as `port - 4`); the Lugdunum
  server binds its client-UDP listener there.
- A server datagram is `[protocol][opcode][payload]` with no length prefix (aMule
  `CMuleUDPSocket`'s 2-byte header), unlike the TCP frame. One datagram may hold several
  packets, each delimited by its own body.
- A Low-ID source can be called back only through the server that assigned its ID. For
  a global source that is some other server, reached by `OP_GLOBCALLBACKREQUEST`
  (`0x9C`), whose body `[ip 4][port 2 LE][client_id 4 LE]` self-reports the requester's
  contact (aMule `UDP.h`; `docs/reference/notes/server-udp.md`), because that server has
  no TCP session to learn it from.
- aMule and eMule send the next global source datagram only while connected to a server
  (aMule `DownloadQueue.cpp:870`, eMule `DownloadQueue.cpp:759-761`): reading the
  answers depends on session facts (our own client ID, whether we are firewalled), and
  the callback request carries our public contact, learned from the session.
- ed2k-server bans a client for 24 hours after a burst of `0x98` faster than about 200 a
  minute.

## Decision

**One engine owns the server-UDP socket.** `ServerUdpEngine` in `rmule-core` demuxes by
opcode into per-concern typed outputs: `0x9B` to the global Discovery Channel, `0x99` to
the global search, `0x97` to the status chain (ADR-0052) and `0xA3` to the description
pair (ADR-0068), the last two running in-engine. The socket is a core-owned port,
`ServerUdpTransport`, implemented over a `tokio` UDP socket; a fake transport drives the
deterministic tier. The codecs are sans-I/O in `rmule-ed2k` (`server_udp`), framed with
`Packet::encode_udp` and a structure-driven `decode_udp` that returns the consumed length
so a multi-packet datagram is walked body by body. The `+4` offset lives in one place on
each side: the Server-UDP Seal on send, which every sender goes through and which also
decides whether a datagram is sealed (ADR-0046), and the engine on receive, which hands each
consumer its datagrams tagged with the server's standard endpoint. The **Awaited Inbound**
registry keys a Pending Callback on that endpoint.

**The swept list is a projection of the Managed Server List** (ADR-0080), never a second
list: every listed server, in list order, minus the dead (ADR-0052), minus those the IP
filter blocks as servers (a DNS-named row passes, as in aMule's add-time exemption), minus
the connected server, which both sweeps leave to the TCP session. It is re-projected on
every change to the list or the connected server, under the level's one lock. A sweep
snapshots it when it starts; a server added mid-sweep joins the next one.

**Global source discovery** is one Core-owned batched channel, not a per-download lookup:

- `GlobalDiscoveryChannel` holds the file hashes of all active downloads and, every
  `CoreConfig::global_source_interval`, sends each swept server one `OP_GLOBGETSOURCES`
  carrying up to 31 hashes (eMule's `MAX_FILES_PER_UDP_PACKET`), then routes each
  answer to its download.
- It asks nobody while no server session is up. The sweep still runs and answers in
  flight are still routed; the first sweep after a login asks.
- Sources enter through `DownloadState::on_sightings` (`Channel::Global`), not the peer-exchange path.
  High-ID sources go straight into the candidate pool (ADR-0030). While rmule can be
  called back, Low-ID sources go into the Source Book's global Low-ID lane as Low-ID Candidate records
  tagged with their source server (`source_server: Some(..)`), apart from the connected
  server's pool, so a callback is never asked of the wrong server; otherwise they are
  dropped.
- `fill()` emits `Decision::RequestGlobalCallback { low_id, source_server }`; the runner
  registers a Pending Callback in the **Awaited Inbound** registry, sends `OP_GLOBCALLBACKREQUEST` with rmule's own
  public IP and advertised TCP port, and arms a per-server deadline. The peer that dials
  in is driven as an Adopted Inbound Worker (ADR-0039). Such a record is bare (no User
  Hash, buddy or NAT-T bit), so it arms no other route and waits out its slot deadline.
- A download is **armed** whenever the swept list is non-empty. An armed download with
  no usable source waits (`DownloadEvent::WaitingForSources`) instead of failing with
  `NoUsableSources`, indefinitely and cancellably, as eMule does. The event carries a
  `SourceWait` read from the same session fact the gate reads (asking, Kad alone, or no
  session and Kad off) and is sent again whenever it moves. An unarmed download fails
  fast.

**Global search** is the engine's second consumer:

- **Variant:** `0x90` with the `CT_SERVER_UDPSEARCH_FLAGS` tag set when the server
  advertises LargeFiles and ExtGetFiles, `0x92` when ExtGetFiles only, `0x98` otherwise.
  The per-server UDP flags come from the status chain's capability store (ADR-0052).
- **One query encoder:** the `rmule_ed2k::SearchRequest` tree is the body for all three,
  wrapped per variant.
- **Each datagram is sized for its addressee.** A bound past `u32::MAX` rides a `0x08`
  term toward a server advertising large-file UDP support and clamps to `0xFFFFFFFF`
  toward any other, which is asked the wider question rather than skipped; Search
  Attribution (ADR-0034) screens the clamped answers by the size every row carries.
- **Pacing:** every sweep books its datagrams through one shared `UdpSearchPacer`,
  300 ms per server, so searches started together cannot trip a server's flood
  detector. Fire-and-forget, no retries; a silent server is harmless.
- **Consume:** `0x99` is walked as aMule does (`position + 2 < size`, stop on a
  non-`0x99` continuation byte), strings forced to UTF-8, and results merged into the
  active search beside TCP results, so a front end sees one stream.

## Consequences

- Deterministic tier: codec fixtures (byte-exact `0x9C`), engine tests over a fake
  transport with distinct UDP and TCP ports, variant selection, the `0x99` multi-packet
  walk against golden vectors, the pure-UDP rescue loopback (no connected-server source,
  then a UDP-discovered source, then a verified part) and the per-server callback
  loopback `crates/rmule-core/tests/core/global_callback_loopback.rs`.
- Real server-UDP stays in the Compatibility Tier. Lugdunum answers status and
  description but not UDP global search, so the `0x99` capture runs against other server
  bodies.
- A join with eD2k switched off skips only the fetch and hand-over; a core whose store
  lists servers still sweeps them.
- Re-advertisement of an already-adopted Low-ID global is bounded by the concurrency cap
  and the per-callback timeout rather than skipped by endpoint.

## Considered options

- **Per-download UDP lookup.** Rejected: it re-queries the same servers N times and does
  not batch one datagram per server across files, as eMule does.
- **Feeding global sources through the peer-exchange path.** Rejected: that path routes
  Low-ID sources to a connected-server callback, which mis-routes a global source's
  callback.
- **A parallel single-purpose channel per concern** (sources, search, status).
  Rejected: each would own a copy of the same socket concern; the engine is the deep
  module, as aMule's one socket is.
- **A second query encoder for the UDP body.** Rejected: the TCP search tree is
  byte-identical inside the UDP variants.
- **Blasting all servers per tick or retrying silent ones.** Rejected: it trips flood
  detectors and is not what a citizen client does.
- **Sweeping while no session is up.** Rejected: aMule does not, and a Low-ID global
  callback needs the contact the session supplies.
- **Status pinging to gate which servers are asked.** Rejected here: a silent server is
  harmless; server health is the status chain's concern (ADR-0052).
- **A sweep-owned server list set by a command.** Rejected: servers added by hand or by
  import never reached it, and a front end that skipped the join left both sweeps empty.
