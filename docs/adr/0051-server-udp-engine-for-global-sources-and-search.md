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
- A Low-ID source can be called back only through the server that assigned its ID, and
  only the connected server takes that ask. A remote server's Low-ID source with no
  buddy has no road: stock removes it (`BaseClient.cpp:1533`, `:1546-1553`).
  `OP_GLOBCALLBACKREQ` (`0x9C`) is declared in every header and sent by no tree: aMule
  2.3.3, 3.1.0, amule-kno, emule-qt and eMuleAI, with no handler in ed2k-server.
- aMule and eMule send the next global source datagram only while connected to a server
  (aMule `DownloadQueue.cpp:870`, eMule `DownloadQueue.cpp:759-761`): reading the
  answers depends on session facts (our own client ID, whether we are firewalled).
- aMule walks one round at a time (`DownloadQueue.cpp:868-958`): one datagram per ten
  passes of `Process` (1 s at the GUI timer, `amule.h:107`; eMule `UDPSEARCHSPEED` 1 s),
  at most 35 files to one server (`MAX_REQUESTS_PER_SERVER`, `:73`, `:1285-1292`), the
  file walk carrying over from server to server, and 1300 s between the end of a round
  and the next (`UDPSERVERREASKTIME`, `Constants.h:37`, `:527`, `:974`). A file at 100
  sources or more is skipped (`:914`, `Preferences.h:274`).
- ed2k-server sanctions one address (a /64 for IPv6) for 24 hours, by rate over at least 10 s
  across UDP searches and source requests: over 600 datagrams a minute is a ban, over 200 at
  uniform timing a throttle. By file over an hour, TCP and UDP together: 2 000 files with 1 000
  different, each asked at most three times, read as a scanner, and 3 000 asks at five a minute
  per file as a hammer (`bot_detector.rs`, v0.9.85). One datagram a second clears the
  first two, and one round in 1300 s clears the last two.

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

- The **Server Pace** owns the rounds: one sans-I/O owner, driven with explicit time. It
  starts a round once `CoreConfig::global_source_interval` (1300 s) has passed since the
  last ended, snapshots the swept list, and puts one datagram on the wire per
  `CoreConfig::global_source_tick` (1 s): up to 31 hashes to a server that advertises
  `ExtGetSources`, one to any other, at most 35 files to one server. The file walk
  carries over from server to server and wraps when every file was asked, so a long
  queue reaches each server in turn, as aMule's does. A server with no status answer yet
  is read from the flags the Managed Server List holds for it, and with none as a legacy
  server: one hash, `0x9A`, no large file. Answers are routed to the download as they arrive.
- It asks nobody while no server session is up. A round in progress waits where it stood
  and goes on after the next login; the pace starts no round meanwhile, and answers in
  flight are still routed.
- **Source gates.** One count, the Source Book's held records, is published by each run
  and read by every road: a file at 100 is left out of a UDP round, at 50 out of a Kad
  ask, at 270 out of a TCP re-ask (ADR-0097). These are aMule's values at its default
  `MaxSourcesPerFile` of 300 (`DownloadQueue.cpp:914`, `PartFile.cpp:1512`, `:1547`).
- **What the round clock survives.** The clock is the Core's: one per process, as aMule's
  `m_lastudpsearchtime`. Pause, Resume, Cancel, a re-add of one hash, a run restart and a
  server change leave it standing, and a process restart zeroes it. A file that starts
  between rounds has its TCP ask and joins the next round; one that starts during a round
  joins at the next wrap of the file walk.
- Sources enter through `DownloadState::on_sightings` (`Channel::Global`), not the peer-exchange path.
  High-ID sources go straight into the candidate pool (ADR-0030). Low-ID sources go into
  the Source Book's global Low-ID lane as Low-ID Candidate records tagged with their
  source server (`source_server: Some(..)`), apart from the connected server's pool, so a
  callback is never asked of the wrong server. Such a record stays until a road opens: our
  session reaches its server, or it names a buddy or a NAT-T bit. A bare one with neither
  has no road and no callback, and leaves as aMule's does.
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

- Deterministic tier: the Server Pace driven with explicit time, engine tests over a fake
  transport with distinct UDP and TCP ports, variant selection, the `0x99` multi-packet
  walk against golden vectors and the pure-UDP rescue loopback (no connected-server
  source, then a UDP-discovered source, then a verified part).
- Real server-UDP stays in the Compatibility Tier. Lugdunum answers status and
  description but not UDP global search, so the `0x99` capture runs against other server
  bodies.
- A join with eD2k switched off skips only the fetch and hand-over; a core whose store
  lists servers still sweeps them.
- A Low-ID road that ends silent spends the source's name for one to two `FILEREASKTIME`
  periods (ADR-0090), so a re-sighting does not call it again before aMule's per-source
  1300 s would.

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
