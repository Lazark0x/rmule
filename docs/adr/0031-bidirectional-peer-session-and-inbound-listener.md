# Bidirectional peer session with core-owned upload scheduling and an inbound listener

## Context

A legitimate eMule node is a source as well as a downloader: it answers inbound
peer requests, admits requesters to an upload queue, serves part bytes, and
announces its files to the server. The peer wire codec is bidirectional — every
packet encodes and decodes — so the work is at the session and orchestration
layers.

A real eMule connection is bidirectional on one socket. A peer we dialed to download
from may queue us and ask for a file we hold on the same connection, and the credit
system rewards exactly that exchange. Queue rank, the slot budget and promotion when a
slot frees are cross-connection facts that no single session can see, just as part
scheduling is (ADR-0026).

## Decision

**One role-neutral `PeerSession`.**

- `PeerSession` in `rmule-peer` has `new_outbound` (sends the hello) and `new_inbound`
  (waits for the peer's hello and answers `OP_HELLOANSWER`) over one shared
  handshake and identity core.
- After the hello, a Requester Capability (our pull, the slot we chase) and a Server
  Capability (the remote's pull from us) run concurrently on the same session. The
  serve verbs live in the same `PeerCommand`, `PeerEvent` and `PeerError` enums and
  are reachable on every session. Both enums group their variants by the side of the
  conversation aMule's handler for them serves: `Connection` (the hello, identity,
  revisions, the close and our `Disconnect`), `Requester`, `Server`, `Side` (Kad
  firewall checks, the buddy relay, the public-IP ask) and, for events only, `Notice`
  (what the session counted or dropped and no capability acts on). Each direction of
  `OP_CANCELTRANSFER` sits with its side (ADR-0056): our cancel is a `Requester`
  command, the peer's is a `Server` event. The events stay one ordered stream, because
  a request is keyed by the identification that precedes it. Packet-to-event
  projection is `PeerEvent::from_peer_packet`.
- The session keeps the wire facts it negotiated: the source-exchange version an
  answer is framed in, and the framing limit that leaves an IPv6-only source out of a
  classic entry list (ADR-0087). Core's `Server` vocabulary names files and sources,
  never a wire form.

**Core owns the upload queue; the session holds none.**

- `UploadSlotQueue` in `rmule-core` admits, ranks, promotes and purges remote
  requesters across all connections. Rank is aMule's credit-weighted score
  (ADR-0041); the serve activity re-ranks idle waiters every
  `CoreConfig::queue_rerank_interval` and sends `OP_QUEUERANKING`.
- Core pushes part bytes down with `ServerCommand::SendBlock`, read from the
  content store's `read_range`. The session compresses a block only when the peer
  advertised compression and the result is smaller, as eMule does. The Server
  Capability reports requests as `Server` events and obeys `Server` commands (answers,
  grant, queue rank, blocks), so the session stays sans-I/O and storage-free.
- The serve activity speaks those groups directly: its input is a connection's
  `Server` events, its `Connection` events, and `Readopted`, the one fact that exists
  only in core (ADR-0039); its output is `Server` commands and the connection's
  `Disconnect`. No core-side mirror of the peer vocabulary sits between them.
- Every route into the queue reaches the one `UploadSlotQueue::admit`, which applies
  every admission limit: the slot budget (`CoreConfig::upload_slot_budget`), the
  wait-list cap (`max_upload_queue_len`), the per-address cap of
  `MAX_WAITING_PER_ADDRESS` (3) waiters per `AccountingKey` — one IPv4 address or
  one IPv6 `/64` (ADR-0088) — and the Low-ID abuse guard. Every refusal is silent,
  as in both references; a refusal is counted and reported as an event, never framed
  as a packet.
- **Low-ID abuse guard.** While we are Low-ID, a slot request is refused when the
  asker holds no slot of ours, is not a friend, is not on our server, and more than
  fifty peers already wait (eMule `srchybrid/UploadQueue.cpp:535-545`, aMule
  `src/UploadQueue.cpp:403-409`, at `irwir/eMule@13983526` and
  `kno/amule@ab483654`). A firewalled node's scarce resource is callback capacity,
  not its wait list. rmule keeps no friend list, so that input is always false. The
  two self-facts — are we Low-ID, which server are we on — come from the login's
  self-facts cell (ADR-0032) and clear when the session ends, because a node between
  sessions is Low-ID and shares a server with nobody.

**The listener is in `rmule-net`; core holds one connection registry.**

- `PeerListener` in `rmule-net` binds the advertised TCP port and yields accepted
  connections built with `new_inbound` and an inverted hello timeout.
- Core keeps accepted and dialed connections in one registry. The download scheduler
  and the upload queue are two consumers of that one set, and a dialed connection
  serves the remote's requests too. One connection is still one conversation with one
  peer (ADR-0026).

**The durable Shared File Registry is the serve source of truth.**

- The registry lives in the typed store (ADR-0083): one record per shared file, keyed
  by its file hash, with its part hashes beside it, written in one transaction.
- Shares arrive from the shared directories and the download directory (ADR-0101)
  and from completed downloads; `ServeCommand::UnshareFile` withdraws one. Beside the
  registry, the serve side answers for every running download larger than one part and
  offers it from its first verified part (ADR-0113); that offer is the download's, never
  a row.
- The serve side answers probes and hash-set requests from it and announces it with
  `OP_OFFERFILES` (`Ed2kCommand::OfferFiles`) to the live server session and each one
  connected after it (ADR-0095).

**The serve activity's lifecycle.**

- `ServeCommand::StartServing` makes the actor bind. `ServingStarted { listen_addr }`
  means the listener is accepting, and nothing more; login facts arrive on
  `CoreEvent::ServerConnection`. A bind failure answers
  `ServingFailed { reason: ServeStartFailure }` with the bind's `io::ErrorKind`, and a
  start while already serving re-answers `ServingStarted` with the held address.
  Every start is answered.
- `ServingStarted` is the activity's first serve event: the task waits on a one-shot
  the actor fires after sending it.
- The task returns what the start lent it: a `ServeOutcome` on its `JoinHandle`
  carrying the adapter and the reask inbox, released — accept pump joined, port
  free, tunnel-admit cell emptied. A second start is therefore a first start.
- `ServingStopped { reason }` is emitted by the actor once the outcome is back, so a
  front end may answer it with `StartServing` and race nothing. `ServeStopReason` is
  `Requested`, `ListenerClosed` or `TaskFailed`; `TaskFailed` cannot recover, because
  the adapter went down with the task. An unrequested end reaches the actor over a
  serve-ended `watch`, which never blocks and never fills.
- A restart rebuilds the bind — bumping the Bind Generation so the port mapper
  re-derives its mappings (ADR-0086) — the handshake context from this start's
  identity at client id 0, and the accept pump. It keeps the user hash, the credit
  ring, the share set, the ban store and the IP filter.
- "Is a listener bound right now" is read live from `SharedServeListener`: a handle is
  present and its task has not finished. A ledger entry alone is not liveness.
  Callback Capability (ADR-0039) reads this cell.
- When the activity ends, `DiagnosticsState::close_all_uploads` closes every open
  upload row with the same stop reason.

## Consequences

- `CoreCommand` and `CoreEvent` wrap `DownloadCommand`/`DownloadEvent` and
  `ServeCommand`/`ServeEvent`, so serve events never carry a `DownloadId`. The actor
  holds a set of activities (ADR-0093), generic in the serve adapter
  (`Activities<L>`).
- The advertised listen port is real once the listener binds it.
- The upload queue is the serve-side sibling of the download scheduler, and core is
  the one place to pace upload bandwidth.

## Considered options

- **Two session types, requester and served.** Rejected: it breaks the moment a peer
  asks for a file on a connection we dialed to download, and splits one handshake into
  two near-duplicates.
- **A per-session upload queue.** Rejected: rank, budget and promotion are
  cross-connection decisions; it would split one budget across N sessions.
- **The accept loop in `rmule-core`.** Rejected: sockets belong to the runtime crate;
  core owning an accept loop collapses the transport/orchestration boundary.
- **Separate pools for dialed and accepted connections.** Rejected: serve requests
  arrive on any connection, so two pools re-fragment what one registry expresses.
