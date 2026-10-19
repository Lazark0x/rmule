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
  content store's `read_range`, and says whether the block may cross compressed. The
  session compresses one only when core allows it, the peer advertised compression
  and the result is smaller (below). The Server
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

**A block request is judged whole before anything is read.**

- A peer holding a slot asks up to three ranges in one `OP_REQUESTPARTS` or
  `OP_REQUESTPARTS_I64`. Every live range is checked as asked, before the ranges
  already served are taken off it: one range that ends past the file's end, or is
  longer than three blocks (`3 × EMBLOCKSIZE`, 552,960 bytes), ends the peer's slot.
  Nothing of the request is read or sent, the slot goes to the next waiter, and the
  peer leaves the queue: a later ask queues it afresh. Its link stays and its address
  is not banned. aMule throws on either range while it cuts the block, and its handler
  only takes the client out of the upload queue (`UploadClient.cpp:211-224`,
  `:270-281`); it bans nobody for it. A Partial Share's request whose unserved rest
  leaves its Verified Range ends the slot the same way (ADR-0113).
- A range whose end is not past its start is skipped, as aMule skips one in
  `OP_REQUESTPARTS` (`UploadClient.cpp:871-882`); the `(0, 0)` padding is one. A pair
  that runs backwards fails the request's decode, so core never sees it.
- **Where rmule departs.** aMule judges each range as its turn comes, so ranges ahead
  of a bad one may already be sent; rmule judges the request whole and sends none of
  it. aMule 3.1.0 and eMule AI drop such a range at the ask and keep the slot
  (aMule 3.1.0 `UploadClient.cpp:317-328`, eMule AI
  `srchybrid/UploadClient.cpp:711-721`); rmule keeps 2.3.3's rule, because no stock
  downloader asks a range longer than one block, so a peer that asks one is not one a
  slot should wait on.
- The refusal is its own serve event, `BlockAskRefused`, naming the fault — past the
  end, longer than three blocks, outside the Verified Range — ahead of the slot's
  release, so the run log and the operator read why the peer lost its slot.
- **No read is longer than three blocks.** The content store refuses a read longer
  than `3 × EMBLOCKSIZE` before it allocates a byte, whoever asks; the check above
  means the serve state never asks one. A shared file's AICH tree (ADR-0038) is built
  from the file one block at a time, so a build holds one block however large the
  file is.

**A served block crosses in packets of about 10 KiB, as aMule cuts it.**

- A stock aMule downloader restarts its 100 s download timeout only when a whole
  part packet lands (`DownloadClient.cpp:848`, `DOWNLOADTIMEOUT` in
  `Constants.h:64`) and sends `OP_CANCELTRANSFER` when none has
  (`DownloadClient.cpp:1189-1193`). A block of 184,320 bytes framed as one packet
  needs more than 1.8 KiB/s to cross inside that window, so a slower link can
  never finish one. The session therefore writes each `SendBlock` as aMule's
  uploader does.
- **Packet size.** A payload of `n` bytes larger than 10,240 is cut into packets of
  `n / (n / 10240)` bytes, integer division, and the last packet takes whatever is
  left once less than two packets' worth remains; a payload of at most 10,240 bytes
  goes whole (`UploadClient.cpp:290-299`, `:349-358`). A full 184,320-byte block is
  eighteen packets of 10,240 bytes, and a payload of more than 10,240 bytes never
  yields a packet under 10,240 or of 20,480 and over.
- **Plain.** Each packet is an `OP_SENDINGPART` naming its own range; the ranges
  tile the block in order. Each packet picks its offset width on its own offsets
  (`UploadClient.cpp:307`).
- **Which blocks may be compressed.** Every block but an archive's: core marks a
  block plain when the name its file is offered under falls in the Archive eD2k File
  Class, as aMule never compresses an archive (`UploadClient.cpp:252`; aMule 3.1.0
  keeps the rule, `UploadDiskIOThread.cpp:252`). rmule skips nothing more. A video or
  a picture rarely shrinks, but those classes hold uncompressed formats too (`wav`,
  `bmp`, `tiff`), and the first pass below makes a block that does not shrink cheap.
  eMule AI skips a fixed list instead (`zip`, `rar`, `7z`, `cbz`, `cbr`, `ace`, `ogm`;
  `srchybrid/UploadDiskIOThread.cpp:452-460`).
- **The level.** Any zlib stream inflates the same, so the level is not on the wire;
  it trades CPU for bytes. The session deflates a block at level 1 first: a block that
  does not shrink goes plain, and one that does is deflated again at level 6 and the
  smaller stream is sent. aMule 2.3.3 deflates at level 9 (`UploadClient.cpp:337`);
  aMule 3.1.0 and eMule 0.70b moved to level 1 for speed (aMule 3.1.0
  `UploadDiskIOThread.cpp:523-525`, eMule AI
  `srchybrid/UploadDiskIOThread.cpp:518-523`). rmule departs from both on its own
  deflate (`flate2` 1.1.9 over `miniz_oxide`), measured on 184,320-byte blocks on an
  Apple M1 Pro: level 9 takes 1.4 to 1.6 times level 6's time for a stream at most
  0.4 % smaller; level 1 takes a fifth to a quarter of it, but its stream is 18 % to
  41 % longer on executables and source text; on random bytes every level from 2 up
  spends about 3.1 ms a block shrinking nothing, and level 1 0.6 ms. Most shared
  content is already compressed, so the first pass cuts the CPU an upload slot spends
  on such a block to a fifth of one pass at level 6, and a block that does shrink costs
  about a quarter more than level 6 alone, for level 6's bytes.
- **Compressed.** The block is deflated whole and sent compressed only when that is
  smaller (above). The one zlib stream is cut by the same rule into a run of
  `OP_COMPRESSEDPART`, every one carrying the block's start and the stream's total
  length, its offset width picked on the block's offsets
  (`UploadClient.cpp:361-370`).
- **What meters it.** rmule paces no upload bytes: TCP back-pressure on the
  connection writer is the only brake. The slot budget counts slots, and the credit
  and upload counters count the block's uncompressed bytes at `SendBlock`, in core,
  before the session cuts it (ADR-0077). The cut happens after every one of those
  decisions, so it changes neither slot fairness nor the budget. One block's packets
  are queued back to back; nothing else of that connection lands between them.
- **Receiving.** rmule's requester already reads a block in several packets of
  either kind: each `OP_SENDINGPART` is its own range, merged into the part
  (ADR-0029), and `OP_COMPRESSEDPART` chunks for one start are buffered until the
  declared total arrives, then inflated as one block.
- Each packet is framed straight from its slice of the one block buffer (or the
  one compressed buffer); no packet copies the block.

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
