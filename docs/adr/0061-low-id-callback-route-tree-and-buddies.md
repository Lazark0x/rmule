# Low-ID connectivity: one callback route tree, and rmule both serves as and uses a buddy

## Context

A Low-ID peer cannot be dialed directly. The eMule family reaches it through callbacks
across four surfaces: peer TCP (`OP_CALLBACK` `0x99`, `OP_REASKCALLBACKTCP` `0x9A`,
`OP_BUDDYPING` `0x9F` / `OP_BUDDYPONG` `0xA0`), peer UDP (`OP_REASKCALLBACKUDP` `0x94`,
`OP_DIRECTCALLBACKREQ` `0x95`), Kad (`KADEMLIA_FINDBUDDY_REQ` `0x51`,
`KADEMLIA_FINDBUDDY_RES` `0x5A`, `KADEMLIA_CALLBACK_REQ` `0x52`) and the server
(`OP_CALLBACKREQUEST`, and the crypt extension of `OP_CALLBACKREQUESTED` `0x35`). A
firewalled node recruits a **buddy**, an open Kad node that holds a TCP link to it and
relays callbacks over that link. aMule's one `m_pBuddy` is our buddy when we are
firewalled, or the client we buddy for when we are open.

aMule chooses a route in a fixed order
([BaseClient.cpp#L1453](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/BaseClient.cpp#L1453)).
Wire facts the captures pinned:

- aMule writes the recruiter's User Hash in the `0x51` with `WriteUInt128`: four
  little-endian 32-bit words, each word of the MD4 hash reversed.
- The `0x52` → `0x99` relay rewrites no byte: aMule reads both 128-bit fields with
  `ReadUInt128` and writes them back with `WriteUInt128`. The firewalled reader compares
  `buddyID` as a `CUInt128` against its own Kad ID, but un-swaps `fileHash` before
  `GetFileByID`
  ([ClientTCPSocket.cpp#L1755](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientTCPSocket.cpp#L1755)).
- The `0x99` requester address is host order: aMule's relay writes the Kad listener's
  host-order IP with `WriteUInt32`, so the octets ride reversed, and the reader swaps
  them back (`BaseClient.cpp:125-129`). The `0x9A` relay's address comes off the client
  UDP socket in eD2k order.
- `OP_CALLBACK` (`ClientTCPSocket.cpp#L1743-L1772`) gates only on Kad running, the check
  ID inverting to the node's own Kad ID and the file being known, never on the buddy
  link, so aMule acts on a `0x99` on any TCP socket.
- The buddy keepalive period is ten minutes: `SetLastBuddyPingPongTime()` stamps the
  clock ten minutes ahead on each ping or pong
  ([updownclient.h#L487-L489](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/updownclient.h#L487)),
  and the answering side's `AllowIncomeingBuddyPingPong()` suppresses pings for thirteen.
- A firewalled publisher's Kad source row is type 3 (5 above the u32 size range), with the
  buddy's endpoint and `TAG_BUDDYHASH` (aMule Fork Pin `ab483654` `Search.cpp:841-884`,
  eMule 0.70b `Search.cpp:666-691`, eMuleAI `Search.cpp:883-913`). A firewalled publisher
  whose UDP is verified open publishes type 6 instead, tested before the buddy slot
  (`Search.cpp:821-839`).
- `TAG_BUDDYHASH` is `~publisherKadID` as hex, spelled two ways: aMule (`ToByteArray`,
  big-endian) and emule-qt (`toHexString`) write upper-case big-endian; eMule 0.70b and
  eMuleAI write `GetData()`, the raw word-ordered bytes. On a little-endian host the two
  differ by a per-word byte swap, so the two families cannot address each other's
  buddies.
- Stock aMule 2.3.3 publishes a firewalled node's sources only with its buddy connected
  (`SharedFileList.cpp:773`); it has no direct-callback branch in its publish gate.

Evidence: `crates/rmule-kad/tests/fixtures/buddy/captured/` (aMule's `0x51`, a
firewalled aMule's type-3 publish, aMule's `0x52` endpoint and FINDSOURCE forms, plain and
keyed), `crates/rmule-kad/tests/fixtures/firewalled/captured/amule-233-publish-source-type6-20260923`
(aMule's type-6 row), and `crates/rmule-peer/tests/fixtures/buddy_callback/captured/`
(the `0x52` → `0x99` relays and the dial-back that carried a transfer).

## Decision

rmule is symmetric: it serves firewalled peers as an open node (buddy service, relays,
callbacks) and operates as a firewalled node itself (buddy recruitment, callback
consumption), keyed off Self Reach (ADR-0060).

### The route tree

One core-side chooser over a candidate's facts answers every caller: the download
worker, Low-ID source-exchange and server candidates, Kad rows and the uploader's grant
dial-back. In order:

0. **IPv6 direct** (ADR-0087): the peer named a usable IPv6 and rmule holds a known one,
   so dial it. The dial meets the candidate's stated crypt stance by the outbound rule
   (ADR-0049); a candidate whose requirement rmule cannot meet is retired off every road.
   A dial that never connects falls, once per IPv6 half, to the routes below; a later
   sighting at another half reopens this rung there.
1. **Low ID to Low ID:** punched through a NAT-T Rendezvous (ADR-0091).
2. **Direct UDP callback:** the target advertises `SupportsDirectUDPCallback` and our UDP
   is on: `0x95 <ourTCPport2><ourUserhash16><connectopts1>` to the target's Kad UDP port
   ([BaseClient.cpp#L1518](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/BaseClient.cpp#L1518)),
   with a 45 s answer timeout.
3. **Server callback:** the target is on our connected server (ADR-0039).
4. **Kad buddy callback:** with the buddy's endpoint known, a plain `0x52
   <buddyID16><fileHash16><ourTCPport2>` to the buddy's UDP port; with only its ID, a
   Callback Walk toward the buddy ID that sends the `0x52` at convergence, keyed under the
   buddy's Kad ID when the crypt layer is on. No valid buddy ID, or Kad down, drops the
   candidate.

A Kad row's Low-ID candidate has its buddy as coordinator and never a server: a Kad row is
in no server's namespace, so the server road is refused for it.

### Open-node roles

- **Buddy service.** One slot. A `0x51` is refused silently unless Kad TCP and UDP both
  read verified open (aMule `KademliaUDPListener.cpp:1427`), and also when rmule already
  has a buddy, the requester is a known client or under a firewall-check collision, or is
  ourselves
  ([ClientList.cpp#L906](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientList.cpp#L906)).
  Otherwise rmule answers `0x5A <buddyID><ourHash><ourTCPport>[connectopts]`.
- **The held link is the one the recruit dials**, adopted at inbound triage before the
  adopt/serve split: `try_attach` holds a connection when its `OP_HELLO` reports the User
  Hash the `0x51` recruited on. The hello decides, never the endpoint, because the recruit
  is behind a NAT. The connection is still served (ADR-0031), and the relays queue their
  frames on it. Its close empties both the link and the slot, so the next `0x51` may
  recruit.
- **Relays, both verified.** `0x52` becomes `OP_CALLBACK` on the held link and `0x94`
  becomes `OP_REASKCALLBACKTCP`, each only when its buddy ID matches the registered one.
  aMule verifies the `0x94` but not the `0x52` (its `// JOHNTODO` names the gap); rmule
  checks both, which compliant requesters never notice and which keeps a spoofed callback
  off the link. The `0x52` relay is byte-faithful: the codec normalises `fileHash` to a
  true `FileHash` and the `0x99` framing writes it back, so the composition is the same
  pass-through aMule performs.
- **The open node also consumes a matching `0x99`** on any link it serves, with no
  held-link requirement, as aMule does. It reads the Kad Presence (running, and as which
  Kad ID) and the mirrored file-known predicate, and a dial-back enters the serve pipeline
  as the dialer's side.
- **Keepalive.** Every `OP_BUDDYPING` on the held link is answered with an empty
  `OP_BUDDYPONG`, and the link's session timeout is extended while it is held. rmule
  answers every ping instead of applying aMule's floor: only the one held link can be
  ponged at all, and a pong is a six-byte frame.

### Firewalled-node roles

- **Recruitment** happens when Kad runs, Kad TCP and Kad UDP both read firewalled, rmule
  holds no buddy, the FindBuddy pacing allows (every 20 minutes, at least five minutes
  after a firewall recheck, at once on losing a buddy), and the crypt policy is not
  `Required` (`RecruitRefusal::CryptRequired`): callback requests cannot be obfuscated,
  aMule's own limitation. A TCP-firewalled, UDP-open node needs no buddy; it advertises
  direct callback and consumes `0x95`. The trigger lives with the Kad pump, because the
  pump's brain holds the inputs it decides on: the recheck clock is its own, the verdicts
  are its reads of Self Reach, and the walk it starts and hears end is its own state. It
  is a pure rule over those and over the buddy slot's published snapshot (whether a buddy
  is held, and when the last one was lost); it never reads or writes the slot itself.
- **The Firewalled Front owns the slot.** It is the slot's only writer: it adopts, dials,
  holds, pings and releases. A verified `0x5A` reaches it as an `AdoptBuddy` command from
  the pump, and the front answers with its verdict, which the pump takes as an input. The
  front publishes a snapshot of the slot on every change, and every other reader goes
  through it: the hello's buddy tags, the buddy row of a Kad source publish, the Run Log
  trail and the recruit rule.
- **The FINDBUDDY walk** targets `~ourKadID` and at convergence asks the single closest
  responded contact inside `SEARCHTOLERANCE` of the target or on a LAN
  (`Search.cpp:624-628`). A walk that finds nobody does not re-arm. The `0x5A` is verified
  by XOR inversion against our Kad ID and the tracked-packet guard.
- **The buddy dial** meets the `0x5A`'s connect-options stance by the outbound rule
  (ADR-0049); a pair that cannot meet is refused without seating the slot. rmule pings the
  held buddy every ten minutes while firewalled. Losing the link empties the slot and arms
  an immediate recruit. rmule releases its buddy when Kad TCP opens, where aMule keeps it
  and stops pinging.
- **`0x99`:** accepted when Kad runs, the check ID inverts to our Kad ID, and the file is
  shared or downloading (a mirrored `SharedFileKnown` cell, read inline). Then rmule dials
  the requester plaintext: the `0x99` carries no User Hash or connect options, so there is
  no key, as aMule's `OP_CALLBACK` arm also dials in the clear.
- **`0x9A`:** the relayed reask is answered directly over UDP to the requester, by the
  reply matrix of ADR-0057.
- **`0x95`:** rate-limited per source Accounting Key (a `/64` for IPv6), accepted only
  while Kad TCP reads firewalled and Kad runs, then dialed back. The `0x95`'s stance meets
  `CoreSettings::obfuscation` by the outbound rule, after the rate limiter; an incompatible
  pair is refused before a socket and counted apart, and there is no plaintext re-dial.
  The body names no address, so the requester is the datagram's source, and an IPv6
  requester is dialed back directly.
- **`0x35` and `0x26`, the server-relayed callback**: a peer on our server asked it to
  invite us (`OP_CALLBACKREQUEST`), and the server names that peer to us, `0x26` for an
  IPv6 one. The peer wants to download from us, so the dial-back feeds the serve
  pipeline, not a download: aMule's `OP_CALLBACKREQUESTED` arm builds a `CUpDownClient`
  with no file and calls `TryToConnect`
  ([ServerSocket.cpp#L554](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ServerSocket.cpp#L554)).
  rmule dials back when all of these hold, read at the request and stored nowhere:
  - the session is Low-ID, by the id its latest `OP_IDCHANGE` assigned;
  - the requester's address passes the Reserved Range check with the server as its
    Informant (ADR-0085), which is also the whole `0x26` address gate;
  - the requester is not our own listen endpoint (`OwnListenEndpoint`, ADR-0058);
  - the node is serving, so a dialed link has a hello to write;
  - no callback dial to that endpoint is in flight, and fewer than eight are.

  The `0x35` crypt extension's connect-options and User Hash are the requester's stance
  for this one dial (ADR-0049); the 6-byte form and every `0x26` state none and dial
  plaintext; a pair that cannot meet is refused before a socket. aMule has no Low-ID
  test, because its server sends the opcode only to a Low-ID client, and keeps one socket
  per client rather than an in-flight cap; both bounds are rmule's own, on one server's
  word.
- **A callback dial-back is an inbound peer** and enters by the inbound path:
  `Connection::dial_stream` runs the crypt handshake when there is a key (the initiator's
  act) and hands the stream to the serve pipeline's admit seam as the dialer's side, so the
  IP filter, the ban store and callback adoption all apply.

### What rmule publishes and advertises

- **Firewalled with a held buddy** (and no direct-callback verdict): the type-3/5 row, in
  the captured order:

  | Tag | Wire type | Value |
  | --- | --- | --- |
  | `TAG_SOURCETYPE` `0xFF` | `UINT8` | 3, or 5 above the u32 size range |
  | `TAG_SERVERIP` `0xFB` | `UINT32` | the buddy's IPv4 as the eD2k address word, swapped by neither side |
  | `TAG_SERVERPORT` `0xFA` | `UINT16` | the buddy's UDP port |
  | `TAG_BUDDYHASH` `0xF8` | `STRING(32)` | upper-case big-endian hex of `~publisherKadID` |
  | `TAG_SOURCEPORT` `0xFD` | `UINT16` | our eD2k TCP port |
  | `TAG_FILESIZE` `0x02` | `UINT32`, `UINT64` past `u32::MAX` | for a v2+ storer |
  | `TAG_ENCRYPTION` `0xF3` | `UINT8` | the connect-options byte, last |

  `bi6` (the buddy's IPv6) comes from the buddy's `CT_MOD_IP_V6` on the held,
  hash-verified link (ADR-0087).
- **Firewalled with UDP verified open:** the type-6 row (`TAG_SOURCETYPE` 6,
  `TAG_SOURCEPORT`, `TAG_FILESIZE`, `TAG_ENCRYPTION` with bit 3 set by the same predicate
  that chose the type). No buddy tags and no address: the storer's observed source IP is
  where a reader's `0x95` goes.
- **Firewalled with neither:** no row (ADR-0060).
- Variable-width tags use the narrowest type that holds the value, and a reader accepts
  every narrowing.
- rmule writes no `TAG_SOURCEUPORT`: the storer substitutes the port it observed the
  datagram from, the only one a NAT in the path leaves correct. aMule writes it only when
  its UDP verdict was read on the intern port.
- `TAG_ENCRYPTION` carries the byte core composes (`KadCommand::SetPublishConnectOptions`);
  a node never told a byte omits the tag rather than claim zero. Its bit 7 is read as uTP
  NAT-T here and only here; only eMuleAI's connect-options writer sets it.
- **Hello buddy tags.** `CT_EMULE_BUDDYIP` (`0xFC`, the held link's IPv4 in wire order),
  `CT_EMULE_BUDDYUDP` (`0xFD`, the `0x5A`'s UDP port) and `CT_EMULE_SERVINGBUDDYIPV6`
  ride after `CT_EMULE_UDPPORTS`, under one gate (firewalled and a held link), on every
  hello including the firewall-check dial-back. The buddy dial itself carries none, as
  aMule links `m_pBuddy` only once connected. Read back by aMule's rules
  (`BaseClient.cpp:542-557`: any integer width, usable only when both are non-zero), a
  source's buddy endpoint is kept by User Hash for the run and fills a Low-ID candidate
  whose Kad row names that buddy by ID. The hello never names the buddy ID, so it opens no
  buddy road alone.

### Reading a Kad source row

`rmule_kad::KadSourceRowFacts` projects the whole row. `TAG_SERVERIP` is read as the eD2k
word, unswapped, while the storer-synthesised `SOURCEIP` is in Kad host order and swapped
back (`DownloadQueue.cpp:1713`). `TAG_BUDDYHASH` is **read in both spellings and written in
one**:

- The aMule reading is the primary buddy ID and the other spelling the
  `fallback_buddy_id()`. When the whole callback wait lapses with no dial-back, rmule sends
  **one** more `0x52` under the fallback (same buddy, file and port) and re-arms the wait;
  never both at once. Only for a buddy with a known endpoint: a buddy named by ID alone gets
  no second Callback Walk.
- A relayed `0x99` whose check inverts to our Kad ID in either spelling is ours. An open
  node accepts either spelling of its registered buddy on a `0x52` and relays it verbatim,
  never rewriting the check ID; the `0x94` keeps its exact match.
- Counters (`SessionCounters::buddy_hash_spelling`): `callback_fallback_spelling_sent_total`,
  `relayed_callbacks_swapped_spelling_total`, `buddy_relays_swapped_spelling_total`.

## Consequences

- The deterministic tier covers the route-selection matrix, the buddy refusal matrix and
  single-slot invariant, relay verification for both opcodes, the XOR checks, the `0x95`
  gates, ping and pong with the timeout extension, the recruit truth table and the publish
  tag layouts.
- Captured on the bench: aMule's `0x51` and rmule's `0x5A` with the held link and
  `OP_BUDDYPING`; route 4 end to end (rmule's `0x52`, rmule's buddy relaying to a
  firewalled aMule, aMule's dial-back carrying a byte-equal transfer); a stock aMule
  requester's own `0x52` in both the endpoint and FINDSOURCE forms, plain and keyed under
  the buddy's Kad ID, relayed by rmule; and both type-6 rows.
- Still source-derived: the fallback-spelling `0x52` (it needs an eMule 0.70b or eMuleAI
  body; emule-qt writes aMule's spelling), a `0x99` relayed by aMule over a link rmule
  serves, and a `TAG_FILESIZE` above 4 GiB.
- The server-relayed callback is decoded from a capture (`0x35`'s 6-byte form), and its
  dial-back is proven on the bench: a High-ID stock aMule downloaded a byte-equal file from
  a Low-ID rmule through ed2k-server over rmule's dial-back alone (`server-callback-serve`,
  `PASS`, 8 of 8). The `0x35` crypt extension stays source-derived, and `0x26` stays
  single-oracle (eNode-go).
- A two-node swarm pings its one contact every 15 s while the extern port is unknown and
  trips both sides' flood bans; a flow that needs a held link places routing contacts.
- The two buddy-hash families' incompatibility is an upstream matter for eMule 0.70b and
  eMuleAI (and an emule-qt defect against its own ancestor), not an rmule change.

## Considered options

- **Open-node only.** Rejected: a NAT-ed rmule, the common home deployment, would go dark
  as a source.
- **An unverified `0x52` relay, as aMule ships it.** Rejected: the verified relay is the
  check aMule's own TODO names, and compliant peers never notice.
- **A buddy while UDP is open.** Rejected: aMule recruits only when both verdicts read
  firewalled; a UDP-open node takes the cheaper direct-callback path.
- **aMule's buddy-ping floor on the answering side.** Rejected: the held-link gate already
  bounds the flood, and the floor drops pings unanswered.
- **A two-minute keepalive.** Rejected: aMule's answering floor drops four of five such
  pings, so it spends frames to learn nothing.
- **Rewriting a swapped-spelling `0x52` to the registered ID while relaying.** Rejected:
  the relayed `0x99` equalling the `0x52`'s bytes is a captured aMule fact; the repair
  belongs upstream.
- **A second Callback Walk toward the swapped ID.** Rejected: the walk is the expensive
  road, and every eMule-spelled row is still a source reading.
- **Writing `TAG_ENCRYPTION` as 0 when no byte is known, or a self-declared
  `TAG_SOURCEUPORT`.** Rejected: the first states "no crypt, no NAT-T, no direct callback"
  as a fact; the second overwrites the storer's correct observation with a port nothing
  outside can reach.
