# NAT Traversal: eMuleAI's dialect, two Rendezvous coordinators, a uTP/QUIC Tunnel under the peer session

## Context

Two firewalled peers cannot reach each other on eD2k: every callback needs one reachable
side, so the route tree of ADR-0061 drops a Low-ID→Low-ID pair. The field has converged on
one machine — learn your address, be introduced, punch simultaneously, raise a reliable
transport over the punched UDP path — and three eD2k implementations speak one wire form of
it: eMuleAI defines it, kno's aMule branch ports it, and ed2k-server coordinates the
server-side introduction. The `0xB3` / `0xD0`–`0xD7` family in ed2k-server's README is eMule
0.72a-community's, a third dialect with no Linux-buildable counterparty.

eMuleAI v1.6 (`a2f05dc`) and kno's `feat/natt-emuleai-framing` are read for facts under
ADR-0082, never ported; eMuleAI citations below are under `srchybrid/` at that commit. The
nine security corrections are those settled in the aMule project's NAT-T review.

Facts that shape the design:

- `librqbit-utp` 0.7.0 sends a dial's `ST_SYN` once and never retransmits it
  (`src/socket.rs`); `UtpSocket::connect` has no timeout of its own; the responder's SYN-ACK
  is resent six times 200 ms apart (`src/constants.rs`, `src/stream_dispatch.rs`). It allows
  four concurrent connects per address and silently refuses a fifth.
- A NAT may map a different port than the one a buddy observed; the endpoint a punch was
  observed from is the mapping that demonstrably works.
- No coordinator ever tells a node its own observed port: `0x60` carries our bound port to
  the server only, `0x61` carries the *peer's* observed port, a `0x9A`-injected endpoint and
  `0xAA` carry the other side's.
- The bench's `symmetric` gateway (`tools/interop-harness/images/natgw/entrypoint.sh:106-110`,
  `snat … fully-random`) draws each mapping's port uniformly from 1024–65535 (Linux
  `nf_nat_core.c`, `get_random_u16() % 64512`, doubling 1024–2047). Pooled over 559 mappings
  from bench archives: χ² 12.79 over 16 bins, 447 distinct consecutive deltas, and eMuleAI's
  ±16 sweep caught none. Two symmetric peers are out of reach at any sane size; one symmetric
  peer facing an endpoint-independent one is reached by a birthday pairing — N = 256 sockets
  against 256 random probes lands 63.9 % of attempts (RFC 4787 §4.1–4.2; RFC 5128 §3.5;
  tailscale's "How NAT traversal works"), and two attempts 86.9 %.

Stock aMule has no NAT traversal, so by ADR-0082's rule the dialect is scored on the
eMule-family counterparty that speaks it, eMuleAI.

Evidence: the `natt-*` flows in `tools/interop-harness/src/flow/nat/natt.rs` on the NAT
harness of ADR-0092 — server punch and buddy rendezvous behind cone, restricted and
symmetric gateways, the one-symmetric birthday row, uTP CAPS, a transfer across a punched
path, and a firewalled aMule as the target of the buddy-callback road; the aMule publish
capture `crates/rmule-kad/tests/fixtures/buddy/captured/amule-233-publish-source-req-20260922`.

## Decision

**Speak eMuleAI's NAT-T dialect byte for byte — `CT_MOD_MISCOPTIONS` bits 1 and 4,
`OP_RENDEZVOUS 0xA0` / `OP_HOLEPUNCH 0xA1` / `OP_NATT_ENDPOINT_HINT 0xAA` under `0xC5`, uTP and
QUIC framed under `0xB2` with the `0xFF` KEY frame — reached by two Rendezvous coordinators
(ed2k-server's `0x60` / `0x61` / `0x62` punch, then the Kad serving buddy in eMuleAI's
embedded form), with the ordinary peer session running unchanged inside the Tunnel. The
Low-ID↔Low-ID drop becomes the punch. No NAT-type gate: outcomes decide, with one narrow
exception, Port prediction, gated on our own observed mapping.**

### Transport

- **uTP and QUIC.** uTP (`0xB2/0x00`, BEP-29) is the reachable population; the engine is
  `librqbit-utp` behind rmule's implementation of its `Transport` seam, fed by rmule's own
  datagram pump — the library never owns a socket. QUIC (`0xB2/0x01`) is `quinn` over
  `quinn-proto` (`crates/rmule-net/src/natt/quic.rs`) with eMuleAI's pinned parameters: ALPN
  `ed2k-ai-natt-quic-v1`, TLS 1.3 only, self-signed RSA-2048 with no verification, SNI
  `emuleai-natt`, and the 37-byte `EAQN1 ‖ our hash ‖ expected hash` proof as the first stream
  bytes. **Bit 4 stays off** until a QUIC handshake is proven against eMuleAI or kno's build:
  an optimistic bit costs every peer a 1500 ms stall. rmule claims bit 1 and is uTP-only,
  like an eMuleAI build without its QUIC runtime.
- **Negotiation** is two-stage: hello bits, then the direct `CAPS` / `CAPS_ACK` frames
  (`0xB2/0x02`, `0x03`) carrying the one connect-options byte (crypt bits and `0x40` = QUIC
  share it). QUIC is preferred when both have it, uTP is the floor, a peer with bit 1 and no
  CAPS answer within 1500 ms is legacy-uTP-only, and a QUIC failure blacklists the endpoint
  for 120 s. The CAPS sender's hash is read live from the own-identity cell (`NattOwnHash`)
  at the moment it is needed; a CAPS frame arriving before an identity exists
  (`CapsBeforeIdentity`) answers nothing. The QUIC proof gate refuses with `NoIdentity` the
  same way.
  A CAPS body (54 bytes) and a KEY body (16) are read by their fixed prefix: a longer body is
  eMuleAI's to extend, and it checks `>=` on both (`ClientUDPSocket.cpp:690`, `:1002-1003`).
  Only a shorter one is malformed.
- **Sharing the client-UDP socket.** Demux by protocol byte, then frame type. `0xB2` is on
  the never-obfuscated whitelist (ADR-0046). Transport frames are obfuscated when a key is
  known; the KEY frame (`0xB2/0xFF`, our 16-byte hash, once per endpoint per 10 s on a uTP
  `ST_SYN` or a QUIC long header) supplies it, offered with a zero hash before identity.
  **Signalling under `0xC5` is unobfuscated on purpose**: a punch that fails to deobfuscate
  is indistinguishable from one that never arrived. Kad and NAT-T share the one client-UDP
  socket (ADR-0057), so the mapping a buddy observes at the recruit is the mapping a punch
  must reach.
- **The Tunnel** is an `AsyncRead + AsyncWrite + Unpin + Send` stream — the bound
  `spawn_connection` takes — so `PeerSession`, `CryptStream` and the capture tap run unchanged
  inside it. SecIdent v1 (no address signed); credits keyed by User Hash.
- **IPv4 only, where the dialect names an address.** `0xAA`'s acceptance rule compares the
  observed source against the buddy's `Ipv4Endpoint`, so an IPv6 hint drops at the driver and
  is counted. `0xB2` and the empty `0xA1` pass in both families. The relayed rendezvous stays
  IPv4 because `0x9A` injects the requester as a 32-bit word (ADR-0087); an IPv6 requester in
  a `0x9A` resolves to `NoUsableTarget`.

### Two Rendezvous coordinators, server first

- **ed2k-server punch.** `CT_EMULE_UDPPORTS 0xF9` (`kadUDP << 16 | clientUDP`) rides the login
  only with an IPv4 client-UDP bind and its send half: its presence is the capability claim,
  and the server refuses to introduce a client that sent none. The login then carries five
  tags, not aMule 2.3.3's four, or six beside `CT_MOD_IP_V6` (`0xAE`, ADR-0087), where `0xF9`
  follows `0xAE`; Lugdunum accepts both with the same High ID and flags.
  `OP_SERVER_NATT_KEEPALIVE 0x9F` (our hash) leaves the client-UDP socket every **60 s** —
  the server trusts an observed port for 600 s, so the cadence is a correctness invariant.
  `OP_LOWID_HOLEPUNCH_REQUEST 0x60 <target_id 4><our_udp 2>`, `OP_LOWID_HOLEPUNCH_INFO 0x61` to
  both sides, `0x62` failure with a reason. IPv4 sessions only. The server is
  transport-agnostic, so the punch and Tunnel are eMuleAI's. The target's NAT-T support is
  not required (the server holds its `0xF9` and answers `TargetNoUdp`). Whether a server speaks
  the punch is learned only by its silence: `INTRODUCTION_TIMEOUT` (15 s, polled by the
  session's own loop), after which the attempt falls to the buddy. A session that ends reports
  every request it still waited on. `0x61` names no target, so it settles a request only when
  exactly one is outstanding; `0x62` names its target. Both sides fire at once; the role byte
  says who asked.
- **Kad serving buddy, eMuleAI's form.** rmule emits `OP_RENDEZVOUS` embedded in
  `OP_REASKCALLBACKUDP` toward the target's buddy and accepts both the embedded and the
  standalone `0xC5 0xA0` form. The buddy strips sixteen bytes and forwards inside
  `OP_REASKCALLBACKTCP`, and when asked (`0x20`) **the buddy** answers the requester with an
  `OP_NATT_ENDPOINT_HINT` naming the target's UDP endpoint as it observes it
  (`ClientUDPSocket.cpp:1271`); both sides punch. A rendezvous toward a buddy named by ID
  alone retires at once (`CoordinatorEndpointUnknown`): eMuleAI's unknown-buddy-IP fallback
  never resolves an endpoint for the punch (`BaseClient.cpp:3273-3323`).
- Fallback runs server → buddy, never back. The server goes first because its introduction
  needs no Kad and no buddy and its keepalive leaves the socket the Tunnel rides.
- eMuleAI's eServer-buddy family (`0xB3`–`0xBB`) is out of scope.

### The rung and the Low-ID roads

- **Rung 1 of the ADR-0061 tree is the NAT-T attempt.** Rung 0 (direct IPv6, ADR-0087)
  precedes it. **A Low-ID↔Low-ID pair** takes no callback — no Low-ID node can be dialed — so
  the fall to the punch is emitted on admission. **A High-ID↔Low-ID pair** takes its callback
  road first and falls to the punch after `CALLBACK_SILENCE_FALLBACK` (12 s) of silence. The
  12 s retracts nothing: the slot stays held, and whichever connection arrives first — the
  callback or the Tunnel — takes it.
- **Admission is a callback road or a coordinator** (`LowIdRoad::of`, the one site; pooling
  is not a second gate). In aMule's order, when we are callback-capable: `DirectUdp` for a Kad
  type-6 row (the `0x95` to the row's observed Kad UDP endpoint; aMule keeps the connect IP only
  for type 6, `DownloadQueue.cpp:1797`), the server `Callback` for a candidate on a server, and
  `BuddyCallback` for a Kad row naming a buddy and a User Hash (`BaseClient.cpp:2114-2172`);
  otherwise the punch when the candidate's facts admit a coordinator (`admits_coordinator`: on
  our server, or the NAT-T bit plus a buddy). Kad-row roads need the User Hash, the only name a
  dial-back can be matched by, and register a **Dial-Back Claim**.
- **Callback Capability** is aMule's `CanDoCallback` (`amule.cpp:3207-3256`): a bound listener,
  plus a server High ID or an open Kad TCP verdict — except that a node Low-ID on its server
  but Kad-open is not callable for a source on that server. The runner samples the listener
  (`SharedServeListener`), the session self-facts and the Kad TCP level every second; a lost
  capability retires nothing already held, a gained one admits waiting rows. The
  Remote-Queued Pool's reask gate reads the same sample (aMule's `!IsFirewalled()`,
  `DownloadClient.cpp:1373`).
- **The buddy callback.** With a known buddy endpoint, a plaintext `0x52
  <buddyID16><fileHash16><ourTCPport2>` goes to it (`KadCommand::RequestBuddyCallback`). With the
  ID alone, the **Callback Walk** — aMule's `FINDSOURCE` (`BaseClient.cpp:2160-2170`,
  `Search.cpp:1081-1122`) — walks toward the buddy ID and sends the `0x52`, through the node's
  obfuscation matrix, to every responded contact inside tolerance, closest first, at most 21; one
  walk per target, the second reported as `AlreadyWalking`. With no Kad node running, the road
  retires at once (`KadNotRunning`), as aMule's `RemoveSource` does (`BaseClient.cpp:2123-2130`).
- **Every road that never opened is answered at once** on the download's retire channel —
  `NoCoordinator`, `NotEnactable`, `CallbackNotSent`, `CoordinatorEndpointUnknown`,
  `KadNotRunning`, `BuddyNotFound`, `CallbackWalkBusy` — so a candidate never holds a slot for a
  road decided dead in the same millisecond. Beside a live callback, a punch's retirement
  retracts only its claim and marks the source unreachable by traversal; as the candidate's
  only road it is the candidate's lapse.
- **No NAT-type gate.** RFC 8489 dropped classification because labels lie and outcomes do
  not. Every eligible pair is attempted within eMuleAI's budget: at most five rendezvous per
  source, a 120 s run, 60 s backoff, then temporarily unreachable with a reason; retry grants
  2 / 4 / 6 by trigger, jittered 50–150 ms. A source whose grant is spent goes idle with its
  clock stopped and its failure count kept.
- **Bursts.** Six empty `0xA1` at the target's endpoint plus a ±16-port sweep. When the relay
  round trip is measured, the burst is held to **half the RTT** after the hint (DCUtR's
  policy), released by the front's own deadline timer. A successful punch asks the mapping
  runtime once for a **PCP `PEER`** pin (ADR-0086); its refusal is ordinary. An idle punched
  path is kept by an empty `OP_HOLEPUNCH` every 60 s.

### The NAT-T Front owns the attempt

- **One task, no mutex.** The NAT-T Front `select!`s over the client-UDP front's NAT-T inbox,
  the uTP accept pump, its command half, the earliest Held Burst deadline and a 1 s tick.
  The requester ledger, punched paths, expectations, dial schedule and prediction plans live on
  it. It never awaits a consumer it does not drain: a risen Tunnel goes to an adopter task
  through a bounded `try_send` backlog, and a refused hand-off closes the tunnel and is counted.
- **One emitter for rung 1.** Peer Reach hands the front one command per traversal: toward
  this peer, through this coordinator. The front puts every rung-1 frame on the wire itself —
  the server's `0x60` on the session, through the Server Coordinator's session half it holds
  and never awaiting it (a full or ended session costs the introduction, which retires as
  `NoCoordinator`); the buddy rendezvous and its retries; and the buddy rendezvous a
  fall-through arms. A `0x60` for a target with no User Hash still leaves and is owned by no
  attempt. The attempt keeps no snapshot of our position: when a coordinator fails, the front
  reads Self Reach's route position at that moment and asks the one selector who is next.
- **The side that asked dials; the other accepts.** The rendezvous requester dials, and on the
  server road the `0x61` role byte says who asked; an unknown role reads as responder.
- **A `0xA1` corrects where the dial goes** — to the endpoint the punch was observed from —
  but never whose dial it is. **Punch Expectations** are keyed by IP and hold a bounded set
  of at most four `{target hash, role, nominal endpoint, since}`; attribution with several
  entries behind one address uses a unique nominal-port match or names no one, and a `0xA1`
  never fans out into several dials.
- **Each dial is bounded at 3 s and re-issued** — at once on a `0xA1` from the expected peer,
  otherwise every 5 s, a cadence re-dial asking first for a fresh burst through the
  destination limiter — within the attempt's 120 s `DIAL_BUDGET`, measured from the attempt's
  Begin. One dial in flight per target. A dial owns its registry slot (`TunnelSlot::Dialing`,
  released on drop); `OPENING_TTL` (30 s) governs only slots an inbound opener created.
- **A risen Tunnel enters through the accept pump's channel** inside a **Punched Path Guard**,
  whose `Drop` tells the front the path closed — the only close signal the dialect allows. It
  passes the IP filter, the ban gate and `inbound_triage`. A Tunnel the front dialed carries the
  target's User Hash, and `inbound_triage` adopts it for the download whose **Pending Tunnel
  Claim** the peer's hello confirms, beside the ADR-0039 callback match; a peer that answers on
  the path but names somebody else is refused and closed, and the claim stays pending. An
  accepted Tunnel, or one dialed toward a hash nobody claimed, takes the serve road. Every
  adoption reports the hello's peer back to the front, which ends that peer's hold. A claim is
  filed in the **Awaited Inbound** registry beside its callback, in the same registration,
  which keeps an ordered list per User Hash, one claim per download (ADR-0107): the oldest
  takes a Tunnel, a retirement reaches every claimant, and only a claim's owner retracts it.

### Attempt lifecycle

| State | Held by | Key | Deadline → what fires | Next | eMuleAI |
|---|---|---|---|---|---|
| **Claimed** | download: Pending Callback + Pending Tunnel Claim | `CallbackKey`; claim by target User Hash, owned by its runner | 12 s silence → fall to NAT-T; 30 s slot release → Abandoned, unless a traversal runs, which the slot then waits on up to its bound (`DIAL_BUDGET` + one 5 s redial) | Introducing, Rendezvous, Abandoned | `DS_WAITCALLBACK` |
| **Introducing** (server) | front: attempt `Server{low_id}`; session: `ServerPunch` | User Hash, joined to `ClientId` until the `0x61` | 15 s → `IntroductionFailed(Silence)`; a `0x62` → the same edge; past the `0x61`, the 120 s run | Opening, Rendezvous, Retired | eServer relay timeout `Opcodes.h:388` |
| **Rendezvous** (buddy) | front: requester ledger | User Hash; a hint believed only from the buddy ID and endpoint | 15 s `HINT_TIMEOUT` → silence (one of five); 120 s → Retired | Held, Rendezvous, Retired, Idle | `BaseClient.cpp:3548-3575` |
| **Held** | front: Held Burst + Dialer expectation | User Hash; IP set | ½ RTT → burst, dial armed | Opening; cancelled by any ending or its path's close | bursts at the hint, `ClientUDPSocket.cpp:1352-1357` |
| **Opening** | front: Dial Schedule + expectation | User Hash | 3 s per dial; 5 s re-dial; 120 s `DIAL_BUDGET` from Begin → `Transport` | Adopted, Opening, Retired | `DoNatTRetry` `BaseClient.cpp:3613` |
| **Expecting** (responder) | front: Responder expectation, no attempt | IP set | 120 s `EXPECTATION_TTL`, refreshed by a `0xA1` | Adopted, gone | 30 s, `ClientUDPSocket.cpp:59,136` |
| **Adopted** | front: Punched Path; download: the confirmed worker | User Hash | idle: 60 s keepalive; session end → closed | gone | `DownloadClient.cpp:915` |
| **Retired** | front: ledger `retired{until}`; download told via the claim | User Hash | 60 s `RENDEZVOUS_BACKOFF` → pruned | gone | `BaseClient.cpp:3577-3604` |
| **Idle** | front: ledger (failure count only) | User Hash | 60 s after the last failure → pruned | Rendezvous, gone | per-session count |
| **Abandoned** | download: claim retracted by its owner | User Hash | immediate | gone | `AbortNatTRendezvousAttempt` |

Invariants:

1. **One attempt per peer at a time.** A second Begin joins the live attempt; the coordinator
   never moves back from buddy to server; an introduced attempt stops answering to its
   `ClientId`.
2. **Every state has its own deadline.** A believed hint stops the rendezvous silence clock.
3. **An ending takes everything the attempt holds** — the Held Burst, the dial schedule entry,
   the prediction plan and, unless retired (which keeps its backoff), the ledger entry —
   through one `end_attempt`.
4. **A lapsed claim returns its budget:** when the claimant lets go, the front ends the attempt.
5. **The key never changes mid-attempt:** the target's User Hash keys the attempt, ledger, hold,
   dial and claim from Claimed to Adopted.

The responder's expectation lives 120 s where eMuleAI's lives 30 s, because the requester
re-dials for its whole 120 s budget and each `librqbit-utp` opener is sent once.

### Security (the nine corrections, all adopted, and two of rmule's own)

1. **Observed source > public claimed hint > hint as lookup key.** A claim is adopted only when
   the observed source is unusable and the claim is public. Arm 3 resolves nothing in core,
   because a relayed rendezvous names a requester we have never spoken to; an unadoptable claim
   is `NoUsableTarget`.
2. Direction is decided by which frame arrived (embedded request or standalone relay), never by a
   bit.
3. The connect-options byte is one byte, one namespace shared with crypt; `0x40` means QUIC.
4. The self-punch guard asks Address Learning's interface set, never "our public IP".
5. Rate limiters are split by direction, so spoofed traffic cannot starve our buddy.
6. `IsPublicIP` is thorough: RFC 1918, link-local, multicast, reserved, CGNAT `100.64/10`,
   TEST-NETs, benchmarking, IPv6 unspecified and loopback.
7. **Relay admission:** rmule relays a rendezvous only for its buddy relations (both directions)
   and served buddies, after verifying the buddy ID and a held link; at most 10 pending, one per
   requester bucket (a re-ask supersedes its own slot), per-source rate-limited, the target
   resolving to a known client. The 10 / 15 s / 8 s numbers are eMuleAI's eServer-buddy path's,
   the only relay numbers in its tree.
8. The 16-byte file-hash slot in the rendezvous body is always written, never inferred.
9. No failure or reset frame exists in the dialect; stale tunnels are state, found by timeout,
   and an active transfer survives a caps change.
10. **Tunnel admission is by expectation.** An opening packet (a uTP `ST_SYN`, a QUIC long
    header) from an endpoint the Tunnel Registry holds no slot for opens one only when its
    source IP is expected, and is otherwise dropped before the engine: no `ST_STATE`, no KEY
    frame. The key is the IP because a hint, an introduction or an acted rendezvous names the
    peer's address while a NAT, or a prediction leg, leaves its port open. Three facts expect an
    IP: a **Punch Expectation** the NAT-T Front holds for it; a live relation in the **Peer
    Roster** (ADR-0059) — kno dials uTP to every peer whose hello claims bit 1
    (`UtpDialPolicy.h:103-139`, `BaseClient.cpp:2271`), so a peer we already deal with may come
    back over uTP with no rendezvous; and, for any IPv4 address, a standing **Dial-Back Claim**
    — eMuleAI answers a buddy callback with a uTP dial (`ListenSocket.cpp:2480-2494`) and a
    Low-ID callback names no address for the dialer. eMuleAI gates the same way, on its
    expected-peer table with an IP-only fallback (`eMuleAI/UtpSocket.cpp:683-1040`). An IPv6 source is never
    expected: the dialect names IPv4 only and core adopts no IPv6 tunnel. `Opening` slots are
    capped at 4 per IP and 64 per node, so a flood spoofing one expected address cannot crowd
    out another, and they age out on the front's one-second tick rather than on every admit.
11. **A held endpoint keeps its key.** A KEY frame whose hash differs from the live learned
    one is refused while the endpoint holds a Tunnel. A NAT rebinding moves the endpoint, never
    the hash at one endpoint, so only a spoof loses anything.

The acting path also keeps a sender gate eMuleAI lacks: a relayed rendezvous is acted on only
when its carrier is our buddy — the held TCP link by address, or the buddy's exact UDP endpoint
for a standalone frame — and its budget is bucketed on where the burst would land, not on the
requester hash. The complement-XOR buddy lookup eMuleAI retries is not adopted. A null claim is
legal and preferred to a guess; the hint's options byte is zero. The live paths enter below the
public-address verdict: `is_public_punch_address` and the self-punch guard refuse loopback and
our own interfaces, with no test bypass.

### Publish connect options

rmule's Kad publish states `TAG_ENCRYPTION` in eMuleAI's form (`OtherFunctions.cpp:4122-4147`),
every bit from its owner, re-derived on every reachability edge and recruit tick by the Kad
pump's reconciler: the crypt ladder from the obfuscation policy (ADR-0046); `0x08` from
`Reachability::accepts_direct_udp_callback` — aMule's `IsFirewalled() && !IsFirewalledUDP(true)
&& IsVerified()` (`Prefs.cpp:224-226`), with `IsFirewalled` the server-High-ID-or-Kad-open union
(`amule.cpp:3118-3125`); `0x80` while the NAT-T front is live on the bind the node rides
(`SharedNattFront::is_live`); `0x40` never while QUIC is dark. A zero byte is stated. With `0x08`
set, the node publishes aMule's **type-6** row (`Search.cpp:821-839`: source type 6, port, file
size to a v2+ storer, then `TAG_ENCRYPTION` and the verified `ip6`), which takes precedence over
a held buddy; the reader projects a type-6 row with bit 3 and an observed Kad UDP endpoint to a
Direct UDP Callback candidate and refuses one without (`DownloadQueue.cpp:1786-1792`).

### Port prediction

The one exception to "no NAT-type gate", gated only on our own mapping as our own observers saw
it.

- **Own Mapping** is read from Address Learning (ADR-0084) for the `Udp` role, from the
  fresh `KadCheck` port reports of the current Extern Port Round, one per distinct observer.
  The best-supported port is the one most observers name; the rest **dissent**.
  **Endpoint-Dependent** when at least two observers dissent, **Endpoint-Independent** when at
  least two observers name the best-supported port and at most one dissents, **Unknown**
  otherwise. Dissent needs corroboration because the Fan is the costly role: one lying
  contact must not pick it. A symmetric NAT still reads dependent within one round, since
  aMule's round asks three observers (`EXTERNAL_PORT_ASKIPS`) and each sees its own port.
- **Peer Mapping** can only veto: **Hard** when the coordinator-observed port differs from the
  peer's advertised client-UDP port, **Easy** when equal, **Unknown** when either half is missing
  (every target today). Nothing a peer claims can make rmule probe.
- **The policy** (`CoreConfig::natt.port_prediction`, `Off | Birthday`, default **Birthday**),
  decided once per introduction; eMuleAI's baseline fires unchanged in every row:

  | Own Mapping | Peer Mapping | Role |
  |---|---|---|
  | Endpoint-Dependent | Easy or Unknown | **Fan**: open 256 ephemeral IPv4 sockets, one empty `0xA1` from each to the punch target |
  | Endpoint-Dependent | Hard | none — both hard, the documented negative |
  | Endpoint-Independent | Hard or Unknown | **Probe**: 256 empty `0xA1` from the client-UDP socket to 256 random ports 1024–65535 at the target's IP |
  | Endpoint-Independent | Easy | none — the baseline reaches them |
  | Unknown | any | none |

- **Pacing and attempts.** 100 datagrams/s; the Probe starts 3 s after the introduction so the
  Fan's mappings exist first. Two attempts, at the introduction and 60 s later, each with fresh
  ports. A Fan's sockets stay open until the plan ends. The plan ends at the Tunnel's adoption,
  at `end_attempt`, or 60 s after its last attempt.
- **Gates, in order:** an owner (a plan only for a peer this node holds a Traversal Attempt
  toward — the Responder road plans nothing); an **observed** target (a claimed one gets the
  burst and dial, not 256 sockets); node-wide caps — `PREDICTION_PLANS_MAX` 4, of which
  `PREDICTION_FAN_PLANS_MAX` 1 a Fan, and `PREDICTION_SOCKET_BUDGET` 512 Fan-born sockets in
  `rmule-net`; and **a Probe fires only after the target's address has punched us**. Every
  refusal is counted (`natt_prediction_refusals_total`, `natt_last_prediction_refusal`). A Fan
  binds all its sockets before spawning any reader.
- **The hit.** The Fan lives in `rmule-net`'s `ClientUdpSocket`. A datagram from exactly the
  peer's endpoint on Fan socket *j* installs a **Prediction Route** (peer endpoint → *j*), *j*
  answers one empty `0xA1`, and the datagram is delivered as if the advertised bind had received
  it; any other endpoint is dropped. While a route stands, every send to that endpoint leaves
  from *j*, so the front, demux, uTP engine, keepalive and reask path need no change. On the
  Probe side, a punch from a port the plan already punched is a hit, answered once. These two
  answers are the only replies to a punch; each goes only to the introduced peer's address, to a
  port already sent to, once. A route is released when its path closes, or with its Fan.
- **Both symmetric stays a negative by construction:** both read Endpoint-Dependent, both Fan
  at the peer's hinted endpoint, neither probes, and the peers' filters drop the Fans.
- **No rmule↔rmule carrier exists** (rmule sends aMule's version word and eMuleAI's bits), so the
  knob and the cost bound stand in for a capability: a Fan facing an eMuleAI easy side lifts
  the hit rate from 0.05 % to 12.3 % within eMuleAI's ±512 attribution window; a Probe facing
  an eMuleAI hard side spends 256 datagrams at about 0.4 %.
- Counters: `natt_prediction_attempts_total`, `natt_prediction_probes_total`,
  `natt_prediction_hits_total`, the refusals, and `natt_own_mapping` on the snapshot.

### Seams

- **`rmule-peer`** (sans-I/O): rendezvous, punch and hint codecs; the `Rendezvous` state machine
  (budgets, bursts, ½-RTT schedule, CAPS, transport pin, blacklist); `PortPrediction`.
- **`rmule-net::natt`**: the `0xB2` demux on the client-UDP Family Pair, KEY frames, the uTP and
  QUIC engines, the `Tunnel`, and the registry of which peers hold a tunnel — an unmatched
  non-SYN frame is dropped, never answered with an unsolicited RST. The Prediction Fan and
  routes live in `rmule-net`'s client-UDP socket.
- **`rmule-ed2k`**: the `0xF9` login tag, `0x60`–`0x62` codecs, the `0x9F` keepalive.
- **`rmule-core`**: the rung, `LowIdRoad`, Peer Reach (the route position read, the choice
  and its enactment), relay admission and the two-direction budgets, the NAT-T Front (the one
  rung-1 emitter), the Awaited Inbound registry, the PCP `PEER` follow-up, diagnostics (attempt,
  outcome, reason, transport, relay counts).

## Consequences

- Two firewalled rmule peers, or rmule and eMuleAI, reach each other behind cone and restricted
  NATs; symmetric and CGNAT pairs fail honestly, except one-symmetric pairs the birthday Fan can
  reach. The limited-relay tier that would reach the rest is an rmule-only extension the dialect
  cannot express, and is not built.
- ADR-0061 rung 1 is the punch; ADR-0047's registry carries bits 1 and 4 and the connect-options
  `0x40`; ADR-0057's peer-UDP engine hosts `0xC5` and `0xB2`; ADR-0046 carries the
  never-obfuscated whitelist and the KEY frame.
- The one-symmetric birthday rate was measured on the bench while the Responder also probed;
  with the Responder road planning nothing, the pairing rests on the requester's role alone.
  Only the "sets met ⇒ Tunnel" direction has been seen live; the converse holds by construction.
- A candidate with no User Hash still punches through the server but has no attempt owner, no
  claim and no hint; whatever Tunnel it raises is served as an ordinary inbound peer, counted.
- `natt-buddy-transfer-cone` is rmule-only at both ends; the buddy-callback road is proven
  against a live firewalled aMule as target, and the direct-UDP road's `0x95` against its KAT.
  The type-6 row is proven publisher → storer → reader in process, and aMule's own type-6
  publish is captured at
  `crates/rmule-kad/tests/fixtures/firewalled/captured/amule-233-publish-source-type6-20260923/`.
- New dependencies: `librqbit-utp` (Apache-2.0), `librqbit-dualstack-sockets` (Apache-2.0),
  `quinn` and `quinn-proto` (MIT OR Apache-2.0), `rcgen` (MIT OR Apache-2.0), `rustls`
  (Apache-2.0 OR ISC OR MIT); all compatible with GPL-3.0-or-later (ADR-0004).
- ed2k-server keys `observed_udp_ports` by IPv4 address alone (`4da4774`), so two NAT-T clients
  behind one NAT overwrite each other's observed port; that is the server's to fix.

## Considered options

- **uTP only, QUIC deferred.** Rejected: both ship; the bit-4 gate keeps the 1500 ms cost off
  peers until QUIC is proven.
- **Kad-buddy coordinator only.** Rejected: it drops the only coordinator that works without Kad.
- **The eServer-buddy family too.** Rejected: nine more opcodes, no oracle, a `0xB3` overlap.
- **0.72a's `0xB3` / `0xD0`–`0xD7` tunnel for the server path.** Rejected: a second transport
  family with no Linux-buildable counterparty; the server does not care which is used.
- **Gate the punch on a NAT-type verdict.** Rejected: rmule has none, and RFC 8489 says not to.
- **NAT-T last after every callback, with no scheduling.** Rejected: it leaves the timing failure
  unaddressed and Low-ID↔Low-ID dropped.
- **Relay for anyone, as eMuleAI.** Rejected: a counterparty-defect pattern.
- **A side datagram so the buddy can see the client-UDP mapping.** Rejected: no stock buddy reads
  it; one shared socket makes the mapping a buddy already observes the right one.
- **A 120 s wait on one `connect()`.** Rejected: the library sends each opener once, so most of
  the wait is dead time.
- **A trigger that dials every expectation behind an address.** Rejected: one unauthenticated
  datagram must not fan out into several dials.
- **Keep the 30 s slot release on the punch road.** Rejected: it left the server → buddy
  fall-through 18 s after the 12 s silence, against eMuleAI's 120 s per-source budget.
- **A Prediction Plan on the Responder road, or for a claimed target.** Rejected: any stranger
  knowing a buddy pairing could open 256 sockets per introduction with no attempt of ours behind
  it.
- **An observed-versus-advertised mismatch as the prediction trigger.** Rejected: no coordinator
  tells a node its own observed port, and the mismatch conflates a port-remapping
  endpoint-independent NAT with an endpoint-dependent one.
- **One `rmule-natt` crate.** Rejected: inverted layering over three protocol families.
