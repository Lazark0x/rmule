# Address Learning: one confidence-tiered store owns our own External Endpoints

## Context

rmule learns its own address from many observers: the server's `OP_IDCHANGE`, the Kad
firewall check's `0x58` observed IP and `0x61` observed port, a port-mapping grant
(ADR-0086), a peer's `CT_MOD_YOUR_IP` vote, and the host's own interfaces. Port mapping
advertises the granted endpoint, the IPv6 dialect (ADR-0087) advertises a *confident* v6
address, and a hole punch (ADR-0091) targets the *observed* port. Three near-duplicate
trust policies, one per consumer, would disagree; so would every cached copy of the
answer that is not refreshed when the answer moves.

Observers are not equally trustworthy. A server's High-ID is literally the address peers
dial. A Low ID is the server saying it could not reach us. Two Kad strangers should not
outvote the server. A peer's claim about our IPv6 is cheap to forge. Some servers write
their own address into the reported-IP field of `OP_IDCHANGE` (ed2k-rust
`src/server/login.rs:132-158` at `4da4774f`, v0.9.75), where eMule and aMule read the
*client's* address as the server saw it (eMule `ServerSocket.cpp:313`, `:350`; aMule
`ServerSocket.cpp:316-332`, `:396-397`).

The IPv6 tiers follow `ModderMule/emule-qt` `docs/protocol/ipv6-spec.md` §2, hardened as
in `amule-org/amule` master `src/PublicIPv6Corroboration.h`. aMule citations without a
link are to the kno/amule fork at `ab483654`.

## Decision

**One core-owned, sans-I/O `AddressLearning` store**, sibling of `Reachability`
(ADR-0058), turns typed `AddressObservation`s into one **External Endpoint** verdict per
(address family, socket role), by descending confidence tier with per-source freshness. A
peer's claim about our address is a vote, never adopted on its own.

### The store

Explicit-time and event-fed: `observe(AddressObservation, now)` in,
`endpoint(family, role) -> EndpointVerdict` out; no socket, clock or channel inside.

- **Socket roles:** `Tcp` (the eD2k listener) and `Udp` — one socket for peer reask,
  NAT-T frames, server status pings and Kad (ADR-0057). One UDP role means a Kad
  `0x58` / `0x61`, the server's observation and a mapping grant all vote on one External
  Endpoint, and a serving buddy's view of us is the view a punch must reach. One port pair
  applies to both families, so a role's port is learned once and the verdict carries
  address and port together. The server-UDP socket is not a role: nobody addresses it.
- **Sources (`ConfidenceTier`), each with its own lifetime:** `Override` (config, never
  expires); `Server` (session-bound: the `OP_IDCHANGE` High-ID for v4, the server's
  `CT_MOD_YOUR_IP` on an IPv6 session for v6); `KadCheck` (`0x58` IP, `0x61` port; a
  sliding 30-minute window); `PeerVote { observer }` (`CT_MOD_YOUR_IP` in a hello;
  30 minutes); `MappingGrant` (a PCP / NAT-PMP / IGD lease's external address and port,
  for the lease's life); `LowIdReport` (the address a Low-ID login reported); `Interface`
  (a global-unicast address on a local interface, until the next refresh).
- **Freshness before ranking:** an observation backs a rung, or votes in a quorum, only while
  it is inside its own window. A lapsed backer never holds a fresh report, and lapsed votes
  never outrank fresh ones: a value is chosen from fresh observations first, and only when
  none holds is the most recent lapsed one the stale last-known.
- **Port 0 is no port.** A port observation of `0` is refused at `observe`
  (`ObservationOutcome::PortZeroRefused`). aMule records it (`Prefs.cpp:280`); rmule refuses
  it because a `0` would also count as a dissenting port in the Own Mapping (ADR-0091).
- **Verdict:** `Known { endpoint, tier }` while a fresh tier holds; `Stale { endpoint,
  since }` when every source has aged out but a last value exists; `Unknown` otherwise.
  Adverts, hello and login tags and Kad publishes require `Known`; the UDP crypt keys
  (ADR-0046) may use `Stale`, so a server reconnect never blanks a key mid-reask.

### IPv4 ladder

`Override` > `Server` (High-ID, while the session lives) > `KadCheck` > `MappingGrant` >
`LowIdReport` > `Interface` (a public IPv4 held locally, the no-NAT case).

- The `KadCheck` **address** rung needs two consecutive agreeing reports; a disagreement
  resets the candidate (aMule's `0x58` guard).
- The `KadCheck` **port** rung is two-of-the-round: the newest report is backed by any
  earlier report of the current round that names the same port, so 5000, 6000, 5000
  adopts 5000, as aMule's `SetExternKadPort` compares each answer with every earlier one
  (`Prefs.cpp:291-324`). Each round starts empty, as `FindExternKadPort(true)` does
  (`Prefs.cpp:305-322`): `KadNode` emits `KadEvent::ExternPortRoundStarted` when it
  restarts an armed UDP self-check, and the store answers with
  `forget_kad_port_round(SocketRole::Udp)`, withdrawing only that rung. The learned port
  stands until the new round settles one.
- `learned_port(role)` answers the port alone — the best fresh port tier with no fallback
  to the bound port — because the Kad UDP self-check waits on exactly that answer before
  engaging a helper.
- **The port ladder learns from IPv4 endpoints only.** An IPv6 pinhole grant translates
  nothing, so its port is always the bound one; recording it would overwrite the IPv4
  NAT's mismatched port. An IPv6 observation records its address alone.
- **A Low-ID report is the weakest claim, not the strongest.** It names no port, is
  absent from the IPv6 ladder, and is single-valued and session-lived like `Server`: a
  session end leaves it stale, a High-ID login withdraws it, a Low-ID login withdraws
  `Server`. A Low-ID report equal to the connected server's own address is refused and
  logged; a server is never us. With no Kad check and no grant, the report is still the
  only fresh rung and is adopted, as aMule's `SetPublicIP(dwServerReportedIP)` does, so
  the crypt keys it feeds stay armed.
- `CT_MOD_YOUR_IP`'s integer (IPv4) form is refused as a source, following kno's aMule and
  emule-qt. Behind NAT the external IPv4 is never on a local interface, so the tier order,
  not an interface filter, is the IPv4 defence.

### IPv6 ladder

`Override` > `Server` reflection on an IPv6 session > `PeerVote` quorum > `Interface`
(the first global-unicast address).

- **Quorum:** three distinct observers within 30 minutes, eight observers remembered,
  keyed on the observer's `AccountingKey` (the IPv4 address, or the IPv6 `/64`) — the
  keying `interval_limiter` applies to the same senders — never on its user hash. One
  delegated prefix mints any number of `/128`s, so per-address keys would let one host be
  a quorum.
- **Security control:** a reflected address (server or peer) is adopted only if it is
  also assigned to a local interface; corroboration only picks which of our own addresses
  the outside world sees. A vote for an address this host does not hold is refused at
  record (`ObservationOutcome::UnheldPeerVoteRefused`), as kno keeps no state for an
  unheld value (`PublicIPv6Corroboration.h:201-207`), so unheld votes cannot evict honest
  ones. Adopted addresses are re-validated on every interface refresh and dropped on
  renumbering or RFC 4941 rotation.

### Disagreement is a fact

When two fresh tiers disagree (the server says A, the gateway granted B, Kad sees C), the
higher tier wins and the disagreement is published on the diagnostics level as a
`NatHint` (double NAT, CGNAT, hairpin) — never silently overwritten, never only logged.
A refused reflection is a hairpin only when it names an address this host holds, or
loopback: the store keeps every enumerated interface address for that question, beside the
publicly usable set the tiers read. A private address nobody here holds is refused with no
hint.

### Seams

- **Reachability keeps "can I be reached"; Address Learning keeps "where am I".**
  `Reachability` holds a per-family IPv6 verdict — `Unknown | ProbedReachable |
  ProbedUnreachable`, fed by the server's `ST_IPV6_STATUS` and cleared on disconnect —
  beside its Kad-fed IPv4 TCP and UDP verdicts.
- **One chooser**, `advertised_endpoints()`, combines `Known` verdicts with
  `Reachability` to decide the connect-option bits of ADR-0047, the hello, login and ExtSX
  tags, and the Kad publish tags. No advert site reads either store ad hoc.
- **Interface enumeration** is an I/O seam in `rmule-net` behind `InterfaceSource`,
  polled at startup, on every server connect and every five minutes; the testkit fakes it.
- **Override** is the per-family `CoreConfig::external_address` field. **Diagnostics** publishes, per
  (family, role), the verdict, tier, freshness and any NAT hint.

### One owner of the Own Address

Address Learning is the sole owner of the node's **Own Address** — per family, the
external IP and the external port of each socket role. A reader reads the owner at use, or
subscribes to it; nothing else holds the value. A change is one event, the **Own Address
Generation** (`own_address_changed()`, a `watch` on `SharedAddressLearning`), bumped by
every write whose projection moved — per family the fresh-or-stale and the fresh address,
per (family, role) the verdict, and the learned ports. A withdrawal is a change to "none".
Time is the one edge a write cannot announce, so a subscriber that caches re-derives on a
clock as well as on the event; a reader at use needs no clock.

| Holder | Role | aMule counterpart |
|---|---|---|
| `AddressLearning` behind `SharedAddressLearning` | **the owner**; written by the server session, the Kad pump, the port mapper, the interface poll, the override and peer votes | `CamuleApp::m_dwPublicIP` (`amule.cpp:1469-1479`) and Kad `CPrefs::m_ip` (`Prefs.cpp:143-158`), joined by `GetPublicIP()` at every read (`amule.cpp:1455-1466`) |
| `SharedOwnIdentity::public_ip()` / `public_ipv6()` | a read-at-use projection, for the UDP crypt keys and the `RequestTCP` self-connect guard | `theApp->GetPublicIP()` per use |
| `KadNode` verify-key IP and routing-table own IP (sans-I/O) | a cache, restated by the Kad pump's reconciler (**Kad Pump State**) whenever the sampled owner differs from what the node holds — sampled at Kad start, on each Own Address Generation, after the pump's own `0x58` write, and on the 30 s recruit tick; a withdrawn IPv4 restates `0.0.0.0` | `CKademlia::GetIPAddress()`; key halves read `GetPublicIP()` per use (`Prefs.cpp:234-243`) |
| `KadNode::udp_extern_port` | a cache, restated by the same reconciler after every `0x61` observation (the same value or not), and whenever it moved at Kad start, on each generation and on the recruit tick | `CPrefs::m_externKadPort` (`Prefs.cpp:280-324`) |
| `SharedIpv6Advert` | a view over the store and the server's probe cell, settled at each read (hello `CT_MOD_IP_V6`, login `SRVCAP_IPV6`, Kad `ip6`, the Dial Chooser's rung 0) | kno's `ObservedPublicIPv6()` read by reference (`PublicIPv6Corroboration.h:424-428`) |
| `SharedUdpPortsAdvert` client-UDP half | holds only the bound port and projects it through the chooser at every read | `GetEffectiveUDPPort()` per hello (`BaseClient.cpp:1062`) |
| Port mapper's Desired Mapping Set | re-derived on the generation and on a 30 s clock | — |
| `DownloadState`'s `DialPosition` | a sans-I/O sample, re-read on the 1 s reask sweep and at each dial | — |
| Diagnostics `AddressDiagnostics` | read at snapshot | — |
| `ConnectedSession::client_id` | the server's ID for the session, read at use; the same event writes the `Server` rung | `CServerConnect::GetClientID()` |

The Kad UDP verdict's port (`KadUdpVerdict::Open { port }`) is not an own-address holder:
it is the port the verdict was proven for, evidence rather than a claim about now.

`KadNode::set_extern_udp_port` treats a zero answer by the round's state: while the Extern
Port Round still collects, a zero stands aside (a later report may settle an early
disagreement); once the round is not collecting, a zero is the store's own verdict and
writes through.

## Consequences

- Every consumer reads one verdict; no trust policy is duplicated, and no copy of our
  address survives a change.
- A client that can parse IPv6 sources but holds no confident IPv6 of its own cannot tell
  a server so — the spec's asymmetry stays.
- A client behind the same hairpin NAT as its server loses the Low-ID report rung and
  learns its address from a grant or the Kad check.
- Evidence per ADR-0045: the deterministic tier covers the ladders, quorum, freshness,
  security filter, round scoping and the NAT-hint matrix; the capture tier runs in the
  NAT-gateway and IPv6 harness of ADR-0092 (server A against gateway B, peer votes against
  local interfaces).

## Considered options

- **Fold the store into `Reachability`.** Rejected: different questions, sources and
  lifetimes; every Reachability consumer would see address churn.
- **A source-agnostic majority vote.** Rejected: two Kad strangers could outvote the server
  that assigned our High-ID.
- **The spec's v6 constants verbatim (three votes within 300 s).** Rejected: on a quiet
  client the first vote expires before the third arrives (kno's finding); 30 minutes is
  interoperable and strictly safer.
- **Local interface addresses only, no reflection.** Rejected: wrong on multi-address
  hosts, where only corroboration picks the address the world sees.
- **Addresses only, ports learned where they are used.** Rejected: the two-agree rule
  would exist three times — Kad, the port mapper, the punch.
- **Hard reset to `Unknown` on top-tier loss.** Rejected: it blanks the crypt key on every
  server reconnect.
- **A Low-ID report at the `Server` tier.** Rejected: it let a misbehaving server's own
  address outrank a correct grant and Kad check.
- **No expiry on the Kad port**, as aMule. Rejected: the store's tiers expire, and a cache
  that keeps an expired answer is a second copy that can disagree.
