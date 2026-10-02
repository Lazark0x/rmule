# Core owns the startup join, with aMule's Kad join mechanics and the ed2k→Kad handoff

## Context

A citizen daemon joins its networks by itself. aMule starts eD2k and Kad
independently and in parallel, each gated only on its own preference and on IP-filter
readiness
([amule.cpp#L565](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/amule.cpp#L565),
[#L598](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/amule.cpp#L598),
[#L1978](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/amule.cpp#L1978)),
with `ConnectToED2K`, `ConnectToKad` and `Autoconnect` all defaulting to true
([Preferences.cpp#L1061](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/Preferences.cpp#L1061),
[#L1026](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/Preferences.cpp#L1026)).
Left to each caller, that policy would be rebuilt, or missed, in every front-end.

The Kad side has three ways to find its first contacts: configured seeds and the
`nodes.dat` files of ADR-0066, the peer handoff from eD2k, and a persisted routing
table. A node that holds contacts without ever greeting them is invisible to the
network: a `nodes.dat` merge adds contacts with no round trip, and a counterparty
learns of a node only when that node's own `HELLO_REQ` reaches it
(`Process2HelloRequest` → `AddContact2`, `KademliaUDPListener.cpp:577-649`). A node
seeded only by merge and with no greeting pass emits nothing and never joins.

aMule citations below without a link are to the kno/amule fork at `ab483654`.
Evidence: the cold-start and handoff flows in
`tools/interop-harness/src/flow/bootstrap/` (`http_cold_start.rs`,
`ed2k_kad_handoff.rs`) drive rmule against the pinned aMule and prove the fetched
bytes and the handoff join a live bench.

## Decision

**The Join Sequence lives in core** (`rmule_core::run_join_sequence`). On session
start it runs, in order:

1. **Load persisted state** — the managed server list from rmule's store.
2. **First-run server.met fetch** (ADR-0065) — only when the list is empty, eD2k is
   being joined, and the operator switch is on. A failed fetch is one-shot and
   non-fatal: the joins still proceed and eD2k idles on an empty list.
3. **Kad seed resolution** (`acquire_kad_seeds`) — read the persisted `nodes.dat`
   the running node writes and merge its contacts straight into the routing table;
   only if nothing seeded it, run the one-shot `nodes.dat` acquisition, gated by
   `should_auto_fetch_nodes_dat` over `BootstrapConfig::auto_fetch_nodes_dat`, which
   defaults **off** (aMule's `UpdateNotesDat` is user-triggered only).
4. **Parallel independent joins** — eD2k and Kad (`CoreCommand::EnableKad`), each
   gated only on its own switch in `JoinConfig`, both defaulting on and overridable
   per network. No eD2k-before-Kad dependency is invented. The Kad join fires whether
   or not seeds were found, because an empty-table node is what arms the handoff.

A Kad node with an empty routing table and an empty dial list idles with a named
event — aMule's "please bootstrap, or download a nodes.dat file"
([RoutingZone.cpp#L221](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/routing/RoutingZone.cpp#L221)).

**Kad join mechanics, at aMule's cadence** (`KadNode`, `rmule-kad`):

- **Self-lookup.** A forced `FindNode(own Kad ID)` 3 minutes after start
  ([Kademlia.cpp#L100](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/Kademlia.cpp#L100)),
  then every 4 hours
  ([#L200](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/Kademlia.cpp#L200)).
- **Dial loop.** Configured endpoints and v3 bootstrap-file contacts feed one
  Bootstrap Dial List. While not joined and the list is non-empty, the node pops the
  front contact, sends `KADEMLIA2_BOOTSTRAP_REQ` and discards it — every 15 s, or
  every 2 s while the routing table is empty
  ([Kademlia.cpp#L284](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/Kademlia.cpp#L284)).
- **Joined predicate.** aMule's `IsConnected` = `HasHadContact`: any Kad datagram
  received within the last 20 minutes (`KADEMLIADISCONNECTDELAY`,
  [Kademlia.h#L76](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/Kademlia.h#L76),
  [kad/Constants.h#L43](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/include/protocol/kad/Constants.h#L43)),
  stamped on every packet accepted at the entry gate of ADR-0064. It gates the dial
  loop and the idle event. The silent→heard transition is `KadEvent::HadContact`,
  the observable the diagnostics snapshot reads.
- **Small-timer hello pass with per-contact aging.** aMule's `CRoutingZone::OnSmallTimer`
  runs every minute for every zone with no `IsConnected` gate
  (`Kademlia.cpp:187,277-280`). rmule's driver arms the pass at join start
  (`arm_small_timer`): it fires 1 s after start, then every minute. Per non-empty
  bucket it looks once at the oldest entry: a due contact gets one hello and a
  2-minute check window and stays at the front; a contact not due moves to the back.
  The routing-table entry (not `KadContact`, which is also a wire row) carries two of
  aMule's `CContact` fields (`Contact.cpp:67`): `expires`, and `created`, which sets
  the answer window to 1 h under an hour old, 1.5 h in the second hour and 2 h after
  (`UpdateType`, `Contact.cpp:101-119`). A contact becomes alive only when a live
  datagram updates a contact already held — a hello request, a probe's hello
  response, or a bootstrap answer's sender — and every first admission starts fresh,
  so it is greeted back once.
- **Two hellos before eviction.** aMule's `CheckingType` steps a due contact's type
  and its dead-entry sweep removes it only at type 4 (`Contact.cpp:87-99`,
  `RoutingZone.cpp:960-968`), which gives the common type-2 band two unanswered
  hellos. `ContactAging::checks` counts unanswered checks and an answer clears it; a
  due contact that has used its two checks is evicted in the same look. A small-timer
  probe does not evict on `PROBE_TIMEOUT` (`evict_on_timeout: false`); every other
  probe — join validation, firewall re-verification — still does.

**The ed2k→Kad handoff.** When an eD2k peer's hello or mule-info tags yield a Kad
endpoint, aMule calls `CKademlia::Bootstrap(ip, kadPort)` on the spot, when
`KadPort ∧ KadVersion > 1`
([BaseClient.cpp#L716](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/BaseClient.cpp#L716)),
and `Bootstrap` dials only while running, not joined, and at least 10 s after the
last bootstrap dial — the same timestamp the dial loop stamps
([Kademlia.h#L91](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/Kademlia.h#L91)).
In rmule the peer session parses the Kad half of `CT_EMULE_UDPPORTS` and the Kad
version (the consume side of the registry of ADR-0047) and emits a peer-Kad-endpoint
fact; core brokers it to the `KadNode`, because protocol crates never talk to each
other; the node applies aMule's gate as written, including the shared 10 s
throttle. The handoff is one-way, as in aMule. A node with zero seeds joins the
moment one eD2k peer connects.

**The app's start.** The TUI does not run the whole sequence, because once core
holds the server-list store the actor is its only writer (ADR-0080). It runs step 2
through the actor and the Kad leg itself:

- **First-run server.met fetch.** At attach, the TUI asks step 2's own gate,
  `should_auto_fetch_server_met`, with eD2k on (the app has no switch that disables it),
  the list as the store holds it, and the operator's `auto_fetch_server_met` (Settings,
  *Fetch list*, default on). When it says fetch, the TUI sends
  `ServerListCommand::UpdateServerList` with the configured mirror: the same acquisition,
  run by the list's one writer, and what Networks' `U` sends. It dials no server.
- **Kad** runs through `acquire_kad_seeds`, the same seed policy. Connecting is the
  operator's act (ADR-0095), and Kad follows it, as below.

The Kad start:

- Kad starts on the run's first eD2k `Connected` edge, which comes only from the
  operator's connect or the connect-at-start preference they set (off by default),
  or on the operator's `K` in Networks. The first-login start is spent once used: a
  reconnect, a server switch or a second login does not restart a Kad the operator
  stopped. Core ignores a second `EnableKad` while a node runs.
- A server disconnect does not stop Kad; the two networks connect and disconnect on
  their own. `c` is the eD2k dial and `K` is Kad's switch.
- The TUI's `nodes.dat` auto-fetch preference defaults **on**, and because Kad starts
  only on the operator's word, the fetch still runs only after the operator asked to
  be on a network. The operator can turn it off in Settings.
- Until Kad starts, the Networks panel reports it off, and the app states the start
  policy once at startup so "off" is not read as "broken".

## Consequences

- Library and headless callers (`rmule-tools`' bootstrap runner among them) get
  amuled's self-starting dual-network join from one call, overridable per network.
- A table-seeded node greets its seeds within about a second, keeps re-reaching an
  otherwise idle table, and loses a good contact only after two missed hellos.
- rmule greets a never-checked contact one pass earlier than aMule: aMule's first
  pass only stamps `m_expires = now`, rmule treats the contact as due at once.
- rmule does not keep aMule's 0..4 type band, because nothing it runs reads it (the
  random-contact and big-timer selections are not implemented). The hello count is
  therefore floored at two for every lapsed contact rather than banded: never fewer
  than aMule, possibly more lenient for a contact that was never verified.
- The rest of aMule's zone maintenance — `OnBigTimer` random lookups, consolidation,
  the type ladder's other readers — is not implemented.
- The deterministic tier owns the timing: the join-sequence truth table, dial
  cadence (15 s / 2 s, pop-one-discard, stop-on-joined), the self-lookup schedule,
  the handoff gate matrix, and mesh-sim cold joins through each seed route.

## Considered options

- **Leave the join to each caller.** Rejected: amuled's self-starting dual-network join
  is out-of-box behaviour; leaving it to callers reproduces the gap per front-end.
- **Join Kad after eD2k in the core.** Rejected: aMule starts the two independently;
  the TUI's "Kad follows the operator's connect" is app sequencing and does not
  change the core.
- **Auto-fetch `nodes.dat` by default in core.** Rejected: aMule's asymmetry with
  `server.met` is deliberate. The TUI opts in, behind the operator's connect.
- **Gate the small-timer pass on not joined.** Rejected: aMule has no such gate, and a
  contact merged into a joined node would go ungreeted for the whole 20-minute
  contact window.
- **Deduplicate handoff dials per peer.** Rejected: aMule's only guard is the shared
  10 s throttle; per-peer memory adds state for no observable difference.
