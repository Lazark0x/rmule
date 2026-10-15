# Port Mapping: PCP, NAT-PMP and UPnP raced, graded on the exact external port, and acting on Reachability

## Context

A firewalled home node is the common rmule deployment. It is Low ID on every server and
Kad-firewalled, so every transfer it makes is brokered, and `Reachability` (ADR-0058) can
observe that verdict but cannot change it. Port mapping turns such a node High-ID and
Kad-open by itself.

eD2k adds one hard constraint: the hello and the login advertise one TCP port and have no
external-port tag, so a mapping granted on a different external port is a silent Low ID.
A UDP grant on a different port is still useful: it is the fact Kad's extern-port rule
learns (ADR-0084).

Reference behaviour is emule-qt's `PortMapper` (read for facts, never ported, ADR-0082),
RFC 6887 (PCP), RFC 6886 (NAT-PMP) and UPnP IGD. Two IPv6 facts shape the design: RFC 6887
§8.2 has the server answer `ADDRESS_MISMATCH` when a request's source differs from its PCP
Client IP field, and §8.4 says global addresses SHOULD be the source; and an IPv6 default
route goes via a link-local next hop on every SLAAC network (Router Advertisements come
from link-local addresses, RFC 4861 §4.2), so the kernel picks a link-local source. A
request bound to `::` therefore leaves from `fe80::…` with a GUA in its header and is
refused: `ADDRESS_MISMATCH` on miniupnpd (`pcpserver.c` `ValidatePCPMsg`), `NOT_AUTHORIZED`
on a FRITZ!Box (emule-qt `UdpMappingBackend.cpp:239-241`, `73fff71`). `crab_nat` 0.8.1
binds the unspecified address with no source option (`src/lib.rs:384-406`).

Evidence: the `portmap-highid`, `portmap-mismatch`, `portmap-ipv6-pinhole` and
`portmap-ipv6-pinhole-link-local` flows in `tools/interop-harness/src/flow/nat/portmap.rs`,
run against a miniupnpd gateway behind the NAT harness of ADR-0092 and stock aMule 2.3.3:
a grant lands, the helpers dial the mapped port back and the Kad verdict reads open; over
a link-local next hop every PCP request leaves from the Known IPv6.

## Decision

A sans-I/O **`PortMapper`** in `rmule-core` races PCP, NAT-PMP and UPnP-IGD concurrently,
trials the survivors with real mappings, grades each trial on the exact external port,
keeps the best, renews per mapping on the RFC ladder, validates gateway epochs, and — unlike
both references — fires a reachability recheck the moment an Exact grant lands.

### What is mapped

The **Desired Mapping Set** is derived, never configured: one mapping per Family Pair
(ADR-0085) rmule actually bound — the eD2k TCP listener and the one client-UDP socket that
Kad, reask and NAT-T share — per family. IPv4 rows are NAT mappings; IPv6 rows are PCP
pinholes, present only while a Known IPv6 exists (ADR-0084). A firewalled dual-stack node
therefore wants two rows per family. Server UDP is never mapped: every datagram it receives
answers one we sent, so our own packet opens the binding. Its Half-Bound fact is therefore
kept out of the Address Learning bind table the derivation reads (`SocketRole` has only
`Tcp` and `Udp`) and recorded beside it in `DiagnosticsState`. The set is re-derived on the
Bind Generation and on a 30 s clock.

**An IPv6 row names its Known IPv6** (`DesiredMapping.pinhole`), not the route table's pick,
which may be a different privacy address or a ULA. The address is part of the row's
identity, so a Known IPv6 that moves takes the old row out of the set: it is released from
its own address and a new row is mapped, as RFC 6887 §8.4 recommends.

### The race and the grade

- All enabled backends probe concurrently; the preference order (PCP, NAT-PMP, UPnP) only
  breaks ties. Grace is 3 s, extended once to 15 s while a backend is still working and
  nothing is available (miniupnpc's description fetch takes about 7 s on an ordinary LAN). A
  probe answering after the round closed is adopted if the round ended empty.
- A trial asks for, and is graded on, only the rows its protocol can express. Each family
  is graded **Exact** (every row granted on its own port) > **Mismatched** (all granted,
  some port differs) > **Partial** > **None**. A trial's standing is two grades compared in
  order: the **lead family** — IPv4 whenever the set wants it, since the hello, the High-ID
  and Kad ride on it — then the other. PCP, the one protocol that can pinhole IPv6, is
  trialled first.
- `Exact` on the lead family ends the race and fires the recheck. Otherwise the best trial
  wins and the losers' mappings are released.
- **Only a winner that granted every row on its own port is remembered** as the learned
  method and probed first next run. Any other winner is re-raced: the other enabled
  protocols (never the incumbent) are probed and trialled every 30 minutes, or at once when
  the winning round was the learned method's short round. The incumbent keeps its leases
  and renews throughout; a challenger replaces it only on a strictly better standing, and a
  re-race that finds nothing better releases the challenger's grants.
- **A mismatched TCP grant is `Degraded`** and never advertised. **A mismatched UDP grant
  flows into Address Learning** as a `MappingGrant` for the `Udp` role, and the Kad
  self-check verifies it. The port ladder learns from IPv4 grants only (ADR-0084). An
  external address that is not publicly routable (CGNAT `100.64/10`) also grades
  `Degraded`, shown as what it is.
- Both UDP backends suggest the internal port as the external one; PCP `PREFER_FAILURE` and
  `FILTER` are not sent — grading after the fact learns what the router would give.

### Leases, renewal, failure

- Ask 3600 s; the requested lease is clamped to 120 s – 24 h, because a lease of zero is a
  delete in both UDP protocols (RFC 6887 §15, RFC 6886 §3.4); a granted lease is clamped to
  24 h (30 minutes on an error hold-off) against a spoofed `0xFFFFFFFF`.
- One renewal timer per mapping on the RFC 6887 §11.2.1 ladder with jitter (NAT-PMP:
  half-life; a permanent IGD1 lease is re-verified every 30 minutes; floor 4 s), the same
  for IPv4 and IPv6.
- PCP and NAT-PMP epochs are validated (§8.5 drift and reordering tolerances); a reset
  re-adds every mapping 100 ms apart.
- No protocol available, or every trial `None`: back off 30 s → 30 minutes. Three
  consecutive renewal failures on one mapping: a full reprobe. The first Low ID after a
  High ID triggers one reprobe.
- **A reprobe drops held leases without a release**: a row being re-raced is not leaving the
  set, and a release aimed at a gateway that is not answering buys nothing. **A row that
  leaves the set** (its socket re-bound or stopped) is released before the replacement's
  map, so a vacated port does not stay forwarded. **A row that survives a set change keeps
  its lease** while the set is re-raced, so a quit mid-race still releases it; when the
  race installs a winner that does not re-grant that row under the lease's protocol, the old
  lease is released rather than overwritten.
- Mappings are released on exit (configurable). A pinhole whose Known IPv6 lapsed entirely
  has no row left to diff and is left to its lease.

### Every grant has one owner and one end

A gateway grant lives in exactly one of four places inside rmule, and each place names its
key and every way the grant leaves it.

| holder | key | holds |
|---|---|---|
| **lease table** | the desired row (role, family, internal port, pinhole) | the installed protocol, external endpoint, lease and renewal rung |
| **open trial** (the one in flight and the completed ones of the open race) | (protocol, desired row) | grants a race has not installed yet |
| **challenger** | (protocol, desired row) | a re-race's trials, while the incumbent stays in the lease table |
| **`MappingGrant` observation** (ADR-0084) | the family's address ladder; the role's port ladder, IPv4 rows only | what a `Mapped` lease fed Address Learning, fresh for its lease |

A gateway keys its own mapping differently per protocol. PCP and NAT-PMP key it by internal
port and transport: a renewal granted on another external port **moved** the one mapping,
and a delete names the internal port. UPnP keys it by external port and transport: a
renewal granted on another external port is a **second** mapping, so the old external port
is released when the lease moves.

Ends, each with what it does to every holder:

- **Renewal answered**: the lease and the observation take the new grant; under UPnP a moved
  external port releases the old one.
- **Departure** (the row left the set, including the set emptying): release, drop the lease,
  withdraw the observation.
- **Reprobe** (operator recheck, smart-LowID, three renewal failures): drop the lease with no
  release (above) and withdraw the observation.
- **Set change** for a surviving row: the lease stays until the race installs; an install
  that does not re-grant it releases it and withdraws the observation.
- **Interrupted race** (a set change, reprobe or quit while trials are open): every grant the
  open trials and the challenger hold is released. An answer that lands for a trial no
  longer open, and names no held lease of its protocol, is released on arrival.
- **Quit**: release when release-on-exit is set; withdraw always.

A withdrawal takes the role's port-ladder grant (an IPv6 row never fed one), and the family's
address-ladder grant only when no other `Mapped` lease in that family remains. The learned
method is the mapper's current value: a race that remembers none (a non-Exact win, a failed
short round, a backoff) clears the stored row as well.

Every call and phase has a deadline. The runtime runs every probe and map under a 20 s
backend deadline, answered as `Timeout`. A probe round closes at 3 s or 15 s. A trial
closes 25 s after its maps went out, its unanswered rows counted as `Timeout`. A renewal
advances its rung when it is sent and never waits. A release is fire-and-forget, and the
exit pass gives the releases 2 s. Nothing the runtime answers can be lost: a call that
never left (no route) is fed back to the mapper directly, the result inbox is awaited, and
the operator's reprobe is a coalesced flag rather than a slot in the 8-deep punched-path
pin inbox.

### Acting on Reachability

A fresh lead-family `Exact` grant, and an epoch reset that re-added the set, each issue a
core-side `RecheckReachability` that reaches the sans-I/O `KadNode`. Guards match emule-qt's
`recheckFirewalled`: one helper lookup at a time, buddy search deferred five minutes, the
next scheduled check an hour out, and at most one externally triggered recheck per five
minutes — a trigger inside that window is deferred to its end, never dropped (ADR-0095). A
recheck re-opens the check's emission budget and hello-probes a bounded set of contacts to
spend it (ADR-0058). Renewals never trigger one. A re-race that improves only IPv6 does not.
The operator's **recheck** command does both halves — re-race the mappers and recheck Kad —
because "am I reachable" and "is my port forwarded" are one question to a user.

### Listen, map, then log in

aMule binds its listener, then its UDP socket, then maps both, and only then autoconnects
(`amule.cpp:1631`, `:1705`, `:1739`, `:1310`); eMule defers its connect while UPnP works
(`EmuleDlg.cpp:1963-1970`). rmule keeps the order for every session:

- A core built to restore at attach binds the eD2k listener at attach (in the Serve activity,
  ADR-0095), on the Core Settings' TCP port — the port the login, the hello and the Kad TCP
  self-check advertise — so its row and mapping exist before any connect. A failed bind is
  reported (`ServingFailed { Bind }`) and the login still goes out, as aMule's does.
- `ConnectToServer` is the only login. When a Port Mapping runtime runs, the connect task
  waits until the set holds the IPv4 TCP row for the listener's port and that row reads
  `Mapped`, `Degraded` or `Failed`, for at most `LOGIN_MAPPING_WAIT` (10 s, eMule's second
  timer), then dials. It waits on the rows the runtime publishes; with mapping off or no
  backend there is no wait.
- A grant landing after the bound does not re-log in: a re-login ends the session every
  search and lookup rides. The late grant's recheck makes the node Kad-reachable, and the
  next connect logs in High ID.
- With nothing mappable, the Low-ID `Connected` note names the listener's TCP row — not
  forwarded (with the router's last error), forwarded as an endpoint peers cannot use,
  forwarded yet unreached, or not mapped — and the port to forward by hand.

### IPv6: rmule's own PCP `MAP` from a pinned source; no IGD2 pinholes

- **PCP over IPv6 is rmule's own `MAP` exchange** (`crates/rmule-net/src/portmap/pcp_map.rs`):
  a sans-I/O codec and a one-socket-per-request transport bound to the header's own address,
  to a link-local next hop by its scope id. It covers `MAP` to create or renew a pinhole and
  `MAP` at lifetime 0 for the probe and the release; the nonce derivation is the crate's, so
  the requests are byte-identical to the crate's captured ones. IPv4 PCP, NAT-PMP and `PEER`
  stay on `crab_nat`, because an IPv4 next hop is not link-local. If `crab_nat` gains a
  source option, `pcp_map.rs` is deleted and IPv6 returns to the crate, provided the captured
  known-answer test still holds against its bytes.
- **IGD2 `AddPinhole` is not issued.** `igd-next` 0.17.1 does not implement
  `WANIPv6FirewallControl:1`, and the consumer stacks that ship IGD2 pinholes ship PCP beside
  them: miniupnpd always compiles PCP, and OpenWrt's package enables it by default; FRITZ!OS
  answers PCP. The only IGD2-without-PCP case found is miniupnpd with `enable_pcp_pmp`
  turned off by hand. rmule adopts the call only if a router shows the 6FC service without
  PCP; it would need the same pinned source (IGD2 §2.6.3).
- Retransmission is 250 ms doubling to 4 s, four sends, a documented divergence from RFC
  6887 §8.1.1 because the race closes at 15 s. `THIRD_PARTY` is not sent: pinning makes it
  unnecessary, and miniupnpd refuses it unless configured.

### Seams

- **`PortMapper`** (`rmule-core`, sans-I/O, explicit time): the set, race, grading,
  renewal schedule, epoch tracking, backoff and learned method; emits `MappingCommand`s and
  consumes `MappingResult`s; tested against a fake backend.
- **`MappingBackend`** (`rmule-net`) over `igd-next` (UPnP), `crab_nat` (PCP, NAT-PMP) and
  `pcp_map` (IPv6 PCP). `rmule-net` owns what `crab_nat` leaves to the caller: epoch
  validation, the retransmit ladder, IPv6 source pinning, one socket per attempt.
- **`GatewaySource`** (`rmule-net`): default-gateway lookup via `netdev`, with the scope id
  of a link-local gateway; faked in the testkit.
- **Config**: `PortMappingMode` `Off | Auto` (default **Auto**) is the operator's setting,
  `CoreSettings::port_mapping`; the engineering knobs are `CoreConfig::port_mapping`: a
  protocol mask in emule-qt's encoding (1 = PCP, 2 = NAT-PMP, 4 = UPnP; all by default),
  lease seconds, release on exit.
- **Diagnostics** per mapping: `NotMapped | Probing | Mapped | Degraded | Failed`, method,
  external endpoint, lease, next renewal, last error; the TUI and CLI read this level, and
  the Run Log writes it.

## Consequences

- A headless node behind an ordinary home router becomes High-ID and Kad-open with no
  settings touched, and learns it within seconds rather than at the next hourly check.
- `KadNode` has an externally triggered, rate-limited recheck entry point.
- Dependencies: `igd-next` (MIT), `crab_nat` (MIT), `netdev` (MIT). `igd-next` pulls
  `attohttpc` (MPL-2.0) unconditionally — the first non-MIT/Apache/BSD crate in the tree. It
  carries no Exhibit B, so it is Secondary-License compatible and the GPL-3.0-or-later
  distribution is unaffected (ADR-0004 asks dependency review to check).
- The mapping knobs live on `CoreConfig`. The `rmule` TUI surfaces only the mode, as the
  Settings row *Port mapping* (on = `Auto`, the default; stored as the `port_mapping`
  preference). Core starts the mapping runtime once, when it is built, so the row takes
  effect at the next start. The protocol mask, lease and release on exit are not surfaced.
- PCP to a link-local next hop is at parity by construction and measured on the bench; the
  refusal the old path would meet is cited from miniupnpd's source, not measured.

## Considered options

- **n0 `portmapper` alone.** Rejected: IPv4-only, one port, and its PCP path suggests no
  port, so it cannot grade Exact.
- **Hand-rolled PCP / NAT-PMP codecs throughout.** Held in reserve and drawn only for the
  IPv6 `MAP` slice; `crab_nat` round-trips MAP and PEER correctly and is MIT with no `unsafe`.
- **Exact-only via `PREFER_FAILURE`.** Rejected: loses the UDP-mismatch fact and what the
  router would grant.
- **No automatic recheck, as both references.** Rejected: a headless node would sit
  Kad-firewalled for up to an hour after a successful mapping.
- **Recheck on every renewal.** Rejected: a helper lookup every half hour per mapping
  pollutes the flood limiter's view of us.
- **Default off, as aMule.** Rejected: it forfeits the win for every operator who never opens
  settings.
- **Grading every row against every backend.** Rejected: an IPv4-only backend graded
  `Partial` on a dual-stack host with every IPv4 row exact, so the recheck never fired, and a
  PCP trial with a shifted TCP port could beat an all-exact UPnP trial.
- **Waiting for the mapping without a bound, or re-logging in on a late grant.** Rejected: a
  router that never answers must cost seconds, not the session.
- **Waiting for `crab_nat` to add a source option.** Rejected: IPv6 port mapping would stay
  broken on real routers for an unknown time.
