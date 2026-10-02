# Family-generic peer endpoints, IPv4 kept as a type invariant where the wire packs 32 bits, and two sockets per port

## Context

eD2k was designed for IPv4, but a peer and a server-handed source are family-generic on
the wire: the IPv6 dialect of ADR-0087 carries them as tags and as **Sentinel Source**
records (`0xFFFFFFFF` id). Other wire fields pack an address into 32 bits and stay IPv4 in
every implementation: Kad contacts (the spec keeps Kad IPv4-only end to end), `ClientId`
High-ID packing, the Kad `0x58` / `0x61` observed address and port, the UDP `0x9B`
6-byte record.

A source-list reader that walks a fixed 6-byte stride mis-parses a sentinel record — the
desync aMule has — and turns sixteen bytes of IPv6 address into live sources at arbitrary
addresses. emule-qt `docs/protocol/ipv6-spec.md` §4.4 (lines 694-703) puts a sentinel's
sixteen address bytes inside its own record, as its last field — after the port, and on
`0x44` after the crypt byte and the optional user hash — and emule-qt's reader consumes
them in place (`src/core/transfer/DownloadQueue.cpp:786-797` at `73fff714`). Its own test
vector (`tests/tst_DownloadQueue.cpp:614-645`: a sentinel first, then `88.77.66.55`) is
the shape a misreading reader gets wrong.

A single dual-stack `::` socket behaves differently per OS (`bindv6only`, Windows
defaults) and leaks `::ffff:` mapped addresses into every path.

## Decision

**Widen exactly the concepts that are family-generic on the wire into closed enums; keep
IPv4 as a type invariant wherever the wire packs 32 bits; bind two sockets per port behind
one pump; make every source-list reader sentinel-safe.** Nothing in the workspace panics or
errors on an IPv6 address.

### Types (`rmule-primitives`)

- **`enum PeerEndpoint { V4(Ipv4Endpoint), V6(Ipv6Endpoint) }`**, with an rmule-owned
  `Ipv6Endpoint` wire value (16-byte address and port, `[addr]:port` text, strict decode,
  no flow-info or scope-id). `family()`, `ip()` and `port()` accessors; conversions to and
  from `SocketAddr` exist only at the `rmule-net` edge. Match arms stay exhaustive so the
  compiler lists every family-sensitive site.
- **`enum PeerSource { HighId(Ipv4Endpoint), LowId { id, port }, Ipv6(Ipv6Endpoint) }`** —
  the three things a server can hand back; dialability follows from the variant. Whether
  an `Ipv6` source is dialed is the Dial Chooser's call (ADR-0087): when this node holds no
  IPv6 to dial from, the source is dropped and counted
  (`undialable_family_sources_total`), so an operator's "no sources" is not mistaken for a
  network fault.
- **IPv4 stays a type** for Kad contacts (`KadNodeEndpoint`, `nodes.dat`, routing, verify
  keys), `ClientId`, the `0x58` / `0x61` observations, the `0x9B` record and the credit
  ledger's SUI v2 address. A type is exactly as wide as its wire meaning.
- **State keyed by a peer widens:** the ban store keys `IpAddr`; the IP filter keeps its
  IPv4 ranges and passes IPv6 through with a diagnostics note; diagnostics rows carry
  `PeerEndpoint`. The store persists no peer endpoint.

### Sockets (`rmule-net`, the **Family Pair**)

- **Two sockets per role, same port:** one `0.0.0.0` and one `::` bound
  `IPV6_V6ONLY=1`, for the eD2k listener (`Ed2kListener`), client UDP (`ClientUdp`, which
  Kad shares, ADR-0057) and server UDP (`ServerUdp`). Captures record the true family.
- **One pump per role merges both sockets** and yields `PeerEndpoint`s. The TCP pump is the
  `InboundSource` seam (the accept loop with a one-byte push-back wrapper in place of
  `TcpStream::peek`, for the byte-0 discrimination of ADR-0042); the listener of ADR-0031
  is that pair and pump.
- **Kad rides the IPv4 half only.** The client-UDP demux drops a Kad datagram that arrives
  on the IPv6 half and counts the declared `0xE4` / `0xE5` form as the dialect gap it is. A
  standalone node (the `rmule-tools` drivers, the Stimulus Node, the mesh sim) binds its
  own pair and applies the same rule at its transport.
- **Per-family enable** in config; a family whose bind fails is reported on diagnostics and
  absent, never fatal. There is no retry (ADR-0057): the pair stays as bound until restart.

### A Half-Bound Pair states what it costs

A **Half-Bound Pair** is a role that came up without a family it selected — distinct from a
family never selected, which costs nothing. The consequence table is stated once, in
`rmule_net::family::PairRole::forfeits`, and every consumer reads it:

| Role | IPv4 refused | IPv6 refused |
| --- | --- | --- |
| client UDP | Kad, NAT traversal and the IPv4 UDP advert are off | the IPv6 reask surface is off |
| eD2k listener | IPv4 dials and any High ID are off | IPv6 dials and the IPv6 advert (`CT_MOD_IP_V6`) are off |
| server UDP | the UDP server sweep is off | nothing rides that family |

- The Address Learning bind table (ADR-0084) is the one writer for the client-UDP and
  listener roles: `record_bind` settles the fact beside the families. Server UDP records
  no row there (ADR-0086 explains why none may exist for this role); its `HalfBound` fact
  is recorded in `DiagnosticsState` at its own bind. All three feed
  `DiagnosticsSnapshot::half_bound_pairs` and one
  `CoreEvent::SocketBoundWithoutFamily { half_bound }` at the bind, and the TUI and CLI
  word the type's own consequence rather than their own.
- `EnableKad` on a client-UDP pair without IPv4 is refused with
  `KadUnavailable(KadUnavailableReason::UdpFamilyMissing { family, kind })`.
- **Adverts follow the bound families, not the configured ones.** The Advertised Endpoints
  chooser gates on the bind table, so a pair without IPv4 names no IPv4 endpoint. The
  login's `0xF9` is omitted outright, because its presence is the capability a server reads
  (ADR-0091) and a zero port would be a claim. The hello's `CT_EMULE_UDPPORTS` client half
  is held at `0` by `SharedUdpPortsAdvert::withhold_client_udp` — the wire's own "no reask
  endpoint" — and a word with both halves `0` omits the tag.

### TCP binds with `SO_REUSEADDR`, never `SO_REUSEPORT`

- The pair binds through `socket2`, which sets nothing by default. The TCP listener sets
  `SO_REUSEADDR`, as aMule's listener does (`ListenSocket.cpp:63`,
  `MULE_SOCKET_REUSEADDR` → `LibSocketAsio.cpp:1696`), so a restart inside 2 × MSL binds
  over the `TIME_WAIT` the previous run's closed peer links left on the port. On Linux and
  macOS it admits nothing more: a second listener on the same address and port is still
  refused. eMule's warning against it (`ListenSocket.cpp:1958`) is about Windows, where the
  option lets two listeners share a port.
- `SO_REUSEPORT` is never set: two rmules on one port would split each other's inbound
  peers without either knowing.
- UDP sets neither: a datagram socket has no `TIME_WAIT`, and on Linux `SO_REUSEADDR` lets
  two UDP sockets share a bind.
- A refused bind is not waited out. With the option set, a refusal means a live socket
  holds the port, which a wait does not cure, and the bind runs on the actor, so a wait
  would stall every command. The operator is told: the Half-Bound Pair line, or, when no
  family bound, `ServeStartFailure`'s sentence that the port is in use by another program
  or a second rmule.

### Sentinel-safe source lists (`rmule-ed2k`, `rmule-peer`)

For `OP_FOUNDSOURCES`, `OP_FOUNDSOURCES_OBFU` and `OP_GLOBFOUNDSOURCES`:

- **Records are walked one at a time;** a `0xFFFFFFFF` id consumes sixteen bytes inline,
  after every other field of its record. The encoders write the same layout.
- **An inline address that is not a usable identity** (`is_usable_tag_identity`: loopback,
  link-local, multicast, ULA, mapped, unspecified) costs its record, never the list.
- **A list that does not measure is a Malformed Tail:** a walk that runs short once a
  sentinel has been met (the spec's "any short read MUST abort the rest of the block"), or
  a frame-delimited `0x42` / `0x44` with bytes left over. Only the records before the first
  sentinel are kept, because they sit at the same offsets in any layout. A classic list with
  no sentinel that runs short stays a rejected frame; one with an unexplained trailer keeps
  every record.
- An inline sentinel does desync a stock 6-byte-stride reader, which is why a server sends
  one only to a session that advertised `SRVCAP_IPV6`.
- `OP_REASKCALLBACKTCP`'s IPv6 form is not a source-list sentinel: both counterparties write
  `<FFFFFFFF><ipv6 16><port 2>`, address before port (ADR-0087).

## Consequences

- Core maps and the callback triage of ADR-0039 need only `Copy + Ord + Hash` and work
  unchanged over the enum.
- No `SocketAddr::V6 => unreachable!()` or "expected an IPv4 local address" exists in the
  workspace.
- A lost IPv4 half is visible with its cost on every surface, not one `warn` line.
- Evidence: sentinel-reader known-answer tests (spec bytes, emule-qt's vector, malformed
  tails, the no-sentinel legacy shape), pump merge tests over a fake pair, the
  exhaustive-match compile guard, and the rebind tests
  `family::tests::a_listener_rebinds_its_port_at_once_after_it_closed_a_connection` and
  `a_second_listener_on_a_held_port_is_still_refused`. The capture tier runs on the IPv6
  network of ADR-0092.

## Considered options

- **Wrap `std::net::SocketAddr`.** Rejected: it carries non-wire fields and breaks the
  primitives rule.
- **A generic `Endpoint<A>` over families.** Rejected: every map, event and session becomes
  generic or boxed, for a type-level family nobody consumes.
- **Widen Kad contacts too.** Rejected: no interoperable IPv6 contact format exists, and the
  spec says adding one forks the DHT.
- **One dual-stack `::` socket.** Rejected: OS-dependent semantics and mapped-address
  leakage.
- **A trailing block of IPv6 addresses after the last record.** Rejected: it reads the spec
  backwards and, on emule-qt's own vector, loses the real source and fabricates a High ID
  out of the address prefix.
- **Reject any packet carrying a sentinel.** Rejected: it discards every IPv4 source in a
  packet that names one IPv6 peer.
- **A bounded bind retry.** Rejected: it cures nothing once `SO_REUSEADDR` is set and stalls
  the actor.
