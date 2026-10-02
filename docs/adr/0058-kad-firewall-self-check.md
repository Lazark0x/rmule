# rmule runs and answers aMule's Kad firewall self-check, TCP and UDP

## Context

Every firewalled-adjacent behaviour (buddies, direct callbacks, crypt gating, the reask
gate of ADR-0057, the publish row type) depends on knowing whether rmule is reachable.
aMule learns it two ways: a server's High ID, and Kad's firewall self-check, which works
without a server and also covers UDP. The Kad check is a set of opcodes:
`KADEMLIA_FIREWALLED_REQ` (`0x50`), `KADEMLIA_FIREWALLED2_REQ` (`0x53`),
`KADEMLIA_FIREWALLED_RES` (`0x58`), the legacy `KADEMLIA_FIREWALLED_ACK_RES` (`0x59`),
`KADEMLIA2_FIREWALLUDP` (`0x62`), plus two TCP legs on the peer socket,
`OP_KAD_FWTCPCHECK_ACK` and `OP_FWCHECKUDPREQ` (`0xA7`)
([ClientTCPSocket.cpp#L1795](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientTCPSocket.cpp#L1795)).

Evidence: `crates/rmule-kad/tests/fixtures/firewalled/captured/` holds aMule's checks
and answers, including `amule-233-udp-firewall-check-20260923` (aMule's `0xA7` to an
rmule helper and the `0x62` it accepted), and
`crates/rmule-net/tests/fixtures/kad_fwcheck/captured/amule-233-required-dialback-20260929`
holds aMule's obfuscated dial-backs.

## Decision

rmule runs aMule's full self-check, answering peers' checks and running its own, TCP and
UDP. The sans-I/O `KadNode` owns every counter and timer with explicit time (ADR-0043);
core brokers the cross-surface legs (TCP dials, the peer-socket packets) through typed
commands and completions, so the peer session stays Kad-ignorant and the Kad crate stays
socket-free.

### TCP check, requester

- **Cadence.** Recheck hourly
  ([Kademlia.cpp#L196](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/Kademlia.cpp#L196));
  a recheck snapshots the last state and zeroes the counter
  ([Prefs.cpp#L176](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/Prefs.cpp#L176)).
  A fresh node starts at zero, so its first hellos carry checks. A port-mapping grant
  also triggers a recheck (ADR-0086); a trigger refused because a round is running still
  runs the probe pass.
- **Emission** rides hello traffic while fewer than `KADEMLIAFIREWALLCHECKS` (4) checks
  are out: a Kad v7+ contact gets `0x53 <tcpport2><userhash16><connectopts1>`, an older
  one `0x50 <tcpport2>`
  ([KademliaUDPListener.cpp#L162](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/net/KademliaUDPListener.cpp#L162)).
  Because rmule's hello cadence is not aMule's every-second zone timer, a recheck
  hello-probes a bounded set of contacts, capped at the budget. The connect options carry
  the crypt bits of the publish byte, and the User Hash is written in aMule's
  `WriteUInt128` order (four little-endian words), so a crypt-enabled helper can dial back
  obfuscated (ADR-0046). Each check opens a **180 s window** on the target's IP
  ([ClientList.cpp#L1042](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientList.cpp#L1042)).
- **Consumption.** `0x58 <ourExternalIP4>` counts only from a window-tracked IP and feeds
  Address Learning (ADR-0084). The proof of reachability is the ack after the helper's
  connect-back lands: `OP_KAD_FWTCPCHECK_ACK` on the TCP link it dialed (v7+,
  window-guarded, bridged from the accept path as `KadCommand::TcpFirewallAck`) or the
  legacy UDP `0x59`. **Two acks mean open**
  ([Prefs.cpp#L185](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/Prefs.cpp#L185)).
- Buddy search waits at least five minutes past a recheck
  ([Kademlia.cpp#L328](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/Kademlia.cpp#L328)),
  so a buddy is never recruited on a stale verdict.

### TCP check, responder

- `0x50` must be exactly 2 bytes, `0x53` at least 19. rmule answers `0x58` with the
  requester's IP at once, then asks core to dial back the requester's TCP port. On
  connect it sends `OP_KAD_FWTCPCHECK_ACK` on that link (v7+) or `0x59` (older), and the
  session ends.
- **Guards.** Self-connect, read against the live public IPv4 from Address Learning
  (`OwnListenEndpoint`: the full endpoint once known, the port alone until then); a busy
  client; and an IP rmule is itself checking.
- **The dial-back's crypt.** The `0x53`'s connect options and User Hash ride the chain to
  `DialBackVerdict::Dial` as the requester's `PeerCrypt`, and the dial meets our policy
  through `PeerCrypt::outbound` (ADR-0049). A `0x50` carries neither and is dialed
  plaintext. An incompatible pair is refused and counted
  (`kad_dial_backs_crypt_incompatible_total`).

### The injected TCP verdict is a level

The node derives no TCP verdict of its own; the UDP tester's firewalled-by-timeout
conclusion composes on the one it is told. `TcpVerdictFeed` holds the published verdict
and what the node was told as one object and syncs it at every Kad start (the node is
constructed assume-open), on every verdict change and on the 30-second recruit tick, so a
level dropped by a full inbox is restated rather than lost.

### UDP check, requester

- **Helpers come from the node's own Helper Lookup** (`KadWalkPurpose::UdpFirewallHelpers`),
  a walk toward a random target that asks `KADEMLIA_FIND_NODE` contacts and never walks
  the answer, as `FindNodeFWCheckUDP` does (`UDPFirewallTester.cpp:225-233`). It starts on
  the first datagram after the check is armed and on every recheck; the target comes from
  the driver's entropy. Candidates are judged as `QueryNextClient` judges them
  (`UDPFirewallTester.cpp:252-302`): Kad version above 5, not ourselves by ID or public
  IP, an IP never engaged for a UDP test, an IP absent from our routing zone. Two run at a
  time (`UDP_FIREWALLTEST_CLIENTSTOASK` = 2).
- **Core's gate:** a helper IP the **Peer Roster** (ADR-0059) already knows is reported
  cancelled without a dial, as aMule's `DoRequestFirewallCheckUDP` refuses a known client
  (`ClientList.cpp:1204-1211`).
- **The dial** is plaintext under every policy, an outbound Test Connection (ADR-0046):
  aMule creates the helper's client without a User Hash, so it cannot obfuscate. rmule
  completes the hello, checks the helper's advertised Kad port and version, sends
  `OP_FWCHECKUDPREQ <intern port2><extern port2><sender key4>` once identified (the key is
  our verify key for the helper, zero until keys are armed), and holds the link until the
  helper closes it or 40 s of idle pass. aMule refuses this dial under "require
  obfuscation" (`ClientList.cpp:1212-1215`); rmule departs so `Required` does not make UDP
  unverifiable.
- **Cancelled is not failed.** A helper that disconnects before the request went out, or
  whose hello names no Kad port or a Kad version of 5 or less, is cancelled
  (`BaseClient.cpp:1730-1734`, `:3972-3979`) and frees the slot. Only a disconnect after
  the request is a failure (`:1735-1739`). The tester queries the next candidate on both.
- **Verdict.** One success is `Open { port }`, verified, the intern port preferred even
  retroactively within 10 s. Both helpers failing is `Firewalled`, verified. Six minutes
  without a result while TCP reads firewalled is firewalled by timeout, unverified
  ([UDPFirewallTester.cpp#L56](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/UDPFirewallTester.cpp#L56)).
- **The extern port is learned first.** While a round needs it, the node pings `0x60` to a
  contact of type 3 or less and Kad version 6 or more every 15 s, and a hello from a
  version 6+ node draws one too. A `0x61` counts only from an IP pinged in the last 180 s,
  once per observer per round. Two observers naming the same port adopt it, compared with
  every earlier answer of the round; three that never agree make the port unreliable
  (`0`), and the check runs on the intern port alone (`Prefs.cpp:305-322`). The port
  belongs to Address Learning (ADR-0084): the node's Extern Port Round only pings, tracks
  and reports `UdpPortObserved`, and the pump answers every observation with
  `SetExternalUdpPort`. Helpers are not queried while the round runs.
- **Recheck.** The hourly recheck restarts the UDP half too, as aMule's
  `RecheckFirewalled` pairs them (`Kademlia.cpp:365-380`): counters reset, a fresh Helper
  Lookup, the prior verified verdict kept as `ReCheckFirewallUDP(false)` keeps it, and a
  result from the abandoned round rejected.

### UDP check, helper

- `OP_FWCHECKUDPREQ` arrives on a peer-TCP session; an intern port of 0 is rejected.
- The answer is biased (error code 1) when the requester is a routing-zone contact or the
  Peer Roster knows it (aMule's active upload, download or chat check,
  `BaseClient.cpp:4002-4007`).
- `0x62 <errorcode1><testedPort2>` goes to the intern port and, when distinct and
  non-zero, the extern port, keyed by the sender key the request carried in the
  KadVerifyKey family, as `ProcessFirewallCheckUDPRequest` does
  (`BaseClient.cpp:4008-4013`). A keyless request is answered plaintext.
- rmule consumes a `0x62` only on its own intern or extern Kad port and only from a helper
  it engaged. A non-zero error code reads as a cancellation of that helper.

## Consequences

- **Documented divergences.** rmule does not dial back an IP it is itself checking:
  aMule's `RequestTCP` has no such guard, but when two nodes check each other in one hello
  burst, aMule reuses rmule's already-connected socket instead of dialing, and both checks
  conclude firewalled having proved nothing. eMule guards the same invariant from the
  other side (`RequestTCP` refuses an existing socket). rmule sends the `0x58` even when it
  refuses the dial-back, where aMule returns without answering; this costs a datagram.
- rmule releases a buddy when Kad TCP opens, where aMule keeps it and stops pinging it.
- The deterministic tier covers the verdict machines (two-ack rule, recheck snapshot,
  180 s window, six-minute timeout, port preference and its 10 s correction), the
  responder guards and parse sizes, helper bias, candidate selection, legacy `0x50` and
  `0x59` in both directions, and the extern-port round.
- On the bench, a firewalled Core behind a pinned full-cone gateway finds two helpers in
  its first Helper Lookup and reads UDP open within seconds, including behind a gateway
  that remaps its Kad port, where the `0xA7` names the learned extern port.

## Considered options

- **The Kad runtime dialing TCP itself.** Rejected: it drags the peer handshake into the
  Kad crate when a broker pattern already exists.
- **Emitting only the modern forms** (`0x53` and the TCP ack). Rejected: the legacy branch
  is the same one-switch `kadVersion` gate aMule carries.
- **Trusting the server High ID alone.** Rejected: it proves TCP only, needs a connected
  server, and says nothing about UDP.
