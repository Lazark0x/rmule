# Kad liveness: aMule's flood limiter in the node, bans reported to a core BanStore, and verified contacts

## Context

aMule protects its Kad node with a per-`(ip, request opcode)` flood limiter, a port-53
drop and a ban, and it routes only to contacts whose IP it has verified. A contact
verifies either by a hello carrying a valid receiver key or by the `KADEMLIA2_HELLO_RES_ACK`
(`0x22`) three-way handshake. `IsIPVerified` gates every `GetClosestTo`
([RoutingBin.cpp#L195](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/routing/RoutingBin.cpp#L195)),
so unverified contacts are never served in `0x21` answers and never seed the node's own
walks.

aMule's flood ban lands in the eD2k client list (`AddBannedClient`,
[ClientList.cpp#L727](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientList.cpp#L727)),
and no Kad receive path consults it: aMule keeps answering a banned IP's other opcodes,
and the per-opcode buckets contain the flood.

`validReceiverKey` is a property of the crypt trailer, not of the key family that
decrypted the datagram. A captured crypt Kad2 `PING` decrypts under the Kad-ID family
while carrying a live `<receiverVerifyKey><senderVerifyKey>` trailer; a NodeID-keyed hello
is exactly the case where the sender has no receiver key for us yet and needs the
three-way. Evidence: `crates/rmule-kad/tests/fixtures/verify_keys/`, including aMule's own
`0x22` echoing rmule's derived key (`amule-233-hello-res-ack-20260728`) and emule-qt's
keyed exchange (`emule-qt-73fff714-hello-res-ack-20260924`).

## Decision

**Entry-point gates in `KadNode`**, in aMule's order, sans-I/O and explicit-time so the
mesh sim can flood them:

1. **Port-53 drop:** a datagram from source port 53 with no sender key is dropped first, a
   DNS-confusion guard
   ([KademliaUDPListener.cpp#L216](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/net/KademliaUDPListener.cpp#L216)).
2. **Flood limiter** (`FloodTable`), per `(ip, request opcode)`
   ([PacketTracking.cpp#L108](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/net/PacketTracking.cpp#L108)),
   allowed per minute: `BOOTSTRAP_REQ` 2, `HELLO_REQ` 3, `REQ` 10,
   `SEARCH_NOTES/KEY/SOURCE_REQ` 3, `PUBLISH_KEY_REQ` 3, `PUBLISH_SOURCE/NOTES_REQ` 2,
   `FIREWALLED(2)_REQ` 2 in one shared bucket, `FINDBUDDY_REQ` 2, `CALLBACK_REQ` 1,
   `PING` 2
   ([#L121](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/net/PacketTracking.cpp#L121)).
   Responses are not limited; solicitation tracking owns them. The semantics are aMule's:
   increment before check, decay one count per `60 / rate` seconds, drop over the limit,
   a 12-minute cleanup sweep, and a LAN-mode bypass.

**Ban: the node reports, core enforces on peer TCP.** At `count > 5 × rate`
([PacketTracking.cpp#L212](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/net/PacketTracking.cpp#L212))
the node emits `KadEvent::FloodOffenderDetected`. Core's `BanStore` (IP to banned-until,
lazy expiry) records it for `CLIENTBANTIME` = 2 hours, checked then evicted as aMule does
([ClientList.cpp#L739](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientList.cpp#L739)).
Enforcement is on the peer-TCP surface: inbound connections from a banned IP are refused
and banned source candidates are not dialed. Kad and server traffic are not ban-gated.
The inbound refusal is the second of the **Accept Gates** — the IP filter, the ban, then the
Test Connection carve-out (ADR-0046), in that order and in one place. They run where a
connection enters the serve accept channel and before it does: in the accept pump for a TCP
accept, in the admit seam for a Tunnel or a callback dial-back. The channel holds only peers
the serve loop will triage, and the loop's accept is a bare receive, so the `select!` that
races it can cancel it without losing a connection it already took — as aMule accepts a socket
and filters it in one step (`ListenSocket.cpp:102-112`). The ban check awaits the store's lock
on the producer's task, never on the serve loop's.

**Solicitation tracking.** rmule's in-flight probe and walk correlation is the mechanism,
equivalent to aMule's out-track list (both drop unmatched responses), with aMule's
**180 s** window
([PacketTracking.cpp#L59](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/net/PacketTracking.cpp#L59))
and **single-use** matches, so a duplicate response is unsolicited. `HELLO_RES` is tracked
outbound, because the `0x22` consume checks it.

**Verified contacts.**

- A **Verified Contact** is routable: the node serves only verified responded contacts in
  answers and seeds walks only from them. Until any contact has verified (a bootstrap file,
  an empty-table bootstrap answer, or a keyed exchange), the responded set is served
  instead, because in an all-plaintext topology a strict gate would serve nothing and
  silently unjoin the node, as aMule serves silence there. The moment one contact
  verifies, unverified contacts stop being served.
- **Lookup-answer rows** never enter the table, and a walk dials a row only when the table
  would take it. aMule hands its search only the rows its routing zone stored or would
  accept (`ProcessKademlia2Response`, `KademliaUDPListener.cpp:741-750`;
  `CRoutingZone::IsAcceptableContact`, `RoutingZone.cpp:897-916`), and rmule applies the
  same judgement. A row from Kad version 1 or older is refused (`:731`, `:901-904`). A row
  naming a stored ID passes only at that contact's UDP port, and only at its IP once the
  contact is verified: the anti-hijack filter (`:905-913`). Any other row must fit the two
  table-wide admission caps below, one per address and ten per /24
  (`CRoutingBin::CheckGlobalIPLimits`, `RoutingBin.cpp:366-390`). The count covers the table
  and the rows of the same answer already let through. aMule stores each row it can before
  it judges the next one. rmule's walk stores none, so it counts the earlier rows as if they
  were stored, and one answer cannot hand a walk more rows of one address or /24 than the
  table would hold. This is stricter than aMule, which counts only the rows its bins took.
  The bucket cap never refuses a row. A UDP firewall check's helper rows skip this
  judgement, because aMule hands them to its tester unjudged (`:734-740`). A refused row is
  diagnosed (`ContactRefused`, `ContactContradictsStored`, `ContactOverAdmissionCap`) and
  never dialed. Bootstrap-file contacts may enter verified (ADR-0066).
- **Admission caps** (aMule `CRoutingBin::AddContact`, `CheckGlobalIPLimits` and
  `ChangeContactIPAddress`,
  [RoutingBin.cpp#L84](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/routing/RoutingBin.cpp#L84),
  [#L269](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/routing/RoutingBin.cpp#L269),
  [#L366](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/routing/RoutingBin.cpp#L366)).
  The table holds at most **one contact per IPv4 address** and **ten per /24**, both
  counted **table-wide** (aMule's two static tracking maps), and at most **two per /24
  inside one bucket**. The two table-wide counts are tallies the routing table owns,
  keyed by the address and by the address masked to its /24. A stored contact is counted
  exactly once, under its current endpoint IP, from the moment it is stored until it is
  evicted, replaced as a `Failed` contact, or moves; the per-bucket count is read off the
  bucket. The gate runs on every add, including the replacement of a `Failed` contact
  (which leaves the tallies first), and on every endpoint move to a new IP; an update at
  the same IP passes untouched. A refusal is `KadRoutingUpdate::RejectedAdmissionCap`,
  naming the cap (`KadAdmissionCap`: the address, the /24 across the table, or the /24 in
  the bucket); a refused add stores nothing, a refused move leaves the entry exactly as it
  was, and the node diagnoses both (`ContactOverAdmissionCap`). The private ranges
  and loopback are exempt from both /24 caps, as aMule exempts `IsLanIP`. Loopback is
  also exempt from the per-IP cap, which aMule never needs: it refuses loopback contacts
  outright, while rmule admits one from an informant on this host (ADR-0085), and
  several nodes on one host share 127.0.0.1 by port.
- **Verification paths:** a hello whose trailer carries a valid receiver key verifies on
  add. Otherwise, the `0x22` three-way: our `HELLO_RES` sets misc-options bit 2 exactly
  when `addedOrUpdated && !validReceiverKey` toward a Kad v8+ contact
  ([KademliaUDPListener.cpp#L539](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/net/KademliaUDPListener.cpp#L539)),
  and their `0x22` is consumed only when tracked, with a valid receiver key, and matching
  ID and IP, which verifies the contact (`KadRoutingTable::verify_contact`).
- **A key is required on both legs.** rmule asks for an ack only in a datagram whose
  trailer carries our non-zero sender key, and sends a `0x22` (`<ownKadID16><tagcnt 0>`)
  only obfuscated in the receiver-key family, its receiver slot echoing the requester's
  sender key. A request with an empty sender key draws nothing, as in aMule. The ack's
  whole proof is that echoed key, so a plaintext ack request or `0x22` is meaningless and
  both references drop it.
- **Misc options** (`TAG_KADMISCOPTIONS`, both hello directions) are written when the ack
  request or either firewalled bit is set toward a v8+ contact
  ([KademliaUDPListener.cpp#L126](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/net/KademliaUDPListener.cpp#L126)).
  The firewalled bits come from Reachability (ADR-0060). `HELLO_REQ` never asks for an ack.

## Consequences

- aMule asks for an ack only while our `HELLO_REQ` does not already echo its key, and rmule
  echoes it from the first trailer it sees, so verification takes the cheaper key path and
  aMule never asks rmule for the three-way. The direction is undriven by protocol, not
  missing.
- The `0x22` rows are scored against an emule-qt capture, which holds only stimulus status
  for Kad (ADR-0045); an aMule-authored capture of the same exchange would make them
  parity.
- rmule does not implement the Kad v<7 legacy challenge (the `KADEMLIA2_REQ` spoof
  challenge aMule sends a contact below v7 that has no valid receiver key) or the v7
  ping-with-key workaround
  ([KademliaUDPListener.cpp#L560](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/net/KademliaUDPListener.cpp#L560)).
  This is a deliberate divergence of the `unprovable` class (ADR-0045): aMule 2.3.3 is
  v8 and no pinned body speaks below v7, so no counterparty could ever answer the
  challenge. Unkeyed ancient contacts stay unverified, never served and never seeding;
  other contacts are served instead, and v<8 clients are pre-2010.
- A bucket stands in for aMule's bin. rmule buckets by the leading-zero count of the
  distance, so its far-half bucket covers ID space aMule's zone tree splits into several
  bins, and the two-per-/24 bucket cap binds harder than aMule's on a
  swarm concentrated in one /24. A deterministic mesh therefore gives every member its
  own /24, and a bench swarm keeps the nodes rmule must hold in its table off a shared
  /24 when more than two of them fall into one bucket.
- The deterministic tier covers the flood matrix per opcode (allow at rate, drop above,
  offender at 5×), the decay arithmetic, the cleanup sweep, the LAN bypass, the port-53
  pair, the solicitation edges, the `0x22` state machine, verified gating with the
  anti-hijack duplicate, the admission caps (per IP, per /24 table-wide and per bucket,
  the LAN exemption, a refused move, a lookup answer's rows of one /24 and a row
  re-homing a verified ID), the misc-options truth table and mesh-sim flood,
  handshake and banned-peer scenarios.
- Captures use inverted roles with absence plus a positive control against the same pinned
  counterparty: rmule's fourth `HELLO_REQ` in a minute draws no answer while the first
  three do, a flood past 5× draws sustained silence and then a refused eD2k dial, and a
  port-53 datagram goes unanswered beside an answered control. aMule's genuine `0x60`
  flood triggers `FloodOffenderDetected` (`crates/rmule-kad/tests/fixtures/flood/captured/`).

## Considered options

- **A Kad inbound ban gate.** Rejected: aMule keeps answering a banned IP's other opcodes,
  and a ban would punish NAT-shared IPs; the per-opcode bucket already contains the flood.
- **The limiter in the socket layer.** Rejected: the deterministic tier needs flood
  scenarios inside the sans-I/O node, and the socket stays thin.
- **`verified := responded` everywhere.** Rejected: it mislabels what the flag means. The
  responded set is served only while nothing has verified at all.
- **The legacy challenge and v7 ping workaround.** Rejected: machinery for extinct clients,
  with real attack surface (challenge state) and no observable absence.
