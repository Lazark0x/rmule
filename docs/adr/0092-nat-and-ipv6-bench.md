# The NAT and IPv6 bench: translating gateways that prove their own type, an IPv6 WAN, four counterparty bodies, and flows that can fail

## Context

The interop bench of ADR-0033 can drop a counterparty's ports but has no NAT and no IPv6
network, and every flow allocates one capture sidecar. Port mapping (ADR-0086), the IPv6
dialect (ADR-0087) and NAT traversal (ADR-0091) need a router that translates, a second
address family the counterparties accept, bodies that speak the new dialects, and captures on
both sides of a translation. ADR-0045 sets what a row may claim: Fork Pins, the NAT Type
Proof, `single-oracle` and `rmule-only` rows, and the four elements a punch-failure negative
must carry. libp2p's `hole-punch-interop` rig is the closest precedent.

Facts the bench has to respect:

- A NAT gateway that answers an unsolicited inbound datagram eats the punch aimed through it.
  The far peer's burst normally reaches our gateway before our client has sent to it; if it
  is delivered locally, conntrack commits an entry whose original tuple is the reply tuple
  our client's own mapping then needs. With the SNAT range pinned to one port the kernel
  drops our datagram at confirmation (`conntrack -S` `insert_failed`); with the whole port
  range it silently picks another port and the endpoint-independent mapping is gone for
  exactly that peer.
- RFC 5780's tests address the reflector's own two ports, so a gateway rule keyed on the
  pinned client port — the port every burst and opener is aimed at — is outside their reach,
  and two gateways pinning the same port toward each other is outside a single reflector's.
- A bounded protocol timer measured by a window of the same length reaches its verdict as the
  driver exits; a conntrack mapping read after the drivers exit may already have aged out of
  the 180 s UDP timeout.
- aMule accepts one Kad contact per IP (`MAX_CONTACTS_IP 1`), and aMule and emule-qt both
  accept only `45.55.200.0/24` among the fake-public prefixes tried.
- A stock aMule 2.3.3 reading a sentinel-bearing `OP_FOUNDSOURCES` dials the records either
  side of the sentinel and keeps its session; the same shape inside a packed
  `OP_GLOBFOUNDSOURCES` datagram costs the next packed body (aMule logs "Server sources reply
  got additional bogus bytes"). So a sentinel-bearing `0x9B` body must be the last in its
  datagram (ADR-0087).

## Decision

### NAT topology

- **`natgw`**: debian-slim with nftables and conntrack, `NET_ADMIN`, IPv4 and IPv6
  forwarding, one per client, with a `NAT_TYPE` knob in RFC 4787 terms:
  `port-restricted` (EIM + APDF, plain SNAT), `restricted` (EIM + ADF, port-pinned SNAT plus
  DNAT gated by a dynamic set of peer addresses), `full-cone-pinned` (EIM + EIF for the pinned
  UDP port only — a static port-forward, never claimed as a general full cone), and `symmetric`
  (APDM + APDF, `snat … fully-random`). Hard/ADM NAT is not expressible in-kernel and is out.
  Conntrack UDP timeout is 180 s (RFC 4787 REQ-5).
- **Every gateway drops unsolicited WAN UDP before conntrack confirms it**:
  `iifname "$WAN_IF" meta l4proto udp ct state new drop` in a `filter input` chain at priority
  0, so no entry is committed and replies to the gateway's own traffic still arrive. The
  `miniupnpd` port-mapping gateway carries the same rule.
- **Networks**: the WAN is the `--internal` fake-public `/24` (gateway `.2`, counterparties
  `.3…`); the LAN is an ordinary bridge with masquerade off and the client's default route at
  the gateway (a Bench Variant Env knob, not a patch). An RFC 1918 LAN address leaking fails
  every client's `IsGoodIP`. Each gateway takes its own fake-public address — one Kad client
  per gateway. Mixed aMule and emule-qt topologies use `45.55.200.0/24`.
- **`natprobe`**: a reflector on the WAN with two fake-public addresses × two UDP ports and a
  **Pinned-Port Sink** on the primary address, driven by `rmule-tools nat probe`. Stimulus,
  never evidence. It runs for every gateway type before the drivers.
- **The NAT Type Proof** has three axes, and a leg passes only with all three: RFC 5780's
  mapping and filtering tests agree with the claimed type (`agrees`; a change test counts only
  when answered from the endpoint the change names, otherwise filtering reads `unknown`);
  the pinned port is reachable through the gateway (`pinned_port_reachable`); and a second
  gateway of the same type beside the first crosses or does not cross as the type demands,
  with `rmule-tools nat peer-reach` staggered so one side opens while the other is silent.
  Every gateway writes `nft list ruleset`, `conntrack -L` and `conntrack -S` and a
  `nat-type.toml` row. **Every gateway row fails on a proof that disagrees**
  (`each-gateway-probed-as-its-claimed-nat-type`).
- **The punch mapping is dumped while the attempt is live.** `natgw-proof.sh` takes a tag;
  the requester driver prints `rmule-natt-first-dial` the instant its dial counter leaves zero,
  and `take_inflight_proof` dumps both gateways tagged `inflight`. The outbound mapping claim
  reads the in-flight dump; the teardown dump confirms the mappings are gone.
- `natgw` and `natprobe` rebuild on every run; the heavier bodies rebuild only with
  `--build-images`. A stale gateway image would produce a wrong NAT Type Proof.

### IPv6 network

- The IPv6 WAN is `--internal --ipv6` with an rmule-owned `fake_public_v6` plan allocating
  `3fff:<harness>:<net>::/64` from RFC 9637's documentation block — global-unicast-shaped,
  unroutable, and on no client's reject list (kno rejects `fc00::/7`, `2001::/32`,
  `2002::/16`…; emule-qt adds `2001:db8::/32` and `5f00::/16`). The acceptance is measured:
  `ipv6-net-accept` asserts each body's log calls its own address global before any IPv6 flow.
- No NAT66: IPv6 flows test firewall filtering, not translation.
- **`bench-doctor`** checks the daemon for `ipv6`, `ip6tables`, `nft`, `br_netfilter` and the
  conntrack sysctl; a missing capability skips the dependent flows with a stated reason, never a
  silent pass.

### Bodies

| Body | Image | Pin | Role |
|---|---|---|---|
| stock aMule 2.3.3 | `amule` | Ubuntu 24.04 package | legacy oracle: ignores every new tag and opcode |
| kno's aMule | `amule-kno` (the fork's Debian Dockerfile, ffprobe stage stripped, a `--quic` variant) | Fork Pin `kno/amule` `integration/network-parity` `ab483654` | IPv6 client↔client, Kad tags, uTP, rendezvous target, the QUIC gate |
| emule-qt 0.4.2 | `emuleqt` | `73fff714` | reference body for the IPv6 and port-mapping rows; a Kad body in `kad-node` mode; stimulus elsewhere |
| ed2k-server | `ed2ksrv` | `4da4774fa8f61f5c1e40ac5054494502c5d75e6d` (`v0.9.75`) | the server punch coordinator |

Plus `natgw`, `natprobe` and a `miniupnpd` gateway (`--ipv6 --igd2`, `enable_pcp_pmp=yes`).
The ed2ksrv pin is verified at build time: `images/ed2ksrv/pin.env` names the commit,
`build.sh` refuses any other or dirty clone and labels the image, and a verdict names the pin
as verified only when the image carries the label.

### Kad mesh with a Seeded Bootstrap

The buddy rows run on a private Kad mesh. The firewalled target bootstraps from a seed; the
buddy's Kad ID is the target's inverted ID, at distance zero from the FINDBUDDY walk's target;
routing-only members are seeded beside it so the walk has alternatives to reject; each body
takes its own fake-public address. The seed is ADR-0065's v1/v2 merge — contacts placed in the
keyspace — because a walk needs contacts. No `ed2ksrv` stands on that WAN, so the server
coordinator ADR-0091 prefers is absent on purpose, and the `0x60` count is read at zero. The
kno image has no seeded-bootstrap surface, so these rows' bodies are rmule and their claims are
`rmule-only`.

### Captures

One capture sidecar per network attachment, declared by the flow: the WAN tap is the evidence
(counterparty bytes after translation), the LAN tap is part of the NAT Type Proof (the same
datagram before it). Punch flows cut every `0xA1` and `0xB2` row on both taps — what the node
fired against what left the gateway.

### Verdicts and claims

- Verdicts are `PASS`, `OBSERVED`, `SMOKE` and documented absence. `SMOKE` is defined and not
  implemented: no flow touches the public network.
- **A documented absence holds only on its own measured zero.** A claim takes the measured
  count of what it names: held on `0`, absent on a positive count or on `-1` (never measured).
  A sum with one unmeasured operand is `-1`. A counter a missed snapshot never filled is `-1`,
  never `0`.
- Evidence classes follow ADR-0045: rmule's own emissions (its `0x60`, `0x9F`, its own rows)
  are `rmule-only`; ed2k-server's `0x61` is `single-oracle`.
- **A bench window exceeds the budget it measures** — `budget + 30 s` — for every flow that
  measures a bounded protocol timer.
- Conntrack counts are read from one listing; `conntrack.txt` holds two.

### Flows

Fast tier: gateway, prefix, tag and codec checks. Slow tier: transfers and punches. Both run in
the Linux VM on a macOS host and on Linux CI, gated by `RMULE_BENCH`. Every gateway flow attaches
its NAT Type Proof; every `-symmetric` variant runs the reflector probe in the same run.

| Flow | Bodies | Asserts | Tier |
|---|---|---|---|
| `natgw-selfproof` | natgw × 4 types, natprobe | probed behaviour equals the claimed type on all three axes | fast |
| `ipv6-net-accept` | amule-kno, emuleqt | each logs its `3fff` address as global | fast |
| `sentinel-sources-legacy` | rmule (stimulus), stock aMule | aMule reads a sentinel-bearing list without desync; the packed UDP form costs the next body | fast |
| `portmap-highid` | miniupnpd gateway, rmule, two stock-aMule Kad helpers | mapping in the gateway table, exact port, a renewal, the Kad verdict flips open | slow |
| `portmap-mismatch` | miniupnpd gateway with a pre-claimed port | `Degraded`, never advertised | fast |
| `portmap-ipv6-pinhole` | miniupnpd gateway (PCP v6) | pinhole granted for the Known IPv6 | fast |
| `portmap-ipv6-pinhole-link-local` | miniupnpd gateway reached at its `fe80::` address | every PCP request leaves from the Known IPv6 its header names; the pinhole is granted | fast |
| `ipv6-hello-tags` | amule-kno, emuleqt | `0xAA` claim, `CT_MOD_IP_V6` round trip | fast |
| `ipv6-extsx` | emuleqt and a queued rmule | the ExtSX record carries the IPv6; unknown tags skipped | fast |
| `ipv6-direct-dial-lowid` | amule-kno (Low ID on IPv4, IPv6 reachable) | rung 0 dials IPv6 directly | slow |
| `ipv6-kad-tags` | amule-kno, emuleqt, rmule storers | `ip6` and `bi6` published, stored, re-served and parsed; a byte-equal transfer off emule-qt's row over IPv6 | slow |
| `ipv6-server-sentinel` | ed2ksrv | a sentinel emitted to a capable session and dialed (a documented absence while the pin has no IPv6) | slow |
| `ipv6-udp-key` | emuleqt | the 35-byte key decrypts an IPv6 datagram | fast |
| `natt-caps-utp` | amule-kno | CAPS / CAPS-ACK, KEY frame, uTP SYN answered | fast |
| `natt-buddy-rendezvous-{cone,restricted,symmetric}` | rmule mesh, natgw | the punch succeeds behind cone and restricted, fails honestly behind symmetric with proof | slow |
| `natt-buddy-transfer-cone` | rmule mesh, natgw | a download finds the buddy row, adopts the Tunnel and completes the file | slow |
| `natt-server-punch-{cone,symmetric}` | ed2ksrv, two rmule, natgw | `0x61` to both, punch and Tunnel | slow |
| `natt-server-punch-one-symmetric` | ed2ksrv, two rmule, `symmetric` + `port-restricted`, three open Kad observers | port prediction: Fan mappings in the symmetric gateway's conntrack, probe sets on the other side's LAN tap, and a Tunnel exactly when the port sets meet | slow |
| `natt-tunnel-transfer` | rmule, natgw `full-cone-pinned` | a file completes over uTP | slow |
| `natt-udp-selfcheck-cone` | rmule target behind `full-cone-pinned`, Kad helpers, a placed storer | ADR-0058's UDP self-check end to end: two fresh helpers found by the target's own lookup, the verdict read open off their `0x62`, the type-6 row published | slow |
| `natt-udp-selfcheck-remapped` | the same, with the public port pinned away from the client's | only a `0x62` aimed at the learned Extern Kad Port lands | slow |
| `natt-udp-selfcheck-amule` | stock aMule 2.3.3 (debug image) as the firewalled body, rmule helpers | aMule's own UDP verdict and the publish it earns, read in the storer's netns | slow |
| `natt-quic-handshake` | amule-kno `--quic` | a QUIC handshake completes — the gate for advertising bit 4 | slow |

**The port-prediction row** stands one gateway per type (requester behind `symmetric`,
responder behind `port-restricted`) and three open Kad observers whose `PONG`s are the only thing
that tells a peer its own mapping; each driver holds its identity back until its Own Mapping
reads known. A run is one draw of a pairing that lands 63.9 %, so it is judged on agreement:
`a-tunnel-rose-exactly-when-the-port-sets-met` fails on a Tunnel without an intersection or an
intersection without a Tunnel. The bench wrapper runs it ten times
(`RMULE_BENCH_PREDICTION_RUNS`) and needs every run `PASS` and at least four with a Tunnel. Its
negative, `natt-server-punch-symmetric --port-prediction`, needs zero Tunnels and no
random-port punch.

## Consequences

- Every NAT-T and port-mapping row carries a proof of the NAT it ran behind, and a gateway
  defect fails the row instead of reading as a product result.
- No positive server-punch row crosses a filtering NAT: every cone positive runs behind
  `full-cone-pinned`, whose pinned port is a static forward, so those rows show coordination and
  transport, not a punch opening a filter. The buddy path has a filtering-NAT positive
  (`natt-buddy-rendezvous-restricted`). Closing the server-path gap needs
  `natt-server-punch-{restricted,port-restricted}` rows or a claim that each peer's first inbound
  `0xB2` followed its own outbound burst.
- The prediction row does not drive the Peer Mapping veto: the driver would have to invent an
  advertised port for a Low-ID target.
- kno as buddy needs a seeded-bootstrap surface in its image; until then the buddy rows are
  `rmule-only`.

## Considered options

- **Userspace NAT (pion `vnet`) instead of netfilter.** Held in reserve: only hard NAT needs it,
  and punching cannot beat hard NAT anyway.
- **Docker's bridge NAT, no gateway.** Rejected: no symmetric case, so every negative NAT-T row
  would be fabricated.
- **A real GUA `/64` the project controls.** Rejected: a routable prefix inside the bench.
- **ULA with clients patched to accept it.** Rejected: patched counterparties are inadmissible.
- **One sidecar per flow (WAN only).** Rejected: the translation itself would go unobserved.
- **`amule-org/amule` master instead of kno's fork.** Rejected: no IPv6 activation, no rendezvous.
- **Trimming the `-restricted`, `-mismatch` and pinhole flows.** Rejected: they are the one NAT
  type between cone and symmetric, and the `Degraded` path grading exists for.
- **A `raw prerouting notrack` instead of the input drop.** Rejected: it would have to restate
  each DNAT's match to avoid untracking traffic the gateway must translate.
- **Collapsing the pinned-port and peer-reach axes into `agrees`.** Rejected: a gateway agreed on
  both RFC 4787 axes while hairpinning the one port the flow depended on.
