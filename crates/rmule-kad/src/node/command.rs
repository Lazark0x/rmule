//! The commands a driver hands the node. Every one is explicit-time: the
//! driver stamps `now` when it applies the command, and nothing here reads a
//! clock.

use crate::keyword::KadKeywordSearchRequest;
use crate::keyword_publisher::KadSharedFile;
use crate::{
    KadBootstrapNode, KadContact, KadId, KadNodeEndpoint, KadPublishRequest, KadSourceLookupRequest,
};

/// Driver-issued instructions.
///
/// Not `Copy`: the keyword commands carry an owned query / shared-file
/// description (aMule derives keywords from the filename), so the driver hands
/// them by value through its command channel.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum KadCommand {
    /// Send a `KADEMLIA2_BOOTSTRAP_REQ` to a known node endpoint.
    Bootstrap {
        /// The endpoint to dial.
        endpoint: KadNodeEndpoint,
    },
    /// Merge externally-decoded contacts directly into the routing table:
    /// each contact already carries a known Kad ID, endpoint, TCP port,
    /// version, and verified flag (a nodes.dat normal-reader load, ADR-0065
    /// execution breakdown 3's "v1/v2-merge" semantics), so it enters
    /// through the ordinary admission path (bucket rules, anti-hijack,
    /// eviction) with no `BOOTSTRAP_REQ` round trip needed to earn a slot —
    /// unlike [`Bootstrap`](Self::Bootstrap), which only carries an endpoint
    /// and must earn its way in via a response. Entered `Responded`: aMule's
    /// own file-loaded contacts are immediately queryable (`AddUnfiltered`),
    /// not gated behind a live probe. Each contact's own verified bit rides
    /// along unchanged.
    ///
    /// Immediate on this side only: a merge sends the contact nothing, so it
    /// learns of *us* only once the small-timer hello pass greets it — joined
    /// or not, on the first pass that finds it at its bucket's front — or we
    /// bootstrap-dial it instead. The **Seeded Bootstrap** glossary entry and
    /// ADR-0067's amendment cite the aMule rule.
    MergeContacts {
        /// The contacts to admit, each already carrying its ID, endpoint,
        /// version and verified bit.
        contacts: Vec<KadContact>,
    },
    /// Append candidates to the one **Bootstrap Dial List** (ADR-0067): the
    /// node dials them one at a time on the 15 s / 2 s cadence until it joins,
    /// discarding each after the dial. Config-endpoint seeds and file-loaded v3
    /// nodes.dat candidates both arrive this way and **unify** into the single
    /// list — repeated commands append, they do not replace. Unlike
    /// [`Bootstrap`](Self::Bootstrap) (dial this endpoint now) and
    /// [`MergeContacts`](Self::MergeContacts) (enter the routing table now), a
    /// seeded candidate only waits its turn in the list; its contacts are never
    /// merged into the table directly (only their bootstrap *answers* seed it).
    SeedBootstrapDialList {
        /// The candidates to append to the dial list, in the order they
        /// should be tried.
        candidates: Vec<KadBootstrapNode>,
    },
    /// The **ed2k→Kad handoff** (ADR-0067): an eD2k peer carried a Kad
    /// node hint (`CT_EMULE_UDPPORTS` kad half + kad version > 1, parsed and
    /// gated peer-side; core brokers it here only while Kad is *running*). Apply
    /// aMule's `CKademlia::Bootstrap` gate — **not joined ∧ ≥ 10 s since the last
    /// bootstrap dial** — and, if it opens, feed `endpoint` into the one
    /// [`Bootstrap Dial List`](Self::SeedBootstrapDialList) so the dial loop
    /// dials it on its cadence. The 10 s throttle is the *same* timestamp the
    /// dial loop stamps (the node's `dial_bootstrap` writes it), so a peer hint
    /// and the list dials rate-couple. A suppressed handoff drops the hint —
    /// aMule queues nothing, it early-returns. One-way: there is no Kad→ed2k
    /// handoff.
    BootstrapFromPeer {
        /// The Kad endpoint the eD2k peer hinted at.
        endpoint: KadNodeEndpoint,
    },
    /// Walk toward the request's Kad target and search the nearest responded
    /// nodes for sources (the **Kad Requester** role).
    SearchSources {
        /// The file to find sources for, carrying the target the walk aims at.
        request: KadSourceLookupRequest,
    },
    /// Register the request's file for publication (the **Kad Publisher**
    /// role): publish immediately, then republish every
    /// [`KadNode::SOURCE_REPUBLISH_INTERVAL`](crate::KadNode::SOURCE_REPUBLISH_INTERVAL) through `tick`.
    PublishSource {
        /// The file to publish ourselves as a source of.
        request: KadPublishRequest,
    },
    /// Withdraw the request's file from publication: its republish stops. A
    /// walk already under way finishes; Kad has no unpublish, so what storers
    /// hold ages out with its lifetime. A target never registered is a no-op.
    WithdrawSource {
        /// The file we no longer offer.
        request: KadPublishRequest,
    },
    /// Walk toward the query's lead keyword and search the nearest nodes'
    /// keyword indexes (`0x33`), merging the rows into the one search stream
    /// (the **Kad Requester** role, ADR-0062).
    SearchKeywords {
        /// The query, from which the lead keyword and the residual tokens are
        /// taken.
        request: KadKeywordSearchRequest,
    },
    /// Register a complete shared file for keyword publication (the **Kad
    /// Publisher** role, ADR-0062): the node derives its keywords and paces
    /// per-keyword publish walks through `tick`, gated by reachability.
    PublishKeywords {
        /// The shared file whose name the keywords are derived from.
        file: KadSharedFile,
    },
    /// Feed the settled **TCP reachability verdict** back into the node (ADR-0058
    /// breakdown 3, the TCP→node verdict feedback path). The sans-I/O node emits
    /// the TCP reachability *lifecycle* ([`ReachabilityConnectBack`] etc.); the
    /// core `Reachability` store folds those onto the ≥2-ack verdict, then commands
    /// the settled result back here so the node's six-minute UDP-timeout gate — the
    /// one place the two self-checks compose (aMule's `IsFirewalled && !m_isFWVerifiedUDP`)
    /// — reads the live verdict, not the injected assume-open default. Also updates
    /// the keyword publish gate's TCP-firewalled input. Idempotent.
    ///
    /// [`ReachabilityConnectBack`]: crate::KadEvent::ReachabilityConnectBack
    SetTcpReachability {
        /// The settled verdict: `true` when fewer than two connect-backs
        /// proved our TCP port open.
        firewalled: bool,
    },
    /// Feed core's **Extern Kad Port** verdict — the Address Learning store's
    /// learned port for the UDP role — back into the node (ADR-0084). The node
    /// states what it observes ([`UdpPortObserved`]) and owns no rule about
    /// it; the store applies the agreement rule, the freshness window and the
    /// ladder, and answers every observation here so the `OP_FWCHECKUDPREQ`
    /// body and the tester's open-port preference read one settled number.
    ///
    /// `port == 0` means the store holds no learned port. It changes nothing
    /// unless it answers the last observation of an **Extern Port Round**
    /// that never agreed, which clears the port to `0` as aMule does. A
    /// nonzero port, or that last answer, ends the round and opens the UDP
    /// test's helper gate. The intern port stands until a
    /// verdict arrives.
    ///
    /// [`UdpPortObserved`]: crate::KadEvent::UdpPortObserved
    SetExternalUdpPort {
        /// The external port the outside world reaches our Kad socket at.
        port: u16,
    },
    /// Carry the Advertised Endpoints chooser's IPv6 verdict in (ADR-0084,
    /// ADR-0087): `Some` while rmule holds a Known address that no server has
    /// probed unreachable, `None` otherwise.
    ///
    /// The node never reads an interface of its own — the same discipline
    /// [`SetExternalUdpPort`](Self::SetExternalUdpPort) follows. While the
    /// address is set, every source publish carries the `ip6` tag; when it
    /// clears, publishes stop carrying it, because the tag is a claim that
    /// this address works right now.
    SetAdvertisedIpv6 {
        /// The chooser's verdict, or `None` to stop advertising.
        address: Option<std::net::Ipv6Addr>,
    },
    /// The publish posture — core's **Self Reach** `firewalled` and, while
    /// firewalled, the buddy row of its Buddy Snapshot
    /// (ADR-0060, ADR-0061).
    ///
    /// Same discipline as [`SetAdvertisedIpv6`](Self::SetAdvertisedIpv6): the
    /// node never reads its own reachability to decide this. Firewalled with
    /// a buddy, every source publish goes out as aMule's type-3/5 row naming
    /// it — with `bi6` when the contact carries the buddy's IPv6;
    /// firewalled with none, no source row is sent (aMule's
    /// `PrepareToStop`); reachable, the direct row.
    SetPublishPosture {
        /// The posture every source publish from here reads.
        posture: crate::KadPublishPosture,
    },
    /// The connect-options byte every source publish states in
    /// `TAG_ENCRYPTION`: crypt support/request/require in bits
    /// 0–2 and eMuleAI's uTP NAT-T in bit 7, as the driver knows them. `None`
    /// leaves the tag absent — silence, not a claim of "none". The node never
    /// derives it: which transports run beside it is the driver's fact.
    SetPublishConnectOptions {
        /// The byte, or `None` to stop stating one.
        options: Option<u8>,
    },
    /// Start a firewall self-check **now**, outside its hourly clock (ADR-0086's
    /// amendment to ADR-0058) — the driver-facing form of
    /// [`recheck_reachability`](crate::KadNode::recheck_reachability).
    ///
    /// Core sends it when a port-mapping grant lands on the exact ports, when a
    /// gateway epoch reset re-added the mapping set, and when the operator asks
    /// — because to a user "am I reachable" and "is my port forwarded" are one
    /// question. Rate-limited node-side (one recheck at a time, at most one per
    /// five minutes), so a burst of triggers costs one round of helper lookups,
    /// not several. Renewals never send it.
    RecheckReachability,
    /// Count one `OP_KAD_FWTCPCHECK_ACK` (`0xA8`) a v7+ helper delivered over the
    /// TCP link it dialed back on — the driver-facing form of
    /// [`consume_tcp_firewall_ack`](crate::KadNode::consume_tcp_firewall_ack)
    /// (ADR-0058 requester, the modern ack path).
    ///
    /// The ack lands on the *peer* socket, not the Kad one, so it cannot reach
    /// the node the way a `0x58` or a legacy `0x59` does: core bridges it here
    /// from the Kad-ignorant peer session, carrying only the dialing peer's IP.
    /// The node applies aMule's 180 s outstanding-check window
    /// (`IsKadFirewallCheckIP`) before it counts a reachability leg, so a
    /// stranger's `0xA8` proves nothing. Without this command the ≥2-ack rule is
    /// reachable only through the legacy `0x59`, which rmule asks for only from a
    /// Kad-version-≤6 contact — unreachable against any modern counterparty.
    TcpFirewallAck {
        /// The IP of the peer that dialed back and sent the ack.
        peer_ip: std::net::Ipv4Addr,
    },
    /// A peer asked us over peer TCP (`OP_FWCHECKUDPREQ`, `0xA7`) to prove its
    /// Kad UDP port reachable — the driver-facing form of
    /// [`consume_udp_firewall_request`](crate::KadNode::consume_udp_firewall_request)
    /// (ADR-0058, rmule as UDP Firewall Helper). The request lands on the
    /// Kad-ignorant peer socket, so core bridges its opaque body here with the
    /// dialing peer's IP; the node answers `0x62` toward the port(s) it names
    /// (aMule `ClientTCPSocket.cpp:1942-1948` →
    /// `CUpDownClient::ProcessFirewallCheckUDPRequest`).
    UdpFirewallRequest {
        /// The IP of the peer that sent the request — where the `0x62` goes.
        requester_ip: std::net::Ipv4Addr,
        /// The `OP_FWCHECKUDPREQ` body as it arrived:
        /// `<intern port 2><extern port 2><sender key 4>`.
        request: Vec<u8>,
        /// Whether core's peer roster already knows this IP — a granted or
        /// queued upload, an active download worker, or a chat (aMule
        /// `GetUploadState() != US_NONE || GetDownloadState() !=
        /// DS_NONE || GetChatState() != MS_NONE`, `BaseClient.cpp:4002-4003`).
        /// `true` biases the answer the same way a routing-zone contact does.
        caller_known: bool,
    },
    /// The peer-TCP link to an engaged UDP Firewall Helper ended after our
    /// `OP_FWCHECKUDPREQ` went out — one **failed** helper unless its `0x62`
    /// already landed (aMule `BaseClient.cpp:1735-1739`, `KS_FWCHECK_UDP` on
    /// disconnect). Two failures conclude the UDP verdict firewalled.
    UdpFirewallCheckFailed {
        /// The helper's IP, as engaged.
        helper_ip: std::net::Ipv4Addr,
    },
    /// The dial to an engaged UDP Firewall Helper ended before our
    /// `OP_FWCHECKUDPREQ` could be sent — refused, a hello that never
    /// completed, or a helper whose hello names no Kad port or a Kad version
    /// below 6. aMule counts this as **cancelled**, not failed
    /// (`BaseClient.cpp:1730-1734`, `:3972-3979`): the slot is freed and the
    /// next candidate is engaged.
    UdpFirewallCheckCancelled {
        /// The helper's IP, as engaged.
        helper_ip: std::net::Ipv4Addr,
    },
    /// Recruit `target` as our buddy (ADR-0061 firewalled-node operation): emit a
    /// `0x51 KADEMLIA_FINDBUDDY_REQ` toward it and track its `0x5A` answer window.
    /// The driver-facing form of [`recruit_buddy`](crate::KadNode::recruit_buddy); the
    /// core-side recruit *trigger* (firewalled ∧ Kad-joined ∧ no buddy ∧ pacing)
    /// decides when to issue it, the requester-capture driver issues it on join.
    RecruitBuddy {
        /// The open node to ask.
        target: KadNodeEndpoint,
    },
    /// Run the **FINDBUDDY walk** (ADR-0061, aMule `Search.cpp#L784`): walk
    /// toward `target` — the recruiting node's `~ourKadID` — and, at
    /// convergence, ask the closest responded contact to be our buddy. The
    /// walk picks the contact [`RecruitBuddy`](Self::RecruitBuddy) would
    /// otherwise have to be told; it ends with
    /// [`BuddyWalkEnded`](crate::KadEvent::BuddyWalkEnded), and a verified
    /// answer arrives as [`BuddyFound`](crate::KadEvent::BuddyFound).
    ///
    /// The recruit *trigger* stays core-side (firewalled ∧ Kad-joined ∧ no
    /// buddy ∧ pacing); this only runs one walk. A second command while a walk
    /// toward the same target is in flight is ignored rather than stacking two.
    FindBuddyWalk {
        /// `~ourKadID` — the recruitment target the `0x51` echoes.
        target: KadId,
    },
    /// Ask a firewalled source's **buddy** to relay a callback (ADR-0061 route 4):
    /// emit a plaintext `0x52 KADEMLIA_CALLBACK_REQ`
    /// `<buddyID><fileHash><tcpPort>` to `buddy`, which the buddy relays to its
    /// firewalled client as `OP_CALLBACK` over the link it holds; the client
    /// then dials us at `tcp_port`. Plaintext always, as aMule sends it: the
    /// buddy's Kad version is unknown (`BaseClient.cpp:2141-2149`). The
    /// admission decision and the dial-back adoption are core-side.
    RequestBuddyCallback {
        /// The buddy's Kad UDP endpoint, from the source row.
        buddy: KadNodeEndpoint,
        /// The buddy relationship ID the row named, in wire order.
        buddy_id: KadId,
        /// The file the callback is for, raw MD4 — the firewalled client
        /// dials back only for a file it knows.
        file_hash: rmule_primitives::FileHash,
        /// Where the firewalled client must dial us.
        tcp_port: u16,
    },
    /// Answer an inbound `0x51 KADEMLIA_FINDBUDDY_REQ` with a `0x5A
    /// KADEMLIA_FINDBUDDY_RES` (ADR-0061 open-node buddy service): the core
    /// single-slot buddy service accepted `requester` as the client we buddy for,
    /// so emit `<buddyID><ourHash><ourTCPport>[connectopts]` back to it. `buddy_id`
    /// is the requester's proposed target, echoed verbatim (the id every later
    /// relay verifies against); `connect_options`, when `Some`, appends the v7+
    /// obfuscation-capability byte aMule sends to kad-version-7 peers (it appends
    /// it only when the `0x51` carried a sender key). Our own client hash and
    /// advertised TCP port are the node config's — the `0x5A` responder identity,
    /// the same fields [`recruit_buddy`](crate::KadNode::recruit_buddy) puts on the
    /// `0x51`. The accept/refuse decision (both surfaces open, slot free, requester
    /// not known/colliding/self) is core-side, surfaced by
    /// [`FindBuddyRequested`](crate::KadEvent::FindBuddyRequested); this only enacts an
    /// accept verdict.
    AnswerFindBuddy {
        /// The client we agreed to buddy for.
        requester: KadNodeEndpoint,
        /// Its proposed buddy ID, echoed verbatim — the id every later relay
        /// is checked against.
        buddy_id: KadId,
        /// Our obfuscation-capability byte for a v7+ requester that carried a
        /// sender key; `None` otherwise.
        connect_options: Option<u8>,
    },
    /// Run a **Callback Walk** (aMule's `FINDSOURCE`, `BaseClient.cpp:2160-2170`):
    /// the sibling of
    /// [`RequestBuddyCallback`](Self::RequestBuddyCallback) for a source row
    /// that named its buddy by ID alone. Walk toward `buddy_id` and send the
    /// same `0x52` body to every responded contact within `SEARCHTOLERANCE`
    /// of it; the walk ends in
    /// [`CallbackWalkEnded`](crate::KadEvent::CallbackWalkEnded). One walk per
    /// target at a time: a second command toward a target any walk is walking
    /// ends at once, [`AlreadyWalking`](crate::KadCallbackWalkEnd::AlreadyWalking).
    CallbackWalk {
        /// The buddy relationship ID the row named, in wire order — the walk's
        /// target and the `0x52`'s first field.
        buddy_id: KadId,
        /// The file the callback is for, raw MD4.
        file_hash: rmule_primitives::FileHash,
        /// Where the firewalled client must dial us.
        tcp_port: u16,
    },
    /// Move the public IP the Kad-UDP verify-key state is bound to
    /// — the driver-facing form of
    /// [`set_own_public_ip`](crate::KadNode::set_own_public_ip). aMule
    /// re-reads `theApp->GetPublicIP()` on every send rather than pinning it
    /// at Kad start (`CPrefs::GetUDPVerifyKey`, `Prefs.cpp:235-243`); this is
    /// the driver's way to feed the same fresh reading in as Address
    /// Learning's IPv4 verdict moves (server `OP_IDCHANGE`, a Kad `0x58`).
    ///
    /// Retires every learned contact key bound to the previous address —
    /// aMule's `CKadUDPKey::GetKeyValue(myIP)` collapsing to `0` the moment
    /// `myIP` moves (`KadUDPKey.h`) — forcing a fresh three-way before that
    /// contact's key rides the wire again. The key this node *hands out* to
    /// a target is unaffected: `GetUDPVerifyKey` derives from the secret and
    /// the target's IP alone, never our own. A no-op while crypt is unarmed
    /// (the node started without verify keys): there is no verify-key state to
    /// move and no stored key reads it yet.
    SetOwnPublicIp {
        /// The address Address Learning now judges as our own.
        public_ip: std::net::Ipv4Addr,
    },
    /// Re-arm the per-datagram crypt live (ADR-0046): obfuscation with its
    /// verify keys, or plaintext — exactly what the start value installs,
    /// replacing what the node held, so the one obfuscation policy holds at
    /// every instant rather than from the next start. aMule reads
    /// `IsClientCryptLayerSupported()` on every send; this is how a driver
    /// whose policy changed feeds the node the same answer.
    ///
    /// The next datagram the node sends follows it. Receive stays dual-path
    /// either way, and a contact key learned while armed is kept for a later
    /// re-arm.
    SetObfuscation {
        /// The crypt to send under from now on; `None` sends plaintext and
        /// hands out no verify key.
        obfuscation: Option<crate::KadObfuscation>,
    },
}
