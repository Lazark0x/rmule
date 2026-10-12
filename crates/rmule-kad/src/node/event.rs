//! What the node reports: the [`KadOutput`] queue a driver drains, the
//! [`KadEvent`]s that queue carries, and the [`RoutingCensus`] fold that turns
//! the event stream into the routing-health numbers a live run is judged by.

use std::net::Ipv4Addr;

use rmule_primitives::{FileHash, Ipv4Endpoint, SourceLookupTarget, UserHash};

use super::KadNodeDiagnostic;
use crate::keyword_store::KadKeywordResult;
use crate::lookup_walk::{KadPublishEnd, KadSearchEnd};
use crate::{KadId, KadNodeEndpoint, KadSourceCandidate};

/// One unit of node output, drained via [`KadNode::poll_output`](crate::KadNode::poll_output).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum KadOutput {
    /// A datagram for the driver to send.
    Datagram {
        /// Where to send it.
        to: KadNodeEndpoint,
        /// The datagram, framed and (where the exchange calls for it) already
        /// obfuscated — the driver writes these bytes unchanged.
        bytes: Vec<u8>,
    },
    /// An observable state change or diagnostic.
    Event(KadEvent),
}

/// Observable node state changes; the deterministic trace the mesh tier
/// compares run-to-run.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum KadEvent {
    /// A contact entered the routing table.
    ContactAdded {
        /// The contact's Kad ID.
        id: KadId,
        /// Where it is reached.
        endpoint: KadNodeEndpoint,
    },
    /// The node went from silent to heard: a well-formed counterparty datagram
    /// passed the ADR-0064 entry gates while [`joined`](crate::KadNode::joined) was
    /// false. This is the **transition edge** of aMule's `HasHadContact` — the
    /// network-joined predicate (ADR-0067) — so it fires once at the first
    /// datagram after start and once more after every 20-min silence lapse
    /// ([`KadRoutingTable::HAD_CONTACT_WINDOW`](crate::KadRoutingTable::HAD_CONTACT_WINDOW)), never per datagram.
    HadContact {
        /// The counterparty whose datagram broke the silence.
        from: KadNodeEndpoint,
    },
    /// A probed contact answered and is now validated-live.
    ContactResponded {
        /// The contact that answered.
        id: KadId,
    },
    /// A contact's IP was proven not spoofed — via a hello with a valid receiver
    /// key or the `0x22` three-way (ADR-0064). Only verified contacts are served
    /// and seed walks. Online verification is key-coupled: it fires only under
    /// the armed verify-key state ([`KadObfuscation::with_verify_keys`](crate::KadObfuscation::with_verify_keys)).
    ContactVerified {
        /// The contact whose IP is now proven.
        id: KadId,
    },
    /// A probed contact stayed silent past its deadline.
    ContactFailed {
        /// The contact that did not answer.
        id: KadId,
    },
    /// A contact left the routing table.
    ContactEvicted {
        /// The contact that was dropped.
        id: KadId,
    },
    /// One solicited `KADEMLIA2_SEARCH_RES` batch, projected through the
    /// sealed **Kad Source Row Projection** (`decode_source_result`): direct
    /// High-ID rows are Peer Sources, everything else is a row diagnostic.
    SourcesFound {
        /// The file these rows answer, hash and size — the lookup the request
        /// carried, echoed back whole.
        target: SourceLookupTarget,
        /// The projected rows: a Peer Source per direct High-ID row, a
        /// diagnostic for every row the projection refused.
        candidates: Vec<KadSourceCandidate>,
    },
    /// The storer indexed a publish (new, refreshed, or evicting-oldest) and
    /// acked it. `rows_for_key` is the key's entry count afterwards.
    SourceIndexed {
        /// The file key the source was indexed under.
        key: KadId,
        /// How many rows that key holds after the publish — the number the
        /// ack's load byte is derived from.
        rows_for_key: usize,
    },
    /// A fanned publish recipient acked with its `0x4B` load byte.
    PublishAcked {
        /// The publish walk's target key.
        target: KadId,
        /// The recipient that acked.
        from: KadNodeEndpoint,
        /// Its self-reported load, 0–100 — how full that storer says it is.
        load: u8,
    },
    /// A publish walk ended — every started publish ends in exactly one of
    /// these. `acked_stores` counts the distinct recipients that acked.
    PublishComplete {
        /// The publish walk's target key.
        target: KadId,
        /// How many distinct recipients acked — the walk's actual reach.
        acked_stores: usize,
        /// Why the walk ended.
        ended_by: KadPublishEnd,
    },
    /// The storer answered a `KADEMLIA2_SEARCH_SOURCE_REQ`. Zero rows means
    /// wire silence (aMule sends nothing for an empty answer) — the event is
    /// the observable either way, and is the mesh tier's bidirectional proof
    /// that a search reached this node.
    SourceSearchServed {
        /// The searcher we answered.
        from: KadNodeEndpoint,
        /// The file key it asked about.
        target: KadId,
        /// How many rows we sent; zero means nothing went on the wire.
        rows: usize,
    },
    /// A source search ended — every walk terminates in exactly one of these.
    /// `result_rows` counts the consumed result rows.
    SourceSearchComplete {
        /// The search walk's target key.
        target: KadId,
        /// How many result rows the walk consumed.
        result_rows: usize,
        /// Why the walk ended.
        ended_by: KadSearchEnd,
    },
    /// The **Kad Storer** indexed a `KADEMLIA2_PUBLISH_KEY_REQ` batch and acked
    /// it (ADR-0062). `indexed` is how many of the batch's files were stored
    /// (the rest hit a cap/validation reject and forced the ack load to 100).
    KeywordPublishServed {
        /// The publisher we acked.
        from: KadNodeEndpoint,
        /// The keyword the batch published under.
        keyword: KadId,
        /// How many of the batch's files were stored; fewer than the batch
        /// size means a cap or validation refused the rest.
        indexed: usize,
        /// The `(keyword, file)` rows the index holds after this batch.
        stored: usize,
    },
    /// The keyword index's sweep expired rows whose publishers stopped
    /// republishing (ADR-0062): `stored` rows remain. With
    /// `KeywordPublishServed::stored`, the index size is known after every
    /// change.
    KeywordIndexExpired {
        /// The `(keyword, file)` rows the index holds after the sweep.
        stored: usize,
    },
    /// The **Kad Storer** answered a `KADEMLIA2_SEARCH_KEY_REQ`. Zero rows means
    /// wire silence (aMule sends nothing for an empty answer); the event is the
    /// observable either way.
    KeywordSearchServed {
        /// The searcher we answered.
        from: KadNodeEndpoint,
        /// The keyword it asked about.
        keyword: KadId,
        /// How many rows we sent; zero means nothing went on the wire.
        rows: usize,
    },
    /// One solicited keyword `KADEMLIA2_SEARCH_RES` batch, residual-filtered
    /// (v1 client-side multi-word) and deduped by file ID into the one search
    /// stream (ADR-0062). Empty batches (all rows filtered or already seen) emit
    /// nothing.
    KeywordsFound {
        /// The keyword being searched.
        keyword: KadId,
        /// The batch's surviving rows — already residual-filtered and deduped
        /// against everything this search has seen.
        results: Vec<KadKeywordResult>,
    },
    /// A fanned keyword-publish recipient acked with its `0x4B` load byte; the
    /// load feeds the publisher's re-publish embargo.
    KeywordPublishAcked {
        /// The keyword the publish targeted.
        keyword: KadId,
        /// The storer that acked.
        from: KadNodeEndpoint,
        /// Its self-reported load, 0–100 — what the re-publish embargo reads.
        load: u8,
    },
    /// A keyword publish walk ended — every started keyword publish ends in
    /// exactly one of these. `acked_stores` counts the distinct recipients that
    /// acked.
    KeywordPublishComplete {
        /// The keyword the publish targeted.
        keyword: KadId,
        /// How many distinct storers acked.
        acked_stores: usize,
        /// Why the walk ended.
        ended_by: KadPublishEnd,
    },
    /// A keyword search ended — every `SearchKeywords` command naming a target
    /// is answered by exactly one of these for that target; commands joined to
    /// one walk share its one. `result_rows` counts the consumed (pre-dedup)
    /// result rows.
    KeywordSearchComplete {
        /// The keyword being searched.
        keyword: KadId,
        /// How many result rows the walk consumed, counted before dedup.
        result_rows: usize,
        /// Why the walk ended.
        ended_by: KadSearchEnd,
    },
    /// The **Kad Storer** answered a `KADEMLIA2_SEARCH_NOTES_REQ` (`0x35`) —
    /// always empty (ADR-0063 Empty-Storer Parity: rmule builds no notes
    /// state, so no note is ever findable). Wire-silent like every notes
    /// branch; the event is the observable that a notes search reached and
    /// was served — the `served-empty` classification counter.
    NotesSearchServedEmpty {
        /// The searcher whose notes request we consumed.
        from: KadNodeEndpoint,
        /// The file key it asked for notes on.
        target: KadId,
    },
    /// A `0x50`/`0x53` firewall check asked us to prove the requester is
    /// TCP-reachable (ADR-0058 responder). The node has already answered `0x58`
    /// over UDP; this is the typed dial-back command core brokers — dial
    /// `requester`'s TCP port (obfuscated per `connect_options`) and, on
    /// connect, send the version-gated ack. `connect_options` is `Some` for a
    /// v7+ `0x53`, `None` for a legacy `0x50` (the ack-form signal).
    DialBackRequested {
        /// The peer to dial back, at the TCP port its request named.
        requester: Ipv4Endpoint,
        /// The requester's connect options for a v7+ `0x53`, or `None` for a
        /// legacy `0x50` — which is also the signal for which ack form to
        /// send.
        connect_options: Option<u8>,
        /// The requester's own **User Hash**, out of the `0x53` body — the
        /// crypt key basis for an obfuscated dial-back. `None`
        /// for a legacy `0x50`, which carries no hash at all and is never
        /// obfuscated.
        user_hash: Option<UserHash>,
    },
    /// A per-`(IP, opcode)` flood bucket crossed the report threshold
    /// (`count > 5 × rate`, ADR-0064). aMule bans the IP at its eD2k
    /// client-list layer here — Kad itself keeps answering the IP's other
    /// opcodes unchanged (the per-opcode bucket already contains the flood).
    /// `KadNode` only reports: a future core-owned `BanStore` is the
    /// enforcement consumer of this event.
    FloodOffenderDetected {
        /// The flooding IP.
        ip: Ipv4Addr,
        /// The opcode whose bucket overflowed — the flood is per-opcode, so
        /// this IP's other traffic is still being served.
        opcode: u8,
    },
    /// A TCP firewall check was asked of `helper` (aMule
    /// `AddKadFirewallRequest`): its connect-back is awaited for
    /// `answerable_for`, the window the node itself judges its ack by. Core
    /// mirrors it into the listener's Awaited Testers, so a helper that dials
    /// plain reaches a node whose policy is `Required` (ADR-0046 "Test
    /// Connections"). A recheck start drops every such window.
    ReachabilityCheckAsked {
        /// The contact asked to connect back.
        helper: Ipv4Addr,
        /// The helper's Kad ID, for the Run Log.
        helper_id: KadId,
        /// The helper's Kad UDP port the request went to.
        helper_udp_port: u16,
        /// The connect-options byte the request carried — `Some` for the v7+
        /// `0x53`, which also names our User Hash (the helper's obfuscation
        /// key); `None` for the legacy `0x50`, which names neither.
        connect_options: Option<u8>,
        /// How long its connect-back is awaited from now.
        answerable_for: std::time::Duration,
    },
    /// Our own hourly firewall recheck began (ADR-0058 requester): the core
    /// [`Reachability`] store snapshots its settled TCP verdict and zeroes the
    /// ack counter (`begin_tcp_recheck`), then reads that snapshot until an ack
    /// reproves open or the recheck concludes. A fresh node emits no start — its
    /// budget already sits at zero (aMule boot posture).
    ///
    /// [`Reachability`]: https://docs.rs/rmule-core "core-owned verdict store"
    ReachabilityRecheckStarted,
    /// A peer's connect-back proved one leg of our TCP reachability — a `0x59`
    /// UDP ack, or a window-guarded `OP_KAD_FWTCPCHECK_ACK` over the TCP link the
    /// peer dialed. The core store counts it (`record_tcp_ack`); two open the
    /// verdict.
    ReachabilityConnectBack,
    /// Our firewall recheck concluded without reproving open — its emission
    /// budget spent or its outstanding windows all lapsed. The core store settles
    /// on the ≥2-ack rule (`conclude_tcp_recheck`): fewer than two acks reads
    /// firewalled.
    ReachabilityRecheckConcluded,
    /// A `0x58` firewall response carried **our own external IP** as this
    /// responder saw it (ADR-0084). The node states the observation and
    /// decides nothing with it: core's Address Learning store owns the
    /// two-agree rule, the freshness window and the ladder that ranks this
    /// against the server's assignment. Emitted only while our own check is
    /// armed and the response passed its window guard, so it is never an
    /// unrequested stranger's claim.
    AddressObserved {
        /// The node that reported — the two-agree rule's key. Never the body's
        /// address: the claim and the claimant must not be the same field.
        observer: Ipv4Addr,
        /// The external IP it says it saw us at.
        address: Ipv4Addr,
    },
    /// A `KADEMLIA2_PONG` (`0x61`) answering one of our own **Extern Port
    /// Round** pings named **the UDP source port our ping was seen to arrive
    /// from** — how a node learns the port a NAT maps its Kad socket to (aMule
    /// `Prefs::SetExternKadPort`). One per observer per round; a pong we never
    /// pinged for states nothing. Stated, never applied here: the same store
    /// that ranks addresses ranks this, so the agreement rule exists once
    /// rather than once per surface, and core answers every one with
    /// [`KadCommand::SetExternalUdpPort`](crate::KadCommand::SetExternalUdpPort).
    UdpPortObserved {
        /// The node that answered — the two-agree rule's key.
        observer: Ipv4Addr,
        /// The source port it saw our datagram arrive from.
        port: u16,
    },
    /// A fresh **Extern Port Round** began (aMule
    /// `FindExternKadPort(true)`, `Prefs.cpp:305-322`, called from every
    /// recheck). Core's Address Learning store owns the reports the round
    /// produced, so this is the boundary signal the store forgets its
    /// UDP-role `KadCheck` reports on, exactly as aMule starts every round's
    /// observer lists empty rather than letting a report from the previous
    /// round back one named after this boundary.
    ExternPortRoundStarted,
    /// Our UDP firewall self-check asked a fresh helper (ADR-0058 requester,
    /// breakdown 3) to prove our UDP port reachable. Core dials `helper`'s TCP
    /// port, completes the hello and sends `request` as an `OP_FWCHECKUDPREQ`
    /// (`0xA7`) peer packet. The helper answers with a `0x62` to our Kad UDP
    /// port(s), consumed back through
    /// [`handle_datagram`](crate::KadNode::handle_datagram); the dial's end is
    /// bridged in as
    /// [`UdpFirewallCheckCancelled`](crate::KadCommand::UdpFirewallCheckCancelled)
    /// (never sent) or
    /// [`UdpFirewallCheckFailed`](crate::KadCommand::UdpFirewallCheckFailed)
    /// (sent, link ended).
    UdpFirewallCheckRequested {
        /// The helper to dial, at its TCP port.
        helper: Ipv4Endpoint,
        /// The already-framed `OP_FWCHECKUDPREQ` body — core sends these bytes
        /// rather than rebuilding the request.
        request: Vec<u8>,
    },
    /// Our UDP reachability verdict flipped to **open** on `port` — a positive
    /// `0x62` landed (ADR-0058). The core store projects it onto its UDP verdict;
    /// an open UDP surface takes the direct-callback path, so the buddy gate needs
    /// no buddy. Re-emitted with the corrected port on the 10 s intern-preference
    /// retro-correction.
    UdpReachabilityOpen {
        /// The port proven reachable. A re-emission with a different port is
        /// the intern-preference correction, not a second verdict.
        port: u16,
    },
    /// Our UDP reachability verdict flipped to **firewalled** — both fresh helpers
    /// failed, or the six-minute timeout fired while the TCP verdict was also
    /// firewalled (ADR-0058). The core store projects it; the buddy gate may then
    /// recruit.
    UdpReachabilityFirewalled,
    /// The **helper-responder** answered a peer's `OP_FWCHECKUDPREQ` (ADR-0058
    /// breakdown 3, rmule-as-helper): `0x62` result packets went to `requester`'s
    /// tested port(s). `biased` flags a result the requester must discard — its IP
    /// was already a routing-zone contact, so we could not test it fairly.
    FwCheckUdpAnswered {
        /// The peer we tested.
        requester: Ipv4Addr,
        /// Whether the result is unusable to the requester: its IP was already
        /// a routing-zone contact, so the test could not be fair.
        biased: bool,
    },
    /// A peer asked us to be its **buddy** (ADR-0061, `0x51 KADEMLIA_FINDBUDDY_REQ`,
    /// rmule-as-open-node). The sans-I/O node decoded the request; core's
    /// single-slot buddy service applies the refusal matrix (both surfaces open, no
    /// slot taken, requester not known/colliding/self) and, on accept, commands the
    /// `0x5A` answer back. `buddy_id` is the requester's proposed target (echoed
    /// into the answer); `requester_hash`/`requester_tcp_port` address its buddy
    /// TCP link.
    FindBuddyRequested {
        /// Where the request came from.
        requester: Ipv4Endpoint,
        /// The buddy ID it proposed, echoed back in an accepting answer.
        buddy_id: KadId,
        /// The requester's user hash — the identity its buddy TCP link is
        /// opened under.
        requester_hash: UserHash,
        /// The TCP port its buddy link is reached at.
        requester_tcp_port: u16,
    },
    /// Our own buddy recruitment succeeded (ADR-0061, `0x5A KADEMLIA_FINDBUDDY_RES`,
    /// rmule-as-firewalled-node): a `0x5A` from an endpoint we sent a `0x51` to,
    /// XOR-verified against our Kad ID (`~buddy_id == ourKadID`). Core fills its
    /// buddy slot with `buddy`/`buddy_id` and opens the keepalive TCP link. Only a
    /// tracked, verified answer reaches here — a stale or spoofed `0x5A` is dropped
    /// as [`UnrequestedBuddyResponse`](KadNodeDiagnostic::UnrequestedBuddyResponse).
    BuddyFound {
        /// Where the accepting buddy answered from.
        buddy: Ipv4Endpoint,
        /// Its buddy ID, already XOR-verified against our own Kad ID.
        buddy_id: KadId,
        /// The buddy's user hash — the identity the keepalive link is opened
        /// under.
        buddy_hash: UserHash,
        /// The TCP port to open that link on.
        buddy_tcp_port: u16,
        /// The buddy's connect options, when it advertised them.
        connect_options: Option<u8>,
    },
    /// A **FINDBUDDY walk** ended (ADR-0061 firewalled-node recruitment). The
    /// walk toward `~ourKadID` converged and either asked its closest
    /// responded contact to be our buddy (`asked == true`, a `0x51` left and a
    /// [`BuddyFound`](Self::BuddyFound) may follow inside the recruit window)
    /// or found nobody to ask at all. The second case is the one core must
    /// hear: a walk that never left the house should re-arm the recruit
    /// trigger rather than spend the 20-minute FindBuddy tick.
    BuddyWalkEnded {
        /// Whether a `0x51` went out.
        asked: bool,
    },
    /// A **Callback Walk** toward a firewalled source's buddy ID ended, or
    /// was refused ([`KadCommand::CallbackWalk`](crate::KadCommand::CallbackWalk)).
    CallbackWalkEnded {
        /// The buddy ID the walk was toward — the walk's key.
        buddy_id: KadId,
        /// What it came to.
        end: KadCallbackWalkEnd,
    },
    /// A peer asked our firewalled buddy to dial it back (ADR-0061,
    /// `0x52 KADEMLIA_CALLBACK_REQ`). Core verifies `buddy_id` against our
    /// registered buddy (the ADR-0061 tightening, both relays) and, on match,
    /// forwards it as `OP_CALLBACK 0x99` over the buddy's TCP link. `requester` is
    /// the datagram source (injected into the relay); `file_hash` is the callback's
    /// file.
    CallbackRelayRequested {
        /// The datagram's source — injected into the relay, since the
        /// firewalled client can only learn it from us.
        requester: Ipv4Endpoint,
        /// The buddy ID named in the request, checked against our registered
        /// buddy before anything is relayed.
        buddy_id: KadId,
        /// The file the callback is about.
        file_hash: FileHash,
        /// The TCP port the requester wants dialed back.
        requester_tcp_port: u16,
    },
    /// The forced **self-lookup** fired (ADR-0067): a `FindNode` walk toward
    /// this node's own Kad ID began, warming its own-ID neighborhood. Emitted on
    /// the schedule — 3 min after the join starts, then every 4 h — whether or
    /// not the routing table can seed a walk yet (an empty table sends no
    /// `KADEMLIA2_REQ`, but the schedule still fires). The join-progress signal a
    /// front-end surfaces and the deterministic tier asserts the cadence on.
    SelfLookupStarted,
    /// A datagram was recognized as invalid, unexpected, or out of role.
    Diagnostic(KadNodeDiagnostic),
}

/// How a **Callback Walk** ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KadCallbackWalkEnd {
    /// The `0x52` went to this many responded contacts within tolerance of
    /// the buddy ID. Whether one of them was the buddy only the firewalled
    /// client's dial-back can tell.
    Asked(usize),
    /// No responded contact was within tolerance of the buddy ID — or none
    /// responded at all — so no `0x52` left: nobody the walk met can be the
    /// buddy.
    NoneNear,
    /// A walk toward the same target was already running, so this one never
    /// started (aMule's `AlreadySearchingFor`, `SearchManager.cpp:153-160`).
    AlreadyWalking,
}

/// Why the storer declined to index a publish.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KadPublishRejection {
    /// No `TAG_SOURCETYPE`: without it the row is not a source (aMule's
    /// `m_bSource == false` reject).
    MissingSourceType,
    /// No usable `TAG_SOURCEPORT` (absent or zero).
    MissingTcpPort,
    /// The total-entry cap is reached and the publish would grow the index
    /// (rmule anti-flood policy; aMule's source index is unbounded).
    IndexFull,
}

/// A running tally of the node's routing-table membership, folded from the
/// observable [`KadEvent`] stream: a contact enters on
/// [`ContactAdded`](KadEvent::ContactAdded), leaves on
/// [`ContactEvicted`](KadEvent::ContactEvicted), and
/// [`ContactResponded`](KadEvent::ContactResponded) marks it validated-live.
///
/// This is the domain half of the `rmule-cli kad join` live-smoke
/// observability (ADR-0043): the peak `live` is the runbook's
/// "routing grows and survives" checkpoint, `served_lookups` its "keeps
/// serving strangers" checkpoint. Drivers only render the fields.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RoutingCensus {
    /// Contacts currently in the routing table.
    pub live: usize,
    /// High-water mark of `live`.
    pub peak_live: usize,
    /// Probed contacts that answered and became validated-live.
    pub responded: usize,
    /// `KADEMLIA2_SEARCH_SOURCE_REQ`s from strangers this node answered
    /// ([`SourceSearchServed`](KadEvent::SourceSearchServed)) — evidence it
    /// keeps serving routing traffic it never asked for.
    pub served_lookups: usize,
}

impl RoutingCensus {
    /// Fold one event into the census.
    pub fn observe(&mut self, event: &KadEvent) {
        match event {
            KadEvent::ContactAdded { .. } => {
                self.live += 1;
                self.peak_live = self.peak_live.max(self.live);
            }
            KadEvent::ContactEvicted { .. } => {
                self.live = self.live.saturating_sub(1);
            }
            KadEvent::ContactResponded { .. } => self.responded += 1,
            KadEvent::SourceSearchServed { .. } => self.served_lookups += 1,
            _ => {}
        }
    }
}
