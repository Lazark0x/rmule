//! The sans-I/O Kad node state machine.
//!
//! `KadNode` implements the **Routing Responder** role plus the bootstrap
//! client and hello-probe liveness that make a node routable (ADR-0043).
//! It is a pure state machine with **time as a parameter**: the
//! driver (a tokio UDP loop in `rmule-net`, or the mesh simulation in
//! tests) feeds it datagrams, commands, and tick instants, and drains
//! datagrams-to-send and events from [`poll_output`](KadNode::poll_output).
//! No clock reads, no RNG, no sockets — identical inputs produce identical
//! outputs, which is what the deterministic mesh tier scores against.
//!
//! ## Liveness and anti-poisoning rules
//!
//! - A node that *speaks to us from its own endpoint* carrying its identity
//!   (hello request, solicited hello/bootstrap response) is stored
//!   [`Responded`](KadContactState::Responded).
//! - A contact learned as *hearsay* (a bootstrap-response row) is stored
//!   [`Pending`](KadContactState::Pending) and hello-probed; it either answers
//!   within [`KadNode::PROBE_TIMEOUT`] or is marked failed and evicted.
//! - Unsolicited responses (hello res, bootstrap res, lookup res, pong) are
//!   diagnosed and their payloads discarded — hearsay from nowhere never
//!   touches the routing table.
//! - Malformed datagrams produce typed diagnostics, never panics and never
//!   state changes.
//!
//! ## Layout
//!
//! This file owns the state and the driver-facing loop — `new`, `tick`,
//! `handle_command`, `poll_output`, `next_wake`. Each protocol leg implements
//! its own half in a private submodule: `join` (bootstrap dials and the join
//! cadence), `small_timer` (the per-minute hello pass), `contact` (hello,
//! `0x22` verification, routing intake), `firewall` (both self-checks), `buddy`, `source`, `keyword`, `notes`,
//! `walk` (the iterative lookup) and `wire` (the datagram boundary). The
//! vocabulary a driver speaks lives in `config`, `command`, `event` and
//! `diagnostic`, re-exported here.

mod buddy;
mod command;
mod config;
mod contact;
mod diagnostic;
mod event;
mod firewall;
mod join;
mod keyword;
mod notes;
mod small_timer;
mod source;
mod start;
mod udp_firewall;
mod walk;
mod wire;

pub use self::command::KadCommand;
pub use self::config::{KadContactAdmission, KadNodeConfig, KadReachability, UdpFirewallHelper};
pub use self::diagnostic::KadNodeDiagnostic;
pub use self::event::{
    KadCallbackWalkEnd, KadEvent, KadOutput, KadPublishRejection, RoutingCensus,
};
pub use self::start::{KadNodeStart, KadObfuscation, KadSelfCheck};

use std::collections::VecDeque;
use std::net::Ipv4Addr;

use rmule_primitives::DatagramNonce;

use crate::flood::FloodTable;
use crate::keyword_publisher::KeywordPublisher;
use crate::keyword_store::{KeywordPublishFile, KeywordStore};
use crate::lookup_walk::{KadLookupWalk, KadWalkAction, KadWalkPurpose};
use crate::reachability::{FirewallSelfCheck, UdpFirewallTester};
use crate::source_store::SourceStore;
use crate::{
    BootstrapDialList, KadContactState, KadId, KadInstant, KadNodeEndpoint, KadPublishRequest,
    KadRoutingTable,
};

/// An outstanding hello probe: `endpoint` must answer as `expected` before
/// `deadline`. What an unanswered deadline does next depends on
/// `evict_on_timeout`: a join or firewall probe fails and evicts the
/// contact it targets, aMule's own behavior for a never-verified contact
/// (`CContact`'s type-3 constructor needs only one `CheckingType` step to
/// reach the type-4 dead sweep, `RoutingZone.cpp:960-968`); a small-timer
/// aging probe does neither — it is dropped so the endpoint is free for the
/// next hello, and eviction is the aging ladder's own call (per-contact
/// `checks`, via `small_timer_pass`), which gives an aged contact a second
/// hello first.
#[derive(Clone, Copy, Debug)]
struct PendingProbe {
    endpoint: KadNodeEndpoint,
    expected: KadId,
    deadline: KadInstant,
    evict_on_timeout: bool,
}

/// An outstanding `KADEMLIA2_BOOTSTRAP_REQ`: `endpoint` must answer before
/// `deadline` or the solicitation expires unmatched (ADR-0064's 180 s
/// out-track alignment — bootstrap correlation is the one delivered
/// mechanism this crate had left with no acceptance window at all).
#[derive(Clone, Copy, Debug)]
struct PendingBootstrap {
    endpoint: KadNodeEndpoint,
    deadline: KadInstant,
}

/// An outstanding `0x22` ack-request: `endpoint` must answer as `expected`
/// before `deadline` or the solicitation is pruned unmatched — the
/// verification counterpart to [`PendingProbe`]. One-shot and
/// single-use (consumed when the matching `0x22` arrives), at most one per
/// endpoint (a re-request replaces it).
#[derive(Clone, Copy, Debug)]
struct AwaitingAck {
    endpoint: KadNodeEndpoint,
    expected: KadId,
    deadline: KadInstant,
}

/// A registered publication: republished every
/// [`KadNode::SOURCE_REPUBLISH_INTERVAL`], anchored at each publish start
/// (the aMule cadence — its shared-file loop schedules the next source
/// publish when one starts).
#[derive(Clone, Copy, Debug)]
struct ScheduledPublish {
    request: KadPublishRequest,
    next_at: KadInstant,
}

/// An in-flight keyword search's node-side state (the walk holds only the
/// target, staying `Copy`): the residual query tokens (v1 client-side
/// multi-word filter) and the file IDs already surfaced (dedup into the one
/// search stream, ADR-0062). Dropped when the search walk completes.
#[derive(Clone, Debug)]
struct KeywordSearch {
    target: KadId,
    residual_tokens: Vec<String>,
    surfaced: Vec<KadId>,
}

/// An in-flight keyword publish round's node-side state (the walk holds only the
/// target): the batch being fanned (for the `0x43` datagrams, chunked ≤ 50 per
/// packet) and the `0x4B` loads collected (for the load embargo). Dropped when
/// the publish walk completes.
#[derive(Clone, Debug)]
struct KeywordPublishRound {
    keyword: KadId,
    files: Vec<KeywordPublishFile>,
    loads: Vec<u8>,
}

/// The crypt provenance the dual-path receive recovers for one datagram,
/// threaded into the hello / `0x22` verification handlers (ADR-0064, the
/// provenance-model pattern carried onto the Kad surface) and, as the per-dispatch
/// reply key, into every response the datagram draws.
///
/// Live under the armed verify-key state. A plaintext datagram reads
/// `(false, None)`; unarmed, `valid_receiver_key` stays `false` (there is no
/// derivation to compare against) while the trailer's sender key still rides —
/// aMule likewise recovers trailer keys in the socket regardless of Kad state.
#[derive(Clone, Copy, Debug, Default)]
struct ReceivedKey {
    /// The trailer's receiver verify key matched our own derivation for the
    /// sender's IP — aMule's `bValidReceiverKey`
    /// (`ClientUDPSocket.cpp#L100`, `GetUDPVerifyKey(ip) == receiverVerifyKey`).
    /// A **trailer** comparison, deliberately not a which-family-decrypted
    /// check: aMule's NodeID-keyed datagrams still carry the receiver key in
    /// the trailer (proven by the captured crypt `0x60` PING
    /// `hello_req_0x60_crypt.bin` — a ping despite the fixture's legacy
    /// `hello_req` name — family bits 0 with a live trailer), so keying-family
    /// would reject the exact datagrams the verification model exists for. The
    /// derived key is never `0`, so a plaintext datagram (no trailer) can
    /// never pass.
    valid_receiver_key: bool,
    /// The sender's verify key recovered from the crypt trailer — present iff we
    /// can key a `0x22` (or any response) back to it. `None` for a plaintext
    /// datagram **and** for a zeroed trailer: key `0` is aMule's
    /// `CKadUDPKey::IsEmpty` no-key sentinel, and the role-B `0x22` reply must
    /// take the silent "didn't send any sender key" branch on it
    /// (`KademliaUDPListener.cpp#L608`).
    sender_key: Option<u32>,
}

impl ReceivedKey {
    /// The provenance of a decrypted datagram (or the plaintext default),
    /// judged against `own_key_for_sender` — this node's [`udp_verify_key`](crate::udp_verify_key)
    /// derivation for the datagram's source IP (`None` until armed).
    fn of(
        decrypted: Option<&rmule_primitives::DecryptedDatagram>,
        own_key_for_sender: Option<u32>,
    ) -> Self {
        Self {
            valid_receiver_key: own_key_for_sender.is_some()
                && decrypted.and_then(|d| d.receiver_verify_key) == own_key_for_sender,
            sender_key: decrypted
                .and_then(|d| d.sender_verify_key)
                .filter(|&key| key != 0),
        }
    }
}

/// The armed Kad UDP verify-key state (the ADR-0046 key state this node's
/// ADR-0064 verification cluster rides): the private per-installation
/// derivation secret (aMule `thePrefs::GetKadUDPKey()`) and the public IP the
/// keys we hand out — and every peer key we store — are bound to.
#[derive(Clone, Copy, Debug)]
struct VerifyKeyState {
    secret: u32,
    public_ip: Ipv4Addr,
}

/// The sans-I/O Kad node (see the module docs for the contract).
#[derive(Debug)]
pub struct KadNode {
    config: KadNodeConfig,
    /// The contact-admission verdict: consulted at every contact
    /// intake — `store`, the bootstrap dial-list seed, and lookup-response
    /// rows. Default admits everything; the driver starts the node with the production
    /// IP-filter closure ([`KadNodeStart::admission`]).
    contact_admission: KadContactAdmission,
    routing: KadRoutingTable,
    outputs: VecDeque<KadOutput>,
    /// Outstanding bootstrap requests, in send order (= deterministic expiry
    /// order); each expires unmatched at its 180 s solicitation deadline
    /// (ADR-0064).
    outstanding_bootstraps: Vec<PendingBootstrap>,
    /// Outstanding hello probes, in send order (= deterministic expiry order).
    pending_probes: Vec<PendingProbe>,
    /// Active source-lookup walks, in start order; a walk is dropped the
    /// moment it completes.
    walks: Vec<KadLookupWalk>,
    /// The **Kad Storer**'s bounded source index.
    source_store: SourceStore,
    /// Registered publications, in registration order.
    scheduled_publishes: Vec<ScheduledPublish>,
    /// Outstanding `0x22` ack-requests recorded when this node's `HELLO_RES`
    /// set misc-options bit 2 (the verification tracked-out set,
    /// ADR-0064). At most one per endpoint (a re-request replaces it); an
    /// inbound `0x22` from an endpoint absent here is unsolicited. Single-use —
    /// consumed when the matching ACK arrives, or pruned at its
    /// [`ACK_REQUEST_WINDOW`](Self::ACK_REQUEST_WINDOW) deadline in
    /// [`tick`](Self::tick) if none does, so a never-answered request cannot
    /// leak an entry forever (the sibling discipline `pending_probes` and
    /// `outstanding_bootstraps` already keep).
    awaiting_acks: Vec<AwaitingAck>,
    /// Per-datagram send-obfuscation (ADR-0046): when `Some`, outbound
    /// datagrams are RC4-encrypted per aMule's key-choice matrix (see
    /// [`obfuscate_outbound`](Self::obfuscate_outbound)), drawing per-packet
    /// entropy from the injected nonce source. `None` (the default) leaves
    /// every datagram plaintext — capture-gated off like the server-UDP
    /// surface until the datagram byte facts are ratified and
    /// per-contact crypt-support tracking (ADR-0058) lands.
    outbound_obfuscation: Option<fn() -> DatagramNonce>,
    /// The armed verify-key state ([`KadObfuscation::with_verify_keys`]);
    /// `None` keeps the whole ADR-0064 verification cluster plaintext-dormant.
    verify_keys: Option<VerifyKeyState>,
    /// Our public IPv4 as core last stated it (`SetOwnPublicIp`, or the
    /// arming IP), whether or not crypt is armed: the UDP check's "not
    /// ourselves" rule reads it. `0.0.0.0` is core's "no address known".
    own_public_ip: Option<Ipv4Addr>,
    /// The sender key of the datagram currently being dispatched, scoped to its
    /// source endpoint — aMule keys **every** response under the requester's
    /// fresh `senderKey` (`SendPacket(…, senderKey, NULL)` on each `Process*`
    /// reply), not under the stored contact key, and a non-contact requester
    /// (a stranger's bootstrap or lookup) has no stored key at all. Set around
    /// dispatch in [`handle_datagram`](Self::handle_datagram), read by
    /// [`obfuscate_outbound`](Self::obfuscate_outbound) for sends addressed
    /// back to that endpoint only, cleared before returning — never leaks
    /// across datagrams.
    reply_key: Option<(KadNodeEndpoint, u32)>,
    /// The per-`(IP, opcode)` leaky flood limiter (ADR-0064, `flood.rs`).
    flood: FloodTable,
    /// Our own firewall self-check requester (ADR-0058 requester cycle). `None`
    /// (the default) leaves it dormant — no emission, no timers, no response
    /// consume — so routing-only nodes (the mesh sim) carry no firewall cadence;
    /// a driver starts the node with [`KadNodeStart::self_check`]. Capture-gated off
    /// like the obfuscation seam above: the live dial-back + ack legs it drives
    /// are the ADR-0058 capture tier, so production arms it once those ratify.
    firewall: Option<FirewallSelfCheck>,
    /// Our own UDP firewall self-check (ADR-0058 requester, breakdown 3), armed
    /// alongside the TCP check by [`KadNodeStart::self_check`]. `None` leaves it
    /// dormant (routing-only nodes run no UDP test). Explicit-time; the
    /// peer-TCP `OP_FWCHECKUDPREQ` dial to each fresh helper is core-brokered,
    /// the `0x60`/`0x61` Extern Port Round is the node's own, and the port it
    /// learns is core's verdict.
    udp_firewall: Option<UdpFirewallTester>,
    /// Where the UDP tester's helper lookup walks (aMule `FindNodeFWCheckUDP`'s
    /// random target), drawn from the driver's entropy — the node draws none.
    /// `None` leaves the lookup unlaunched, so a node that never armed it offers
    /// helpers only through
    /// [`offer_udp_firewall_helper`](Self::offer_udp_firewall_helper).
    udp_helper_target: Option<fn() -> KadId>,
    /// The **Extern Kad Port** the outside world reaches us at (aMule
    /// `Prefs::GetExternalKadPort`) — **core's Address Learning verdict,
    /// injected** (ADR-0084), never a rule of this node's own. The node's
    /// Extern Port Round pings for it and states each answer
    /// ([`KadEvent::UdpPortObserved`]); the store applies the agreement rule,
    /// so the rule exists once rather than once per surface. Defaults to the
    /// intern port ([`KadNodeConfig::udp_port`]) — "no distinct PAT mapping" —
    /// until [`crate::KadCommand::SetExternalUdpPort`] carries a verdict in;
    /// `0` after a round that never agreed.
    udp_extern_port: u16,
    /// Our Known IPv6 as the Advertised Endpoints chooser settled it
    /// (ADR-0084), or `None` — **core's verdict, injected** through
    /// [`crate::KadCommand::SetAdvertisedIpv6`], never this node's own reading
    /// of an interface. `Some` puts the `ip6` tag on every source publish; the
    /// tag is the fact, so a node that does not hold an address publishes none
    /// and is not offered as an IPv6 source (ADR-0087). Kad's own contacts stay
    /// IPv4 either way.
    advertised_ipv6: Option<std::net::Ipv6Addr>,
    /// The publish posture — **core's verdict, injected** through
    /// [`crate::KadCommand::SetPublishPosture`] from Self Reach's
    /// `firewalled` and the buddy row of its Buddy Snapshot, never this
    /// node's own reading. See [`crate::KadPublishPosture`] for the rows it
    /// selects.
    publish_posture: crate::KadPublishPosture,
    /// The `TAG_ENCRYPTION` byte source publishes carry — the driver's
    /// [`crate::KadCommand::SetPublishConnectOptions`]; `None` omits the tag.
    publish_connect_options: Option<u8>,
    /// Endpoints we sent a `0x51 KADEMLIA_FINDBUDDY_REQ` to and their tracked-packet
    /// deadlines (ADR-0061 firewalled-node recruitment): the guard a `0x5A` answer
    /// must match (aMule's `CHECK_TRACKED_PACKET(KADEMLIA_FINDBUDDY_REQ)`). Empty
    /// until [`recruit_buddy`](Self::recruit_buddy) emits; pruned as windows lapse.
    buddy_recruit: Vec<(Ipv4Addr, KadInstant)>,
    /// The **Kad Keyword Store** this node serves inbound `0x43`/`0x33` from
    /// (ADR-0062).
    keyword_store: KeywordStore,
    /// The **Kad Publisher**'s keyword scheduling state (ADR-0062).
    keyword_publisher: KeywordPublisher,
    /// In-flight keyword searches, keyed by keyword target (see [`KeywordSearch`]).
    keyword_searches: Vec<KeywordSearch>,
    /// In-flight keyword publish rounds, keyed by keyword target (see
    /// [`KeywordPublishRound`]).
    keyword_publishes: Vec<KeywordPublishRound>,
    /// The node's own reachability/buddy inputs to the keyword publish gate and
    /// storer refusal (ADR-0062). Injected; defaults to assume-open. See
    /// [`KadReachability`].
    reachability: KadReachability,
    /// The unified **Bootstrap Dial List** (ADR-0067): config-endpoint seeds
    /// and file-loaded v3 nodes.dat candidates fed via
    /// [`KadCommand::SeedBootstrapDialList`], dialed one at a time on the
    /// [`next_bootstrap_dial`](Self::next_bootstrap_dial) cadence.
    bootstrap_dial_list: BootstrapDialList,
    /// When the next front-of-list candidate is due to be dialed, or `None` when
    /// the dial loop is not running (never seeded, drained, or stopped because
    /// the node joined). Armed to `now` on the first seed of an empty list so the
    /// first dial fires promptly, then paced by the 15 s / 2 s cadence.
    next_bootstrap_dial: Option<KadInstant>,
    /// When the forced self-lookup next fires (ADR-0067), or `None` until a
    /// driver starts the node with [`KadNodeStart::self_lookup`]. Set to
    /// `start + 3 min`, then re-armed `+ 4 h` on each fire. Left `None` by
    /// routing-only nodes (the mesh sim), which run no join cadence.
    next_self_lookup: Option<KadInstant>,
    /// When the next **small-timer hello pass** fires, or `None`
    /// until a driver starts the node with [`KadNodeStart::small_timer`] —
    /// aMule's per-zone `OnSmallTimer` minute, which greets each bucket's oldest
    /// due contact joined or not. It is what reaches a table-seeded start (a
    /// v1/v2 nodes.dat merge feeds the routing table, not the Bootstrap Dial
    /// List) and a contact merged later. Left `None` by routing-only nodes (the
    /// mesh sim).
    next_small_timer: Option<KadInstant>,
    /// aMule's `m_bootstrap` — the instant of the **last bootstrap dial**, the
    /// shared 10 s throttle (ADR-0067). Stamped by
    /// [`dial_bootstrap`](Self::dial_bootstrap), so *every* bootstrap dial
    /// updates it: the list-dial loop and the ed2k→Kad handoff both
    /// stamp and both read it, which is what rate-couples them. `None` until the
    /// first dial (an un-throttled fresh node). Not a wake source — a pure gate,
    /// so routing-only nodes still quiesce.
    last_bootstrap: Option<KadInstant>,
}

impl KadNode {
    /// The Kad2 protocol version rmule advertises. aMule 2.3.3 emits 8 for
    /// itself and its stored contacts (capture-proven in the node-message
    /// fixtures).
    pub const KAD_VERSION: u8 = 8;

    /// The node before its start-up value is applied: empty routing table, no
    /// outstanding exchanges, nothing scheduled, plaintext.
    fn unstarted(config: KadNodeConfig) -> Self {
        Self {
            config,
            contact_admission: KadContactAdmission::default(),
            routing: KadRoutingTable::new(config.id),
            outputs: VecDeque::new(),
            outstanding_bootstraps: Vec::new(),
            pending_probes: Vec::new(),
            walks: Vec::new(),
            source_store: SourceStore::new(Self::MAX_SOURCES_PER_KEY, Self::MAX_SOURCE_INDEX_TOTAL),
            scheduled_publishes: Vec::new(),
            awaiting_acks: Vec::new(),
            outbound_obfuscation: None,
            verify_keys: None,
            own_public_ip: None,
            reply_key: None,
            flood: FloodTable::new(),
            firewall: None,
            udp_firewall: None,
            udp_helper_target: None,
            udp_extern_port: config.udp_port,
            advertised_ipv6: None,
            publish_posture: crate::KadPublishPosture::Reachable,
            publish_connect_options: None,
            buddy_recruit: Vec::new(),
            keyword_store: KeywordStore::new(),
            keyword_publisher: KeywordPublisher::new(),
            keyword_searches: Vec::new(),
            keyword_publishes: Vec::new(),
            reachability: KadReachability::default(),
            bootstrap_dial_list: BootstrapDialList::new(),
            next_bootstrap_dial: None,
            next_self_lookup: None,
            next_small_timer: None,
            last_bootstrap: None,
        }
    }

    /// Drain one unit of output. Call until `None` after every `handle_*` or
    /// `tick`.
    pub fn poll_output(&mut self) -> Option<KadOutput> {
        self.outputs.pop_front()
    }

    /// The earliest instant at which [`tick`](Self::tick) has work to do.
    #[must_use]
    pub fn next_wake(&self) -> Option<KadInstant> {
        let bootstraps = self.outstanding_bootstraps.iter().map(|p| p.deadline);
        let probes = self.pending_probes.iter().map(|p| p.deadline);
        let walks = self.walks.iter().filter_map(KadLookupWalk::next_wake);
        let republishes = self.scheduled_publishes.iter().map(|s| s.next_at);
        // The firewall self-check contributes a wake only while armed — a
        // routing-only node reports none, so the mesh sim still quiesces.
        let firewall = self.firewall.as_ref().map(FirewallSelfCheck::next_wake);
        // The UDP tester contributes its six-minute timeout instant, and only
        // while the test could still time out (armed, running, unconcluded,
        // and TCP-firewalled — `check_timeout`'s conclude gate).
        let udp_firewall = self
            .udp_firewall
            .as_ref()
            .and_then(|tester| tester.next_wake(self.reachability.tcp_firewalled));
        // The join cadences also contribute only while active: the dial timer is
        // cleared once the list drains or the node joins, and the self-lookup is
        // `None` until a driver arms it — so a routing-only node stays quiescible.
        // A tracked buddy recruit contributes its expiry so an otherwise-idle
        // node still ticks the prune — without it an unanswered `0x51`'s entry
        // would sit in the tracker until unrelated traffic next woke the node.
        let buddy_recruits = self.buddy_recruit.iter().map(|(_, deadline)| *deadline);
        bootstraps
            .chain(probes)
            .chain(walks)
            .chain(republishes)
            .chain(self.source_store.next_wake())
            .chain(firewall)
            .chain(udp_firewall)
            .chain(buddy_recruits)
            .chain(self.keyword_sweep_next_wake())
            .chain(self.keyword_publish_next_wake())
            .chain(self.next_bootstrap_dial)
            .chain(self.next_self_lookup)
            .chain(self.next_small_timer)
            .min()
    }

    /// Apply a driver command.
    pub fn handle_command(&mut self, now: KadInstant, command: KadCommand) {
        match command {
            KadCommand::Bootstrap { endpoint } => self.dial_bootstrap(now, endpoint),
            KadCommand::SeedBootstrapDialList { candidates } => {
                self.seed_bootstrap_dial_list(now, candidates);
            }
            KadCommand::BootstrapFromPeer { endpoint } => self.handoff_from_peer(now, endpoint),
            KadCommand::MergeContacts { contacts } => {
                // A merged contact is rmule's own: it passed the nodes.dat
                // gate before the command was sent (ADR-0066).
                for contact in contacts {
                    self.store(
                        now,
                        contact.in_state(KadContactState::Responded),
                        rmule_primitives::Informant::Own,
                    );
                }
            }
            KadCommand::SearchSources { request } => self.start_source_search(now, request),
            KadCommand::PublishSource { request } => self.register_publish(now, request),
            KadCommand::WithdrawSource { request } => self.withdraw_publish(request),
            KadCommand::SearchKeywords { request } => self.start_keyword_search(now, &request),
            KadCommand::PublishKeywords { file } => {
                self.keyword_publisher.register(now, &file);
                self.drive_keyword_publishes(now);
            }
            KadCommand::SetTcpReachability { firewalled } => {
                self.reachability.tcp_firewalled = firewalled;
            }
            KadCommand::SetExternalUdpPort { port } => self.set_extern_udp_port(port),
            KadCommand::SetOwnPublicIp { public_ip } => self.set_own_public_ip(public_ip),
            KadCommand::SetObfuscation { obfuscation } => self.install_obfuscation(obfuscation),
            // The readers refuse an `ip6` that fails `IsUsableTagIdentity`, so
            // the writer never states one, whatever the driver passed.
            KadCommand::SetAdvertisedIpv6 { address } => {
                self.advertised_ipv6 =
                    address.filter(|address| rmule_primitives::is_usable_tag_identity(*address));
            }
            KadCommand::SetPublishPosture { posture } => self.publish_posture = posture,
            KadCommand::SetPublishConnectOptions { options } => {
                self.publish_connect_options = options;
            }
            KadCommand::RecheckReachability => {
                self.recheck_reachability(now);
            }
            KadCommand::TcpFirewallAck { peer_ip } => self.consume_tcp_firewall_ack(now, peer_ip),
            KadCommand::UdpFirewallRequest {
                requester_ip,
                request,
                caller_known,
            } => self.consume_udp_firewall_request(requester_ip, &request, caller_known),
            KadCommand::UdpFirewallCheckFailed { helper_ip } => {
                self.consume_udp_firewall_failure(now, helper_ip);
            }
            KadCommand::UdpFirewallCheckCancelled { helper_ip } => {
                self.consume_udp_firewall_cancelled(now, helper_ip);
            }
            KadCommand::RecruitBuddy { target } => self.recruit_buddy(now, target),
            KadCommand::FindBuddyWalk { target } => self.start_findbuddy_walk(now, target),
            KadCommand::AnswerFindBuddy {
                requester,
                buddy_id,
                connect_options,
            } => self.answer_findbuddy(requester, buddy_id, connect_options),
            KadCommand::RequestBuddyCallback {
                buddy,
                buddy_id,
                file_hash,
                tcp_port,
            } => self.request_buddy_callback(buddy, buddy_id, file_hash, tcp_port),
            KadCommand::CallbackWalk {
                buddy_id,
                file_hash,
                tcp_port,
            } => self.start_callback_walk(now, buddy_id, file_hash, tcp_port),
        }
    }

    /// Expire due probes, walk deadlines, stored-source lifetimes, and
    /// unmatched bootstrap solicitations. Idempotent between deadlines; the
    /// driver calls it at (or after) [`next_wake`](Self::next_wake).
    pub fn tick(&mut self, now: KadInstant) {
        self.source_store.tick(now);
        let stored_before = self.keyword_store.len();
        self.keyword_store.tick(now);
        let stored = self.keyword_store.len();
        if stored != stored_before {
            self.emit_event(KadEvent::KeywordIndexExpired { stored });
        }
        // An expired solicitation is silently dropped: unlike a probed
        // contact, nothing was ever added to the routing table for it, so
        // there is nothing to fail or evict — just one fewer live candidate
        // for a genuine (if late) `KADEMLIA2_BOOTSTRAP_RES` to match, per the
        // single-use out-track semantics (ADR-0064).
        self.outstanding_bootstraps
            .retain(|pending| pending.deadline > now);
        // An expired `0x22` ack-request is pruned the same way, and for the
        // same reason: the solicited contact was already stored when we set the
        // ack-request bit, so an unanswered request has nothing to fail or
        // evict — dropping it just frees the slot and leaves a late `0x22`
        // (correctly) unsolicited, rather than leaking the entry forever.
        self.awaiting_acks
            .retain(|awaiting| awaiting.deadline > now);
        // Vec order = send order, so expiry order is deterministic.
        let due: Vec<PendingProbe> = {
            let (due, keep) = self
                .pending_probes
                .drain(..)
                .partition(|probe| probe.deadline <= now);
            self.pending_probes = keep;
            due
        };
        for probe in due {
            // A small-timer aging probe's timeout decides nothing on its
            // own: dropping the entry here just frees the endpoint
            // for the next hello. Eviction is the aging ladder's call, made
            // when the contact is next due and has already used up its
            // checks (`small_timer_pass`).
            if !probe.evict_on_timeout {
                continue;
            }
            if let Some(contact) = self.routing.get(probe.expected).copied() {
                self.routing
                    .upsert(now, contact.in_state(KadContactState::Failed));
                self.emit_event(KadEvent::ContactFailed { id: probe.expected });
                self.routing.evict(probe.expected);
                self.emit_event(KadEvent::ContactEvicted { id: probe.expected });
            }
        }

        // Walks tick in start order; actions are applied after the borrow of
        // each walk ends.
        let batches: Vec<(KadWalkPurpose, Vec<KadWalkAction>)> = self
            .walks
            .iter_mut()
            .map(|walk| (walk.purpose(), walk.tick(now)))
            .filter(|(_, actions)| !actions.is_empty())
            .collect();
        for (purpose, actions) in batches {
            self.apply_walk_actions(now, purpose, actions);
        }

        // Fire due republishes last, in registration order, so a walk that
        // completed in this same tick is already gone.
        for index in 0..self.scheduled_publishes.len() {
            let scheduled = self.scheduled_publishes[index];
            if scheduled.next_at > now {
                continue;
            }
            self.scheduled_publishes[index].next_at = now + Self::SOURCE_REPUBLISH_INTERVAL;
            self.start_publish_walk(now, scheduled.request);
        }

        // Expired, unanswered buddy recruits leave the tracker (their `0x5A`
        // would fail the tracked-packet guard anyway); their deadlines drive
        // `next_wake`, so a long-lived recruiting node cannot accumulate them.
        self.buddy_recruit.retain(|(_, deadline)| now < *deadline);

        // Our own firewall self-check clocks last, so their recheck/timeout events
        // trail this tick's routing events.
        self.tick_firewall(now);
        self.tick_udp_firewall(now);
        // Keyword publishes fire after any walk that completed this tick
        // has freed its concurrency slot.
        self.drive_keyword_publishes(now);
        // The join cadences last (ADR-0067): the dial loop dials the next
        // bootstrap candidate if due and still not joined; the self-lookup fires
        // its scheduled `FindNode` walk; the small timer hellos each bucket's
        // oldest due contact. All trail the routing events above.
        self.tick_bootstrap_dials(now);
        self.tick_self_lookup(now);
        self.tick_small_timer(now);
    }

    fn emit_event(&mut self, event: KadEvent) {
        self.outputs.push_back(KadOutput::Event(event));
    }

    fn emit_diagnostic(&mut self, diagnostic: KadNodeDiagnostic) {
        self.emit_event(KadEvent::Diagnostic(diagnostic));
    }
}
