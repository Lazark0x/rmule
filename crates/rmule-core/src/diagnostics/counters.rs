//! The process-lifetime counters (ADR-0077): monotonic totals a consumer differences itself, and the session-level facts beside them.

use std::time::Instant;

use super::{
    ActingRefusal, BuddyHashSpellingCounters, BuddyState, NattHintRefusal, NattPredictionRefusal,
    NattRetirement, RecruitRefusal,
};

/// Process-lifetime byte totals across every transfer (ADR-0077).
///
/// Strictly monotonic and independent of the per-transfer maps: a download or
/// upload row disappearing on teardown never subtracts from these, so a
/// consumer that polls slower than transfers complete still sees every byte.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionCounters {
    /// Payload bytes received from peers by every download since core start.
    pub down_bytes_total: u64,
    /// Payload bytes served to peers by the serve activity since core start.
    pub up_bytes_total: u64,
    /// Sources dropped at ingest because this build cannot dial their
    /// **Address Family** (ADR-0085). The address was real — a Sentinel Source
    /// the reader resolved — but this build has no dialect for that family, so
    /// pooling it would spend a worker slot on a conversation rmule cannot
    /// hold. Counted rather than silent, so "no sources" never hides a family
    /// gap.
    pub undialable_family_sources_total: u64,
    /// Client-UDP datagrams dropped because the opcode they carry has **no
    /// wire form that can express the sender's Address Family** (ADR-0087).
    ///
    /// The sibling of the count above, one layer down: there the *source* was
    /// undialable, here the *body* is unanswerable. An `OP_REASKCALLBACKUDP`
    /// (`0x94`) from an IPv6 requester is the case that arises — the
    /// relay it would become packs the requester into 32 bits, so honouring it
    /// would send a firewalled client to the wrong address. Counted rather
    /// than silent, so a dialect gap looks like a gap and not like packet loss.
    pub unanswerable_family_datagrams_total: u64,
    /// Peer hellos refused under a named code (ADR-0050) — a hello counting
    /// a tag it never wrote. Counted beside the
    /// [`CoreEvent::PeerHelloRefused`](crate::CoreEvent::PeerHelloRefused) each
    /// one raises, so a client that can never complete a hello with rmule
    /// shows as a number, not as silence.
    pub peer_hellos_refused_total: u64,
    /// Client-UDP datagrams on the IPv6 half that bore a crypt header no key
    /// opened (ADR-0087's divergence note). eMuleAI's 35-byte key leaves one
    /// byte unwritten, so its obfuscated IPv6 datagrams land here unless that
    /// byte happens to equal the magic; so does junk shaped like a header.
    pub ipv6_undecryptable_datagrams_total: u64,
    /// Rendezvous rmule emitted toward a target's serving buddy — NAT
    /// traversal attempts begun (ADR-0091 rung 1).
    pub natt_rendezvous_emitted_total: u64,
    /// Introductions rmule asked its server for (`0x60`) — NAT traversal
    /// attempts begun through the server coordinator (ADR-0091 rung 1).
    pub natt_server_requests_emitted_total: u64,
    /// Rendezvous rmule forwarded as somebody's serving buddy.
    pub natt_relays_forwarded_total: u64,
    /// Rendezvous rmule was asked to forward and did not — wrong buddy ID, no
    /// held link, the pending cap, or the per-source limit. Beside the count
    /// above this is what tells a relay service in demand from one under
    /// attack.
    pub natt_relays_refused_total: u64,
    /// Introductions from our server (`OP_LOWID_HOLEPUNCH_INFO`) that became a
    /// punch burst — ours asked for, or a peer's that named us.
    pub natt_server_punches_total: u64,
    /// Introductions the server refused (`OP_LOWID_HOLEPUNCH_FAIL`).
    pub natt_server_refusals_total: u64,
    /// Why the most recent one was refused. A refusal is the only thing the
    /// server ever *says* about a failed punch — everything after the
    /// introduction fails by silence — so the reason is worth keeping: a run
    /// of `TargetNoUdp` means the targets are not NAT-T clients at all, a run
    /// of `TargetNotConnected` means our source list is stale.
    pub natt_server_last_refusal: Option<rmule_ed2k::HolepunchFailReason>,
    /// **Tunnels** rmule dialed after a punch — the requester's side, and the
    /// only one of the two counts that says the whole ladder worked: a
    /// rendezvous went out, a hint came back, a burst landed and a transport
    /// rose over the pinhole it opened.
    pub natt_tunnels_dialed_total: u64,
    /// Tunnels rmule accepted over a punched path — the responder's side.
    /// Counted apart from the dialed ones because the asymmetry is the
    /// dialect's (the requester dials, the other side accepts), so the two
    /// numbers answer different questions about the same node.
    pub natt_tunnels_accepted_total: u64,
    /// Which transport carried the most recent tunnel. uTP for every tunnel
    /// this build raises; the field exists so the day `CT_MOD_MISCOPTIONS`
    /// bit 4 lights up, the surface already says which one ran.
    pub natt_last_tunnel_transport: Option<rmule_net::natt::TunnelTransport>,
    /// Endpoint hints dropped without a punch, and why the last one was. A run
    /// of `NotExpected` is unsolicited traffic; a run of `UntrustedSource`
    /// means a buddy is answering from an endpoint we did not send to.
    pub natt_hint_refusals_total: u64,
    /// Why the most recent hint was refused.
    pub natt_last_hint_refusal: Option<NattHintRefusal>,
    /// `OP_HOLEPUNCH` triggers from an endpoint nothing was expected from.
    /// Never answered (answering would make rmule a reflector); counted,
    /// because a steady stream of them is either a scan or a punch aimed at a
    /// mapping that moved.
    pub natt_unexpected_holepunches_total: u64,
    /// **Port Prediction** attempts fired in either role, Fan or Probe
    /// (ADR-0091's amendment). Zero while `natt.port_prediction` is off.
    pub natt_prediction_attempts_total: u64,
    /// The extra `0xA1` those attempts sent: one per Fan socket, one per Probe
    /// Set port.
    pub natt_prediction_probes_total: u64,
    /// Pairings that met: a Prediction Route a Fan socket installed, or a
    /// punch from a port in the current Probe Set.
    pub natt_prediction_hits_total: u64,
    /// Introductions that started no plan, and attempts that did not fire,
    /// under the plan gates and caps: a stranger's introduction,
    /// a claimed target, a cap, the socket budget, a silent peer.
    pub natt_prediction_refusals_total: u64,
    /// Why the most recent one was refused.
    pub natt_last_prediction_refusal: Option<NattPredictionRefusal>,
    /// NAT-T datagrams the client-UDP front could not hand to the front — a
    /// full inbox, or no front running.
    pub natt_inbox_drops_total: u64,
    /// Risen **Tunnels** the front closed because the serve pipeline's
    /// hand-off backlog was full (ADR-0091). Zero on a healthy
    /// node: anything else means admissions stopped being drained for as long
    /// as a whole node's punched paths took to rise, and each count cost a
    /// peer that had already completed its handshake.
    pub natt_adoptions_dropped_total: u64,
    /// Kad datagrams the client-UDP front could not hand to the running node
    /// — a full inlet, or a node that stopped between the read and the send
    /// (ADR-0057). A datagram that arrives while Kad is simply *off* is not
    /// counted here: nothing was lost, there was nothing to lose it to.
    pub kad_inlet_drops_total: u64,
    /// Peer-UDP datagrams (a `0x90` reask ping, or a `0x91`/`0x92`/`0x93`
    /// reply) the client-UDP front could not hand on — an inbox full because
    /// no serve activity or download pool is draining it, or one gone
    /// (ADR-0057). Never awaited, so each count is one reask lost rather than
    /// a stalled socket.
    pub peer_udp_inbox_drops_total: u64,
    /// Reask replies (`0x91`/`0x92`/`0x93`) that answered no ping in flight
    /// to their endpoint, or one past its 20 s lead, so no download took them
    /// (ADR-0107). A reply a download took and could not use is counted on
    /// that download's row instead.
    pub reask_replies_unasked_total: u64,
    /// Targets retired as *temporarily unreachable*, and the most recent
    /// reason. The honest-failure count: a symmetric or CGNAT pair lands here.
    pub natt_retirements_total: u64,
    /// Why the most recent target retired — a spent **Rendezvous Schedule**,
    /// or a coordinator that could not introduce us and had no successor.
    pub natt_last_retire_reason: Option<NattRetirement>,
    /// Dials started over punched paths — `connect()` calls, not attempts.
    /// `librqbit-utp` sends an opener **once** and never retransmits it, so a
    /// traversal spends several of these inside one attempt's budget (ADR-0091);
    /// the ratio against `natt_tunnels_dialed_total` is how many
    /// openers a path swallows before one lands.
    pub natt_dials_total: u64,
    /// How many dials the most recent finished attempt spent — one when the
    /// first opener landed, many when the path needed re-opening, and the
    /// budget's worth when it never worked.
    pub natt_last_attempt_dials: Option<u32>,
    /// **Punch Expectation**s pushed out because one address was carrying more
    /// traversals than the per-address set holds. Zero on an ordinary node: a
    /// run of these means attribution is being lost behind a busy CGNAT.
    pub natt_expectations_evicted_total: u64,
    /// Tunnels accepted from an address expecting several peers, where nothing
    /// named which. Attributed to **none** on purpose — a wrong `UserHash` is
    /// worse than none, and the hello names the peer a few round trips later.
    pub natt_tunnels_unattributed_total: u64,
    /// `OP_HOLEPUNCH` triggers from an address expecting several peers to dial,
    /// where the observed port named none of them. Refreshed, dialed nothing:
    /// one datagram may not fan out into several dials.
    pub natt_ambiguous_holepunches_total: u64,
    /// Search Result rows that reached no live search (ADR-0034, **Search
    /// Attribution**): an answer no running query proves — late,
    /// after its search ended, or never matching — is dropped, never shown in a
    /// search it does not answer, and counted here so a missing row has a
    /// trace.
    pub search_rows_unattributed_total: u64,
    /// Where this node's own buddy stands (ADR-0061 firewalled-node
    /// operation): none, walking, recruited-but-not-yet-linked, or held.
    pub buddy_state: BuddyState,
    /// Since when the buddy link has been held — `None` in every other state.
    /// Together with the state above this is the whole answer to "can a
    /// firewalled rmule be reached at all right now".
    pub buddy_held_since: Option<Instant>,
    /// Buddy links established since core start. A run of these against a
    /// stable `buddy_state` of `None` is a buddy that keeps hanging up.
    pub buddy_links_held_total: u64,
    /// Buddy links lost or released.
    pub buddy_links_lost_total: u64,
    /// Buddy dials that failed before a link was held — the buddy refused the
    /// connect, never finished its hello, or answered as someone else.
    /// A run of these against `buddy_links_held_total` staying put is
    /// a node whose recruited buddies it cannot reach.
    pub buddy_dials_failed_total: u64,
    /// Buddy dials not started because one to the same buddy was already in
    /// flight — a re-adopt or a duplicate `0x5A` mid-dial. A
    /// climbing count is a recruit path adopting the one buddy repeatedly.
    pub buddy_dials_refused_total: u64,
    /// Buddies refused before any dial because the `0x5A`'s connect-options
    /// and our obfuscation policy cannot meet — one side requires the crypt
    /// layer the other does not speak (ADR-0049; aMule `BaseClient.cpp:1913-1919`).
    /// A climbing count is a policy turning
    /// every recruited buddy away.
    pub buddy_dials_crypt_incompatible_total: u64,
    /// Relayed `OP_CALLBACK` (`0x99`) frames that became a dial-back.
    pub relayed_callbacks_dialed_total: u64,
    /// Relayed `0x99` frames dropped by the ADR-0061 gates (Kad down, the
    /// buddy-ID XOR check, the file we do not have) — including the subset
    /// below.
    pub relayed_callbacks_dropped_total: u64,
    /// Of the drops above, how many arrived while this node held no buddy
    /// link at all — our own state, not a counterparty error,
    /// so it never reached the ADR-0061 gates. A bench run wants this at
    /// zero: anything left in `relayed_callbacks_dropped_total` once this is
    /// subtracted out is a genuine wrong-address relay worth looking at.
    pub relayed_callbacks_no_buddy_total: u64,
    /// `TAG_BUDDYHASH`'s other spelling at work, per role.
    pub buddy_hash_spelling: BuddyHashSpellingCounters,
    /// `OP_DIRECTCALLBACKREQ` (`0x95`) requests honoured with a dial-back.
    pub direct_callbacks_dialed_total: u64,
    /// `0x95` requests refused — no longer firewalled, Kad down, or the
    /// per-source-IP rate limit. A run of refusals beside zero dials is a
    /// flood, which is exactly what the limiter is for.
    pub direct_callbacks_refused_total: u64,
    /// Why the most recent recruit tick refused to walk. A
    /// level, not a count — the trigger ticks every thirty seconds
    /// regardless, so most refusals are `PacingNotDue` and counting them
    /// would only measure the clock. Most informative beside
    /// `buddy_state: None`: `CryptRequired` there means this node will never
    /// hold a buddy while its obfuscation policy reads `Required`
    /// (ADR-0046), because aMule's callback requests are not obfuscatable
    /// (ADR-0061) — not merely that the last tick found nothing due.
    pub buddy_last_recruit_refusal: Option<RecruitRefusal>,
    /// Relayed rendezvous this node acted on: a burst asked for and a
    /// Responder expectation armed (ADR-0091's acting path).
    pub acting_punches_total: u64,
    /// Relayed rendezvous refused, and why the last one was. `NotFromOurBuddy`
    /// dominating means somebody is forwarding at us; `NoUsableTarget` means
    /// the precedence rule resolved nothing public.
    pub acting_refusals_total: u64,
    /// Why the most recent relayed rendezvous was refused. `None` for a frame
    /// that claimed the rendezvous marker and was malformed — it never reached
    /// a gate that could name a reason.
    pub acting_last_refusal: Option<ActingRefusal>,
    /// Of the `0x95` dial-backs above, how many were dialed **obfuscated** —
    /// the crypt handshake running before the serve pipeline adopted the
    /// stream. A subset of `direct_callbacks_dialed_total`, so the
    /// two read together: equal means every requester that called us asked for
    /// obfuscation and got it, zero beside an obfuscation policy of `Requested`
    /// means nobody is asking. Counted at the decision, so a handshake the
    /// requester then fails still shows here — as a dial-back that went out
    /// obfuscated, which it did.
    pub direct_callbacks_obfuscated_total: u64,
    /// Of the `0x95` refusals above, how many were **our own** obfuscation
    /// policy refusing a requester whose stance could not meet it
    /// — a requester that requires obfuscation while the obfuscation policy is unset, or
    /// a `Required` policy facing a requester with no crypt support. These
    /// requesters are reachable; this node chose not to reach them, and this
    /// counter is the only place that choice leaves a trace.
    pub direct_callbacks_crypt_incompatible_total: u64,
    /// **The open-node half of the buddy relationship** (ADR-0061)
    /// — the counters above are this node *having* a buddy; these four are this
    /// node *being* one. Buddy links held: a recruit we answered `0x5A` dialed
    /// our listener and its `OP_HELLO` reported the user hash the slot was
    /// waiting on, so its connection became the held link every relay rides.
    /// Zero beside a non-zero `served_buddy_pings_refused_total` is exactly
    /// the failure of a buddy on the wire that never attached.
    pub served_buddy_links_held_total: u64,
    /// Held buddy links lost: the link closed (or a re-dialing buddy replaced
    /// it), which frees the service slot for the next recruit. Counted against
    /// the total above, a gap of one is a link held right now.
    pub served_buddy_links_lost_total: u64,
    /// `OP_BUDDYPING` (`0x9F`) frames answered with `OP_BUDDYPONG` (`0xA0`) on
    /// the held link. This is what keeps a firewalled aMule's buddy status at
    /// `Connected`, so a buddy that publishes us as its relay depends on it.
    pub served_buddy_pings_answered_total: u64,
    /// Pings that got no pong: from a connection that is not the held buddy
    /// link (aMule's own `GetBuddy() != client` drop), or from the held link
    /// when its driver would not take the pong. Strangers pinging is ordinary;
    /// this climbing while `served_buddy_links_held_total` stays zero is the
    /// open-node half being unwired rather than idle.
    pub served_buddy_pings_refused_total: u64,
    /// Upload-slot asks turned away by the per-address queue cap (ADR-0088):
    /// one accounting key — one IPv4 address, one IPv6 `/64` — already held
    /// [`MAX_WAITING_PER_ADDRESS`](crate::MAX_WAITING_PER_ADDRESS) wait-list
    /// places. The reference answers such an ask with silence, so without this
    /// counter the refusal leaves no trace anywhere; a climbing total beside a
    /// static `PeerQueued` rate is one host trying to take the whole queue.
    pub upload_address_cap_refusals_total: u64,
    /// Upload-slot asks turned away by the **Low-ID abuse guard** (ADR-0031
    /// amendment): while we are Low-ID, a stranger asked for a slot
    /// with more than
    /// [`LOW_ID_ABUSE_WAIT_LIST_THRESHOLD`](crate::LOW_ID_ABUSE_WAIT_LIST_THRESHOLD)
    /// peers already waiting. Silent on the wire like the cap above, so this
    /// counter is its whole record — and a total that climbs only while
    /// `connected_server` reports a Low-ID session is the guard working, not a
    /// fault.
    pub upload_low_id_abuse_refusals_total: u64,
    /// `OP_REASKFILEPING` (`0x90`) datagrams from a queued waiter that claims
    /// UDPv4 and extended requests but were cut short for that claim — the
    /// file hash alone, a short status, or no complete-source count from a
    /// claim above `1` (ADR-0055's name-ask / reask audit). aMule answers
    /// such a ping with nothing — its reader throws — and so does rmule, so
    /// this counter is the ping's whole record. Non-zero means some client
    /// writes a reask its hello's claim does not cover.
    pub malformed_reask_pings_total: u64,
    /// `OP_REQUESTFILENAME` (`0x58`) asks for a shared file that carried the
    /// file hash alone from a peer whose hello claimed extended requests
    /// (ADR-0055's name-ask / reask audit). aMule's reader throws and its packet
    /// handler disconnects the client; rmule closes the connection unanswered
    /// too, so this counter names why those connections ended.
    pub malformed_name_asks_total: u64,
    /// The deepest the serve activity's **accept backlog** has been seen this
    /// session: peers past the **Accept Gates** queued behind the one the
    /// runner just took, plus that one — a refused peer never queues. The
    /// channel holds sixteen, so a reading that approaches it says the runner
    /// was away — in `enact` — long enough for a burst to stack up behind it,
    /// and a reading that reaches it says peers were made to wait on the
    /// producers' side, where the NAT-T adopter drops rather than blocks.
    ///
    /// `None` on a core whose serve adapter keeps no such channel, and on one
    /// that has not accepted a peer yet: "not measured" is not depth zero.
    pub serve_accept_backlog_max: Option<usize>,
    /// Downloads that fell to NAT traversal because their Low-ID callback had
    /// said nothing for twelve seconds (ADR-0091). The denominator the four
    /// counts below are read against: every one of them is an outcome of one
    /// of these.
    pub natt_download_fallbacks_total: u64,
    /// Fallbacks whose candidate carried **no User Hash**, so no Tunnel it
    /// raises can ever be claimed — a `0x42` server answer names an id and a
    /// port and nothing else. The punch still runs (the server coordinator
    /// needs only the id) and a Tunnel it raises takes the serve road, where
    /// it is an ordinary inbound peer. A high count against
    /// `natt_download_fallbacks_total` means the sources are arriving over
    /// plain channels, not that traversal is failing.
    pub natt_download_fallbacks_unclaimable_total: u64,
    /// Fallbacks the one selector refused: no coordinator this session could
    /// ask could introduce us to that target (ADR-0061/0091). Nothing went on
    /// the wire, and the callback's own 30 s deadline still governs it.
    pub natt_download_adoptions_no_coordinator_total: u64,
    /// **Dialer Tunnels** a download adopted — the count that says the whole
    /// ladder worked *for a transfer*: a callback went silent, a punch landed,
    /// a Tunnel rose toward the claimed target, and its hello was that target.
    pub natt_download_adoptions_total: u64,
    /// Adoptions refused because the peer on the punched path identified as
    /// somebody other than the target the punch was aimed at. The endpoint
    /// proves nothing behind a NAT, so this is the check that means it; a
    /// steady count is a coordinator handing out stale or wrong introductions.
    pub natt_download_adoptions_refused_total: u64,
    /// Claims retracted without an adoption: the callback's own connection
    /// landed first, its slot was released, or the **Traversal Attempt**
    /// toward the target retired. The ordinary end of the road not taken.
    pub natt_download_claims_retired_total: u64,
    /// **Traversal Attempt**s begun with our connected server as the first
    /// **Rendezvous coordinator** (ADR-0091's preferred one).
    pub natt_attempts_server_total: u64,
    /// Traversal Attempts begun with the target's Kad serving buddy as the
    /// coordinator — the target is on another server, or ours does not speak
    /// the punch.
    pub natt_attempts_buddy_total: u64,
    /// Attempts that fell through from the server coordinator to the buddy:
    /// the server refused the introduction or never answered, and the
    /// candidate named a buddy that could be asked instead. Read against
    /// `natt_attempts_server_total`, this is how often ADR-0091's ordering
    /// actually earns its second rung.
    pub natt_attempt_fallthroughs_total: u64,
    /// The client-UDP demux front's transport returned closed and the front
    /// wound down. In production this happens only when the
    /// receive-error budget (`RuntimeClientUdpTransport::recv`) is
    /// exhausted — a dead socket, not a graceful stop, and since Kad, the
    /// reask surface and NAT-T all ride this one socket (ADR-0057), it is
    /// the single "the front went dark" signal. Zero on a healthy node.
    pub client_udp_transport_ended_total: u64,
    /// The server-UDP engine's transport returned closed and the engine
    /// wound down. In production this happens only when
    /// the receive-error budget (`RuntimeServerUdpTransport::recv`) is
    /// exhausted — a dead socket, not a graceful stop — and since global
    /// search, get-sources and the status/desc chain all ride this one
    /// socket, it is the server-UDP twin of
    /// `client_udp_transport_ended_total`. Zero on a healthy node.
    pub server_udp_transport_ended_total: u64,
    /// ADR-0058 firewall-check (`0x53`) dial-backs this node's own
    /// obfuscation policy refused (the same two-reading rule
    /// `direct_callbacks_crypt_incompatible_total` counts for the `0x95`
    /// route) — a requester whose crypt stance could not meet this node's.
    /// This requester proved it can be dialed; this node chose not to, and
    /// this counter is the only place that choice leaves a trace.
    pub kad_dial_backs_crypt_incompatible_total: u64,
    /// `KadEvent::Diagnostic(UndecodableEnvelope)`: a datagram
    /// that opened with the Kad protocol byte (or decrypted to one) but did
    /// not decode into a well-formed envelope — bad protocol byte,
    /// truncation, or a malformed/oversized packed payload. Never a panic;
    /// the node logs and carries on. Zero on a healthy node speaking to a
    /// well-behaved counterparty; a crypt-armed run reading nonzero here
    /// means the keyed exchange did not open cleanly, not that nothing
    /// arrived.
    pub kad_undecodable_envelopes_total: u64,
}
