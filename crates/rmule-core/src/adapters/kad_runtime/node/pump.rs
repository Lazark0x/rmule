//! The Kad pump: the one task that drains the node's events, enacts the
//! core's commands on the node, and keeps the levels it owns — reachability,
//! own address, buddy — in step with the node, until Kad stops.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::time::Instant;

use rmule_primitives::FileHash;
use tokio::sync::{mpsc, oneshot};

use crate::adapters::kad_runtime::buddy_publish;
use crate::adapters::kad_runtime::connect_options::ConnectOptionsFeed;
use crate::adapters::kad_runtime::extern_port_feed::ExternPortFeed;
use crate::adapters::kad_runtime::public_ip_feed::PublicIpFeed;
use crate::adapters::kad_runtime::self_check::{CheckAsked, SelfCheckProjection};
use crate::adapters::kad_runtime::{KadPumpCommand, project_keyword_rows};
use crate::address_learning::AddressObservation;

mod buddy_service;
mod dial_back;
mod recruit;

pub(super) use buddy_service::BuddyService;
pub(super) use dial_back::DialBack;

/// How often the pump re-reads its own position for the ADR-0061 recruit
/// trigger. The trigger paces itself at twenty minutes; this only bounds how
/// long a node that just became eligible waits to notice.
const RECRUIT_TICK: std::time::Duration = std::time::Duration::from_secs(30);

/// Everything the pump task owns, handed over by `start` once the node is up.
pub(super) struct Pump {
    pub(super) dial_back: DialBack,
    pub(super) buddy_service: BuddyService,
    pub(super) kad_udp_port: u16,
    pub(super) kad_stop_rx: Option<oneshot::Receiver<()>>,
    pub(super) kad_stopped_tx: Option<oneshot::Sender<()>>,
    pub(super) handle: rmule_net::kad::KadNetHandle,
    pub(super) commands_rx: mpsc::Receiver<KadPumpCommand>,
    pub(super) sources_tx: mpsc::Sender<(FileHash, crate::kad_sources::KadAnswer)>,
    pub(super) ban_store: crate::ban_store::SharedBanStore,
    pub(super) awaited_testers: crate::awaited_testers::SharedAwaitedTesters,
    pub(super) firewalled_slot: crate::firewalled::link::SharedFirewalledSlot,
    pub(super) firewalled_front: crate::firewalled::front::SharedFirewalledFront,
    pub(super) crypt_required: bool,
    pub(super) envelope_diagnostics: crate::diagnostics::DiagnosticsState,
    pub(super) published: crate::reachability::SharedKadVerdicts,
    pub(super) assume_open_reachability: bool,
    pub(super) had_contact: Arc<AtomicBool>,
    pub(super) contact_count: Arc<AtomicUsize>,
    pub(super) keywords_stored: Arc<AtomicUsize>,
    pub(super) addresses: crate::address_learning::SharedAddressLearning,
    pub(super) ipv6_advert: crate::adapters::ipv6_advert::SharedIpv6Advert,
    pub(super) hello: crate::adapters::HelloAdverts,
    pub(super) kad_inlet: crate::client_udp::SharedKadInlet,
    pub(super) kad_pump_slot: crate::adapters::kad_runtime::SharedKadPump,
    pub(super) kad_bootstrap: crate::adapters::kad_runtime::SharedKadBootstrap,
    pub(super) peer_roster: crate::peer_roster::SharedPeerRoster,
    pub(super) reach_generation: crate::reachability::ReachGeneration,
    pub(super) own: crate::own_identity::SharedOwnIdentity,
    pub(super) options_feed: ConnectOptionsFeed,
    pub(super) reach: crate::reachability::SharedSelfReach,
}

impl Pump {
    /// Pump until the core drops the command channel, the node's driver
    /// stops, or the external stop lever fires; then close the gates that
    /// say the node runs and shut it down.
    pub(super) async fn run(self) {
        let Self {
            dial_back,
            buddy_service,
            kad_udp_port,
            mut kad_stop_rx,
            mut kad_stopped_tx,
            mut handle,
            mut commands_rx,
            sources_tx,
            ban_store,
            awaited_testers,
            firewalled_slot,
            firewalled_front,
            crypt_required,
            envelope_diagnostics,
            published,
            assume_open_reachability,
            had_contact,
            contact_count,
            keywords_stored,
            addresses,
            ipv6_advert,
            hello,
            kad_inlet,
            kad_pump_slot,
            kad_bootstrap,
            peer_roster,
            mut reach_generation,
            own,
            mut options_feed,
            reach,
        } = self;
        // Resolved select step; the `next_event` future's `&mut handle`
        // borrow must end before a command arm can `handle.command(..)`.
        enum Step {
            Command(Option<KadPumpCommand>),
            Event(Option<rmule_kad::KadEvent>),
            /// The ADR-0061 recruit trigger's own clock — the one step
            /// no datagram produces.
            RecruitTick,
            /// A **Reach Generation**: some family of Self Reach moved.
            Reach,
            /// An **Own Address Generation**: Address
            /// Learning's projection moved, from whichever task wrote it.
            OwnAddress,
            /// The external stop lever fired (caller- or
            /// `DisableKad`-installed).
            Shutdown,
        }
        let mut walked: HashMap<rmule_kad::KadId, FileHash> = HashMap::new();
        let mut callback_walks =
            crate::adapters::kad_runtime::callback_walk::CallbackWalks::default();
        let mut keyword_subscribers =
            crate::adapters::kad_runtime::keyword_subscribers::KeywordSubscribers::default();
        // The core-owned ADR-0058 Reachability store: the sans-I/O node owns
        // the recheck cadence, emission budget, and 180 s windows and emits
        // the reachability lifecycle; this pump projects those events onto the
        // ≥2-ack TCP verdict and surfaces each verdict change. The downstream
        // gate readers (the ADR-0057 reask pool, the ADR-0061 buddy triggers)
        // are wired separately; today the transition is surfaced for
        // observability, the requester leg's live signal.
        let mut self_check = SelfCheckProjection::new(published, awaited_testers.clone());
        // The buddy-publish verdict's one writer.
        let mut buddy_feed =
            buddy_publish::BuddyPublishFeed::new(&hello, envelope_diagnostics.clone());
        // The own-IPv4 level: what the node's verify-key
        // state is bound to, re-derived alongside the TCP verdict below.
        // Cloned rather than moved: the ADR-0058 self-connect guard
        // reads the same `own` below, at every dial-back and
        // FINDBUDDY check.
        let mut ip_feed = PublicIpFeed::new(own.clone());
        // The Extern Kad Port level: the store's the one
        // owner, the node's `udp_extern_port` a cache this feed refreshes
        // — re-derived alongside the other two levels below, and on
        // every observation answer (`UdpPortObserved`) regardless.
        let mut extern_port_feed = ExternPortFeed::new(addresses.clone());
        // Both node caches above subscribe to their one owner (ADR-0084
        // "Own address ownership"): every store write that
        // moved our own address is one wake here, whichever task wrote it.
        let mut own_address_changed = addresses.own_address_changed();
        if assume_open_reachability {
            // The stimulus posture: declare the surface open so
            // the ADR-0061 recruit gate can accept, since neither self-check
            // can converge in a stimulus swarm. rmule's own posture only —
            // every counterparty byte stays genuine (ADR-0045).
            self_check.assume_open(kad_udp_port);
            tracing::info!(
                udp_port = kad_udp_port,
                "kad stimulus posture: reachability declared open (Core-Pumped Stimulus Node)"
            );
        }
        // Kad start injects the **current** verdict as a level. A fresh store reads `Firewalled`
        // and never leaves it unaided, so an edge-only feed left the node believing it was open
        // — and `UdpFirewallTester::check_timeout`'s conclude gate, which
        // composes on this very bit, could never fire. Sent before the pump
        // takes its first step, and re-derived on every recruit tick below.
        self_check.sync_tcp(&handle);
        // Same start-time statement for the own-IPv4 level:
        // the value `enable_verify_keys` was already armed with at
        // `start`'s own `self.own.public_ip()` read, restated here so a
        // verdict that moved between that read and this line is not
        // missed.
        ip_feed.sync(&handle);
        // Same start-time statement for the Extern Kad Port level: a fresh node's cache is the
        // bound port, so a store that already holds a fresher answer (a still-warm previous Kad run
        // in this same core process) is not missed either.
        extern_port_feed.sync(&handle);
        options_feed.sync(&reach, &handle);
        // The ADR-0061 recruit trigger's clock. The trigger itself paces
        // at 20 minutes; this only decides how promptly a node that just
        // became eligible (a UDP verdict settling firewalled, a recheck
        // guard elapsing, a buddy lost) notices. Thirty seconds is far
        // finer than every input it reads and costs one lock per tick.
        let mut recruit_tick = tokio::time::interval(RECRUIT_TICK);
        recruit_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let step = tokio::select! {
                command = commands_rx.recv() => Step::Command(command),
                event = handle.next_event() => Step::Event(event),
                _ = recruit_tick.tick() => Step::RecruitTick,
                () = reach_generation.changed() => Step::Reach,
                // The sender lives in the store this pump holds a handle
                // to, so it never closes; the `Ok` pattern still disables
                // the arm rather than spin if it ever did.
                Ok(()) = own_address_changed.changed() => Step::OwnAddress,
                () = async {
                    match kad_stop_rx.as_mut() {
                        Some(rx) => { let _ = rx.await; }
                        None => std::future::pending().await,
                    }
                } => Step::Shutdown,
            };
            match step {
                Step::Command(Some(command)) => {
                    crate::adapters::kad_runtime::pump_command::apply(
                        &handle,
                        command,
                        &mut walked,
                        &mut callback_walks,
                        &mut keyword_subscribers,
                        &ipv6_advert,
                    )
                    .await;
                }
                // The Core actor dropped the channel: shut the node down.
                Step::Command(None) => break,
                // The confirmation fires below, after the tap
                // (if any) has finalized.
                Step::Shutdown => break,
                Step::Event(Some(rmule_kad::KadEvent::SourcesFound { target, candidates })) => {
                    if let Some(file_hash) = walked.get(&target) {
                        // Every decoded row crosses, not just the
                        // dialable ones — a firewalled row carries the
                        // buddy that is the only way to reach it.
                        let sources: crate::kad_sources::KadAnswer = candidates
                            .iter()
                            .map(crate::kad_sources::KadSource::from_candidate)
                            .collect();
                        if !sources.is_empty()
                            && sources_tx.send((*file_hash, sources)).await.is_err()
                        {
                            break;
                        }
                    }
                }
                Step::Event(Some(rmule_kad::KadEvent::KeywordsFound { keyword, results })) => {
                    // ADR-0062 requester merge: the node already residual-
                    // filtered and deduped by file ID into its own stream; the
                    // pump projects each dual-form row to a `SearchResult` and
                    // hands the batch to the search walking this keyword,
                    // where it merges into the one ADR-0051 result set; a
                    // row that does not stand travels as its reason.
                    let (batch, skipped) = project_keyword_rows(&results);
                    if !batch.is_empty() || !skipped.is_empty() {
                        keyword_subscribers.deliver(keyword, batch, skipped);
                    }
                }
                Step::Event(Some(rmule_kad::KadEvent::KeywordSearchComplete {
                    keyword,
                    ended_by,
                    ..
                })) => keyword_subscribers.complete(keyword, ended_by.into()),
                Step::Event(Some(rmule_kad::KadEvent::Diagnostic(
                    rmule_kad::KadNodeDiagnostic::KeywordPublishPreempted { keyword },
                ))) => keyword_subscribers.publish_deferred(keyword),
                Step::Event(Some(rmule_kad::KadEvent::DialBackRequested {
                    requester,
                    connect_options,
                    user_hash,
                })) => dial_back.requested(requester, connect_options, user_hash),
                Step::Event(Some(rmule_kad::KadEvent::UdpFirewallCheckRequested {
                    helper,
                    request,
                })) => {
                    // ADR-0058 requester, UDP half: the node engaged a
                    // fresh helper; dial it, send the `0xA7`, and report
                    // the link's end. Off the pump's path — the `0x62`
                    // comes back on the Kad socket, and the end rides the
                    // pump sink, which a stopped node has closed.
                    tokio::spawn(
                        crate::adapters::kad_runtime::udp_firewall_check::run_udp_firewall_check(
                            helper,
                            request,
                            crate::server_session::live_peer_handshake_context(
                                &dial_back.ctx.identity,
                                &own,
                            ),
                            hello.clone(),
                            kad_pump_slot.clone(),
                            peer_roster.clone(),
                        ),
                    );
                }
                Step::Event(Some(rmule_kad::KadEvent::FwCheckUdpAnswered {
                    requester,
                    biased,
                })) => {
                    tracing::info!(
                        %requester,
                        biased,
                        "kad UDP firewall helper: 0x62 sent (ADR-0058)"
                    );
                }
                Step::Event(Some(rmule_kad::KadEvent::FindBuddyRequested {
                    requester,
                    buddy_id,
                    requester_hash,
                    requester_tcp_port,
                })) => {
                    buddy_service
                        .find_buddy_requested(
                            requester,
                            buddy_id,
                            requester_hash,
                            requester_tcp_port,
                            &reach,
                            &handle,
                        )
                        .await;
                }
                Step::Event(Some(rmule_kad::KadEvent::CallbackRelayRequested {
                    requester,
                    buddy_id,
                    file_hash,
                    requester_tcp_port,
                })) => {
                    buddy_service.callback_relay_requested(
                        requester,
                        buddy_id,
                        file_hash,
                        requester_tcp_port,
                    );
                }
                Step::Event(Some(rmule_kad::KadEvent::FloodOffenderDetected { ip, opcode })) => {
                    // ADR-0064: the node only *reports* a flood
                    // offender — this is where the report becomes a
                    // peer-TCP ban. Kad's own datagram path never
                    // consults `ban_store` (no Kad ban gate: the
                    // per-opcode bucket already contains the flood).
                    ban_store
                        .lock()
                        .await
                        .ban(std::net::IpAddr::V4(ip), Instant::now());
                    tracing::debug!(
                        %ip,
                        opcode,
                        "flood offender banned at the peer-TCP surface"
                    );
                }
                Step::Event(Some(
                    event @ (rmule_kad::KadEvent::ReachabilityRecheckStarted
                    | rmule_kad::KadEvent::ReachabilityConnectBack
                    | rmule_kad::KadEvent::ReachabilityRecheckConcluded
                    | rmule_kad::KadEvent::UdpReachabilityOpen { .. }
                    | rmule_kad::KadEvent::UdpReachabilityFirewalled),
                )) => self_check.observe(&event, &handle),
                Step::Event(Some(rmule_kad::KadEvent::ReachabilityCheckAsked {
                    helper,
                    helper_id,
                    helper_udp_port,
                    connect_options,
                    answerable_for,
                })) => self_check.check_asked(&CheckAsked {
                    helper,
                    helper_id,
                    helper_udp_port,
                    connect_options,
                    answerable_for,
                }),
                Step::Event(Some(rmule_kad::KadEvent::Diagnostic(
                    rmule_kad::KadNodeDiagnostic::UnrequestedFirewallAck { from },
                ))) => self_check.ack_discarded(from),
                Step::Event(Some(rmule_kad::KadEvent::AddressObserved { observer, address })) => {
                    // One rung of the IPv4 ladder (ADR-0084). The store
                    // owns the two-agree rule and the 30-minute window, so
                    // a single stranger's `0x58` moves nothing on its own
                    // and the server's assignment still outranks a quorum
                    // of them.
                    // A move is announced by the Own Address Generation
                    // like any other writer's.
                    addresses.observe(AddressObservation::kad_observed_address(observer, address));
                }
                Step::Event(Some(rmule_kad::KadEvent::UdpPortObserved { observer, port })) => {
                    addresses.observe(AddressObservation::kad_observed_port(observer, port));
                    // Every observation gets the store's answer — its
                    // learned Extern Kad Port, or 0 while none holds —
                    // because the node's helper gate waits on exactly this
                    // answer and the `0xA7` then carries it.
                    // Unconditional, unlike `sync` below: the round ends
                    // on this very answer regardless of whether the value
                    // repeats.
                    extern_port_feed.observed(&handle);
                }
                Step::Event(Some(rmule_kad::KadEvent::ExternPortRoundStarted)) => {
                    // The round boundary: forget the UDP
                    // role's Kad port reports so a report from the round
                    // this replaces cannot back one named after it,
                    // matching aMule's `FindExternKadPort(true)` starting
                    // every round's observer lists empty.
                    extern_port_feed.round_started();
                }
                Step::Event(Some(
                    rmule_kad::KadEvent::HadContact { .. }
                    | rmule_kad::KadEvent::ContactResponded { .. },
                )) => {
                    // aMule's `HasHadContact` (ADR-0067): any counterparty
                    // datagram marks the node joined — the node emits the
                    // silent→heard edge itself (`HadContact`), so the
                    // latch does not wait for a probe answer that only
                    // the bootstrap-dial path could produce. Monotonic —
                    // never cleared while running.
                    had_contact.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                Step::Event(Some(rmule_kad::KadEvent::ContactAdded { .. })) => {
                    // The live table size: the node pairs every
                    // eviction with its event, so adds-minus-evicts is the
                    // exact count.
                    contact_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                Step::Event(Some(
                    rmule_kad::KadEvent::KeywordPublishServed { stored, .. }
                    | rmule_kad::KadEvent::KeywordIndexExpired { stored },
                )) => keywords_stored.store(stored, std::sync::atomic::Ordering::Relaxed),
                Step::Event(Some(rmule_kad::KadEvent::ContactEvicted { .. })) => {
                    let _ = contact_count.fetch_update(
                        std::sync::atomic::Ordering::Relaxed,
                        std::sync::atomic::Ordering::Relaxed,
                        |count| Some(count.saturating_sub(1)),
                    );
                }
                Step::RecruitTick => {
                    // The tick re-derives the node's TCP level from the
                    // same read: the level is an input to the
                    // UDP verdict this gate then reads, and a level lost to
                    // a full inbox is lost silently —
                    // so it rides the clock that is already here.
                    self_check.sync_tcp(&handle);
                    // The time edge of both Own Address caches: every write already woke the
                    // `OwnAddress` arm, but a freshness window that lapses
                    // with nobody writing — a `KadCheck` rung's 30 minutes
                    // with no fresh observer — announces nothing, and this
                    // tick reconciles the node within one cycle. It also
                    // repairs a restatement a full inbox deferred.
                    ip_feed.sync(&handle);
                    extern_port_feed.sync(&handle);
                    options_feed.sync(&reach, &handle);
                    // The buddy link is held, and lost, on the front's
                    // task: this tick carries its `bi6` in.
                    buddy_feed.sync(reach.firewalled(), &handle);
                    recruit::consider(
                        &handle,
                        &reach,
                        self_check.last_recheck(),
                        &firewalled_slot,
                        crypt_required,
                    );
                }
                Step::OwnAddress => {
                    ip_feed.sync(&handle);
                    extern_port_feed.sync(&handle);
                }
                Step::Reach => {
                    // The byte (aMule `Prefs.cpp:228`) and the buddy row
                    // (`Search.cpp:596-633`) read the owner's union; the
                    // node's injected TCP level, the `0x95` consume gate
                    // and the recruit gate read the Kad flag alone.
                    options_feed.sync(&reach, &handle);
                    buddy_feed.sync(reach.firewalled(), &handle);
                }
                Step::Event(Some(rmule_kad::KadEvent::BuddyWalkEnded { asked })) => {
                    // The walk is over either way; whether to try again
                    // sooner than the 20-minute tick is the trigger's
                    // pacing to decide, and re-arming on an empty walk
                    // would start one per tick on a node whose routing
                    // table is merely cold.
                    firewalled_slot.on_walk_ended();
                    tracing::debug!(asked, "FINDBUDDY walk ended (ADR-0061)");
                }
                Step::Event(Some(rmule_kad::KadEvent::CallbackWalkEnded { buddy_id, end })) => {
                    callback_walks.on_end(buddy_id, end);
                }
                Step::Event(Some(found @ rmule_kad::KadEvent::BuddyFound { .. })) => buddy_feed
                    .adopt_found_buddy(found, &handle, &firewalled_front, reach.firewalled()),
                Step::Event(Some(rmule_kad::KadEvent::Diagnostic(
                    rmule_kad::KadNodeDiagnostic::UndecodableEnvelope { from, error },
                ))) => {
                    // The node's own diagnostic vocabulary is ordinary
                    // trace data (a hostile or malformed datagram never
                    // panics it), but until this arm existed the count
                    // was unfalsifiable in either direction: a crypt-armed run's own decode
                    // failures never reached a log a bench verdict could read.
                    envelope_diagnostics.count_kad_undecodable_envelope();
                    tracing::warn!(?from, ?error, "kad: UndecodableEnvelope");
                }
                Step::Event(Some(_)) => {}
                Step::Event(None) => break, // driver already stopped
            }
        }
        crate::adapters::kad_runtime::pump_command::refuse_queued(&mut commands_rx);
        // The node is going away: close the gates that say it is running
        // before the driver is torn down, so neither the demux front, an
        // out-of-band signaller, nor the handoff forwarder (whose
        // `handoff_rx.recv()` this sender's drop finally ends) can
        // address a stopped node.
        if let Ok(mut slot) = kad_inlet.lock() {
            *slot = None;
        }
        if let Ok(mut slot) = kad_pump_slot.lock() {
            *slot = None;
        }
        self_check.stopped();
        // Kad Presence and the verdicts clear when the actor retires this
        // activity (ADR-0093): this task's end drops the
        // sources channel, which ends the discovery task the ledger
        // watches.
        *kad_bootstrap.lock().await = None;
        let _ = handle.shutdown().await;
        // The tap (if any) is finalized by now.
        if let Some(tx) = kad_stopped_tx.take() {
            let _ = tx.send(());
        }
    }
}
