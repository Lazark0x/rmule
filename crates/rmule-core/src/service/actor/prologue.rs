//! The actor's **prologue**: everything that runs once before the first
//! command — the credit ring seeded, the server-UDP and client-UDP fronts
//! bound, the port-mapping runtime started, the Durable Store's downloads
//! attached — ending in the [`CoreActor`] that owns them for the session's
//! life (ADR-0093: "the actor's prologue").

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use tokio::sync::{mpsc, watch};

use crate::adapters::{
    KadRuntimeFactory, PeerTransferService, RuntimeServerUdpTransport, ServeRuntimeService,
    SourceLookupService,
};
use crate::address_learning::SocketRole;
use crate::credit::SharedCreditStore;
use crate::global_sources::{GlobalSourceRegistry, SharedServerList};
use crate::kad_sources::KadSourceRegistry;
use crate::search::LiveSearches;
use crate::server_list::ServerFacts;
use crate::server_session::SharedServerSession;

use super::client_udp::{ClientUdpSinks, NattFrontWiring, spawn_client_udp_front};
use super::download::DownloadRuntime;
use super::server_udp_front::spawn_server_udp_front;
use crate::download::SharedRuntime;
use crate::service::activity::{Activities, unix_now};
use crate::service::{CoreEvent, SharedReaskReplySink};

use super::{CoreActor, CoreWiring, download, registry_check, send_event, share_flush};

/// Run the prologue over `wiring`, then the actor it builds, until the
/// inbox closes and Quit has run.
pub(in crate::service) async fn run_core_with_adapters<S, P, L, K>(
    mut wiring: CoreWiring<S, P, L, K>,
    inbox: crate::service::inbox::Inbox,
    evt_tx: mpsc::Sender<CoreEvent>,
    diagnostics: crate::diagnostics::DiagnosticsState,
) where
    S: SourceLookupService,
    P: PeerTransferService,
    L: ServeRuntimeService,
    K: KadRuntimeFactory,
{
    // Our obfuscation posture first (ADR-0046, ADR-0075): every crypt
    // decision after reads this cell, so the Run Log states it before any.
    send_event(
        &evt_tx,
        CoreEvent::ObfuscationPolicyAtStart {
            policy: wiring.hello_adverts.obfuscation.get(),
        },
    )
    .await;
    // Credit-ring restart continuity: the ring is seeded before
    // any activity can touch it.
    if let Some(dir) = wiring.clients_met_dir.as_deref() {
        seed_credit_ring_from_clients_met(dir, &wiring.credit).await;
    }
    // The managed server list is a level from the actor's first instant
    // (ADR-0080): a consumer that snapshots before sending any command still
    // sees what the store holds, exactly as it sees a recovered download.
    match wiring.server_list.servers() {
        Ok(servers) => diagnostics.set_servers(servers),
        Err(error) => {
            tracing::warn!(%error, "managed server list unreadable at start; surfacing it empty");
        }
    }
    // The operator's server policy before anything is judged under it
    // (ADR-0052): the sweep's first verdict and the swept list's first
    // projection already know the limit they chose.
    let policy = wiring.settings.server_policy;
    diagnostics.set_server_policy(policy);
    wiring
        .shared_server_session
        .set_withhold_shares(policy.withhold_from_related_search);
    // The write side of what happened with a server (ADR-0080 §Dynamic server
    // facts): one seam over the same store, level and event bus, held by the
    // four surfaces that reach a server — the status-ping sweep, the `0x97`
    // challenge gate, the connected session's welcome burst, and the session
    // lifecycle itself. Installed on the shared session before the actor takes
    // a command, because the adapters holding that cell were woven before this
    // actor existed — and because a session established by an adapter must
    // report on the same bus as one the operator asked for.
    let server_facts = ServerFacts::new(
        wiring.server_list.clone(),
        diagnostics.clone(),
        Some(evt_tx.downgrade()),
    );
    wiring
        .shared_server_session
        .install_facts(server_facts.clone());
    // The hello-refusal cell, installed for the same reason: the adapters
    // that read peer hellos were woven before this actor existed.
    wiring
        .hello_refusals
        .install(diagnostics.clone(), evt_tx.downgrade());
    // The login deadline every establishment arms, installed on
    // the same cell and for the same reason: establishment runs off this actor
    // and must not hold a serve start — or a front end — open on a server that
    // accepted the socket and then went mute.
    wiring
        .shared_server_session
        .install_login_timeout(wiring.config.server_login_timeout);
    let (finished_tx, finished_rx) = mpsc::channel(32);
    let (scan_tx, scan_rx) = mpsc::unbounded_channel();
    // The serve activity's "I have ended" bump. A `watch` rather
    // than a message: sending never blocks and never fills, so a task that
    // ends while the actor is awaiting *another* serve teardown cannot wedge
    // either one; and a bump the actor already acted on is a no-op, because
    // the arm reads the ledger rather than the notice. The actor keeps this
    // sender for its whole life, which is what stops the arm ever seeing a
    // closed channel.
    let serve_ended_tx = Arc::new(watch::channel(0u64).0);
    let serve_ended_rx = serve_ended_tx.subscribe();
    // The Kad activity's own "I have ended" bump, the same
    // shape for the same reason: `on_enable_kad`'s discovery task drops its
    // clone the moment it returns, so a bump the actor has already reclaimed
    // is a no-op and the sender the actor keeps never reads back closed.
    let kad_ended_tx = Arc::new(watch::channel(0u64).0);
    let kad_ended_rx = kad_ended_tx.subscribe();
    // Server-UDP global source discovery (ADR-0051): one Core-owned task sweeps the
    // swept server list for active downloads' hashes. The registry maps each
    // active download's hash to its runner's sink (the runner registers/deregisters
    // its own entry); the server list it sweeps is the level's projection of the
    // Managed Server List (ADR-0051).
    // A UDP-bind failure disables discovery — downloads still work via the connected
    // server and peer source-exchange.
    let global_source_registry: GlobalSourceRegistry =
        Arc::new(std::sync::Mutex::new(HashMap::new()));
    let global_source_servers: SharedServerList = Arc::new(std::sync::Mutex::new(Vec::new()));
    // The level keeps it the managed list minus the dead and the IP-filtered
    // (ADR-0051, ADR-0052).
    diagnostics.install_swept_servers(Arc::clone(&global_source_servers), wiring.ip_filter.clone());
    // The runner → callback-relay channel for per-server Low-ID callbacks
    // (ADR-0051). The download runtime holds `global_callback_tx` (cloned to
    // each runner) so the relay's recv stays open for the actor's lifetime.
    let (global_callback_tx, global_callback_rx) = mpsc::channel(32);
    let kad_source_registry: KadSourceRegistry = Arc::new(std::sync::Mutex::new(HashMap::new()));
    let own_identity = wiring.shared_server_session.own_identity().clone();
    // A late Kad helper test names no server to report through, so the
    // Awaited Testers report it on the bus itself (ADR-0075, Run Log).
    own_identity
        .awaited_testers()
        .install_events(evt_tx.downgrade());
    let user_hash = wiring.user_hash;
    // The operator's External Endpoint override (ADR-0084), applied before any
    // socket binds: a configured address outranks every observation, so it
    // must already be on the ladder when the first one arrives.
    own_identity
        .addresses()
        .set_override(wiring.config.external_address);
    // The Interface Source poll (ADR-0084): once now, then every five minutes,
    // plus once per server connect from the establishment path. The set is both
    // a tier of its own and the corroboration filter's evidence, so a renumber
    // or an RFC 4941 rotation has to be *noticed* — and a snapshot comparison
    // is what notices it. The task ends when this actor drops its sender, so it
    // never outlives the core it serves.
    if let Some(source) = wiring.interface_source.clone() {
        wiring.shared_server_session.install_interfaces(source);
    }
    let interface_refresh = spawn_interface_refresh(&wiring.shared_server_session);
    let share_flush = share_flush::ShareFlush::start(&wiring.registry, &diagnostics);
    // The Address Learning rows a snapshot reports (ADR-0084) are read from
    // the store, never copied into the diagnostics state: one writer, one
    // truth, and a row that cannot drift from the verdict it describes.
    diagnostics.install_addresses(own_identity.addresses().clone());
    // The Awaited Inbound registry is woven before this actor exists (the
    // serve adapter that asks it is), so the counters for the outcomes only
    // it sees are handed over here (ADR-0091).
    wiring
        .awaited_inbound
        .install_diagnostics(diagnostics.clone());
    // The open-node buddy slot is woven before this actor too, and it is the
    // single writer of the held-link/pong facts the snapshot reports
    // (ADR-0061) — so it counts them itself, once it has somewhere
    // to count them.
    wiring.buddy_slot.install_diagnostics(diagnostics.clone());
    // The Kad factory is the ADR-0058 dial-back broker's own counter's single
    // writer: it decides the two-reading crypt verdict inside its
    // pump, so it is the one that can count an incompatible refusal without a
    // second copy of that decision reaching the actor.
    wiring.kad_cells.diagnostics = diagnostics.clone();
    // Every running search, for **Search Attribution** (ADR-0034): the session
    // loop and the `0x99` forwarder deliver through it.
    let live_searches = LiveSearches::new(diagnostics.clone());
    let server_udp = match RuntimeServerUdpTransport::bind(
        wiring.config.server_udp_port,
        wiring.config.address_families,
    )
    .await
    {
        Ok(transport) => {
            // The server-UDP pair's Half-Bound Pair fact, said
            // at the bind exactly as the client-UDP pair's is above: recorded
            // beside the Address Learning bind table rather than in it — see
            // `DiagnosticsState::record_server_udp_bind` for why a row here
            // must never be able to reach the Desired Mapping Set
            // (ADR-0086) — and the same `SocketBoundWithoutFamily` a
            // consumer already knows from the other two roles.
            if let Some(half_bound) = diagnostics.record_server_udp_bind(transport.binds()) {
                tracing::warn!(%half_bound, "server-UDP Family Pair came up half");
                send_event(&evt_tx, CoreEvent::SocketBoundWithoutFamily { half_bound }).await;
            }
            Some(spawn_server_udp_front(
                Arc::new(transport),
                &wiring.config,
                &wiring.hello_adverts.obfuscation,
                &server_facts,
                &own_identity,
                global_callback_rx,
                &global_source_servers,
                &global_source_registry,
                diagnostics.clone(),
                &live_searches,
            ))
        }
        Err(error) => {
            tracing::warn!(%error, "server-UDP global source discovery disabled (UDP bind failed)");
            None
        }
    };
    // The one client-UDP socket (ADR-0057, socket unification): one bound port
    // carries the peer-UDP reask surface (`0xC5`), the NAT-T transport frames
    // (`0xB2`) and the Kad node (`0xE4`/`0xE5` plus whatever obfuscation hides
    // behind an unclaimed byte), demuxed by the `ClientUdpEngine` front. Bound
    // eagerly like the server-UDP socket, at the **configured** port rather
    // than an ephemeral one, because this number is advertised and mapped; a
    // bind failure disables peer-UDP reask *and* Kad (the adverts then stay
    // empty — Honest Capability Advertisement), because there is no second
    // socket left for either to fall back to.
    let reask_reply_sink: SharedReaskReplySink = Arc::default();
    // Where a running Kad node installs its inbound half for the front to find
    // (ADR-0057). Woven before the bind because the front is spawned by it,
    // and filled far later — `EnableKad` may never arrive at all.
    let kad_inlet = crate::client_udp::SharedKadInlet::default();
    // The NAT-T front's two late-bound cells (ADR-0091): its command half,
    // which Peer Reach, the firewalled front and the server coordinator
    // address, and where
    // a punched path asks the port mapper for its PCP `PEER` pin. Both are
    // woven before the socket binds and filled after, because the front is
    // spawned by the bind and the mapping runtime starts after it.
    let natt_front = crate::natt::front::SharedNattFront::default();
    // The client-UDP send half's family of Self Reach: written by the bind
    // below and by Quit, and by nothing else.
    let client_udp_bound = crate::reachability::ClientUdpBound::default();
    // **Self Reach** (ADR-0060): the one owner of our own
    // reachability, woven from its families' writers — the Kad runtime's
    // published verdicts, the session self-facts, the NAT-T front's
    // liveness, the client-UDP bind and the server session's coordinator —
    // and cloned into every reader.
    let self_reach = crate::reachability::SharedSelfReach::new(
        wiring.kad_reach.clone(),
        own_identity.clone(),
        natt_front.clone(),
    )
    // "Kad running" is the Kad runtime's Presence cell, which the Kad
    // Activity alone leases (ADR-0093): read once here, so this
    // owner and the firewalled front below read the same cell.
    .with_kad_presence(wiring.kad_cells.presence.clone())
    .with_client_udp(client_udp_bound.clone())
    .with_server_coordinator(
        wiring
            .shared_server_session
            .server_punch()
            .coordinator_session(),
    )
    .with_ipv6_advert(wiring.ipv6_advert.clone());
    // The hello's buddy tags ask the owner per hello.
    wiring.hello_adverts.install_reach(self_reach.clone());
    // And the session's offer names the same Presented Client ID.
    wiring
        .shared_server_session
        .install_reach(self_reach.clone());
    let peer_pin = crate::adapters::SharedPeerPin::default();
    let (client_udp_reask_rx, client_udp_reply_tx, client_udp_bind) =
        match rmule_net::ed2k::ClientUdpSocket::bind_with(
            wiring.settings.udp_port,
            wiring.config.address_families,
        )
        .await
        {
            Ok(socket) => {
                let socket = Arc::new(socket);
                // What came up, not what was asked for (ADR-0084). The bind
                // table is also where the **Half-Bound Pair** fact is settled
                // — one writer for both, so "which families" and
                // "what that costs" can never disagree.
                own_identity.addresses().record_bind(
                    SocketRole::Udp,
                    socket.binds(),
                    socket.local_port(),
                );
                // A pair that came up without a family it selected is not a
                // failure (ADR-0085's rule stays) but it is a *fact*: on a
                // `::`-only client-UDP pair, Kad, the NAT-T punch path and
                // the IPv4 UDP advert are all dead, and nothing else says so.
                // Said once here, at the bind, and read back
                // from the bind table by every gate afterward.
                if let Some(half_bound) = own_identity.addresses().half_bound(SocketRole::Udp) {
                    tracing::warn!(%half_bound, "client-UDP Family Pair came up half");
                    // The adverts follow the bound families, not the
                    // configured ones: a reask port only an IPv6 datagram can
                    // reach is a dead invitation, so the hello's
                    // `CT_EMULE_UDPPORTS` client half is withheld for the
                    // session. The login's `0xF9` needs no latch — it is
                    // built from the bind table's IPv4 port, which is absent.
                    if half_bound.forfeited(rmule_net::family::Consequence::Ipv4UdpAdvert) {
                        wiring.udp_ports_advert.withhold_client_udp();
                    }
                    send_event(&evt_tx, CoreEvent::SocketBoundWithoutFamily { half_bound }).await;
                }
                let (reask_rx, reply_tx) = spawn_client_udp_front(
                    Arc::clone(&socket),
                    &wiring.config,
                    &own_identity,
                    ClientUdpSinks {
                        buddy_slot: &wiring.buddy_slot,
                        reask_reply: &reask_reply_sink,
                        kad_inlet: kad_inlet.clone(),
                    },
                    &diagnostics,
                    NattFrontWiring {
                        reach: &self_reach,
                        natt_front: natt_front.clone(),
                        server: wiring
                            .shared_server_session
                            .server_punch()
                            .coordinator_session(),
                        admit: wiring.tunnel_admit.clone(),
                        claims: wiring.awaited_inbound.clone(),
                        peer_pin: peer_pin.clone(),
                        roster: wiring.peer_roster.clone(),
                        events: evt_tx.downgrade(),
                        hello_adverts: wiring.hello_adverts.clone(),
                        firewalled_front: wiring.firewalled_front.clone(),
                        file_known: wiring.file_known.clone(),
                        // Kad Presence, the cell Self Reach
                        // reads and the Kad Activity leases —
                        // live, so it is current even though `EnableKad`
                        // may not arrive until well after this front spawns.
                        kad_presence: self_reach.kad_presence().clone(),
                    },
                );
                // The send half is up: the family's one set.
                client_udp_bound.set();
                (
                    reask_rx,
                    reply_tx,
                    Some(crate::adapters::ClientUdpBind {
                        socket,
                        kad_inlet,
                        reach: self_reach.clone(),
                    }),
                )
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    "client-UDP socket bind failed; peer-UDP reask and Kad disabled"
                );
                // Named, not just logged: the port and the OS's
                // reason ride a diagnostics row that outlives this log line
                // and a start event a consumer sees exactly once. There is no
                // retry (ADR-0057 amendment) — this is the whole session's
                // answer to "why is Kad off" until an operator restarts.
                diagnostics.record_client_udp_bind_failure(wiring.settings.udp_port, error.kind());
                send_event(
                    &evt_tx,
                    CoreEvent::ClientUdpBindFailed {
                        port: wiring.settings.udp_port,
                        kind: error.kind(),
                    },
                )
                .await;
                (None, None, None)
            }
        };
    // The server coordinator's send half (ADR-0091). The `0x9F` keepalive and
    // the punch burst must leave *this* socket — the port the server observes
    // is the port it hands out — so the cell establishment reads gets the
    // same half the reask replies ride, and gets it before any login can
    // build its `0xF9` advert.
    if let Some(tx) = &client_udp_reply_tx {
        let punch = wiring.shared_server_session.server_punch();
        punch.install_client_udp(tx.clone());
        punch.install_diagnostics(diagnostics.clone());
        // The introduction's second half (ADR-0091): the burst leaves inside
        // the session's own event loop, and the role — who dials, who accepts
        // — is the NAT-T front's to enact, so the coordinator carries its
        // command half as it carries the send half.
        punch.install_natt_front(natt_front.clone());
    }
    // The **Port Mapping** runtime (ADR-0086). Started after the client-UDP
    // bind so its first Desired Mapping Set already holds whatever came up; the
    // eD2k listener and the Kad socket bind later in the session, and the
    // runtime learns each from the bind table itself rather than
    // from a notice their starters would have to remember to send.
    let port_mapping = crate::adapters::spawn_port_mapping(
        wiring.settings.port_mapping,
        wiring.config.port_mapping,
        own_identity.addresses().clone(),
        wiring.gateway_source.clone(),
        wiring.mapping_backends.clone(),
        wiring.kad_pump.clone(),
        diagnostics.clone(),
        Arc::clone(&wiring.port_mapping_preferences),
        self_reach.clone(),
    );
    // A **Punched Path**'s one PCP `PEER` pin (ADR-0091) goes to the running
    // mapping runtime, which owns the backends and the route table. Weakly, so
    // the actor's own handle stays the runtime's only lifeline.
    if let Some(handle) = &port_mapping {
        peer_pin.install(handle.pin_sender());
    }
    // The **Reachability Trail** (ADR-0075): each of core's own levels into
    // the Run Log when its owner moves it. Started before the listener binds
    // at attach, so that bind is a move it writes.
    let trail = crate::run_log::trail::spawn(crate::run_log::trail::TrailSources {
        diagnostics: diagnostics.clone(),
        mapping_rows: port_mapping
            .as_ref()
            .map(crate::adapters::PortMappingHandle::rows),
        addresses: own_identity.addresses().clone(),
        reach: self_reach.clone(),
        buddy: wiring.hello_adverts.buddy.clone(),
    });
    let remember_peers = wiring.settings.remember_peers;
    let (restoring, remembered) = download::attach_downloads(
        &wiring.store,
        &diagnostics,
        &evt_tx,
        wiring.restore_at_attach,
        &wiring.served_downloads,
    )
    .await;

    // The spawn-invariant runner runtime, built once. The two
    // download arms clone their `DownloadTask` out of it via `spawn_download`;
    // the wiring's handles stay usable elsewhere in the loop because every
    // field is a cheap clone.
    // The runner → reach-arm channel for ADR-0091's 12 s callback fallback: a
    // download that measured twelve seconds of callback silence holds the
    // counterparty's facts but not ours, so it sends them here and this actor
    // asks the one selector (ADR-0061). Bounded and never awaited on the answer
    // — a full inbox costs a punch attempt, not a download.
    let (download_reach_tx, download_reach_rx) = mpsc::channel(16);
    // The runs' in-place reports (ADR-0115, step 6): each waits on its own
    // answer, so a report never queues behind another run's.
    let (in_place_tx, in_place_rx) = mpsc::channel(16);
    let download_runtime = DownloadRuntime {
        shared: Arc::new(SharedRuntime {
            download_reach_tx,
            source_lookup_timeout: wiring.config.source_lookup_timeout,
            callback_timeout: wiring.config.callback_timeout,
            store: Arc::clone(&wiring.store),
            source_lookup: Arc::clone(&wiring.source_lookup),
            source_asks: Arc::default(),
            peer_transfer: Arc::clone(&wiring.peer_transfer),
            credit: Arc::clone(&wiring.credit),
            evt_tx: evt_tx.clone(),
            diagnostics: diagnostics.clone(),
            server_session: wiring.shared_server_session.clone(),
            awaited_inbound: wiring.awaited_inbound.clone(),
            global_source_registry,
            global_callback_tx,
            kad_source_registry: kad_source_registry.clone(),
            reask_reply_sink,
            client_udp_tx: client_udp_reply_tx.clone(),
            ip_filter: wiring.ip_filter.clone(),
            ipv6_advert: wiring.ipv6_advert.clone(),
            // Also the one serve-listener cell, bound and cleared by
            // `on_serve_command` exactly where the serve activity is.
            reach: self_reach.clone(),
            peer_roster: wiring.peer_roster.clone(),
            resolver: crate::name_resolver::system_resolver(),
            completion_fs: Arc::new(crate::download::OsCompletionFs),
            copy_turn: Arc::new(tokio::sync::Semaphore::new(1)),
            in_place_tx,
        }),
        peer_concurrency: wiring.config.effective_peer_concurrency_per_download(),
        streaming_window_parts: wiring.config.streaming_window_parts,
        finished_tx: finished_tx.clone(),
        discovery: crate::download::DiscoveryLiveness {
            global_servers: Arc::clone(&global_source_servers),
            reach: self_reach.clone(),
            session: diagnostics.clone(),
        },
    };

    // Read before the actor takes a command: the Registry Check's start look.
    let registry_at_start = crate::registry::SharedFileRegistry::list(&*wiring.registry).ok();
    let share_guards = wiring.share_guards.clone();
    let temp_dir = wiring.settings.temp_dir.clone();
    // **Peer Reach** (ADR-0061, ADR-0091): both reach arms end in it, over
    // the handles woven above.
    let peer_reach = crate::peer_reach::PeerReacher::new(crate::peer_reach::PeerReachWiring {
        reach: self_reach.clone(),
        client_udp: client_udp_reply_tx.clone(),
        natt: natt_front,
        kad_pump: wiring.kad_pump.clone(),
        own: own_identity.clone(),
        obfuscation: wiring.hello_adverts.obfuscation.clone(),
        diagnostics: diagnostics.clone(),
        events: evt_tx.clone(),
    });
    let mut actor = CoreActor {
        wiring,
        evt_tx,
        diagnostics,
        server_list_update_in_flight: Arc::new(AtomicBool::new(false)),
        server_connect_in_flight: Arc::new(AtomicBool::new(false)),
        finished_tx,
        registry_check: registry_check::spawn_registry_check(scan_tx.clone(), registry_at_start),
        directories: super::shared_directory::DirectoryList {
            temp_dir,
            guards: share_guards,
            ..Default::default()
        },
        scan_tx,
        serve_ended_tx,
        kad_ended_tx,
        activities: Activities::restoring(restoring, remembered),
        live_searches,
        global_source_servers,
        kad_source_registry,
        kad: None,
        activity_generation: 0,
        server_udp,
        own_identity,
        user_hash,
        download_runtime,
        client_udp_reask_rx,
        client_udp_reply_tx,
        client_udp_bind,
        self_reach,
        client_udp_bound,
        peer_reach,
        interface_refresh,
        share_flush,
        port_mapping,
        trail,
        intent: super::server_intent::IntentLedger::default(),
        remember_peers,
        offer_checks: super::offer_check::OfferChecks::default(),
    };
    // The listener is up from attach (ADR-0095): before any download
    // restored below starts, and before any connect.
    actor.listen_at_attach().await;
    // Every directory on the Shared Directory List is scanned from the
    // start: the download directory the Core Settings name, and every one the
    // operator added (ADR-0101).
    actor.start_shared_directories().await;
    actor
        .run(
            inbox,
            super::RunNotices {
                finished: finished_rx,
                in_place: in_place_rx,
            },
            scan_rx,
            download_reach_rx,
            serve_ended_rx,
            kad_ended_rx,
        )
        .await;
}

/// Start the **Interface Source** poll (ADR-0084) and return the guard that
/// stops it: refresh once immediately, then on a five-minute tick, until the
/// returned sender drops with the actor. `None` when no source is installed —
/// core then simply holds no interface tier and no corroboration evidence,
/// which the store already reads as "nothing known" rather than as "nothing
/// held".
fn spawn_interface_refresh(session: &SharedServerSession) -> Option<mpsc::Sender<()>> {
    if !session.has_interface_source() {
        return None;
    }
    session.refresh_interfaces();
    let session = session.clone();
    let (guard_tx, mut guard_rx) = mpsc::channel::<()>(1);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(INTERFACE_REFRESH_INTERVAL);
        tick.tick().await; // the immediate first tick; the poll above is it
        loop {
            tokio::select! {
                _ = tick.tick() => session.refresh_interfaces(),
                // The actor dropped its guard: the core this served is gone.
                _ = guard_rx.recv() => return,
            }
        }
    });
    Some(guard_tx)
}

/// How often the **Interface Source** is re-polled (ADR-0084; kno's aMule
/// `SetLocalAddresses` cadence). Fast enough that a renumber unseats an
/// adopted address well inside the 30-minute observation window, slow enough
/// that the enumeration is never a cost.
const INTERFACE_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);

/// Seed the credit ring from `dir`'s `clients.met`. Load tolerance follows
/// aMule's `LoadList` (absent/corrupt file ⇒ empty ring); only peers the store
/// has never met are replayed, so a self-persisting ring is never
/// double-counted.
async fn seed_credit_ring_from_clients_met(dir: &Path, credit: &SharedCreditStore) {
    match crate::clients_met::load_clients_met(dir, unix_now()) {
        Ok(records) => match crate::clients_met::seed_credit_ring(&**credit, &records) {
            Ok(seeded) if seeded > 0 => {
                tracing::info!(seeded, "credit ring seeded from clients.met");
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(%error, "credit ring seed failed; continuing unseeded");
            }
        },
        Err(error) => {
            tracing::warn!(%error, "clients.met unreadable; starting with the ring as-is");
        }
    }
}
