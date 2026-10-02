//! The core actor: one task owning every activity a session runs. It takes
//! [`CoreCommand`]s off the front end's channel, drives the
//! download, serve, search, server-list and Kad legs against the seams the
//! builder wove, and reports back as [`CoreEvent`]s. Nothing
//! here decides protocol behaviour — each activity's brain does that; the actor
//! owns their lifecycle and the runtime they share.

mod client_udp;
mod download;
mod kad;
mod peer;
mod prologue;
mod quit;
mod registry_check;
mod scan;
mod search;
mod serve;
mod server;
mod server_intent;
mod server_udp_front;
mod share_flush;
mod shared_directory;

pub use server_intent::RECONNECT_ATTEMPTS;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use tokio::sync::{Mutex, mpsc, watch};

use crate::adapters::{
    KadRuntimeFactory, PeerTransferService, RuntimeServerUdpTransport, ServeRuntimeService,
    SharedCallbackTable, SharedDialedServeSink, SharedUdpPortsAdvert, SourceLookupService,
    relay_global_callbacks,
};
use crate::buddy_link::SharedBuddySlot;
use crate::client_udp::{ClientUdpDatagram, ClientUdpSend};
use crate::credit::SharedCreditStore;
use crate::global_sources::{
    GlobCallbackSend, GlobalDiscoveryChannel, GlobalSourceRegistry, SharedServerList,
};
use crate::ip_filter::SharedIpFilter;
use crate::kad_sources::KadSourceRegistry;
use crate::own_identity::SharedOwnIdentity;
use crate::registry::auto_share_completed_download;
use crate::search::LiveSearches;
use crate::server_capabilities::SharedServerCapabilities;
use crate::server_list::{ServerFacts, ServerListFetcher, SharedServerListStore};
use crate::server_session::SharedServerSession;
use crate::server_udp::{ServerUdpEngine, StatusChallenges};
use crate::source_discovery::SourceDiscovery;
use crate::store::download::DurableDownloadRepository;
use crate::store::registry::DurableSharedFileRegistry;

use self::download::DownloadRuntime;
use super::activity::{Activities, GlobalSearchContext, ServerUdpFront, unix_now};
use super::{CoreCommand, CoreConfig, CoreEvent, FinishedActivity};

pub(super) use self::prologue::run_core_with_adapters;

async fn send_event(evt_tx: &mpsc::Sender<CoreEvent>, event: CoreEvent) {
    let _ = evt_tx.send(event).await;
}

/// Nudge the **Kad Publisher** to re-sweep the **Shared File
/// Registry** after a share-set change — the publish-side twin of the serve
/// activity's `share_changed_tx`. A no-op until `EnableKad` installs the
/// trigger; `try_send` because one pending nudge already coalesces the re-sweep
/// (the publisher reads the whole current registry, not a per-change delta).
fn notify_kad_publisher<C>(kad: &Option<kad::KadActivity<C>>) {
    if let Some(kad) = kad {
        kad.share_changed();
    }
}

/// The adapter set and shared handles the actor is built over — everything
/// `CoreBuilder::build` assembles, handed across as one value and held whole by
/// `CoreActor` for the session's life. The stores arrive already shared
/// (`Arc<_>`, every seam method `&self` — ADR-0083) and the two services
/// behind `Arc<Mutex<_>>`: the actor's own arms and the download runtime reach
/// the same instances. The serve runtime arrives in an `Option` because
/// `StartServing` takes it by value exactly once.
pub(super) struct CoreWiring<S, P, L, K> {
    pub(super) config: CoreConfig,
    pub(super) store: Arc<DurableDownloadRepository>,
    pub(super) registry: Arc<DurableSharedFileRegistry>,
    pub(super) credit: SharedCreditStore,
    /// The node's User Hash, fixed at build (ADR-0048 "Identity ownership"):
    /// the one every login and hello this actor starts presents.
    pub(super) user_hash: rmule_primitives::UserHash,
    pub(super) source_lookup: Arc<Mutex<S>>,
    pub(super) peer_transfer: Arc<Mutex<P>>,
    pub(super) serve_runtime: Option<L>,
    pub(super) kad_factory: K,
    pub(super) shared_server_session: SharedServerSession,
    pub(super) dialed_serve_sink: SharedDialedServeSink,
    pub(super) callbacks: SharedCallbackTable,
    pub(super) udp_ports_advert: SharedUdpPortsAdvert,
    /// The **Advertised IPv6** (ADR-0087): the Advertised Endpoints chooser's
    /// IPv6 verdict, published once and read by the hello tag, the Kad publish
    /// tag, the Dial Chooser and source ingest — so no two of them can decide
    /// differently.
    pub(super) ipv6_advert: crate::adapters::SharedIpv6Advert,
    pub(super) buddy_slot: SharedBuddySlot,
    /// The one **Hello Adverts** read — which carries the enacted
    /// firewalled slot (ADR-0061) — and the late-bound command
    /// half of the front that drives it: the Kad factory already holds both,
    /// and the actor holds them to spawn that front over the one client-UDP
    /// bind, whose buddy dial states what every other hello does.
    pub(super) hello_adverts: crate::adapters::HelloAdverts,
    pub(super) firewalled_front: crate::firewalled::front::SharedFirewalledFront,
    /// The file-known predicate: the serve and download command
    /// arms push every share-set and download-lifecycle change here inline;
    /// the firewalled front reads it for its `0x99` gate without awaiting
    /// this actor.
    pub(super) file_known: crate::known_files::SharedFileKnown,
    /// Where a risen NAT-T **Tunnel** enters the serve pipeline (ADR-0091):
    /// filled by the serve adapter's accept pump, read by the NAT-T front.
    pub(super) tunnel_admit: crate::adapters::SharedTunnelAdmit,
    /// Where a refused peer hello is counted and raised (ADR-0050): the
    /// adapters hold clones; the prologue installs the bus and diagnostics.
    pub(super) hello_refusals: crate::hello_refusals::SharedHelloRefusals,
    /// The **Pending Tunnel Claim** table (ADR-0091): filled by a download
    /// whose callback went silent, consulted by the serve adapter's triage.
    pub(super) tunnel_claims: crate::adapters::SharedTunnelClaims,
    pub(super) ip_filter: SharedIpFilter,
    /// The **Interface Source** (ADR-0084) core polls for the addresses this
    /// host holds. `Core::builder` installs the live enumeration; the
    /// adapter-level constructors leave it `None`, so a test core asks the OS
    /// nothing and drives the set through the store directly.
    pub(super) interface_source: Option<Arc<dyn rmule_net::interfaces::InterfaceSource>>,
    /// The **Gateway Source** and **Mapping Backends** (ADR-0086) the port
    /// mapping runtime drives, and the sink that reaches a running Kad node
    /// with an externally triggered recheck.
    pub(super) gateway_source: Arc<dyn rmule_net::portmap::GatewaySource>,
    pub(super) mapping_backends: Vec<Arc<dyn rmule_net::portmap::MappingBackend>>,
    pub(super) kad_pump: crate::adapters::SharedKadPump,
    /// The core-owned Peer Roster (ADR-0059): cloned into the
    /// serve adapter and the Kad factory at build time, and into every
    /// download's `DownloadRuntime` here so its worker fleet's
    /// connect/disconnect can mark and forget it too.
    pub(super) peer_roster: crate::peer_roster::SharedPeerRoster,
    pub(super) port_mapping_preferences: Arc<dyn crate::adapters::PortMappingPreferences>,
    pub(super) clients_met_dir: Option<PathBuf>,
    /// What the Shared Directory List's guards refuse beyond the
    /// filesystem's own facts: the operator's home and rmule's data
    /// directory, as the front end names them.
    pub(super) share_guards: crate::ShareGuards,
    pub(super) restore_credentials: Option<super::ClientCredentials>,
    pub(super) server_list: SharedServerListStore,
    pub(super) server_list_fetcher: Option<Arc<dyn ServerListFetcher>>,
}

/// The actor's loop-carried state: every seam, shared handle and activity the
/// command arms read or write between one command and the next. Built once the
/// transports are bound and the recovered downloads are reported, then owned by
/// [`CoreActor::run`] for the session's life — so an arm reaches its runtime
/// through `self` rather than through a dozen captured locals.
struct CoreActor<S, P, L, K: KadRuntimeFactory> {
    /// The builder's adapter set and shared handles, held whole.
    wiring: CoreWiring<S, P, L, K>,
    evt_tx: mpsc::Sender<CoreEvent>,
    diagnostics: crate::diagnostics::DiagnosticsState,
    /// One server-list update at a time (aMule's own posture). Set by the
    /// actor when it accepts an `UpdateServerList`, cleared by the update task
    /// when it lands, so the guard survives the task the actor never awaits.
    server_list_update_in_flight: Arc<AtomicBool>,
    /// The same posture for the connect, and for the same reason:
    /// the dial runs off the actor, so the guard must outlive the arm.
    server_connect_in_flight: Arc<AtomicBool>,
    finished_tx: mpsc::Sender<FinishedActivity>,
    /// The scan's and the Registry Check's report lane (ADR-0100), held for
    /// the actor's life.
    scan_tx: registry_check::RegistrySender,
    /// The **Registry Check** (ADR-0106), running for the actor's life.
    registry_check: registry_check::RegistryCheckHandle,
    /// The **Shared Directory List** besides its scans (ADR-0101).
    directories: shared_directory::DirectoryList,
    /// The **serve-ended** bump every serve task fires as its last act,
    /// cloned into each one. Held here too so the actor's own arm can
    /// never see the channel closed.
    serve_ended_tx: Arc<watch::Sender<u64>>,
    /// The **Kad Activity**'s own bump, the same shape and the
    /// same reason: held for the actor's whole life so the reclaim arm never
    /// sees a closed channel.
    kad_ended_tx: Arc<watch::Sender<u64>>,
    activities: Activities<L>,
    /// The searches running now, by what they ask (**Search Attribution**).
    live_searches: LiveSearches,
    /// The swept list both global sweeps read (ADR-0051): the
    /// level keeps it a projection of the Managed Server List.
    global_source_servers: SharedServerList,
    /// Kad source discovery (ADR-0043): dormant until `CoreCommand::EnableKad`
    /// starts the node through the consumed-once factory. The registry always
    /// exists — a runner registers its sink unconditionally, and with Kad
    /// disabled nothing ever reads it.
    kad_source_registry: KadSourceRegistry,
    /// The **Kad Activity** (ADR-0093): `Some` exactly while a Kad node runs.
    /// It holds the one Kad Presence lease, so "is Kad running" — read
    /// through [`SharedSelfReach::kad_running`](crate::reachability::SharedSelfReach::kad_running)
    /// by every reader, in the actor or out — is this value's presence.
    kad: Option<kad::KadActivity<K::Channel>>,
    /// The last generation handed to an activity whose end bumps a watch
    /// (the Kad pump, the serve task), so a stale bump names an activity the
    /// ledger no longer holds.
    activity_generation: u64,
    /// The server-UDP front (ADR-0051): present once the server-UDP socket is
    /// bound. `StartSearch` reads its context to spawn the per-search sweep.
    server_udp: Option<ServerUdpFront>,
    /// What rmule knows about itself on the wire — its user hash, and its
    /// external address projected from **Address Learning** (ADR-0084). Both
    /// UDP crypt surfaces read it; it is taken from the session the adapters
    /// and this actor already share, which is also how every feeder reaches
    /// the one store behind it.
    own_identity: SharedOwnIdentity,
    /// The node's User Hash, fixed at build — the same one the
    /// builder wrote into `own_identity`; a command's credentials are
    /// composed with it into the wire identity ([`Self::identity`]).
    user_hash: rmule_primitives::UserHash,
    /// The spawn-invariant runner runtime, built once; the two
    /// download arms clone their `DownloadTask` out of it.
    download_runtime: DownloadRuntime<S, P>,
    /// The reask-ping inbox (`0x90`) the serve task takes on `StartServing`;
    /// `None` when the client-UDP socket did not bind.
    client_udp_reask_rx: Option<mpsc::Receiver<ClientUdpDatagram>>,
    /// The client-UDP send half; `None` when the socket did not bind.
    client_udp_reply_tx: Option<mpsc::Sender<ClientUdpSend>>,
    /// The one bound client-UDP socket and the Kad inlet that rides it
    /// (ADR-0057); `None` when the socket did not bind — which disables the
    /// reask surface and Kad together, because there is no second socket.
    /// Handed to the Kad factory on `EnableKad`.
    client_udp_bind: Option<crate::adapters::ClientUdpBind>,
    /// **Self Reach** (ADR-0060): the one owner of our own
    /// reachability every actor-side reader asks — and, as its NAT-T family,
    /// the **NAT-T Front**'s command half where the reach arm begins a
    /// rendezvous (empty when the client-UDP socket did not bind).
    self_reach: crate::reachability::SharedSelfReach,
    /// The **Interface Source** poll's life guard (ADR-0084). Never read: the
    /// poll task selects on this sender's receiver, so dropping the actor ends
    /// the poll. `None` when no source is installed.
    #[expect(dead_code, reason = "held for its Drop: it ends the interface poll")]
    interface_refresh: Option<mpsc::Sender<()>>,
    /// The **Share Totals** flush, finished at Quit.
    share_flush: Option<share_flush::ShareFlush>,
    /// The **Port Mapping** runtime (ADR-0086), or `None` when port mapping is
    /// off or no backend is installed. Held for two reasons: to tell it when a
    /// socket binds — the Desired Mapping Set grows over a session's life — and
    /// for its `Drop`, which is what triggers the release-on-exit pass.
    port_mapping: Option<crate::adapters::PortMappingHandle>,
    /// The operator's intent to stay connected, and its retries.
    intent: server_intent::IntentLedger,
    /// How many peers each running download writes as its **Source Seeds**
    /// (ADR-0109): the config's at start, then the operator's latest.
    remember_peers: crate::RememberPeers,
}

impl<S, P, L, K> CoreActor<S, P, L, K>
where
    S: SourceLookupService,
    P: PeerTransferService,
    L: ServeRuntimeService,
    K: KadRuntimeFactory,
{
    /// The wire identity a command's `credentials` present: its nickname,
    /// port and version as this node — the build-time hash (ADR-0048 "Identity ownership").
    pub(super) fn identity(
        &self,
        credentials: &super::ClientCredentials,
    ) -> rmule_primitives::ClientIdentity {
        credentials.identity(self.user_hash)
    }

    /// Tell the **Port Mapping** runtime something happened (ADR-0086). A
    /// no-op when nothing is running — port mapping off, or no backend
    /// installed — which is exactly what an operator who turned it off should
    /// get from a recheck.
    pub(super) fn notify_port_mapping(&self, control: crate::adapters::PortMappingControl) {
        if let Some(handle) = self.port_mapping.as_ref() {
            handle.notify(control);
        }
    }

    /// The one bound UDP port — the reask surface's, the NAT-T surface's and
    /// Kad's, since they are one socket (ADR-0057). `None` when it did not
    /// bind.
    pub(super) fn client_udp_port(&self) -> Option<u16> {
        self.client_udp_bind
            .as_ref()
            .map(|bind| bind.socket.local_port())
    }

    /// The **Reachability** facts the **Advertised Endpoints** chooser reads
    /// (ADR-0084): our own TCP verdict as the Kad runtime publishes it, and
    /// the IPv6 probe verdict as the connected server stated it.
    ///
    /// Both are read fresh at every advert rather than cached: a verdict that
    /// changed since the last hello must change the next one, and the whole
    /// point of one chooser is that no site keeps its own copy.
    pub(super) fn advert_reachability(&self) -> crate::address_learning::AdvertReachability {
        crate::address_learning::AdvertReachability {
            // The Kad flag of Self Reach, open or not: a
            // recheck in flight reads its pre-recheck verdict.
            tcp: if self.self_reach.kad_tcp_open() {
                crate::reachability::TcpReachability::Open
            } else {
                crate::reachability::TcpReachability::Firewalled
            },
            ipv6: self.wiring.shared_server_session.ipv6_probe().get(),
        }
    }

    /// Take commands until the front end drops every handle, then flush what
    /// the session owes to disk.
    async fn run(
        mut self,
        mut cmd_rx: mpsc::Receiver<CoreCommand>,
        mut finished_rx: mpsc::Receiver<FinishedActivity>,
        mut scan_rx: mpsc::UnboundedReceiver<registry_check::RegistryMessage>,
        mut download_reach_rx: mpsc::Receiver<crate::callback::DownloadReach>,
        mut serve_ended_rx: watch::Receiver<u64>,
        mut kad_ended_rx: watch::Receiver<u64>,
    ) {
        // The **Session Generation** (ADR-0095): each session the operator's
        // connect installs wakes the searches that waited for one.
        let mut session_rx = self.wiring.shared_server_session.session_changes();
        let mut intent_news = self.intent.take_news();
        let mut lost_legs = self.intent.take_lost_legs();
        let mut restore_tick = tokio::time::interval(self.wiring.config.download_restore_pace);
        restore_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut seed_tick = tokio::time::interval_at(
            tokio::time::Instant::now() + crate::download::source_seeds::SEED_WRITE_INTERVAL,
            crate::download::source_seeds::SEED_WRITE_INTERVAL,
        );
        seed_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = seed_tick.tick(), if !self.activities.downloads.is_empty() => {
                    self.write_source_seeds();
                }
                _ = restore_tick.tick(), if !self.activities.restoring.is_empty() => {
                    self.restore_next().await;
                }
                Some(reach) = download_reach_rx.recv() => {
                    // A download's callback has been silent for twelve seconds
                    // (ADR-0091). The actor keeps its own clone of the sender in
                    // `download_runtime`, so this arm never closes and never
                    // becomes the shutdown signal — `cmd_rx` alone is that.
                    self.on_download_reach(reach).await;
                }
                command = cmd_rx.recv() => {
                    // A closed command channel (every `Core` handle dropped or
                    // `Core::shutdown` called) is the actor's shutdown signal —
                    // the persistence flush below must actually run, so shutdown
                    // cannot ride the `else` arm (the actor holds its own
                    // `finished_tx` clone, which keeps that arm from ever firing).
                    let Some(command) = command else { break };
                    match command {
                        CoreCommand::Download(command) => {
                            self.on_download_command(command).await;
                        }
                        CoreCommand::SetServerPolicy(policy) => {
                            self.on_set_server_policy(policy);
                        }
                        CoreCommand::SetRememberPeers(peers) => {
                            self.remember_peers = peers;
                        }
                        CoreCommand::ServerList(command) => {
                            self.on_server_list_command(command).await;
                        }
                        CoreCommand::ConnectToServer {
                            server,
                            credentials,
                        } => {
                            self.on_connect_to_server(server, credentials).await;
                        }
                        CoreCommand::DisconnectFromServer => {
                            self.on_disconnect_from_server().await;
                        }
                        CoreCommand::EnableKad(kad_config) => {
                            self.on_enable_kad(kad_config).await;
                        }
                        CoreCommand::DisableKad => {
                            self.on_disable_kad().await;
                        }
                        CoreCommand::ReachPeer(peer) => {
                            self.on_reach_peer(peer).await;
                        }
                        CoreCommand::RecheckReachability => {
                            // Both halves, together (ADR-0086): to an operator
                            // "am I reachable" and "is my port forwarded" are
                            // one question, and a stale mapping is the usual
                            // reason a firewall recheck keeps coming back
                            // negative. Re-racing the mappers without
                            // rechecking Kad would leave the verdict stale for
                            // an hour; rechecking Kad without re-racing would
                            // re-confirm the same stale mapping.
                            self.notify_port_mapping(
                                crate::adapters::PortMappingControl::Reprobe,
                            );
                            crate::adapters::request_kad_recheck(&self.wiring.kad_pump);
                        }
                        CoreCommand::DumpDiagnostics => {
                            let mut snapshot = self.diagnostics.snapshot();
                            // The Kad join state lives with the actor's factory
                            // (ADR-0067): `None` while no Kad activity runs — the
                            // ledger value is the whole record's one gate.
                            snapshot.kad = self.kad.as_ref().map(|kad| {
                                crate::diagnostics::KadRuntimeDiagnostics {
                                    contact_responded: self.wiring.kad_factory.has_had_contact(),
                                    contacts: self.wiring.kad_factory.contact_count(),
                                    keywords_stored: self.wiring.kad_factory.keywords_stored(),
                                    node_id: kad.node_id(),
                                    firewall: self.self_reach.kad_firewall_verdict(),
                                    firewall_check: self.self_reach.kad_firewall_check(),
                                    udp: self.self_reach.kad_udp_verdict(),
                                    traffic: self.wiring.kad_factory.kad_traffic(),
                                }
                            });
                            snapshot.kad_tasks_live =
                                self.kad.as_ref().map_or(0, kad::KadActivity::tasks_live);
                            send_event(&self.evt_tx, CoreEvent::DiagnosticsSnapshot { snapshot }).await;
                        }
                        CoreCommand::DumpFileHistory => {
                            let history = crate::file_history::read(
                                &*self.wiring.registry,
                                &self.registry_check.withheld,
                                &self.wiring.registry.had_set(),
                                &*self.wiring.store,
                            );
                            send_event(&self.evt_tx, CoreEvent::FileHistory { history }).await;
                        }
                        CoreCommand::Search(command) => {
                            self.on_search_command(command).await;
                        }
                        CoreCommand::Serve(command) => {
                            self.on_serve_command(command).await;
                        }
                        CoreCommand::Scan(command) => self.on_scan_command(command).await,
                    }
                }
                Some(message) = scan_rx.recv() => self.on_registry_message(message).await,
                Some(news) = intent_news.recv() => self.on_intent_news(news).await,
                Some(lost) = lost_legs.recv() => self.on_server_leg_lost(lost).await,
                () = server_intent::until_retry(self.intent.retry_at()) => {
                    self.on_reconnect_due().await;
                }
                changed = session_rx.changed() => {
                    if changed.is_err() {
                        // Unreachable: the session cell holds the sender for
                        // as long as this actor holds the cell.
                        break;
                    }
                    self.on_session_established().await;
                }
                ended = serve_ended_rx.changed() => {
                    // The serve activity ended without being asked to — a dead
                    // listener — so nothing else would retire it. The bump names
                    // the ended activity's generation: one the `StopServing` arm
                    // already retired names no activity the ledger holds, so it
                    // can never take a successor's live task (ADR-0093).
                    if ended.is_err() {
                        // Unreachable: this actor holds the sender. Read as
                        // shutdown rather than re-polled, because a closed
                        // watch answers `Err` immediately and forever.
                        break;
                    }
                    let generation = *serve_ended_rx.borrow_and_update();
                    self.on_serve_ended(generation).await;
                }
                ended = kad_ended_rx.changed() => {
                    // The Kad activity's pump ended on its own;
                    // the serve arm's generation reading applies.
                    if ended.is_err() {
                        // Unreachable, the `serve_ended_rx` arm's own reasoning:
                        // this actor holds the sender for its whole life.
                        break;
                    }
                    let generation = *kad_ended_rx.borrow_and_update();
                    self.on_kad_ended(generation).await;
                }
                Some(finished) = finished_rx.recv() => {
                    let download_id = match finished {
                        FinishedActivity::Download(download_id, run) => {
                            // A download that ended on its own (a death,
                            // ADR-0093) retires here; one a stop already
                            // retired is gone from the ledger, or replaced by
                            // a later run, so its late notice retires nothing.
                            if self.activities.downloads.get(&download_id).is_some_and(|active| active.run == run) {
                                self.retire_download(download_id);
                            }
                            download_id
                        }
                        FinishedActivity::Search(search_id) => {
                            if let Some(mut active) = self.activities.searches.remove(&search_id) {
                                active.stop_global();
                            }
                            continue;
                        }
                    };
                    // The join point where the download and serve halves meet
                    // (ADR-0031): a download that reached `Completed` auto-shares.
                    // The policy — the `Completed` gate, the behind-the-seam
                    // per-part hash authority, the registry write, and
                    // the `FileShared` event — lives in `auto_share_completed_download`
                    // So the actor keeps no storage-model knowledge and
                    // only fires the two share-set triggers once the file registers.
                    if let Some(file_hash) = auto_share_completed_download(download_id, &*self.wiring.store, &*self.wiring.registry, &self.evt_tx).await {
                        // A share-set change like any other: the
                        // predicate, the serve snapshot and the Kad publisher.
                        self.row_shared(file_hash);
                    }
                }
                else => break,
            }
        }

        // Quit is every stop, in order (ADR-0093), before the flush.
        self.retire_all().await;
        if let Some(share_flush) = self.share_flush.take() {
            share_flush.finish().await;
        }
        // Shutdown flush: make the ring durable, then snapshot it
        // back to `clients.met`. Runs on the command-channel-close path above;
        // the event sender drops when this function returns, which is what
        // `Core::shutdown` awaits. The checkpoint is unconditional — the ring
        // is durable whether or not a `clients.met` copy was asked for.
        if let Err(error) = self.wiring.credit.checkpoint() {
            tracing::warn!(%error, "credit checkpoint failed; the last accrual may not be durable");
        }
        if let Some(dir) = self.wiring.clients_met_dir.as_deref() {
            let snapshot = self.wiring.credit.snapshot();
            match snapshot {
                Ok(snapshot) => {
                    if let Err(error) =
                        crate::clients_met::save_clients_met(dir, &snapshot, unix_now())
                    {
                        tracing::warn!(%error, "clients.met save failed; credit ring not persisted");
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "credit snapshot failed; clients.met not written");
                }
            }
        }
        // The event stream's end is `Core::shutdown`'s completion, so the
        // last sender drops after everything else the actor holds — the store
        // views above all — whatever order the fields would drop in.
        let last_sender = self.evt_tx.clone();
        drop(self);
        drop(last_sender);
    }
}
