//! The **Port Mapping** runtime (ADR-0086): the task that gives the sans-I/O
//! [`PortMapper`] its sockets.
//!
//! The mapper decides; this enacts. It turns each [`MappingCommand`] into one
//! [`MappingBackend`] call, feeds the answer back as a [`MappingResult`], and
//! republishes the diagnostics level — and it does the enacting **off the
//! loop**, one spawned task per call, because the whole point of the race is
//! that three protocols are asked at once. A runtime that awaited each backend
//! in turn would make the slowest protocol the subsystem's latency and turn the
//! 3-second grace into a lie.
//!
//! Two translations live here and nowhere else:
//!
//! - **Which gateway a request goes to.** The mapper speaks
//!   [`AddressFamily`]; the route table speaks
//!   next hops. A mapping in a family with no default route is reported as
//!   `Unsupported` rather than silently dropped, so the diagnostics row says
//!   what happened.
//! - **A probe is one question per protocol, not per gateway.** The mapper asks
//!   "is PCP there, and what can it map"; a dual-stack host has two gateways and
//!   PCP may answer differently on each, so the runtime asks both and merges the
//!   family lists into the one answer the mapper expects.

use std::sync::Arc;
use std::time::{Duration, Instant};

use rmule_net::portmap::{
    Gateway, GatewaySource, MappedTransport, MappingBackend, MappingError, MappingProtocol,
    MappingRequest,
};
use rmule_primitives::AddressFamily;
use tokio::sync::{mpsc, watch};

use crate::address_learning::SharedAddressLearning;
use crate::diagnostics::DiagnosticsState;
use crate::port_mapping::{
    DesiredMapping, GrantAnswer, MappingCommand, MappingDiagnostics, MappingResult, PortMapper,
    PortMappingConfig, PortMappingMode, ProbeAnswer,
};
use crate::reachability::SharedSelfReach;

use super::kad_runtime::{SharedKadPump, request_kad_recheck};

/// How long a clean exit waits for its release datagrams. A release is
/// fire-and-forget by design — at least one firmware never acknowledges a PCP
/// delete, and the finite lease is the real cleanup — so this is a courtesy
/// budget, not a guarantee.
const RELEASE_BUDGET: Duration = Duration::from_secs(2);

/// The deadline every backend call runs under.
///
/// A backend that never answers would strand the mapper: a trial is judged only
/// once every mapping has answered, so one silent call holds the whole race
/// open for the rest of the session. The two UDP backends bound themselves with
/// their own retransmit ladder, but the UPnP one makes a blocking HTTP request
/// to a device that can simply stop replying — and a cancelled `spawn_blocking`
/// keeps running, so this bounds the *answer*, not the thread. Comfortably past
/// the race's own 15-second cap, so it never pre-empts a slow-but-live gateway.
const BACKEND_DEADLINE: Duration = Duration::from_secs(20);

/// The runtime's clock period: a due-time backstop for the re-derivation
/// that no event announces (a Known IPv6 verdict lapsing with nobody
/// writing). The connected server's ID verdict is not polled on it — it is
/// **Self Reach**'s High-ID half, and the runtime wakes on its **Reach
/// Generation** (ADR-0060).
const RECHECK_PERIOD: Duration = Duration::from_secs(30);

/// What the actor tells the mapping runtime.
///
/// Deliberately *not* "a socket bound". The **Desired Mapping Set** is derived
/// from the **Address Learning** bind table and nothing else, so the runtime
/// watches that table's own **Bind Generation** rather than trusting a notice
/// sent beside the bind — a notice the eD2k listener lost, costing a whole
/// session the mapping that earns its High-ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PortMappingControl {
    /// The operator's recheck: re-race the mappers. Its other half — rechecking
    /// Kad — is the actor's, because to a user "am I reachable" and "is my port
    /// forwarded" are one question and a stale mapping is the usual reason a
    /// recheck keeps failing.
    Reprobe,
    /// A **Punched Path** came up and wants its one PCP `PEER` pin (ADR-0091).
    ///
    /// It arrives as a control rather than through a handle of its own because
    /// the backends and the route table are this task's, and a second owner of
    /// either would be a second answer to "which gateway". Unlike the mapper's
    /// own commands it carries no state: a pin is asked once per path, its
    /// refusal is ordinary, and a path never depends on it.
    PinPeer(rmule_net::portmap::PeerPinRequest),
}

/// The actor's handle on the running mapping task. Closing its control
/// channel is the task's shutdown signal — and what triggers the
/// release-on-exit pass, which quit awaits through [`retire`](Self::retire).
#[derive(Debug)]
pub(crate) struct PortMappingHandle {
    control: mpsc::Sender<PortMappingControl>,
    task: tokio::task::JoinHandle<()>,
    /// The **Mapping Status** rows as the runtime last published them — the
    /// values the diagnostics level carries, on a watch so a waiter wakes on
    /// the change instead of polling (the **Login Mapping Wait**).
    rows: watch::Receiver<Vec<MappingDiagnostics>>,
}

impl PortMappingHandle {
    /// Tell the runtime something happened. Best effort: a full inbox drops the
    /// notice rather than blocking the actor, and every control here is
    /// idempotent or re-derivable on the next one.
    pub(crate) fn notify(&self, control: PortMappingControl) {
        let _ = self.control.try_send(control);
    }

    /// A **weak** sender for the NAT-T front's punched-path pins.
    ///
    /// Weak because dropping *this* handle is the runtime's shutdown signal
    /// (and what triggers the release-on-exit pass): a strong clone parked in
    /// another subsystem would keep the task alive past the core it serves.
    pub(crate) fn pin_sender(&self) -> mpsc::WeakSender<PortMappingControl> {
        self.control.downgrade()
    }

    /// A receiver of the published **Mapping Status** rows.
    pub(crate) fn rows(&self) -> watch::Receiver<Vec<MappingDiagnostics>> {
        self.rows.clone()
    }

    /// Retire the runtime at quit (ADR-0093): close the control channel —
    /// its shutdown signal — and wait for the release-on-exit pass, which is
    /// itself bounded by `RELEASE_BUDGET`, so the `DeletePortMapping`s have
    /// left before the core reports it is down. Aborted if the task is still
    /// running past that budget and a margin.
    pub(crate) async fn retire(self) {
        let Self { control, task, .. } = self;
        drop(control);
        let abort = task.abort_handle();
        if tokio::time::timeout(RELEASE_BUDGET + Duration::from_secs(1), task)
            .await
            .is_err()
        {
            abort.abort();
        }
    }
}

/// The bound on the **Login Mapping Wait** (ADR-0086): eMule's second UPnP connect-delay timer
/// (`EmuleDlg.cpp:3493`). Past it the login goes out whatever the listener's row reads — a router
/// that never answers costs the operator seconds, not the session.
pub(crate) const LOGIN_MAPPING_WAIT: Duration = Duration::from_secs(10);

/// Wait, at most [`LOGIN_MAPPING_WAIT`], for the listener's row on `port` to
/// settle (`port_mapping::listener_mapping_settled`). Answers whether it
/// did; a runtime that ended mid-wait ends the wait too.
pub(crate) async fn await_listener_mapping(
    mut rows: watch::Receiver<Vec<MappingDiagnostics>>,
    port: u16,
) -> bool {
    tokio::time::timeout(
        LOGIN_MAPPING_WAIT,
        rows.wait_for(|rows| crate::port_mapping::listener_mapping_settled(rows, port)),
    )
    .await
    .is_ok_and(|settled| settled.is_ok())
}

/// Where a **Punched Path** asks for its PCP `PEER` pin (ADR-0091), late-bound
/// like the server coordinator's send half: the client-UDP socket — and with
/// it the NAT-T front — comes up before the mapping runtime does.
///
/// Empty means no mapping runtime at all (port mapping off, or no backend
/// installed), which is an ordinary posture: the 60 s keepalive carries every
/// path by itself, and the pin was never more than a repair the router can
/// make and rmule cannot.
#[derive(Clone, Debug, Default)]
pub(crate) struct SharedPeerPin(
    std::sync::Arc<std::sync::OnceLock<mpsc::WeakSender<PortMappingControl>>>,
);

impl SharedPeerPin {
    /// Install the running runtime's control half. Idempotent: one runtime per
    /// core.
    pub(crate) fn install(&self, sender: mpsc::WeakSender<PortMappingControl>) {
        let _ = self.0.set(sender);
    }

    /// Ask for one pin. Best effort in every direction — no runtime, a runtime
    /// that has since exited, or a full control inbox all mean the path keeps
    /// itself alive on the keepalive alone.
    pub(crate) fn request(&self, pin: rmule_net::portmap::PeerPinRequest) {
        let Some(sender) = self.0.get().and_then(mpsc::WeakSender::upgrade) else {
            tracing::debug!(?pin, "no port-mapping runtime to pin a punched path with");
            return;
        };
        let _ = sender.try_send(PortMappingControl::PinPeer(pin));
    }
}

/// Start the mapping runtime, or answer `None` when there is nothing to run:
/// port mapping is off, or no backend was installed.
///
/// `None` is a real outcome rather than a degenerate task — it is what a build
/// with no mapping backends, or an operator who turned the feature off, should
/// produce, and it keeps the actor from holding a handle that can only no-op.
#[allow(clippy::too_many_arguments)] // one seam per family the runtime reads
pub(crate) fn spawn_port_mapping(
    mode: PortMappingMode,
    config: PortMappingConfig,
    addresses: SharedAddressLearning,
    gateways: Arc<dyn GatewaySource>,
    backends: Vec<Arc<dyn MappingBackend>>,
    kad_pump: SharedKadPump,
    diagnostics: DiagnosticsState,
    preferences: Arc<dyn PortMappingPreferences>,
    reach: SharedSelfReach,
) -> Option<PortMappingHandle> {
    if mode == PortMappingMode::Off || backends.is_empty() {
        return None;
    }
    let (control_tx, control_rx) = mpsc::channel(8);
    let (rows_tx, rows_rx) = watch::channel(Vec::new());
    // The renewal jitter's seed. Per process rather than per install: it only
    // decorrelates renewal storms across clients, so any value no other client
    // shares will do.
    let seed = u64::from(std::process::id()) ^ 0x5DEE_CE66_D125_u64;
    let learned = preferences.learned_method();
    let task = tokio::spawn(
        Runtime {
            mapper: PortMapper::new(config, addresses.clone(), seed).with_learned_method(learned),
            addresses,
            gateways,
            backends,
            kad_pump,
            diagnostics,
            preferences,
            learned,
            reach,
            routes: Vec::new(),
            rows: rows_tx,
        }
        .run(control_rx),
    );
    Some(PortMappingHandle {
        control: control_tx,
        task,
        rows: rows_rx,
    })
}

/// Where the **learned method** is remembered between runs (ADR-0086).
///
/// A seam rather than a direct store call so a test core can run the whole
/// subsystem without persisting a preference into a shared file, and so the
/// mapper stays ignorant of storage — the same split every other durable seam
/// in core keeps.
pub(crate) trait PortMappingPreferences: Send + Sync {
    /// The method that last won a race, or `None` — never raced, or the stored
    /// value names a protocol this build does not know.
    fn learned_method(&self) -> Option<MappingProtocol>;
    /// Remember the method that just won.
    fn set_learned_method(&self, method: MappingProtocol);
}

/// The task's own state: the mapper, the seams, and the cached route lookup.
struct Runtime {
    mapper: PortMapper,
    /// The **Address Learning** store, held for the bind table and the Own
    /// Address Generation the runtime wakes on.
    addresses: SharedAddressLearning,
    gateways: Arc<dyn GatewaySource>,
    backends: Vec<Arc<dyn MappingBackend>>,
    kad_pump: SharedKadPump,
    diagnostics: DiagnosticsState,
    /// Where the learned method is remembered between runs, and what it was at
    /// startup — so a win is written once, on the change, rather than on every
    /// loop turn.
    preferences: Arc<dyn PortMappingPreferences>,
    learned: Option<MappingProtocol>,
    /// **Self Reach** (ADR-0060): the one owner of "does a live session hold a
    /// High ID", read for the smart-LowID edge (see
    /// [`observe_server_id`](Runtime::observe_server_id)).
    reach: SharedSelfReach,
    /// Where the rows are published beside the diagnostics level.
    rows: watch::Sender<Vec<MappingDiagnostics>>,
    /// The default-route next hops, refreshed at the start of every probe
    /// round. Not per request: the route table is an OS call, and a round of
    /// three protocols over two families would make six of them for one answer
    /// that cannot have changed in between.
    routes: Vec<Gateway>,
}

impl Runtime {
    async fn run(mut self, mut control_rx: mpsc::Receiver<PortMappingControl>) {
        let (results_tx, mut results_rx) = mpsc::channel(32);
        // Every socket records what it bound in **Address Learning**, and the
        // **Desired Mapping Set** is derived from exactly that table — so the
        // table's own writes are what this runtime waits on. The
        // set grows over a session's life: the client-UDP pair comes up with
        // the core, the eD2k listener when the serve side starts, the Kad
        // socket when Kad is enabled.
        let mut binds_changed = self.addresses.binds_changed();
        // The set's other input, a Known IPv6 for a pinhole, is Address
        // Learning's too, so its **Own Address Generation** is the second
        // wake: an interface poll or a server reflection learns
        // it on a task that has no reason to know a port mapper exists.
        let mut own_address_changed = self.addresses.own_address_changed();
        // The smart-LowID edge is a **Reach Generation** wake (a session
        // write), read from Self Reach's High-ID half at the wake.
        let mut reach_generation = self.reach.changes();
        self.observe_server_id(Instant::now());
        self.mapper.start(Instant::now());
        loop {
            self.drain(&results_tx);
            self.persist_learned_method();
            self.publish_rows();
            let poll_at = Instant::now() + RECHECK_PERIOD;
            let wake = self
                .mapper
                .next_wake()
                .map_or(poll_at, |at| at.min(poll_at));
            tokio::select! {
                Some(result) = results_rx.recv() => {
                    self.mapper.on_result(result, Instant::now());
                }
                // A socket came up (or came up differently): re-derive. The
                // mapper leaves an unchanged set — and the leases held for it
                // — alone, so this costs one derivation per bind and never a
                // needless race.
                bound = binds_changed.changed() => {
                    // Unreachable while this runtime holds its own store
                    // handle, and still ruled on rather than discarded: a
                    // closed `watch` answers `Err` forever, which is a spin,
                    // not a wakeup.
                    if bound.is_err() {
                        break;
                    }
                    self.mapper.start(Instant::now());
                }
                // Our own address moved. Unreachable closed for the reason
                // `binds_changed` is; the `Ok` pattern disables the arm rather
                // than spin if it ever were.
                Ok(()) = own_address_changed.changed() => {
                    self.mapper.start(Instant::now());
                }
                // Self Reach moved — a login, a re-assignment, a session's end
                // (or a Kad verdict, which the edge ignores).
                () = reach_generation.changed() => {
                    self.observe_server_id(Instant::now());
                }
                control = control_rx.recv() => {
                    let now = Instant::now();
                    match control {
                        Some(PortMappingControl::Reprobe) => self.mapper.reprobe(now),
                        Some(PortMappingControl::PinPeer(request)) => self.pin_peer(request),
                        // The actor dropped its handle: the core this served is
                        // gone.
                        None => break,
                    }
                }
                () = sleep_until(Some(wake)) => {
                    let now = Instant::now();
                    // Re-derive on the clock as well as on the two events. An
                    // IPv6 pinhole is desired only while a Known IPv6 exists
                    // (ADR-0084), and a Known verdict can also lapse with
                    // nobody writing — the one edge the Own Address
                    // Generation cannot announce.
                    self.mapper.start(now);
                    self.mapper.tick(now);
                }
            }
        }
        self.release_on_exit().await;
        self.diagnostics.set_mappings(Vec::new());
    }

    /// Write the method that just won a race, if it is not the one already
    /// remembered — so the next run opens with one short probe instead of a
    /// full three-protocol race.
    fn persist_learned_method(&mut self) {
        let Some(method) = self.mapper.learned_method() else {
            return;
        };
        if self.learned == Some(method) {
            return;
        }
        self.learned = Some(method);
        self.preferences.set_learned_method(method);
    }

    /// Feed the connected server's current ID verdict to the mapper, so the
    /// first LowID after a High-ID re-maps once (the references' "smart
    /// LowID"): the mapping that earned the High-ID has evidently stopped
    /// working, and nothing else would notice until the lease ran out.
    ///
    /// The verdict is **Self Reach**'s High-ID half (`IsConnectedED2K() &&
    /// !IsLowID()`), not a second derivation of it from Address Learning's
    /// `Server` tier (ADR-0060).
    /// Publish the rows to the diagnostics level and, when they moved, to the
    /// watch — the one write both readers see.
    fn publish_rows(&self) {
        let rows = self.mapper.diagnostics();
        self.rows.send_if_modified(|held| {
            let moved = *held != rows;
            if moved {
                held.clone_from(&rows);
            }
            moved
        });
        self.diagnostics.set_mappings(rows);
    }

    fn observe_server_id(&mut self, now: Instant) {
        let high_id = self.reach.server_high_id();
        self.mapper.on_server_id(high_id, now);
    }

    /// Enact everything the mapper has queued.
    fn drain(&mut self, results: &mpsc::Sender<MappingResult>) {
        while let Some(command) = self.mapper.next_command() {
            self.enact(command, results);
        }
    }

    fn enact(&mut self, command: MappingCommand, results: &mpsc::Sender<MappingResult>) {
        match command {
            MappingCommand::Probe { protocol } => self.probe(protocol, results),
            MappingCommand::Map {
                protocol,
                mapping,
                suggested_external_port,
                lease,
            } => {
                let request = MappingRequest {
                    family: mapping.family,
                    transport: mapping.transport(),
                    internal_port: mapping.internal_port,
                    suggested_external_port,
                    lease,
                };
                let Some((backend, gateway)) = self.route_mapping(protocol, mapping) else {
                    let _ = results.try_send(MappingResult::Mapped {
                        protocol,
                        mapping,
                        outcome: Err(MappingError::Unsupported(protocol)),
                    });
                    return;
                };
                let results = results.clone();
                tokio::spawn(async move {
                    let outcome = backend
                        .map(gateway, request)
                        .await
                        .map(|grant| GrantAnswer {
                            external: grant.external,
                            lease: grant.lease,
                            epoch_reset: grant.epoch.is_reset(),
                        });
                    let _ = results
                        .send(MappingResult::Mapped {
                            protocol,
                            mapping,
                            outcome,
                        })
                        .await;
                });
            }
            MappingCommand::Release {
                protocol,
                mapping,
                external_port,
            } => {
                if let Some((backend, gateway)) = self.route_mapping(protocol, mapping) {
                    let request =
                        release_request(mapping.family, mapping.transport(), mapping.internal_port);
                    tokio::spawn(async move {
                        backend.release(gateway, request, external_port).await;
                    });
                }
            }
            // The one command that does not reach a gateway (ADR-0086's
            // amendment to ADR-0058).
            MappingCommand::RecheckReachability => request_kad_recheck(&self.kad_pump),
        }
    }

    /// Pin one **Punched Path**'s five-tuple with PCP `PEER` (ADR-0091).
    ///
    /// Outside the mapper entirely: the pin holds a mapping the *punch*
    /// created, not one the **Desired Mapping Set** asked for, so there is no
    /// lease to renew and no trial to judge — asking once and reading the
    /// answer is the whole interaction. NAT-PMP and UPnP cannot express a
    /// remote peer at all, so no PCP route means no pin, and the path's 60 s
    /// keepalive carries it exactly as it does when a router refuses.
    fn pin_peer(&self, request: rmule_net::portmap::PeerPinRequest) {
        let Some((backend, gateway)) = self.route(MappingProtocol::Pcp, AddressFamily::V4) else {
            tracing::debug!(
                ?request,
                "no PCP route for a punched-path pin; its keepalive carries it"
            );
            return;
        };
        tokio::spawn(async move {
            match backend.pin_peer(gateway, request).await {
                Ok(grant) => tracing::info!(
                    external = %grant.external,
                    remote = %request.remote,
                    "punched path pinned with PCP PEER"
                ),
                Err(error) => tracing::debug!(
                    %error,
                    remote = %request.remote,
                    "punched-path pin refused; its keepalive carries it"
                ),
            }
        });
    }

    /// Ask one protocol, on every gateway it could speak to, and merge the
    /// answers into the one report the mapper expects.
    fn probe(&mut self, protocol: MappingProtocol, results: &mpsc::Sender<MappingResult>) {
        self.routes = self.gateways.gateways();
        let Some(backend) = self.backend(protocol) else {
            let _ = results.try_send(MappingResult::Probed {
                protocol,
                outcome: Err(MappingError::Unsupported(protocol)),
            });
            return;
        };
        let reachable: Vec<Gateway> = self
            .routes
            .iter()
            .copied()
            .filter(|gateway| protocol.supports(gateway.family()))
            .collect();
        let results = results.clone();
        tokio::spawn(async move {
            let mut families = Vec::new();
            let mut epoch_reset = false;
            let mut refusal = None;
            for gateway in reachable {
                let call = Arc::clone(&backend).probe(gateway);
                let answered = tokio::time::timeout(BACKEND_DEADLINE, call)
                    .await
                    .unwrap_or(Err(MappingError::Timeout(protocol)));
                match answered {
                    Ok(report) => {
                        epoch_reset |= report.epoch.is_reset();
                        for family in report.families {
                            if !families.contains(&family) {
                                families.push(family);
                            }
                        }
                    }
                    Err(error) => refusal = Some(error),
                }
            }
            let outcome = if families.is_empty() {
                Err(refusal.unwrap_or(MappingError::Unsupported(protocol)))
            } else {
                Ok(ProbeAnswer {
                    families,
                    epoch_reset,
                })
            };
            let _ = results
                .send(MappingResult::Probed { protocol, outcome })
                .await;
        });
    }

    /// Withdraw every mapping still held, within a courtesy budget.
    async fn release_on_exit(&mut self) {
        self.mapper.shutdown();
        let mut pending = Vec::new();
        while let Some(command) = self.mapper.next_command() {
            if let MappingCommand::Release {
                protocol,
                mapping,
                external_port,
            } = command
                && let Some((backend, gateway)) = self.route_mapping(protocol, mapping)
            {
                let request =
                    release_request(mapping.family, mapping.transport(), mapping.internal_port);
                pending.push(async move {
                    backend.release(gateway, request, external_port).await;
                });
            }
        }
        // Awaited rather than spawned: the task is ending, and a spawned
        // release would be cancelled before its datagram left.
        let _ = tokio::time::timeout(RELEASE_BUDGET, async {
            for release in pending {
                release.await;
            }
        })
        .await;
    }

    /// The backend speaking `protocol`, if one is installed.
    fn backend(&self, protocol: MappingProtocol) -> Option<Arc<dyn MappingBackend>> {
        self.backends
            .iter()
            .find(|backend| backend.protocol() == protocol)
            .map(Arc::clone)
    }

    /// The backend and the gateway one mapping needs, spoken to from the
    /// address the mapping is for.
    ///
    /// An IPv6 row names its pinhole — the Known IPv6 it was derived under —
    /// and the PCP request must leave from exactly that address (RFC 6887 §8.2):
    /// the route table's own pick is merely *an* address of the
    /// interface, which may be another privacy address than the one the hello
    /// advertises.
    fn route_mapping(
        &self,
        protocol: MappingProtocol,
        mapping: DesiredMapping,
    ) -> Option<(Arc<dyn MappingBackend>, Gateway)> {
        let (backend, mut gateway) = self.route(protocol, mapping.family)?;
        if let Some(pinhole) = mapping.pinhole {
            gateway.local_address = std::net::IpAddr::V6(pinhole);
        }
        Some((backend, gateway))
    }

    /// The backend and the gateway one request in `family` needs.
    fn route(
        &self,
        protocol: MappingProtocol,
        family: AddressFamily,
    ) -> Option<(Arc<dyn MappingBackend>, Gateway)> {
        if !protocol.supports(family) {
            return None;
        }
        let gateway = self
            .routes
            .iter()
            .copied()
            .find(|gateway| gateway.family() == family)?;
        self.backend(protocol).map(|backend| (backend, gateway))
    }
}

/// The request shape a release names. A withdrawal identifies the mapping by
/// its family, transport and internal port; the external port rides beside it,
/// so the suggested port and lease are immaterial and stated as such — a
/// zero lease is what both UDP protocols' delete already means on the wire.
const fn release_request(
    family: AddressFamily,
    transport: MappedTransport,
    internal_port: u16,
) -> MappingRequest {
    MappingRequest {
        family,
        transport,
        internal_port,
        suggested_external_port: internal_port,
        lease: Duration::ZERO,
    }
}

/// The learned method over the one open **Durable Store** the core runs on —
/// the same handle the managed server list is a view of, so a restart reads
/// back what the last run learned with no second file and no app plumbing.
///
/// A failed read or write is a storage fault, not a caller mistake: it costs
/// one extra full race next run and is traced, never propagated.
#[derive(Debug)]
pub(crate) struct DurablePortMappingPreferences(
    pub(crate) Arc<crate::store::app_config::DurableAppConfig>,
);

impl PortMappingPreferences for DurablePortMappingPreferences {
    fn learned_method(&self) -> Option<MappingProtocol> {
        use crate::app_config::{AppConfigStore, Preference};
        self.0
            .preference(Preference::PortMapMethod)
            .ok()
            .flatten()
            .as_deref()
            .and_then(MappingProtocol::from_persisted_name)
    }

    fn set_learned_method(&self, method: MappingProtocol) {
        use crate::app_config::Preference;
        if let Err(error) = self
            .0
            .set_preference(Preference::PortMapMethod, method.persisted_name())
        {
            tracing::warn!(%error, %method, "could not persist the learned port-mapping method");
        }
    }
}

/// Sleep until `wake`, or forever when the mapper has no scheduled work — its
/// state then changes only on a result or a control.
async fn sleep_until(wake: Option<Instant>) {
    match wake {
        Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
        None => std::future::pending::<()>().await,
    }
}

#[cfg(test)]
mod tests;
