//! The Kad Activity (ADR-0093): Kad Presence, the published
//! verdicts and the ledger's own diagnostics row are one lease, so a pump
//! death flips every reader together; and the activity's stop is the one
//! lever, which a caller's own lever calls.

use rmule_kad::KadId;
use rmule_primitives::{FileHash, SourceLookupTarget};
use tokio::sync::{Mutex, oneshot};
use tokio::time::Duration;

use crate::adapters::{
    ClientUdpBind, KadEnableConfig, KadPresenceView, KadRuntimeFactory, KadShutdownSlot,
    KadSourceChannel,
};
use crate::kad_sources::KadAnswer;
use crate::reachability::{KadVerdicts, SharedKadVerdicts, TcpReachability};
use crate::{
    Core, CoreCommand, CoreCommandRejectReason, CoreConfig, CoreError, CoreEvent, KadStopReason,
    KadUnavailableReason, ServeEvent,
};

/// A channel whose `next_sources` ends — the deep node's death, as the
/// discovery task sees it — once the test fires `kill`. Cancel-safe, as the
/// seam requires: the receiver stays in its slot across a cancelled wait, so
/// a discovery sweep never reads as the node's death.
struct KillableChannel(Mutex<Option<oneshot::Receiver<()>>>);

impl KadSourceChannel for KillableChannel {
    async fn search_sources(&self, _target: SourceLookupTarget) {}

    async fn publish_source(&self, _target: SourceLookupTarget) {}

    async fn next_sources(&self) -> Option<(FileHash, KadAnswer)> {
        let mut slot = self.0.lock().await;
        if let Some(killed) = slot.as_mut() {
            let _ = killed.await;
            *slot = None;
        }
        None
    }
}

/// A runtime with no node underneath: the Presence and verdicts cells the
/// Kad Activity leases are the core's own, lent to `start`.
struct PublishingKad {
    killed: Option<oneshot::Receiver<()>>,
}

impl KadRuntimeFactory for PublishingKad {
    type Channel = KillableChannel;

    async fn start(
        &mut self,
        _config: &KadEnableConfig,
        _node: &crate::KadNodeIdentity,
        _bind: ClientUdpBind,
        _cells: &crate::KadCells,
    ) -> Result<KillableChannel, CoreError> {
        Ok(KillableChannel(Mutex::new(self.killed.take())))
    }
}

fn enable_config() -> KadEnableConfig {
    KadEnableConfig {
        bootstrap: Vec::new(),
        contacts: Vec::new(),
        nodes_dat_path: None,
        assume_open_reachability: false,
        kad_capture_dir: None,
        kad_shutdown: None,
    }
}

async fn next_matching(core: &mut Core, want: impl Fn(&CoreEvent) -> bool) -> CoreEvent {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let event = core.next_event().await.expect("core alive");
            if want(&event) {
                return event;
            }
        }
    })
    .await
    .expect("the expected event arrived")
}

/// What each reader says about Kad: Presence (the serve bridge's and the
/// firewalled front's `0x99` gate, and Self Reach's `kad_running` every
/// download and route reads), the published TCP verdict, and the ledger's
/// diagnostics row.
async fn readings(
    core: &mut Core,
    presence: &KadPresenceView,
    verdicts: &SharedKadVerdicts,
) -> (bool, bool, bool) {
    core.send(CoreCommand::DumpDiagnostics)
        .await
        .expect("core alive");
    let CoreEvent::DiagnosticsSnapshot { snapshot } = next_matching(core, |event| {
        matches!(event, CoreEvent::DiagnosticsSnapshot { .. })
    })
    .await
    else {
        unreachable!("filtered for DiagnosticsSnapshot")
    };
    assert_eq!(
        snapshot.kad,
        core.diagnostics_snapshot().kad,
        "the sync accessor and the echo return the same value (ADR-0028)"
    );
    (
        presence.running_as().is_some(),
        verdicts.get().tcp.is_reachable(),
        snapshot.kad.is_some(),
    )
}

/// The discovery sweep cadence the liveness test runs under.
const SWEEP: Duration = Duration::from_millis(10);

#[tokio::test]
async fn a_pump_death_flips_every_kad_liveness_reader_together() {
    let (kill, killed) = oneshot::channel();
    // Discovery races `next_sources` against its sweep tick, so a live node's
    // pending `next_sources` is cancelled at every sweep: sweep
    // often, so a running node is read only after it has been swept.
    let config = CoreConfig {
        kad_sweep_interval: SWEEP,
        ..CoreConfig::default()
    };
    let builder = Core::builder(config, rmule_testkit::memory_store())
        .settings(crate::CoreSettings::default())
        .kad_id(KadId::from_bytes([0x5A; KadId::BYTE_LEN]))
        .kad(PublishingKad {
            killed: Some(killed),
        });
    let (presence, verdicts) = (
        builder.kad_cells().presence.clone(),
        builder.kad_cells().verdicts.clone(),
    );
    let mut core = builder.build();

    core.send(CoreCommand::EnableKad(enable_config()))
        .await
        .expect("core alive");
    // The node proves itself open, as its self-check would.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while presence.running_as().is_none() {
        assert!(tokio::time::Instant::now() < deadline, "Kad never started");
        tokio::task::yield_now().await;
    }
    tokio::time::sleep(SWEEP * 5).await;
    verdicts.set_tcp(TcpReachability::Open);
    assert_eq!(
        readings(&mut core, &presence, &verdicts).await,
        (true, true, true),
        "a running node: every reader says so"
    );

    drop(kill);
    next_matching(&mut core, |event| {
        matches!(event, CoreEvent::KadStopped { .. })
    })
    .await;
    assert_eq!(
        readings(&mut core, &presence, &verdicts).await,
        (false, false, false),
        "a dead pump: every reader reads the node gone at the one retire"
    );
    assert_eq!(verdicts.get(), KadVerdicts::FRESH, "nothing proven");
}

/// A channel that honours the lever wired into its pump the way
/// `RuntimeKadFactory`'s does: on a stop request it confirms and ends. The
/// lever stays in its slot across a cancelled wait (the seam's cancel-safety),
/// so only a stop request ends the pump.
struct LeveredChannel(Mutex<Option<(oneshot::Receiver<()>, oneshot::Sender<()>)>>);

impl KadSourceChannel for LeveredChannel {
    async fn search_sources(&self, _target: SourceLookupTarget) {}

    async fn publish_source(&self, _target: SourceLookupTarget) {}

    async fn next_sources(&self) -> Option<(FileHash, KadAnswer)> {
        let mut slot = self.0.lock().await;
        if let Some((stop, _)) = slot.as_mut() {
            let _ = stop.await;
            if let Some((_, stopped)) = slot.take() {
                let _ = stopped.send(());
            }
        }
        None
    }
}

/// A runtime whose pump takes the lever the activity wired into its config.
struct LeveredKad;

impl KadRuntimeFactory for LeveredKad {
    type Channel = LeveredChannel;

    async fn start(
        &mut self,
        config: &KadEnableConfig,
        _node: &crate::KadNodeIdentity,
        _bind: ClientUdpBind,
        _cells: &crate::KadCells,
    ) -> Result<LeveredChannel, CoreError> {
        let lever = config.kad_shutdown.as_ref().and_then(KadShutdownSlot::take);
        Ok(LeveredChannel(Mutex::new(lever)))
    }
}

/// A caller installed its own lever (the `ed2k serve start --kad` tap-finalize path): `DisableKad`
/// still stops the node through the activity's one lever — a clean stop, not
/// an abort — and the caller's lever reads that stop as its own confirmation.
#[tokio::test]
async fn disable_kad_stops_a_node_whose_caller_holds_its_own_lever() {
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(crate::CoreSettings::default())
        .kad_id(KadId::from_bytes([0x5B; KadId::BYTE_LEN]))
        .kad(LeveredKad)
        .build();
    let (slot, external) = KadShutdownSlot::new();
    let mut config = enable_config();
    config.kad_shutdown = Some(slot);
    core.send(CoreCommand::EnableKad(config))
        .await
        .expect("core alive");
    core.send(CoreCommand::DisableKad)
        .await
        .expect("core alive");

    let CoreEvent::KadStopped { reason } = next_matching(&mut core, |event| {
        matches!(event, CoreEvent::KadStopped { .. })
    })
    .await
    else {
        unreachable!("filtered for KadStopped")
    };
    assert_eq!(
        reason,
        KadStopReason::Stopped,
        "a clean stop through the lever"
    );
    assert!(
        external.request_and_wait(Duration::from_secs(1)).await,
        "the caller's lever is confirmed by the one stop"
    );
}

/// A runtime that keeps the TCP port the node was started to present.
struct PortRecordingKad {
    presented: std::sync::Arc<std::sync::Mutex<Option<u16>>>,
    killed: Option<oneshot::Receiver<()>>,
}

impl KadRuntimeFactory for PortRecordingKad {
    type Channel = KillableChannel;

    async fn start(
        &mut self,
        _config: &KadEnableConfig,
        node: &crate::KadNodeIdentity,
        _bind: ClientUdpBind,
        _cells: &crate::KadCells,
    ) -> Result<KillableChannel, CoreError> {
        *self.presented.lock().unwrap() = Some(node.peer_credentials.tcp_port());
        Ok(KillableChannel(Mutex::new(self.killed.take())))
    }
}

/// The node presents its TCP port in every firewall check and every source
/// it publishes, for its whole life: with an injected port of `0` and no
/// listener up, the start brings the listener up first and presents the
/// port it bound, as a login does.
#[tokio::test]
async fn a_kad_start_with_no_listener_up_listens_first_and_presents_the_bound_port() {
    let presented = std::sync::Arc::default();
    let (_alive, killed) = oneshot::channel();
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(crate::CoreSettings::default())
        .kad_id(KadId::from_bytes([0x5C; KadId::BYTE_LEN]))
        .kad(PortRecordingKad {
            presented: std::sync::Arc::clone(&presented),
            killed: Some(killed),
        })
        .build();

    core.send(CoreCommand::EnableKad(enable_config()))
        .await
        .expect("core alive");
    let CoreEvent::Serve(ServeEvent::ServingStarted { listen_addr }) =
        next_matching(&mut core, |event| {
            matches!(event, CoreEvent::Serve(ServeEvent::ServingStarted { .. }))
        })
        .await
    else {
        unreachable!("filtered for ServingStarted")
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while presented.lock().unwrap().is_none() {
        assert!(tokio::time::Instant::now() < deadline, "Kad never started");
        tokio::task::yield_now().await;
    }
    assert_ne!(listen_addr.port(), 0);
    assert_eq!(*presented.lock().unwrap(), Some(listen_addr.port()));
    core.shutdown().await;
}

/// With an injected port of `0`, a listener that stopped and starts again
/// rebinds the port it first had: a Kad node enabled after the restart
/// presents the same port the first one did, not a fresh OS-assigned one.
#[tokio::test]
async fn a_kad_start_after_a_listener_restart_presents_the_port_the_listener_first_bound() {
    let presented = std::sync::Arc::default();
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(crate::CoreSettings::default())
        .kad_id(KadId::from_bytes([0x5E; KadId::BYTE_LEN]))
        .kad(PortRecordingKad {
            presented: std::sync::Arc::clone(&presented),
            killed: None,
        })
        .build();
    core.send(CoreCommand::EnableKad(enable_config()))
        .await
        .expect("core alive");
    let CoreEvent::Serve(ServeEvent::ServingStarted { listen_addr: first }) =
        next_matching(&mut core, |event| {
            matches!(event, CoreEvent::Serve(ServeEvent::ServingStarted { .. }))
        })
        .await
    else {
        unreachable!("filtered for ServingStarted")
    };

    core.send(CoreCommand::DisableKad)
        .await
        .expect("core alive");
    core.send(CoreCommand::Serve(crate::ServeCommand::StopServing))
        .await
        .expect("core alive");
    *presented.lock().unwrap() = None;
    core.send(CoreCommand::EnableKad(enable_config()))
        .await
        .expect("core alive");
    let CoreEvent::Serve(ServeEvent::ServingStarted {
        listen_addr: second,
    }) = next_matching(&mut core, |event| {
        matches!(event, CoreEvent::Serve(ServeEvent::ServingStarted { .. }))
    })
    .await
    else {
        unreachable!("filtered for ServingStarted")
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while presented.lock().unwrap().is_none() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "Kad never restarted"
        );
        tokio::task::yield_now().await;
    }
    assert_eq!(second.port(), first.port());
    assert_eq!(*presented.lock().unwrap(), Some(first.port()));
    core.shutdown().await;
}

/// A listener that never binds.
struct UnbindableServe;

impl crate::ServeRuntimeService for UnbindableServe {
    async fn start(
        &mut self,
        _identity: rmule_primitives::ClientIdentity,
        _listen_addr: std::net::SocketAddrV4,
    ) -> Result<std::net::SocketAddrV4, CoreError> {
        Err(CoreError::ListenerBind(std::io::ErrorKind::AddrInUse))
    }

    async fn accept(&mut self) -> Option<crate::ServeConnection> {
        None
    }

    async fn announce(
        &mut self,
        files: Vec<rmule_ed2k::OfferedFile>,
    ) -> Result<crate::AnnounceOutcome, CoreError> {
        Ok(crate::AnnounceOutcome::Announced {
            file_count: files.len(),
        })
    }
}

/// With an injected port of `0` and a listener that cannot bind, the node
/// would present port `0` for its whole life: the start is refused with
/// that reason, and no node starts.
#[tokio::test]
async fn a_kad_start_whose_listener_cannot_bind_is_refused_for_want_of_a_tcp_port() {
    let presented = std::sync::Arc::default();
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(crate::CoreSettings::default())
        .serve_runtime(UnbindableServe)
        .kad_id(KadId::from_bytes([0x5D; KadId::BYTE_LEN]))
        .kad(PortRecordingKad {
            presented: std::sync::Arc::clone(&presented),
            killed: None,
        })
        .build();

    core.send(CoreCommand::EnableKad(enable_config()))
        .await
        .expect("core alive");
    let CoreEvent::CommandRejected { reason } = next_matching(&mut core, |event| {
        matches!(event, CoreEvent::CommandRejected { .. })
    })
    .await
    else {
        unreachable!("filtered for CommandRejected")
    };
    assert_eq!(
        reason,
        CoreCommandRejectReason::KadUnavailable(KadUnavailableReason::TcpPortUnbound)
    );
    assert_eq!(*presented.lock().unwrap(), None, "no node started");
    core.shutdown().await;
}
