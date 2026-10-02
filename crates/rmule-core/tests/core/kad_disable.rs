//! `on_enable_kad` spawns the discovery pump, the `KadPublisher`
//! and the ed2k→Kad handoff forwarder as independent tasks that used to
//! unwind only by `Arc<RuntimeKadChannel>` refcount — harmless for a CLI that
//! exits, a leak per stop for a long-lived front end, since there was no
//! `CoreCommand::DisableKad` to reach for. This leg drives a real Kad
//! activity (the production `RuntimeKadFactory`, so the Kad Shutdown Lever is
//! genuinely wired into the pump's own select loop) through a full
//! enable → disable → enable round trip and watches `kad_tasks_live` —
//! [`DiagnosticsSnapshot`]'s count of tasks the actor still holds a
//! `JoinHandle` for — go 3 → 0 → 3, proving no task from the first activity
//! survives the stop.

use std::time::Duration;

use rmule_core::diagnostics::DiagnosticsSnapshot;
use rmule_core::{Core, CoreCommand, CoreConfig, CoreEvent, KadEnableConfig, KadId, KadStopReason};
use tokio::time::timeout;

use crate::fixture::identity;

fn reserve_tcp_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

async fn until(core: &mut Core, wanted: impl Fn(&CoreEvent) -> bool) -> CoreEvent {
    loop {
        let event = timeout(Duration::from_secs(10), core.next_event())
            .await
            .expect("core emitted the awaited event within 10s")
            .expect("core event stream stayed open");
        if wanted(&event) {
            return event;
        }
    }
}

async fn diagnostics(core: &mut Core) -> DiagnosticsSnapshot {
    core.send(CoreCommand::DumpDiagnostics).await.unwrap();
    match until(core, |event| {
        matches!(event, CoreEvent::DiagnosticsSnapshot { .. })
    })
    .await
    {
        CoreEvent::DiagnosticsSnapshot { snapshot } => snapshot,
        _ => unreachable!("filtered above"),
    }
}

async fn kad_stopped_reason(core: &mut Core) -> KadStopReason {
    match until(core, |event| matches!(event, CoreEvent::KadStopped { .. })).await {
        CoreEvent::KadStopped { reason } => reason,
        _ => unreachable!("filtered above"),
    }
}

fn kad_config(kad_id: [u8; 16], tcp_port: u16) -> KadEnableConfig {
    KadEnableConfig {
        kad_id: KadId::from_bytes(kad_id),
        peer_credentials: rmule_core::ClientCredentials::new(
            identity().nickname().clone(),
            tcp_port,
            identity().protocol_version(),
        ),
        bootstrap: Vec::new(),
        contacts: Vec::new(),
        nodes_dat_path: None,
        assume_open_reachability: true,
        kad_udp_key: 0,
        kad_capture_dir: None,
        // Left empty: this activity installs its own lever.
        kad_shutdown: None,
    }
}

#[tokio::test]
async fn disable_kad_joins_every_task_and_a_later_enable_restarts_clean() {
    let tcp = reserve_tcp_port();
    let mut core = Core::new(CoreConfig::default(), rmule_testkit::memory_store());

    core.send(CoreCommand::EnableKad(kad_config([0x11; 16], tcp)))
        .await
        .unwrap();
    let up = diagnostics(&mut core).await;
    assert!(
        up.kad.is_some(),
        "the first activity reports a running node"
    );
    assert_eq!(up.kad_state, rmule_core::diagnostics::KadState::Running);
    assert_eq!(
        up.kad_tasks_live, 3,
        "the pump, the publisher and the handoff forwarder are all tracked"
    );

    core.send(CoreCommand::DisableKad).await.unwrap();
    assert_eq!(
        kad_stopped_reason(&mut core).await,
        KadStopReason::Stopped,
        "the operator's lever-confirmed stop reads as theirs, not a forced TaskFailed"
    );

    let down = diagnostics(&mut core).await;
    assert!(down.kad.is_none(), "the node is gone after DisableKad");
    assert_eq!(down.kad_state, rmule_core::diagnostics::KadState::Off);
    assert_eq!(
        down.kad_tasks_live, 0,
        "no task from the first activity survives DisableKad"
    );

    // A later EnableKad starts a second activity clean: a fresh node id,
    // and every one of the three tasks tracked again — nothing left over
    // from the first activity to collide with or crowd out.
    core.send(CoreCommand::EnableKad(kad_config([0x22; 16], tcp)))
        .await
        .unwrap();
    let restarted = diagnostics(&mut core).await;
    assert_eq!(
        restarted.kad.map(|kad| kad.node_id),
        Some(KadId::from_bytes([0x22; 16])),
        "the restart's own id is the one now running"
    );
    assert_eq!(restarted.kad_tasks_live, 3);

    core.shutdown().await;
}

#[tokio::test]
async fn disable_kad_before_any_enable_is_a_no_op() {
    let mut core = Core::new(CoreConfig::default(), rmule_testkit::memory_store());
    core.send(CoreCommand::DisableKad).await.unwrap();

    // Nothing to observe from a no-op: prove it by getting a diagnostics
    // round trip back at all — a wedged actor would never answer.
    let snapshot = diagnostics(&mut core).await;
    assert!(snapshot.kad.is_none());
    assert_eq!(snapshot.kad_tasks_live, 0);

    core.shutdown().await;
}
