//! ADR-0093 through a live core: the serve activity's stop returns the
//! listener's mapping lease, a stale serve-end bump never retires the
//! activity started after it, and quit stops everything — the listener
//! closed and every mapping released — before `Core::shutdown` returns.

use rmule_testkit::HANG_GUARD;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;

use rmule_core::port_mapping::MappingStatus;
use rmule_core::{Core, CoreCommand, CoreConfig, CoreEvent, ServeCommand, ServeEvent, SocketRole};
use rmule_net::portmap::{MappedTransport, MappingProtocol};
use rmule_testkit::{FakeGateways, ScriptedBackend};
use tokio::time::{Duration, timeout};

use crate::fixture::next_expected;

fn mapped_core(pcp: &Arc<ScriptedBackend>) -> Core {
    Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .gateway_source(FakeGateways::home_lan())
        .mapping_backends(vec![pcp.clone()])
        .build()
}

async fn start_serving(core: &mut Core) -> SocketAddrV4 {
    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
    }))
    .await
    .expect("serve accepted");
    match next_expected(core, "ServingStarted", |event| {
        matches!(event, CoreEvent::Serve(ServeEvent::ServingStarted { .. }))
    })
    .await
    {
        CoreEvent::Serve(ServeEvent::ServingStarted { listen_addr }) => listen_addr,
        other => unreachable!("filtered for ServingStarted: {other:?}"),
    }
}

async fn mapped_row(core: &Core, role: SocketRole, wanted: bool) {
    timeout(HANG_GUARD, async {
        loop {
            let mapped = core
                .diagnostics_snapshot()
                .mappings
                .iter()
                .any(|row| row.mapping.role == role && row.status == MappingStatus::Mapped);
            if mapped == wanted {
                return;
            }
            // A polled level with no change notification.
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the mapping row settled");
}

fn released_tcp(pcp: &ScriptedBackend) -> usize {
    pcp.released()
        .into_iter()
        .filter(|(request, _)| request.transport == MappedTransport::Tcp)
        .count()
}

/// The serve stop returns what the start took: the listener's bind leaves
/// Address Learning, so its Desired Mapping Set row departs and the lease is
/// handed back at once — not renewed for a port nothing listens on.
#[tokio::test]
async fn stopping_serve_releases_the_listener_mapping() {
    let pcp = Arc::new(ScriptedBackend::available(MappingProtocol::Pcp));
    let mut core = mapped_core(&pcp);
    start_serving(&mut core).await;
    mapped_row(&core, SocketRole::Tcp, true).await;

    core.send(CoreCommand::Serve(ServeCommand::StopServing))
        .await
        .expect("stop accepted");
    next_expected(&mut core, "ServingStopped", |event| {
        matches!(event, CoreEvent::Serve(ServeEvent::ServingStopped { .. }))
    })
    .await;
    mapped_row(&core, SocketRole::Tcp, false).await;
    assert_eq!(
        released_tcp(&pcp),
        1,
        "the vacated listener's lease was released"
    );
}

/// A serve task's end bumps the watch with its own generation, so the bump a
/// requested stop leaves behind can never retire the activity a following
/// `StartServing` began — which, awaited, would park the actor on a live
/// listener. Stop and start back to back, several times: the actor must keep
/// answering.
#[tokio::test]
async fn a_stale_serve_end_never_retires_the_next_activity() {
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();
    start_serving(&mut core).await;
    for _ in 0..6 {
        core.send(CoreCommand::Serve(ServeCommand::StopServing))
            .await
            .expect("stop accepted");
        start_serving(&mut core).await;
        for _ in 0..4 {
            core.send(CoreCommand::DumpDiagnostics)
                .await
                .expect("core alive");
            next_expected(&mut core, "the actor still answers", |event| {
                matches!(event, CoreEvent::DiagnosticsSnapshot { .. })
            })
            .await;
        }
    }
}

/// Quit is every stop: with serving running, `Core::shutdown` returns only
/// after the listener has closed (its port binds again at once) and the
/// mapping runtime's release pass has handed back both leases.
#[tokio::test]
async fn shutdown_stops_serving_and_releases_every_mapping_before_it_returns() {
    let pcp = Arc::new(ScriptedBackend::available(MappingProtocol::Pcp));
    let mut core = mapped_core(&pcp);
    let listen = start_serving(&mut core).await;
    mapped_row(&core, SocketRole::Tcp, true).await;
    mapped_row(&core, SocketRole::Udp, true).await;

    core.shutdown().await;

    let released = pcp.released();
    assert!(
        released
            .iter()
            .any(|(request, _)| request.transport == MappedTransport::Tcp),
        "the listener's lease was released before shutdown returned: {released:?}"
    );
    assert!(
        released
            .iter()
            .any(|(request, _)| request.transport == MappedTransport::Udp),
        "the client-UDP lease was released before shutdown returned: {released:?}"
    );
    std::net::TcpListener::bind(listen).expect("the listener's port is free again");
}
