//! **Connecting is the operator's act** (ADR-0095),
//! through a live core over a Fake eD2k Server whose login runs the
//! real High-ID port check.
//!
//! The manual restart that found it: two downloads left running, restored at
//! attach, and the first one's source lookup logged in to its stored server in
//! the same millisecond — no listener, nothing mapped, a Low ID. Here the
//! stored server is reachable on purpose, so a lazy login would succeed and be
//! seen; none may happen until the operator connects, and the connect lands
//! behind the listener attach already bound and the mapping it already made.

use rmule_testkit::HANG_GUARD;
use std::sync::Arc;
use std::time::Duration;

use rmule_core::port_mapping::MappingStatus;
use rmule_core::{
    Core, CoreConfig, CoreEvent, DownloadEvent, DownloadId, DownloadLifecycle, DownloadPaths,
    DownloadRepository, DurableDownloadRepository, ServeEvent, ServerConnectionEvent, SocketRole,
    open_durable_store,
};
use rmule_net::portmap::MappingProtocol;
use rmule_primitives::{ClientId, ED2K_PART_SIZE, PeerSource};
use rmule_testkit::{
    FakeEd2kServer, FakeGateways, PendingPeerTransfer, ScriptedBackend, file_link,
};
use tokio::time::timeout;

use crate::fixture::{free_port, next_expected};

/// Two downloads the last process left running, both naming `server`.
fn two_running_downloads(
    repo: &DurableDownloadRepository,
    dir: &std::path::Path,
    server: &rmule_primitives::ServerEndpoint,
) -> [DownloadId; 2] {
    ["first.bin", "second.bin"].map(|name| {
        let mut bytes = vec![name.len() as u8; ED2K_PART_SIZE as usize];
        bytes.push(0x4B);
        let record = repo
            .create_download(
                &file_link(name, &bytes),
                Some(server),
                &DownloadPaths::from_final_path(dir.join(name)),
                None,
            )
            .unwrap();
        repo.set_lifecycle(record.id(), DownloadLifecycle::Active)
            .unwrap();
        record.id()
    })
}

#[tokio::test]
async fn attach_listens_and_waits_and_only_the_operators_connect_logs_in() {
    let server = FakeEd2kServer::start_scripted().await;
    server
        .set_sources(vec![PeerSource::new(ClientId::from_u32(0x0100_007F), 4663)])
        .await;
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    let ids = two_running_downloads(&repo, dir.path(), &server.endpoint());
    let port = free_port().await;
    let upnp = Arc::new(ScriptedBackend::available(MappingProtocol::Upnp));

    let mut core = Core::builder(
        CoreConfig {
            download_restore_pace: Duration::from_millis(10),
            ..CoreConfig::default()
        },
        Arc::clone(&store),
    )
    .settings(crate::fixture::settings_on(port))
    .gateway_source(FakeGateways::home_lan())
    .mapping_backends(vec![upnp])
    .peer_transfer(PendingPeerTransfer)
    .restore_at_attach()
    .build();

    // The listener is up from attach, on the settings' port.
    let mut waiting = Vec::new();
    let mut listening = None;
    timeout(HANG_GUARD, async {
        while listening.is_none() || waiting.len() < 2 {
            match core.next_event().await.expect("core is alive") {
                CoreEvent::Serve(ServeEvent::ServingStarted { listen_addr }) => {
                    listening = Some(listen_addr);
                }
                CoreEvent::Download(DownloadEvent::WaitingForConnection { download_id }) => {
                    waiting.push(download_id);
                }
                CoreEvent::ServerConnection(edge) => {
                    panic!("nothing may dial before the operator connects: {edge:?}")
                }
                CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                    panic!("a restored download with no session waits: {reason:?}")
                }
                _ => {}
            }
        }
    })
    .await
    .expect("the listener bound and both downloads say they wait");
    assert_eq!(listening.map(|addr| addr.port()), Some(port));
    waiting.sort();
    assert_eq!(waiting, ids.to_vec(), "both restored downloads wait");

    // The mapping for the attach listener settles with nobody logged in.
    timeout(HANG_GUARD, async {
        loop {
            let mapped = core.diagnostics_snapshot().mappings.into_iter().any(|row| {
                row.mapping.role == SocketRole::Tcp
                    && row.mapping.internal_port == port
                    && row.status == MappingStatus::Mapped
            });
            if mapped {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the listener's TCP row is mapped at attach");
    assert!(
        server.assigned_ids().await.is_empty(),
        "a reachable stored server was never dialed behind the operator's back"
    );

    // The operator's word: one login, High ID, both downloads start on it.
    rmule_testkit::connect_to(&core, &server.endpoint()).await;
    next_expected(&mut core, "the operator's connect", |event| {
        matches!(
            event,
            CoreEvent::ServerConnection(ServerConnectionEvent::Connected { .. })
        )
    })
    .await;
    let logins = server.assigned_ids().await;
    assert_eq!(logins.len(), 1, "the operator's login is the only one");
    assert!(
        logins[0].is_high_id(),
        "the attach listener answered the port check"
    );
    let mut found = Vec::new();
    timeout(HANG_GUARD, async {
        while found.len() < 2 {
            if let CoreEvent::Download(DownloadEvent::SourcesFound { download_id, .. }) =
                core.next_event().await.expect("core is alive")
            {
                found.push(download_id);
            }
        }
    })
    .await
    .expect("both waiting downloads asked on the operator's session");
    found.sort();
    assert_eq!(found, ids.to_vec());
}
