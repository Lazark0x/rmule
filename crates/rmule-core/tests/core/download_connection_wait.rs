//! A download with no connection waits for one (ADR-0093, "Waiting for a
//! connection"): restored at attach, its server unreachable and Kad off, it
//! does not fail — it says it is waiting, and it starts on its own once the
//! operator connects to a server.

use std::sync::Arc;
use std::time::Duration;

use rmule_core::{
    Core, CoreCommand, CoreCommandRejectReason, CoreConfig, CoreEvent, DownloadCommand,
    DownloadEvent, DownloadLifecycle, DownloadPaths, DownloadRepository, DurableDownloadRepository,
    ManagedServer, ServerConnectionEvent, ServerListCommand, SourceWait, open_durable_store,
};
use rmule_primitives::{ClientId, ED2K_PART_SIZE, PeerSource, ServerEndpoint};
use rmule_testkit::{FakeEd2kServer, PendingPeerTransfer, file_link};

use crate::fixture::{dead_port, next_expected};

#[tokio::test]
async fn a_restored_download_with_no_connection_waits_then_starts_when_one_comes_up() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    let mut bytes = vec![0x4B; ED2K_PART_SIZE as usize];
    bytes.push(0x4B);
    let link = file_link("waiting.bin", &bytes);
    let record = repo
        .create_download(
            &link,
            Some(&ServerEndpoint::new("127.0.0.1", dead_port().await).unwrap()),
            &DownloadPaths::from_final_path(dir.path().join("waiting.bin")),
            None,
        )
        .unwrap();
    repo.set_lifecycle(record.id(), DownloadLifecycle::Active)
        .unwrap();
    let id = record.id();

    let mut core = Core::builder(
        CoreConfig {
            download_restore_pace: Duration::from_millis(10),
            ..CoreConfig::default()
        },
        Arc::clone(&store),
    )
    .settings(crate::fixture::attach_settings().await)
    .peer_transfer(PendingPeerTransfer)
    .restore_at_attach()
    .build();

    let waiting = next_expected(&mut core, "the download waiting, not failed", |event| {
        matches!(
            event,
            CoreEvent::Download(
                DownloadEvent::WaitingForConnection { .. } | DownloadEvent::DownloadFailed { .. }
            )
        )
    })
    .await;
    assert!(
        matches!(waiting, CoreEvent::Download(DownloadEvent::WaitingForConnection { download_id }) if download_id == id),
        "{waiting:?}"
    );
    assert_eq!(
        repo.load_download(id).unwrap().lifecycle(),
        DownloadLifecycle::Active,
        "still the operator's running download"
    );

    // The operator connects by hand; nothing is sent about the download.
    let server = FakeEd2kServer::start_scripted().await;
    server
        .set_sources(vec![PeerSource::new(ClientId::from_u32(0x0100_007F), 4663)])
        .await;
    core.send(CoreCommand::ServerList(ServerListCommand::AddServer {
        server: ManagedServer::listed(server.endpoint()),
    }))
    .await
    .unwrap();
    core.send(CoreCommand::ConnectToServer {
        server: server.endpoint(),
    })
    .await
    .unwrap();
    next_expected(&mut core, "the connect", |event| {
        matches!(
            event,
            CoreEvent::ServerConnection(ServerConnectionEvent::Connected { .. })
        )
    })
    .await;
    let found = next_expected(&mut core, "the waiting download asking again", |event| {
        matches!(
            event,
            CoreEvent::Download(
                DownloadEvent::SourcesFound { .. } | DownloadEvent::DownloadFailed { .. }
            )
        )
    })
    .await;
    assert!(
        matches!(
            found,
            CoreEvent::Download(DownloadEvent::SourcesFound {
                download_id,
                usable_high_id: 1,
                ..
            }) if download_id == id
        ),
        "{found:?}"
    );
    next_expected(&mut core, "a part assigned", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::PartAssigned { download_id, .. }) if *download_id == id
        )
    })
    .await;
}

/// A paused run's finish notice is already queued when a resume of the same
/// download is taken first: the late notice must not retire the new run.
/// The actor picks between a command and a notice at random, so the pause
/// and resume go back to back many times; each resumed run must still be
/// there for the next pause.
#[tokio::test]
async fn a_late_finish_notice_never_retires_the_run_a_resume_started() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    let mut bytes = vec![0x4C; ED2K_PART_SIZE as usize];
    bytes.push(0x4C);
    let link = file_link("resumed.bin", &bytes);
    let id = repo
        .create_download(
            &link,
            Some(&ServerEndpoint::new("127.0.0.1", dead_port().await).unwrap()),
            &DownloadPaths::from_final_path(dir.path().join("resumed.bin")),
            None,
        )
        .unwrap()
        .id();
    repo.set_lifecycle(id, DownloadLifecycle::Active).unwrap();
    let mut core = Core::builder(
        CoreConfig {
            download_restore_pace: Duration::from_millis(10),
            ..CoreConfig::default()
        },
        Arc::clone(&store),
    )
    .settings(crate::fixture::attach_settings().await)
    .peer_transfer(PendingPeerTransfer)
    .restore_at_attach()
    .build();
    next_expected(&mut core, "the restored run waiting", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::WaitingForConnection { .. })
        )
    })
    .await;

    for round in 0..16 {
        core.send(CoreCommand::Download(DownloadCommand::PauseDownload {
            download_id: id,
        }))
        .await
        .unwrap();
        core.send(CoreCommand::Download(DownloadCommand::ResumeDownload {
            download_id: id,
        }))
        .await
        .unwrap();
        next_expected(&mut core, "the resume", |event| {
            matches!(
                event,
                CoreEvent::Download(DownloadEvent::DownloadResumed { .. })
            )
        })
        .await;
        // Time for a queued finish notice to be taken.
        tokio::time::sleep(Duration::from_millis(30)).await;
        core.send(CoreCommand::Download(DownloadCommand::PauseDownload {
            download_id: id,
        }))
        .await
        .unwrap();
        let answer = next_expected(&mut core, "the pause's answer", |event| {
            matches!(
                event,
                CoreEvent::Download(DownloadEvent::DownloadPaused { .. })
                    | CoreEvent::CommandRejected {
                        reason: CoreCommandRejectReason::UnknownDownload
                    }
            )
        })
        .await;
        assert!(
            matches!(
                answer,
                CoreEvent::Download(DownloadEvent::DownloadPaused { .. })
            ),
            "round {round}: the resumed run was retired by the paused run's notice: {answer:?}"
        );
        core.send(CoreCommand::Download(DownloadCommand::ResumeDownload {
            download_id: id,
        }))
        .await
        .unwrap();
        next_expected(&mut core, "the run back", |event| {
            matches!(
                event,
                CoreEvent::Download(DownloadEvent::DownloadResumed { .. })
            )
        })
        .await;
    }
}

/// A download waiting for sources says who can still find it one, and says it
/// again as that moves (ADR-0051's amendment): the global sweep asks only
/// while a server session is up, so the session ending leaves it waiting on
/// a session — or on Kad, once Kad starts.
#[tokio::test]
async fn a_waiting_downloads_reason_follows_the_session_and_kad() {
    let dir = tempfile::tempdir().unwrap();
    let server = FakeEd2kServer::start_scripted().await;
    let mut core = rmule_core::Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            dir.path(),
        ))
        .peer_transfer(PendingPeerTransfer)
        .kad(crate::fixture::StubKad::new())
        .build();
    // A second server for the sweep to ask: the swept list leaves out the
    // connected one.
    let swept = ServerEndpoint::new("127.0.0.1", dead_port().await).unwrap();
    crate::fixture::list_server(&core, &swept).await;
    rmule_testkit::connect_to(&core, &server.endpoint()).await;
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: crate::fixture::stub_link("reason.bin", 1024, 0x5B),
        source_hint: Some(server.endpoint()),
        name: rmule_testkit::file_name("reason.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
        kad_aich_root: None,
    }))
    .await
    .unwrap();
    waits_for(
        &mut core,
        "asking while the session is up",
        SourceWait::Asking,
    )
    .await;

    core.send(CoreCommand::DisconnectFromServer).await.unwrap();
    waits_for(&mut core, "no session, Kad off", SourceWait::NoSession).await;

    core.send(CoreCommand::EnableKad(crate::fixture::kad_enable_config()))
        .await
        .unwrap();
    waits_for(&mut core, "Kad asking alone", SourceWait::KadAlone).await;
}

/// Pump events until a download says it waits for sources for `want`.
async fn waits_for(core: &mut rmule_core::Core, step: &str, want: SourceWait) {
    next_expected(core, step, |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::WaitingForSources { reason, .. }) if *reason == want
        )
    })
    .await;
}
