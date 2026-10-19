//! The legs of a search, and the sources of a download, are independent
//! (ADR-0034 "The legs are independent", ADR-0097): with Kad running
//! and no server session a search goes out over Kad at once and nothing
//! dials a server. Its server leg waits while the operator's Server Intent
//! stands and is sent on the session it brings; with no intent it is not
//! sent, and the search completes on Kad (ADR-0034, "A server leg's states").
//! A download on Kad alone gains the server's sources when the operator
//! connects. A session lost under a sent server leg fails nothing: the
//! leg waits for the reconnect while the intent stands and is sent again, and
//! ends unanswered once no intent stands; the Kad leg and its rows stand
//! either way.

use rmule_testkit::HANG_GUARD;
use std::time::Duration;

use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadEvent, LegNotSent,
    SearchEvent, SearchId, SearchLegState, SearchLegs,
};
use rmule_primitives::{ClientId, ED2K_PART_SIZE, PeerSource, ServerEndpoint};
use rmule_testkit::{FakeEd2kServer, PendingPeerTransfer, file_link};

use crate::fixture::{
    StubKad, kad_enable_config, list_and_connect, next_expected, search_config, search_query,
    search_result, start_search,
};

async fn legs_reach(
    core: &mut Core,
    search_id: SearchId,
    what: &str,
    pred: impl Fn(SearchLegs) -> bool,
) {
    next_expected(core, what, |event| {
        assert!(
            !matches!(
                event,
                CoreEvent::Search(SearchEvent::SearchCompleted { search_id: id, .. }) if *id == search_id
            ),
            "the search completed before {what}"
        );
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchLegsChanged { search_id: id, legs })
                if *id == search_id && pred(*legs)
        )
    })
    .await;
}

/// With Kad alone and no intent, nothing is going to send the server leg: it
/// and its sweep are not sent, and the search completes on the Kad row.
#[tokio::test]
async fn with_kad_alone_and_no_intent_the_server_leg_is_not_sent_and_the_search_completes() {
    let server = FakeEd2kServer::start_scripted().await;
    let mut core = Core::builder(
        CoreConfig {
            search_quiet_timeout: Duration::from_millis(100),
            ..search_config()
        },
        rmule_testkit::memory_store(),
    )
    .settings(rmule_core::CoreSettings::default())
    .kad(StubKad::new().answering_keywords(vec![search_result(0xBB, 1024, "linux kad.iso")]))
    .build();
    core.send(CoreCommand::EnableKad(kad_enable_config()))
        .await
        .unwrap();

    let search_id = start_search(&core, search_query("linux")).await;
    let not_sent = SearchLegState::NotSent(LegNotSent::NoServer);
    legs_reach(
        &mut core,
        search_id,
        "the Kad leg to settle beside a server leg not sent",
        |legs| {
            legs.kad == SearchLegState::Settled && legs.server == not_sent && legs.sweep == not_sent
        },
    )
    .await;
    let completed = next_expected(&mut core, "the search to complete on Kad", |event| {
        assert!(
            !matches!(event, CoreEvent::Search(SearchEvent::SearchWaitingForConnection { .. })),
            "with Kad running the search does not wait whole"
        );
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchCompleted { search_id: id, .. }) if *id == search_id
        )
    })
    .await;
    assert!(
        matches!(
            completed,
            CoreEvent::Search(SearchEvent::SearchCompleted {
                total_results: 1,
                ..
            })
        ),
        "the Kad row: {completed:?}"
    );
    assert!(server.search_phrases().await.is_empty());
    assert!(server.assigned_ids().await.is_empty(), "nothing logged in");
}

/// A search asked while the operator's session is being re-made, with its Kad
/// row already in: `(core, search id, server)`. Its server leg never went out.
async fn search_while_reconnecting() -> (Core, SearchId, FakeEd2kServer) {
    let server = FakeEd2kServer::start_scripted().await;
    server
        .set_search_results(vec![search_result(0xAA, 1024, "linux server.iso")])
        .await;
    let mut core = Core::builder(
        CoreConfig {
            search_quiet_timeout: Duration::from_millis(100),
            server_reconnect_first: Duration::from_secs(1),
            server_reconnect_ceiling: Duration::from_secs(1),
            ..search_config()
        },
        rmule_testkit::memory_store(),
    )
    .settings(rmule_core::CoreSettings::default())
    .kad(StubKad::new().answering_keywords(vec![search_result(0xBB, 1024, "linux kad.iso")]))
    .build();
    core.send(CoreCommand::EnableKad(kad_enable_config()))
        .await
        .unwrap();
    list_and_connect(&core, &server.endpoint()).await;
    next_expected(&mut core, "the operator's session", |event| {
        matches!(
            event,
            CoreEvent::ServerConnection(rmule_core::ServerConnectionEvent::Connected { .. })
        )
    })
    .await;
    server.hang_up_all().await;
    next_expected(&mut core, "the reconnect to be scheduled", |event| {
        matches!(
            event,
            CoreEvent::ServerConnection(rmule_core::ServerConnectionEvent::Reconnecting { .. })
        )
    })
    .await;
    let search_id = start_search(&core, search_query("linux")).await;
    legs_reach(
        &mut core,
        search_id,
        "the server leg to wait for the reconnect beside the settled Kad leg",
        |legs| {
            legs.kad == SearchLegState::Settled
                && legs.server == SearchLegState::WaitingForSession
                && legs.sweep == SearchLegState::WaitingForSession
        },
    )
    .await;
    (core, search_id, server)
}

/// While the intent stands the server leg waits, holding the search open, and
/// the re-made session sends it into the same entry.
#[tokio::test]
async fn while_a_reconnect_is_pending_the_server_leg_waits_and_the_session_sends_it() {
    let (mut core, search_id, server) = search_while_reconnecting().await;
    legs_reach(
        &mut core,
        search_id,
        "the server leg sent on the re-made session",
        |legs| legs.server != SearchLegState::WaitingForSession,
    )
    .await;
    let completed = next_expected(&mut core, "the same entry to complete with both rows", |event| {
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchCompleted { search_id: id, .. }) if *id == search_id
        )
    })
    .await;
    assert!(
        matches!(
            completed,
            CoreEvent::Search(SearchEvent::SearchCompleted {
                total_results: 2,
                ..
            })
        ),
        "the Kad row and the server's row, one entry: {completed:?}"
    );
    assert_eq!(server.search_phrases().await, ["linux"]);
}

/// The intent ends while the leg waits: it never went out, so it ends not
/// sent, its sweep with it, and the search completes on the Kad row.
#[tokio::test]
async fn an_intent_ending_under_a_waiting_server_leg_leaves_it_not_sent_and_completes() {
    let (mut core, search_id, server) = search_while_reconnecting().await;
    core.send(CoreCommand::DisconnectFromServer).await.unwrap();
    let not_sent = SearchLegState::NotSent(LegNotSent::NoServer);
    legs_reach(
        &mut core,
        search_id,
        "the server leg to end not sent",
        |legs| legs.server == not_sent && legs.sweep == not_sent,
    )
    .await;
    let completed = next_expected(&mut core, "the search to complete", |event| {
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchCompleted { search_id: id, .. }) if *id == search_id
        )
    })
    .await;
    assert!(
        matches!(
            completed,
            CoreEvent::Search(SearchEvent::SearchCompleted {
                total_results: 1,
                ..
            })
        ),
        "the Kad row stands: {completed:?}"
    );
    assert!(server.search_phrases().await.is_empty(), "nothing was sent");
}

#[tokio::test]
async fn with_neither_a_session_nor_kad_the_whole_search_waits_and_the_connect_sends_it() {
    let server = FakeEd2kServer::start_scripted().await;
    server
        .set_search_results(vec![search_result(0xAA, 1024, "linux server.iso")])
        .await;
    let endpoint = server.endpoint();
    let mut core = Core::builder(search_config(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();

    let search_id = start_search(&core, search_query("linux")).await;
    next_expected(&mut core, "the search to wait whole", |event| {
        assert!(
            !matches!(event, CoreEvent::Search(SearchEvent::SearchStarted { .. })),
            "nothing to send it on"
        );
        matches!(event, CoreEvent::Search(SearchEvent::SearchWaitingForConnection { search_id: id }) if *id == search_id)
    })
    .await;
    assert!(server.assigned_ids().await.is_empty(), "nothing logged in");

    list_and_connect(&core, &endpoint).await;
    next_expected(&mut core, "the search to start on the session", |event| {
        matches!(event, CoreEvent::Search(SearchEvent::SearchStarted { search_id: id }) if *id == search_id)
    })
    .await;
    // Kad never came: its leg lets go once the others settle, and says so.
    let completed = next_expected(&mut core, "the search to complete on the server's answer", |event| {
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchCompleted { search_id: id, .. }) if *id == search_id
        )
    })
    .await;
    assert!(
        matches!(
            completed,
            CoreEvent::Search(SearchEvent::SearchCompleted {
                total_results: 1,
                ..
            })
        ),
        "{completed:?}"
    );
}

#[tokio::test]
async fn a_download_on_kad_alone_gains_the_servers_sources_when_the_operator_connects() {
    let dir = tempfile::tempdir().unwrap();
    let server = FakeEd2kServer::start_scripted().await;
    server
        .set_sources(vec![PeerSource::new(ClientId::from_u32(0x0100_007F), 4663)])
        .await;
    let mut bytes = vec![0x4B; ED2K_PART_SIZE as usize];
    bytes.push(0x4B);

    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            dir.path(),
        ))
        .peer_transfer(PendingPeerTransfer)
        .kad(StubKad::new().answering_keywords(vec![search_result(0xBB, 1024, "unused")]))
        .build();
    // Commands are taken in order: Kad runs before the download starts.
    core.send(CoreCommand::EnableKad(kad_enable_config()))
        .await
        .unwrap();
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: file_link("kad-first.bin", &bytes),
        source_hint: Some(server.endpoint()),
        name: rmule_testkit::file_name("kad-first.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
        kad_aich_root: None,
    }))
    .await
    .unwrap();

    // Kad runs, no session: the run starts on Kad and waits for its
    // sources — it does not read No network.
    let started = next_expected(&mut core, "the run to start on Kad", |event| {
        assert!(
            !matches!(
                event,
                CoreEvent::Download(DownloadEvent::WaitingForConnection { .. })
            ),
            "Kad is a connection"
        );
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::SourcesFound { total: 0, .. })
        )
    })
    .await;
    let CoreEvent::Download(DownloadEvent::SourcesFound {
        download_id: id, ..
    }) = started
    else {
        unreachable!()
    };
    assert!(server.assigned_ids().await.is_empty(), "nothing logged in");

    list_and_connect(&core, &server.endpoint()).await;
    next_expected(&mut core, "the new session's sources to join the run", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::SourcesFound { download_id, usable_high_id: 1, .. }) if *download_id == id
        )
    })
    .await;
    next_expected(&mut core, "a part assigned to the server's source", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::PartAssigned { download_id, .. }) if *download_id == id
        )
    })
    .await;
}

/// A run on Kad alone waiting for sources writes nothing, so its part
/// file is looked at each second: a delete is told while it waits.
#[tokio::test]
async fn a_part_file_removed_while_the_run_waits_for_sources_is_told() {
    let dir = tempfile::tempdir().unwrap();
    let mut bytes = vec![0x4B; ED2K_PART_SIZE as usize];
    bytes.push(0x4B);
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            dir.path(),
        ))
        .peer_transfer(PendingPeerTransfer)
        .kad(StubKad::new().answering_keywords(vec![search_result(0xBB, 1024, "unused")]))
        .build();
    core.send(CoreCommand::EnableKad(kad_enable_config()))
        .await
        .unwrap();
    let output = dir.path().join("waits.bin");
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: file_link("waits.bin", &bytes),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        name: rmule_testkit::file_name("waits.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
        kad_aich_root: None,
    }))
    .await
    .unwrap();
    next_expected(&mut core, "the run waiting for sources on Kad", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::WaitingForSources { .. })
        )
    })
    .await;

    std::fs::remove_file(rmule_core::DownloadPaths::from_final_path(output).part_path()).unwrap();
    next_expected(&mut core, "the delete told while the run waits", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::PartFileLost {
                found: rmule_core::PartFileChange::Gone,
                ..
            })
        )
    })
    .await;
}

/// A search whose server has not answered yet when its session is lost, with
/// the Kad leg's row already in: `(core, search id, server)`.
async fn search_lost_under_the_server_leg() -> (Core, SearchId, FakeEd2kServer) {
    let server = FakeEd2kServer::start_scripted().await;
    server.set_search_silent(true).await;
    let mut core = Core::builder(
        CoreConfig {
            search_quiet_timeout: Duration::from_millis(100),
            server_reconnect_first: Duration::from_millis(20),
            server_reconnect_ceiling: Duration::from_millis(20),
            ..search_config()
        },
        rmule_testkit::memory_store(),
    )
    .settings(rmule_core::CoreSettings::default())
    .kad(StubKad::new().answering_keywords(vec![search_result(0xBB, 1024, "linux kad.iso")]))
    .build();
    core.send(CoreCommand::EnableKad(kad_enable_config()))
        .await
        .unwrap();
    list_and_connect(&core, &server.endpoint()).await;
    next_expected(&mut core, "the operator's session", |event| {
        matches!(
            event,
            CoreEvent::ServerConnection(rmule_core::ServerConnectionEvent::Connected { .. })
        )
    })
    .await;
    let search_id = start_search(&core, search_query("linux")).await;
    legs_reach(
        &mut core,
        search_id,
        "the Kad row in, the server leg sent and silent",
        |legs| legs.kad == SearchLegState::Settled && legs.server == SearchLegState::Sent,
    )
    .await;
    requests_reach(&server, 1).await;
    (core, search_id, server)
}

/// The server has received `count` search requests.
async fn requests_reach(server: &FakeEd2kServer, count: usize) {
    tokio::time::timeout(HANG_GUARD, async {
        while server.search_phrases().await.len() < count {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the server never received {count} search requests"));
}

/// The operator's intent stands: the server hangs up, the leg waits for the
/// reconnect and is sent again on the re-made session — nothing fails.
#[tokio::test]
async fn a_lost_session_sends_the_unanswered_server_leg_again_on_the_reconnect() {
    let (mut core, search_id, server) = search_lost_under_the_server_leg().await;
    server.hang_up_all().await;
    legs_reach(
        &mut core,
        search_id,
        "the leg to wait for the reconnect",
        |legs| {
            legs.server == SearchLegState::WaitingForSession && legs.kad == SearchLegState::Settled
        },
    )
    .await;
    legs_reach(
        &mut core,
        search_id,
        "the leg sent on the re-made session",
        |legs| legs.server == SearchLegState::Sent,
    )
    .await;
    requests_reach(&server, 2).await;
    assert_eq!(
        server.search_phrases().await,
        ["linux", "linux"],
        "the unanswered request went out again, once"
    );
}

/// No intent stands — the operator disconnected: the leg ends unanswered, and
/// the search completes with the Kad row it already had.
#[tokio::test]
async fn with_no_intent_a_lost_server_leg_ends_unanswered_and_the_kad_rows_stand() {
    let (mut core, search_id, server) = search_lost_under_the_server_leg().await;
    core.send(CoreCommand::DisconnectFromServer).await.unwrap();
    legs_reach(&mut core, search_id, "the leg to end unanswered", |legs| {
        legs.server == SearchLegState::Unanswered
    })
    .await;
    let completed = next_expected(&mut core, "the search to complete", |event| {
        assert!(
            !matches!(event, CoreEvent::Search(SearchEvent::SearchFailed { .. })),
            "a lost session fails no search: {event:?}"
        );
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchCompleted { search_id: id, .. }) if *id == search_id
        )
    })
    .await;
    assert!(
        matches!(
            completed,
            CoreEvent::Search(SearchEvent::SearchCompleted {
                total_results: 1,
                ..
            })
        ),
        "the Kad row stands: {completed:?}"
    );
    assert_eq!(server.search_phrases().await, ["linux"], "nothing re-sent");
}
