//! What a search looks like from the outside: the started/results/completed
//! trail, the quiet timeout that ends it, a cancel that leaves the session
//! up, and the result folding — duplicates merge their names, a conflicting size does
//! not. A download started mid-search rides the same server session.
use std::time::Duration;

use crate::fixture::LoopbackSearchServer;
use crate::fixture::next_matching;
use crate::fixture::search_query;
use crate::fixture::stub_link;
use crate::fixture::{search_result as result, start_search_confirmed};
use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, SearchCommand, SearchEvent,
};
use rmule_ed2k::{Opcode, SearchResultSkipReason};
use rmule_primitives::{Ed2kFileLink, Ed2kText};

fn file_link() -> Ed2kFileLink {
    stub_link("download.bin", 4096, 0x44)
}

#[tokio::test]
async fn start_search_emits_started_and_results() {
    let mut server = LoopbackSearchServer::start().await;
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();

    rmule_testkit::connect_to(&core, &server.endpoint).await;

    let search_id =
        start_search_confirmed(&mut core, "the search to start", search_query("ubuntu")).await;
    server.wait_for_search_request().await;
    let batch = vec![result(0xAA, 1024, "ubuntu.iso")];
    server.send_results(batch.clone()).await;

    let event = next_matching(&mut core, |event| {
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchResultsReceived { .. })
        )
    })
    .await;
    assert!(
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchResultsReceived {
                search_id: id,
                ref results,
            }) if id == search_id && *results == batch
        ),
        "expected search results for {search_id:?}, saw {event:?}",
    );
}

#[tokio::test]
async fn search_completes_after_quiet_timeout() {
    let mut server = LoopbackSearchServer::start().await;
    let mut core = Core::builder(
        CoreConfig {
            search_quiet_timeout: Duration::from_millis(20),
            ..CoreConfig::default()
        },
        rmule_testkit::memory_store(),
    )
    .settings(rmule_core::CoreSettings::default())
    .build();

    rmule_testkit::connect_to(&core, &server.endpoint).await;

    let search_id =
        start_search_confirmed(&mut core, "the search to start", search_query("ubuntu")).await;
    server.wait_for_search_request().await;
    server
        .send_results(vec![result(0xAA, 1024, "ubuntu.iso")])
        .await;
    let _ = next_matching(&mut core, |event| {
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchResultsReceived { .. })
        )
    })
    .await;

    let completed = next_matching(&mut core, |event| {
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchCompleted { .. })
        )
    })
    .await;
    assert!(
        matches!(
            completed,
            CoreEvent::Search(SearchEvent::SearchCompleted {
                search_id: id,
                total_results: 1,
            }) if id == search_id
        ),
        "expected SearchCompleted for {search_id:?}, saw {completed:?}",
    );
}

#[tokio::test]
async fn cancel_search_keeps_server_session_alive() {
    let mut server = LoopbackSearchServer::start().await;
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();

    rmule_testkit::connect_to(&core, &server.endpoint).await;

    let search_id =
        start_search_confirmed(&mut core, "the search to start", search_query("ubuntu")).await;
    server.wait_for_search_request().await;
    core.send(CoreCommand::Search(SearchCommand::CancelSearch {
        search_id,
    }))
    .await
    .unwrap();
    let cancelled = next_matching(&mut core, |event| {
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchCancelled { .. })
        )
    })
    .await;
    assert!(
        matches!(
            cancelled,
            CoreEvent::Search(SearchEvent::SearchCancelled { search_id: id }) if id == search_id
        ),
        "expected SearchCancelled for {search_id:?}, saw {cancelled:?}",
    );

    // The session outlives the cancel: the next search goes out on it at once,
    // without waiting for the cancelled request's answer.
    let second_id =
        start_search_confirmed(&mut core, "the search to start", search_query("ubuntu")).await;
    server.wait_for_search_request().await;
    assert_ne!(second_id, search_id);
}

#[tokio::test]
async fn duplicates_merge_names_and_preserve_primary() {
    let mut server = LoopbackSearchServer::start().await;
    let mut core = Core::builder(
        CoreConfig {
            search_quiet_timeout: Duration::from_millis(200),
            ..CoreConfig::default()
        },
        rmule_testkit::memory_store(),
    )
    .settings(rmule_core::CoreSettings::default())
    .build();

    rmule_testkit::connect_to(&core, &server.endpoint).await;

    let search_id =
        start_search_confirmed(&mut core, "the search to start", search_query("ubuntu")).await;
    server.wait_for_search_request().await;
    server
        .send_results(vec![
            result(0xAA, 1024, "first.iso"),
            result(0xAA, 1024, "alias.iso"),
        ])
        .await;

    let event = next_matching(&mut core, |event| {
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchResultsReceived { .. })
        )
    })
    .await;
    let CoreEvent::Search(SearchEvent::SearchResultsReceived {
        search_id: id,
        results,
    }) = event
    else {
        panic!("expected SearchResultsReceived");
    };
    assert_eq!(id, search_id);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].primary_name().to_display_string(), "first.iso");
    assert_eq!(
        results[0]
            .names()
            .iter()
            .map(Ed2kText::to_display_string)
            .collect::<Vec<_>>(),
        vec!["first.iso", "alias.iso"],
    );
}

#[tokio::test]
async fn conflicting_size_does_not_merge() {
    let mut server = LoopbackSearchServer::start().await;
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();

    rmule_testkit::connect_to(&core, &server.endpoint).await;

    let search_id =
        start_search_confirmed(&mut core, "the search to start", search_query("ubuntu")).await;
    server.wait_for_search_request().await;
    server
        .send_results(vec![
            result(0xAA, 1024, "small.iso"),
            result(0xAA, 2048, "large.iso"),
        ])
        .await;

    let event = next_matching(&mut core, |event| {
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchResultsReceived { .. })
        )
    })
    .await;
    assert!(
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchResultsReceived {
                search_id: id,
                ref results,
            }) if id == search_id && results.len() == 2
        ),
        "expected two distinct same-hash/different-size results, saw {event:?}",
    );
}

#[tokio::test]
async fn search_result_skipped_is_visible_warning() {
    let mut server = LoopbackSearchServer::start().await;
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();

    rmule_testkit::connect_to(&core, &server.endpoint).await;

    let search_id =
        start_search_confirmed(&mut core, "the search to start", search_query("ubuntu")).await;
    server.wait_for_search_request().await;
    server.send_malformed_search_result().await;

    let event = next_matching(&mut core, |event| {
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchResultSkipped { .. })
        )
    })
    .await;
    assert!(
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchResultSkipped {
                search_id: id,
                reason: SearchResultSkipReason::MalformedPayload,
            }) if id == search_id
        ),
        "expected SearchResultSkipped for {search_id:?}, saw {event:?}",
    );
}

#[tokio::test]
async fn default_core_search_and_source_lookup_share_server_session() {
    let output_dir = tempfile::tempdir().expect("temp dir");
    let mut server = LoopbackSearchServer::start().await;
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            output_dir.path(),
        ))
        .build();
    rmule_testkit::connect_to(&core, &server.endpoint).await;

    let _search_id =
        start_search_confirmed(&mut core, "the search to start", search_query("ubuntu")).await;
    server.wait_for_search_request().await;
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: file_link(),
        source_hint: Some(server.endpoint.clone()),
        name: rmule_testkit::file_name("shared-session.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
        kad_aich_root: None,
    }))
    .await
    .unwrap();

    server.wait_for_client_opcode(Opcode::GetSources).await;
}
