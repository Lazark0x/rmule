//! Search on the **standing-session path**. The operator
//! connects first (`ConnectToServer`) and searches later, so the
//! session exists with no activity attached when `StartSearch` arrives. The
//! manual run against a real server saw zero results and a stuck-active
//! search; these tests drive that exact order over a loopback fake server and
//! assert the full trail: started → results → completed → a second search
//! starts fresh.

use std::time::Duration;

use crate::fixture::next_expected;
use crate::fixture::search_config;
use crate::fixture::search_query;
use crate::fixture::{connect_and_settle, search_result as result, start_search_confirmed};
use rmule_core::{Core, CoreCommand, CoreConfig, CoreEvent, SearchCommand, SearchEvent};
use rmule_primitives::{Ed2kFileClass, Ed2kText};
use rmule_testkit::FakeEd2kServer;

/// The manual run's exact order: connect via the Servers tab,
/// then search. The standing session must serve the later-attached search
/// identically to one it was established for — results stream, the quiet
/// window completes it, and the active slot frees for the next search.
#[tokio::test]
async fn a_search_on_the_standing_session_streams_results_and_completes() {
    let server = FakeEd2kServer::start_scripted().await;
    let batch = vec![result(0xAA, 1024, "linux.iso")];
    server.set_search_results(batch.clone()).await;
    let endpoint = server.endpoint();
    let mut core = Core::builder(search_config(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();

    connect_and_settle(&mut core, &endpoint).await;
    let first = start_search_confirmed(&mut core, "first search", search_query("linux")).await;

    let event = next_expected(&mut core, "results on the standing session", |event| {
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
                search_id,
                ref results,
            }) if search_id == first && *results == batch
        ),
        "expected the scripted batch for {first:?}, saw {event:?}",
    );

    let completed = next_expected(&mut core, "quiet-window completion", |event| {
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
                search_id,
                total_results: 1,
            }) if search_id == first
        ),
        "expected completion for {first:?}, saw {completed:?}",
    );

    // The slot freed: a second search on the same standing session starts
    // fresh instead of being rejected as already active — and its results
    // arriving proves the query reached the server over the same session.
    let second = start_search_confirmed(
        &mut core,
        "second search after completion",
        search_query("linux"),
    )
    .await;
    assert_ne!(second, first, "a fresh search id for a fresh search");
    next_expected(&mut core, "the second search's results", |event| {
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchResultsReceived { search_id, .. })
                if *search_id == second
        )
    })
    .await;
}

/// A search that never hears a single result batch still completes — as
/// `Completed {{ total: 0 }}` after the quiet window — instead of holding the
/// active slot forever (the "stuck active" half of the standing-session failure).
#[tokio::test]
async fn a_search_that_hears_nothing_completes_with_zero_results() {
    // Scripted default: the server answers the search with an *empty* result
    // set, which merges nothing and must not arm-reset anything.
    let server = FakeEd2kServer::start_scripted().await;
    let endpoint = server.endpoint();
    let mut core = Core::builder(search_config(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();

    connect_and_settle(&mut core, &endpoint).await;
    let search_id = start_search_confirmed(
        &mut core,
        "first search (zero-result)",
        search_query("linux"),
    )
    .await;

    let completed = next_expected(&mut core, "zero-result completion", |event| {
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
                total_results: 0,
            }) if id == search_id
        ),
        "expected zero-result completion for {search_id:?}, saw {completed:?}",
    );

    // And the slot freed: the retry is accepted.
    let second = start_search_confirmed(
        &mut core,
        "retry after zero-result completion",
        search_query("linux"),
    )
    .await;
    assert_ne!(second, search_id);
}

/// Re-search while one is RUNNING:
/// the second search runs beside the first on the same standing session —
/// no `SearchCancelled` for the first — and streams its own results.
#[tokio::test]
async fn a_second_search_runs_beside_a_running_one() {
    let server = FakeEd2kServer::start_scripted().await;
    server
        .set_search_results(vec![result(0xAA, 1024, "linux.iso")])
        .await;
    let endpoint = server.endpoint();
    // A quiet window long enough that the first search is still running when
    // the second arrives.
    let mut core = Core::builder(
        CoreConfig {
            status_ping_tick: Duration::from_secs(3600),
            search_quiet_timeout: Duration::from_secs(3600),
            ..CoreConfig::default()
        },
        rmule_testkit::memory_store(),
    )
    .settings(rmule_core::CoreSettings::default())
    .build();

    connect_and_settle(&mut core, &endpoint).await;
    let first = start_search_confirmed(&mut core, "first", search_query("linux")).await;
    next_expected(&mut core, "first search's results", |event| {
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchResultsReceived { .. })
        )
    })
    .await;

    core.send(CoreCommand::Search(SearchCommand::StartSearch {
        search_id: rmule_core::SearchId::mint(),
        query: search_query("linux").into(),
    }))
    .await
    .expect("core accepts the command");

    let started = next_expected(&mut core, "the second search started", |event| {
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchCancelled { .. })
                | CoreEvent::Search(SearchEvent::SearchStarted { .. })
                | CoreEvent::CommandRejected { .. }
        )
    })
    .await;
    let CoreEvent::Search(SearchEvent::SearchStarted { search_id: second }) = started else {
        panic!("expected the second SearchStarted and no cancel of the first, got {started:?}");
    };
    assert_ne!(second, first);

    // Both searches ask for "linux", so the second answer's row proves the
    // first search's query too (ADR-0034, Search Attribution): each search
    // republishes its set, in no order the model fixes. Wait for both by id.
    let mut republished = Vec::new();
    while !(republished.contains(&first) && republished.contains(&second)) {
        let event = next_expected(&mut core, "both sets after the second answer", |event| {
            matches!(
                event,
                CoreEvent::Search(SearchEvent::SearchResultsReceived { .. })
            )
        })
        .await;
        let CoreEvent::Search(SearchEvent::SearchResultsReceived { search_id, results }) = event
        else {
            unreachable!("matched above")
        };
        assert_eq!(
            results.len(),
            1,
            "the one file, merged, in {search_id:?}'s set"
        );
        republished.push(search_id);
    }
}

/// A server's per-row **metadata** reaches the app, not just the
/// name and size. The scripted answer carries both source counts and a type
/// tag; the app-facing row must show all three, or the Searches view can only
/// print `Sources 0` / `Type —` — which is exactly what the manual run saw.
#[tokio::test]
async fn a_search_result_reaches_the_app_with_its_source_counts_and_type() {
    let server = FakeEd2kServer::start_scripted().await;
    let scripted = result(0xAA, 1024, "linux.iso")
        .with_reported_availability(1234)
        .with_complete_sources(900)
        .with_file_type(Ed2kText::from_utf8("Pro"));
    server.set_search_results(vec![scripted]).await;
    let endpoint = server.endpoint();
    let mut core = Core::builder(search_config(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();

    connect_and_settle(&mut core, &endpoint).await;
    start_search_confirmed(&mut core, "metadata search", search_query("linux")).await;

    let event = next_expected(&mut core, "results with metadata", |event| {
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchResultsReceived { .. })
        )
    })
    .await;
    let CoreEvent::Search(SearchEvent::SearchResultsReceived { results, .. }) = event else {
        unreachable!("matched above")
    };

    let row = &results[0];
    assert_eq!(row.reported_availability(), Some(1234), "FT_SOURCES");
    assert_eq!(row.complete_sources(), Some(900), "FT_COMPLETE_SOURCES");
    assert_eq!(
        row.file_type().map(Ed2kText::to_display_string),
        Some("Pro".to_owned()),
        "FT_FILETYPE"
    );
    assert_eq!(
        row.file_class(),
        Some(Ed2kFileClass::CdImage),
        "the name's `.iso` refines the lossy `Pro` term the wire can carry"
    );
}
