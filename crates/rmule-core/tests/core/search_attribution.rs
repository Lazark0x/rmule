//! **Search Attribution** at the core seam (ADR-0034):
//! searches started together go out together, none waiting on another, and
//! the server's answers — which name no search — land each row in exactly the
//! searches it answers. Commands and a scripted server in; per-search result
//! sets out.

use crate::fixture::identity_with_port;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use rmule_core::{
    Core, CoreCommand, CoreCommandRejectReason, CoreConfig, CoreEvent, SearchCommand, SearchEvent,
    SearchId,
};
use rmule_primitives::{ClientId, Ed2kText, FileHash, PeerSource, SearchResult};

use crate::fixture::{LoopbackSearchServer, next_expected, search_query};

fn row(hash: u8, name: &str) -> SearchResult {
    SearchResult::new(
        FileHash::from_bytes([hash; FileHash::BYTE_LEN]),
        1024,
        vec![Ed2kText::from_utf8(name)],
        vec![PeerSource::new(ClientId::from_u32(0x0100_007F), 4662)],
    )
    .unwrap()
}

fn core(answer_wait: Duration) -> Core {
    Core::new(
        CoreConfig {
            search_quiet_timeout: Duration::from_millis(150),
            search_server_answer_timeout: answer_wait,
            ..CoreConfig::default()
        },
        rmule_testkit::memory_store(),
    )
}

async fn start(core: &mut Core, phrase: &str) -> SearchId {
    let search_id = SearchId::mint();
    core.send(CoreCommand::Search(SearchCommand::StartSearch {
        search_id,
        query: search_query(phrase).into(),
    }))
    .await
    .unwrap();
    next_expected(core, "the search to start", |event| {
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchStarted { search_id: id }) if *id == search_id
        )
    })
    .await;
    search_id
}

/// Each search's final result set, by name, in the order each search ended.
#[derive(Default)]
struct Outcome {
    sets: BTreeMap<SearchId, BTreeSet<String>>,
    ended: Vec<SearchId>,
}

impl Outcome {
    fn names(&self, search_id: SearchId) -> Vec<&str> {
        self.sets
            .get(&search_id)
            .map(|names| names.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }
}

/// Fold events until every search in `ids` has ended.
async fn run_until_ended(core: &mut Core, ids: &[SearchId]) -> Outcome {
    let mut outcome = Outcome::default();
    tokio::time::timeout(Duration::from_secs(10), async {
        while ids.iter().any(|id| !outcome.ended.contains(id)) {
            let Some(CoreEvent::Search(event)) = core.next_event().await else {
                continue;
            };
            match event {
                SearchEvent::SearchResultsReceived { search_id, results } => {
                    outcome.sets.insert(
                        search_id,
                        results
                            .iter()
                            .map(|row| row.primary_name().to_display_string())
                            .collect(),
                    );
                }
                SearchEvent::SearchCompleted { search_id, .. }
                | SearchEvent::SearchCancelled { search_id }
                | SearchEvent::SearchFailed { search_id, .. }
                | SearchEvent::SearchRefused { search_id, .. } => outcome.ended.push(search_id),
                SearchEvent::SearchStarted { .. }
                | SearchEvent::SearchResultSkipped { .. }
                | SearchEvent::SearchWaitingForTurn { .. }
                | SearchEvent::SearchWaitingForConnection { .. }
                | SearchEvent::SearchSentToServer { .. }
                | SearchEvent::SearchDeferredKadPublish { .. }
                | SearchEvent::SearchLegsChanged { .. }
                | SearchEvent::SearchMoreRequested { .. }
                | SearchEvent::SearchMoreRefused { .. } => {}
            }
        }
    })
    .await
    .expect("every search ended within 10s");
    outcome
}

/// Three searches started together, answers interleaved: every request is on
/// the wire before any answer, and each row lands in exactly the searches it
/// satisfies — its own answer's search whole, any other it proves.
#[tokio::test]
async fn three_searches_started_together_each_hold_exactly_what_answers_them() {
    let mut server = LoopbackSearchServer::start().await;
    let mut core = core(Duration::from_secs(12));
    rmule_testkit::connect_to(&core, &server.endpoint, identity_with_port(0).into()).await;
    let ubuntu = start(&mut core, "ubuntu").await;
    let debian = start(&mut core, "debian").await;
    let desktop = start(&mut core, "ubuntu desktop").await;
    for _ in 0..3 {
        server.wait_for_search_request().await;
    }

    server
        .send_results(vec![
            row(1, "ubuntu-desktop-22.iso"),
            row(2, "ubuntu-server-22.iso"),
        ])
        .await;
    server.send_results(vec![row(3, "debian-12.iso")]).await;
    server
        .send_results(vec![row(4, "Ubuntu Desktop 24.iso")])
        .await;

    let outcome = run_until_ended(&mut core, &[ubuntu, debian, desktop]).await;
    assert_eq!(
        outcome.names(ubuntu),
        [
            "Ubuntu Desktop 24.iso",
            "ubuntu-desktop-22.iso",
            "ubuntu-server-22.iso"
        ]
    );
    assert_eq!(outcome.names(debian), ["debian-12.iso"]);
    assert_eq!(
        outcome.names(desktop),
        ["Ubuntu Desktop 24.iso", "ubuntu-desktop-22.iso"]
    );
    assert_eq!(
        core.diagnostics_snapshot()
            .session
            .search_rows_unattributed_total,
        0
    );
}

/// An answer that arrives after its search was closed is shown nowhere it
/// does not answer, and counted.
#[tokio::test]
async fn an_answer_after_its_search_was_closed_is_shown_nowhere_and_counted() {
    let mut server = LoopbackSearchServer::start().await;
    let mut core = core(Duration::from_secs(12));
    rmule_testkit::connect_to(&core, &server.endpoint, identity_with_port(0).into()).await;
    let closed = start(&mut core, "alpha").await;
    let open = start(&mut core, "beta").await;
    server.wait_for_search_request().await;
    server.wait_for_search_request().await;
    core.send(CoreCommand::Search(SearchCommand::CancelSearch {
        search_id: closed,
    }))
    .await
    .unwrap();
    next_expected(&mut core, "the cancel", |event| {
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchCancelled { search_id }) if *search_id == closed
        )
    })
    .await;

    server.send_results(vec![row(1, "alpha.iso")]).await;
    server.send_results(vec![row(2, "beta.iso")]).await;
    let outcome = run_until_ended(&mut core, &[open]).await;
    assert_eq!(outcome.names(open), ["beta.iso"]);
    assert!(outcome.names(closed).is_empty());
    assert_eq!(
        core.diagnostics_snapshot()
            .session
            .search_rows_unattributed_total,
        1
    );
}

/// An answer that never arrives delays no other search: the answered one
/// completes on its own quiet window, the silent one after its own wait.
///
/// The session puts a link's searches two seconds apart (ADR-0035), so the
/// silent search's request leaves two seconds after the answered one's, and
/// the test answers only once it has seen both. The answer wait is therefore
/// set well past that spacing: the answer then reaches the answered search
/// with its wait still running and takes that search's place, whatever the
/// scheduler does between the second request's arrival and the answer. A wait
/// equal to the spacing lapses the answered search's wait at the very instant
/// the silent request leaves, so the answer would always arrive owed — its
/// rows landing only by proof, inside the answered search's quiet window, and
/// the two searches' quiet windows opening within microseconds of each other.
#[tokio::test]
async fn an_answer_never_arriving_leaves_the_other_searches_on_time() {
    let mut server = LoopbackSearchServer::start().await;
    let mut core = core(Duration::from_secs(4));
    rmule_testkit::connect_to(&core, &server.endpoint, identity_with_port(0).into()).await;
    let answered = start(&mut core, "alpha").await;
    let silent = start(&mut core, "beta").await;
    server.wait_for_search_request().await;
    server.wait_for_search_request().await;

    server.send_results(vec![row(1, "alpha.iso")]).await;
    let outcome = run_until_ended(&mut core, &[answered, silent]).await;
    assert_eq!(outcome.ended, [answered, silent], "the answered one first");
    assert_eq!(outcome.names(answered), ["alpha.iso"]);
    assert!(outcome.names(silent).is_empty());
}

/// The same query twice: both requests go out, and each answer — satisfying
/// both — shows in both.
#[tokio::test]
async fn identical_queries_both_show_both_answers() {
    let mut server = LoopbackSearchServer::start().await;
    let mut core = core(Duration::from_secs(12));
    rmule_testkit::connect_to(&core, &server.endpoint, identity_with_port(0).into()).await;
    let first = start(&mut core, "ubuntu").await;
    let second = start(&mut core, "ubuntu").await;
    server.wait_for_search_request().await;
    server.wait_for_search_request().await;

    server.send_results(vec![row(1, "ubuntu-a.iso")]).await;
    server.send_results(vec![row(2, "ubuntu-b.iso")]).await;
    let outcome = run_until_ended(&mut core, &[first, second]).await;
    assert_eq!(outcome.names(first), ["ubuntu-a.iso", "ubuntu-b.iso"]);
    assert_eq!(outcome.names(second), ["ubuntu-a.iso", "ubuntu-b.iso"]);
}

/// The caller names the search, so a second `StartSearch` under a running
/// search's id is refused and the running search is left alone.
#[tokio::test]
async fn a_start_under_a_running_searchs_id_is_rejected() {
    let mut server = LoopbackSearchServer::start().await;
    let mut core = core(Duration::from_secs(12));
    rmule_testkit::connect_to(&core, &server.endpoint, identity_with_port(0).into()).await;
    let running = start(&mut core, "alpha").await;
    server.wait_for_search_request().await;
    core.send(CoreCommand::Search(SearchCommand::StartSearch {
        search_id: running,
        query: search_query("beta").into(),
    }))
    .await
    .unwrap();
    next_expected(&mut core, "the duplicate's rejection", |event| {
        matches!(
            event,
            CoreEvent::CommandRejected {
                reason: CoreCommandRejectReason::SearchIdInUse
            }
        )
    })
    .await;

    server.send_results(vec![row(1, "alpha.iso")]).await;
    let outcome = run_until_ended(&mut core, &[running]).await;
    assert_eq!(outcome.names(running), ["alpha.iso"]);
}

/// A multi-word query reaches the server as one AND-ed `0x01` term per word
/// (`docs/protocol/search-request.md`; derived vector), and attribution reads
/// the same words: the explicit `AND` is the join, not a keyword another
/// answer's row would have to carry.
#[tokio::test]
async fn a_multi_word_query_reaches_the_server_as_one_term_per_word() {
    let mut server = LoopbackSearchServer::start().await;
    let mut core = core(Duration::from_secs(12));
    rmule_testkit::connect_to(&core, &server.endpoint, identity_with_port(0).into()).await;
    let both = start(&mut core, "rock AND roll").await;
    let roll = start(&mut core, "roll").await;
    let expected: Vec<u8> = [
        &[0x00, 0x00, 0x01, 0x04, 0x00][..],
        b"rock",
        &[0x01, 0x04, 0x00],
        b"roll",
    ]
    .concat();
    assert_eq!(server.next_search_payload().await, expected);
    assert_eq!(
        server.next_search_payload().await,
        [&[0x01, 0x04, 0x00][..], b"roll"].concat()
    );

    server
        .send_results(vec![row(1, "Rock_n_Roll.Live.mkv")])
        .await;
    server
        .send_results(vec![row(2, "roll-call.mp3"), row(3, "rock-roll.mp3")])
        .await;

    let outcome = run_until_ended(&mut core, &[both, roll]).await;
    assert_eq!(
        outcome.names(both),
        ["Rock_n_Roll.Live.mkv", "rock-roll.mp3"]
    );
    assert_eq!(
        outcome.names(roll),
        ["Rock_n_Roll.Live.mkv", "rock-roll.mp3", "roll-call.mp3"]
    );
}
