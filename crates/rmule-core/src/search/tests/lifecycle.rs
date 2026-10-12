//! A **Search Activity** completes on *settled legs plus quiet*,
//! never on one quiet window from the start. The first search after a start
//! must not close at 3 s with nothing while the Kad keyword walk, the
//! **Global Search Sweep** or a slow server is still due to answer.

use std::time::Duration;

use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;

use super::{result, sweep_already_done};
use crate::search::{LiveSearches, SearchTask, SearchWindows};
use crate::server_session::{SearchStream, ServerSearchEvent};
use crate::service::{CoreEvent, SearchEvent, SearchId};
use rmule_primitives::{Ed2kText, KeywordQuery};

/// The production windows: 3 s quiet, 45 s Kad lifetime.
fn production_windows() -> SearchWindows {
    SearchWindows {
        quiet: Duration::from_secs(3),
        kad_lifetime: Duration::from_secs(45),
    }
}

fn query() -> KeywordQuery {
    KeywordQuery::new(Ed2kText::from_utf8("d")).expect("valid phrase")
}

/// The next search event past the leg picture, which these tests do not
/// assert on.
async fn next_event(evt_rx: &mut mpsc::Receiver<CoreEvent>) -> SearchEvent {
    match super::next_past_legs(evt_rx).await.expect("events open") {
        CoreEvent::Search(event) => event,
        other => panic!("expected a search event, got {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn a_kad_answer_later_than_the_quiet_window_is_kept_while_the_walk_is_live() {
    let start = Instant::now();
    let (tcp_tx, tcp_rx) = mpsc::channel::<ServerSearchEvent>(8);
    let live = LiveSearches::default();
    let (sweep_tx, sweep_rx) = oneshot::channel::<u32>();
    let (kad_tx, kad_rx) = crate::search::kad_keyword_leg();
    let (evt_tx, mut evt_rx) = mpsc::channel(16);
    let (_cancel_tx, cancel_rx) = watch::channel(false);
    let task = tokio::spawn(
        SearchTask {
            search_id: SearchId::from_u64(552),
            stream: SearchStream { event_rx: tcp_rx },
            rows: live.register(SearchId::from_u64(552), query().into()),
            kad_rx,
            global_sweep: sweep_rx,
            windows: production_windows(),
            evt_tx,
            cancel_rx,
            paging: crate::search::Paging::inert(
                rmule_primitives::KeywordQuery::new(rmule_primitives::Ed2kText::from_utf8("a"))
                    .expect("a query")
                    .into(),
            ),
            legs: crate::service::SearchLegs::SENT,
            late: crate::search::LateLegs::default(),
            lost: tokio::sync::mpsc::unbounded_channel().0,
        }
        .run(),
    );

    // The server answers empty at 1 s; the sweep sends its last datagram at 2 s.
    tokio::time::sleep(Duration::from_secs(1)).await;
    drop(tcp_tx);
    tokio::time::sleep(Duration::from_secs(1)).await;
    drop(sweep_tx);

    // The cold Kad walk's first storer answers at 10 s — three quiet windows in.
    tokio::time::sleep(Duration::from_secs(8)).await;
    kad_tx
        .send(vec![result(0xDD, "d.bin")])
        .await
        .expect("kad open");
    let SearchEvent::SearchResultsReceived { results, .. } = next_event(&mut evt_rx).await else {
        panic!("the Kad row must land in the live search, not after its completion");
    };
    assert_eq!(results.len(), 1);

    // The walk ends at 11 s; completion follows one quiet window later.
    tokio::time::sleep(Duration::from_secs(1)).await;
    drop(kad_tx);
    let SearchEvent::SearchCompleted { total_results, .. } = next_event(&mut evt_rx).await else {
        panic!("expected completion");
    };
    assert_eq!(total_results, 1);
    assert_eq!(start.elapsed(), Duration::from_secs(14));
    task.await.expect("task ended cleanly");
}

/// A search nobody answers still completes
/// with zero results — once the server's answer wait has run out (the session
/// closes the leg then), not after one quiet window from the start.
#[tokio::test(start_paused = true)]
async fn a_search_nobody_answers_completes_after_the_server_answer_wait() {
    let start = Instant::now();
    let (tcp_tx, tcp_rx) = mpsc::channel::<ServerSearchEvent>(8);
    let live = LiveSearches::default();
    let (evt_tx, mut evt_rx) = mpsc::channel(16);
    let (_cancel_tx, cancel_rx) = watch::channel(false);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(12)).await;
        drop(tcp_tx);
    });
    let task = tokio::spawn(
        SearchTask {
            search_id: SearchId::from_u64(553),
            stream: SearchStream { event_rx: tcp_rx },
            rows: live.register(SearchId::from_u64(553), query().into()),
            // Kad off: a pre-closed leg.
            kad_rx: crate::search::KadKeywordLeg::settled(),
            global_sweep: sweep_already_done(),
            windows: production_windows(),
            evt_tx,
            cancel_rx,
            paging: crate::search::Paging::inert(
                rmule_primitives::KeywordQuery::new(rmule_primitives::Ed2kText::from_utf8("a"))
                    .expect("a query")
                    .into(),
            ),
            legs: crate::service::SearchLegs::SENT,
            late: crate::search::LateLegs::default(),
            lost: tokio::sync::mpsc::unbounded_channel().0,
        }
        .run(),
    );

    let SearchEvent::SearchCompleted { total_results, .. } = next_event(&mut evt_rx).await else {
        panic!("expected completion");
    };
    assert_eq!(total_results, 0);
    assert_eq!(start.elapsed(), Duration::from_secs(15));
    task.await.expect("task ended cleanly");
}

/// Each accepted batch pushes completion out by a whole quiet window. The
/// server answers once, so the second batch here is the global sweep's,
/// arriving inside the window the server's answer opened.
#[tokio::test(start_paused = true)]
async fn each_accepted_batch_restarts_the_quiet_window() {
    let start = Instant::now();
    let (tcp_tx, tcp_rx) = mpsc::channel::<ServerSearchEvent>(8);
    let live = LiveSearches::default();
    let (evt_tx, mut evt_rx) = mpsc::channel(16);
    let (_cancel_tx, cancel_rx) = watch::channel(false);
    let task = tokio::spawn(
        SearchTask {
            search_id: SearchId::from_u64(554),
            stream: SearchStream { event_rx: tcp_rx },
            rows: live.register(SearchId::from_u64(554), query().into()),
            kad_rx: crate::search::KadKeywordLeg::settled(),
            global_sweep: sweep_already_done(),
            windows: production_windows(),
            evt_tx,
            cancel_rx,
            paging: crate::search::Paging::inert(
                rmule_primitives::KeywordQuery::new(rmule_primitives::Ed2kText::from_utf8("a"))
                    .expect("a query")
                    .into(),
            ),
            legs: crate::service::SearchLegs::SENT,
            late: crate::search::LateLegs::default(),
            lost: tokio::sync::mpsc::unbounded_channel().0,
        }
        .run(),
    );

    tokio::time::sleep(Duration::from_secs(1)).await;
    live.deliver(vec![result(0xA1, "d-a.bin")], Some(SearchId::from_u64(554)));
    drop(tcp_tx);
    assert!(matches!(
        next_event(&mut evt_rx).await,
        SearchEvent::SearchResultsReceived { .. }
    ));

    tokio::time::sleep(Duration::from_secs(2)).await;
    live.deliver(vec![result(0xB2, "d-b.bin")], None);
    assert!(matches!(
        next_event(&mut evt_rx).await,
        SearchEvent::SearchResultsReceived { .. }
    ));

    let SearchEvent::SearchCompleted { total_results, .. } = next_event(&mut evt_rx).await else {
        panic!("expected completion");
    };
    assert_eq!(total_results, 2);
    assert_eq!(start.elapsed(), Duration::from_secs(6));
    task.await.expect("task ended cleanly");
}
