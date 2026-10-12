//! The Kad leg tells the operator what its walk did: a walk that never asked
//! anybody ends the leg as not sent, saying why, and a walk that put off the
//! keyword's publish round says so on the search (ADR-0034 §5, ADR-0062 walk
//! ownership).

use std::time::Duration;

use tokio::sync::{mpsc, watch};

use super::sweep_already_done;
use crate::search::{
    KadKeywordEnd, KadWalkFact, LiveSearches, SearchTask, SearchWindows, kad_keyword_leg,
};
use crate::server_session::{SearchStream, ServerSearchEvent};
use crate::service::{CoreEvent, LegNotSent, SearchEvent, SearchId, SearchLegState};
use rmule_primitives::{Ed2kText, KeywordQuery};

#[tokio::test(start_paused = true)]
async fn a_held_keyword_ends_the_kad_leg_not_sent_and_a_put_off_publish_is_told() {
    let (tcp_tx, tcp_rx) = mpsc::channel::<ServerSearchEvent>(8);
    drop(tcp_tx);
    let live = LiveSearches::default();
    let (evt_tx, mut evt_rx) = mpsc::channel(16);
    let (_cancel_tx, cancel_rx) = watch::channel(false);
    let (sink, kad_rx) = kad_keyword_leg();
    let query = KeywordQuery::new(Ed2kText::from_utf8("song")).expect("a query");
    let search_id = SearchId::from_u64(692);
    let task = tokio::spawn(
        SearchTask {
            search_id,
            stream: SearchStream { event_rx: tcp_rx },
            rows: live.register(search_id, query.clone().into()),
            kad_rx,
            global_sweep: sweep_already_done(),
            windows: SearchWindows {
                quiet: Duration::from_secs(3),
                kad_lifetime: Duration::from_secs(45),
            },
            evt_tx,
            cancel_rx,
            paging: crate::search::Paging::inert(query.into()),
            legs: crate::service::SearchLegs::SENT,
            late: crate::search::LateLegs::default(),
            lost: mpsc::unbounded_channel().0,
        }
        .run(),
    );

    sink.tell(KadWalkFact::PublishDeferred);
    sink.tell(KadWalkFact::Ended(KadKeywordEnd::TargetHeld));
    drop(sink);

    let mut deferred = false;
    let mut kad = None;
    loop {
        match evt_rx.recv().await.expect("events open") {
            CoreEvent::Search(SearchEvent::SearchDeferredKadPublish { search_id: id }) => {
                assert_eq!(id, search_id);
                deferred = true;
            }
            CoreEvent::Search(SearchEvent::SearchLegsChanged { legs, .. }) => kad = Some(legs.kad),
            CoreEvent::Search(SearchEvent::SearchCompleted { total_results, .. }) => {
                assert_eq!(total_results, 0);
                break;
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!(deferred, "the put-off publish is told on the search");
    assert_eq!(
        kad,
        Some(SearchLegState::NotSent(LegNotSent::KadKeywordHeld))
    );
    task.await.expect("task ended cleanly");
}

/// A row the Kad walk could not keep is counted on the search by its reason,
/// as a server answer's skipped row is.
#[tokio::test(start_paused = true)]
async fn a_dropped_kad_row_is_told_as_a_skipped_row() {
    let (_tcp_tx, tcp_rx) = mpsc::channel::<ServerSearchEvent>(8);
    let live = LiveSearches::default();
    let (evt_tx, mut evt_rx) = mpsc::channel(16);
    let (_cancel_tx, cancel_rx) = watch::channel(false);
    let (sink, kad_rx) = kad_keyword_leg();
    let query = KeywordQuery::new(Ed2kText::from_utf8("film")).expect("a query");
    let search_id = SearchId::from_u64(700);
    tokio::spawn(
        SearchTask {
            search_id,
            stream: SearchStream { event_rx: tcp_rx },
            rows: live.register(search_id, query.clone().into()),
            kad_rx,
            global_sweep: sweep_already_done(),
            windows: SearchWindows {
                quiet: Duration::from_secs(3),
                kad_lifetime: Duration::from_secs(45),
            },
            evt_tx,
            cancel_rx,
            paging: crate::search::Paging::inert(query.into()),
            legs: crate::service::SearchLegs::SENT,
            late: crate::search::LateLegs::default(),
            lost: mpsc::unbounded_channel().0,
        }
        .run(),
    );

    sink.tell(KadWalkFact::RowSkipped(
        rmule_ed2k::SearchResultSkipReason::FileSizeAboveLimit,
    ));
    loop {
        match evt_rx.recv().await.expect("events open") {
            CoreEvent::Search(SearchEvent::SearchResultSkipped {
                search_id: id,
                reason,
            }) => {
                assert_eq!(id, search_id);
                assert_eq!(
                    reason,
                    rmule_ed2k::SearchResultSkipReason::FileSizeAboveLimit
                );
                break;
            }
            CoreEvent::Search(SearchEvent::SearchLegsChanged { .. }) => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    drop(sink);
}
