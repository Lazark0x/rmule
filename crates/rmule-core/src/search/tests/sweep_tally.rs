//! The sweep leg's count (ADR-0034's amendment): how many servers the
//! **Global Search Sweep** asked, set when it settles, and how many answered
//! this search, counted as their `0x99`s arrive — each server once.

use std::time::Duration;

use tokio::sync::{mpsc, oneshot, watch};

use super::{result, server_udp};
use crate::search::{LiveSearches, SearchTask, SearchWindows};
use crate::server_session::{SearchStream, ServerSearchEvent};
use crate::service::{CoreEvent, SearchEvent, SearchId, SearchLegState, SearchLegs, SweepTally};
use rmule_primitives::{Ed2kText, KeywordQuery};

fn query() -> KeywordQuery {
    KeywordQuery::new(Ed2kText::from_utf8("tally")).expect("valid phrase")
}

/// The next leg picture, skipping every other event.
async fn next_legs(evt_rx: &mut mpsc::Receiver<CoreEvent>) -> SearchLegs {
    loop {
        match evt_rx.recv().await.expect("events open") {
            CoreEvent::Search(SearchEvent::SearchLegsChanged { legs, .. }) => return legs,
            _ => continue,
        }
    }
}

#[tokio::test(start_paused = true)]
async fn the_sweep_leg_counts_the_servers_asked_and_each_server_that_answered_once() {
    let (tcp_tx, tcp_rx) = mpsc::channel::<ServerSearchEvent>(8);
    let live = LiveSearches::default();
    let (sweep_tx, sweep_rx) = oneshot::channel::<u32>();
    let (evt_tx, mut evt_rx) = mpsc::channel(32);
    let (_cancel_tx, cancel_rx) = watch::channel(false);
    let (finished_tx, _finished_rx) = mpsc::channel(4);
    let search_id = SearchId::from_u64(730);
    let task = tokio::spawn(
        SearchTask {
            search_id,
            stream: SearchStream { event_rx: tcp_rx },
            rows: live.register(search_id, query().into()),
            kad_rx: crate::search::KadKeywordLeg::settled(),
            global_sweep: sweep_rx,
            windows: SearchWindows {
                quiet: Duration::from_secs(3),
                kad_lifetime: Duration::from_secs(45),
            },
            evt_tx,
            cancel_rx,
            finished_tx,
            paging: crate::search::Paging::inert(query().into()),
            legs: SearchLegs {
                kad: SearchLegState::NotRun,
                ..SearchLegs::SENT
            },
            late: crate::search::LateLegs::default(),
            lost: mpsc::unbounded_channel().0,
        }
        .run(),
    );

    assert_eq!(
        next_legs(&mut evt_rx).await.sweep_servers,
        SweepTally::default(),
        "nothing is known as the search starts"
    );

    // Two answers from one server count it once.
    live.deliver_udp_answer(vec![result(0x3A, "tally one.bin")], server_udp(11));
    assert_eq!(
        next_legs(&mut evt_rx).await.sweep_servers,
        SweepTally {
            asked: 0,
            answered: 1
        }
    );
    live.deliver_udp_answer(vec![result(0x4B, "tally two.bin")], server_udp(11));

    // The sweep settles having asked twelve servers.
    sweep_tx.send(12).expect("task listening");
    let legs = next_legs(&mut evt_rx).await;
    assert_eq!(legs.sweep, SearchLegState::Settled);
    assert_eq!(
        legs.sweep_servers,
        SweepTally {
            asked: 12,
            answered: 1
        }
    );

    // A second server answering after the sweep settled still counts; a TCP
    // answer names no server and counts nothing.
    live.deliver(vec![result(0x5C, "tally three.bin")], Some(search_id));
    live.deliver_udp_answer(vec![result(0x6D, "tally four.bin")], server_udp(12));
    assert_eq!(
        next_legs(&mut evt_rx).await.sweep_servers,
        SweepTally {
            asked: 12,
            answered: 2
        }
    );

    drop(tcp_tx);
    task.await.expect("task ended cleanly");
}
