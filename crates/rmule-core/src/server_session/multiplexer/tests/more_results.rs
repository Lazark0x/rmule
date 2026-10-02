//! Asking a server for more results (ADR-0036) over the fake
//! link: the answer that says more names its search as the **pager** only while
//! its request is the newest on the link; a request for more is spaced, owned
//! and answered like any request; any later search request lets the pages go;
//! and a search asks at most [`MORE_RESULTS_ASKS`] times. The more-results
//! byte on these answers is derived (eMule `SearchList.cpp:266-277`,
//! ed2k-server `search.rs:186-187`) — no captured answer has said more.

use rmule_ed2k::Ed2kCommand;

use super::search::{Bench, news, phrase, row};
use crate::search::{MORE_RESULTS_ASKS, ServerMoreResults};
use crate::server_session::ServerSearchEvent;
use crate::service::SearchId;

fn pager(id: u64, asks_left: u8) -> Option<ServerMoreResults> {
    Some(ServerMoreResults {
        search_id: SearchId::from_u64(id),
        asks_left,
    })
}

/// The first page says more; the request for the next is the bare opcode,
/// spaced from the search's own; its answer is the search's, whole,
/// and joins nothing else — even a row that proves another live search's query
/// reaches that one only by proof, as any answer's.
#[tokio::test(start_paused = true)]
async fn the_next_page_is_the_asking_searchs_own_answer() {
    let mut bench = Bench::new();
    let mut linux = bench.start(1, phrase("linux")).await;
    assert!(matches!(
        bench.next_sent().await,
        Ed2kCommand::Search { .. }
    ));
    bench.answer_page(vec![row(1, "linux-1.iso")], true).await;
    assert_eq!(news(&mut linux.leg).await, None);
    assert_eq!(bench.pager(), pager(1, MORE_RESULTS_ASKS));

    let mut other = bench.start(2, phrase("gamma")).await;
    // …which lets the pages go: the server keeps one search's rows per link.
    assert!(matches!(
        bench.next_sent().await,
        Ed2kCommand::Search { .. }
    ));
    assert_eq!(bench.pager(), None);
    bench.answer_page(Vec::new(), false).await;
    assert_eq!(news(&mut other.leg).await, None);
    let mut refused = bench.more(1).await;
    assert_eq!(
        refused.next_event().await,
        Some(ServerSearchEvent::MoreNotOffered)
    );

    // A fresh search that says more, asked for its next page.
    let mut beta = bench.start(3, phrase("beta")).await;
    assert!(matches!(
        bench.next_sent().await,
        Ed2kCommand::Search { .. }
    ));
    bench.answer_page(vec![row(3, "beta-1.iso")], true).await;
    assert_eq!(news(&mut beta.leg).await, None);
    let mut page = bench.more(3).await;
    assert_eq!(bench.next_sent().await, Ed2kCommand::QueryMoreResults);
    assert_eq!(bench.pager(), None, "out on the link, not askable twice");
    bench.answer_page(vec![row(4, "beta-2.iso")], true).await;
    assert_eq!(news(&mut page).await, None);
    assert_eq!(bench.pager(), pager(3, MORE_RESULTS_ASKS - 1));

    let names = |rows: &mut crate::search::AttributedRows| -> Vec<String> {
        rows.drain()
            .iter()
            .map(|row| row.primary_name().to_display_string())
            .collect()
    };
    assert_eq!(names(&mut beta.rows), ["beta-1.iso", "beta-2.iso"]);
    assert_eq!(names(&mut linux.rows), ["linux-1.iso"]);
    assert!(names(&mut other.rows).is_empty());
}

/// An answer that says more while a later request is already on the link
/// names nobody: the server replaced those rows with the later search's.
#[tokio::test(start_paused = true)]
async fn more_said_after_a_later_request_went_out_is_nobodys() {
    let mut bench = Bench::new();
    let mut first = bench.start(1, phrase("alpha")).await;
    let mut second = bench.start(2, phrase("beta")).await;
    for _ in 0..2 {
        assert!(matches!(
            bench.next_sent().await,
            Ed2kCommand::Search { .. }
        ));
    }
    bench.answer_page(vec![row(1, "alpha.iso")], true).await;
    assert_eq!(news(&mut first.leg).await, None);
    assert_eq!(bench.pager(), None);
    bench.answer_page(Vec::new(), false).await;
    assert_eq!(news(&mut second.leg).await, None);
}

/// A request for more waits its turn like any request; a search request that
/// goes out ahead of it lets the pages go, and it is never sent.
#[tokio::test(start_paused = true)]
async fn a_request_for_more_behind_another_search_is_not_sent() {
    let mut bench = Bench::new();
    let mut first = bench.start(1, phrase("alpha")).await;
    assert!(matches!(
        bench.next_sent().await,
        Ed2kCommand::Search { .. }
    ));
    bench.answer_page(vec![row(1, "alpha.iso")], true).await;
    assert_eq!(news(&mut first.leg).await, None);

    let _second = bench.start(2, phrase("beta")).await;
    let mut more = bench.more(1).await;
    assert!(matches!(
        bench.next_sent().await,
        Ed2kCommand::Search { .. }
    ));
    assert_eq!(
        news(&mut more).await,
        Some(ServerSearchEvent::MoreNotOffered)
    );
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    assert!(bench.sent.try_recv().is_err(), "no request for more left");
}

/// eMule's limit: a search asks for at most five pages past the first; the
/// server may still say more, and says so, but rmule stops asking.
#[tokio::test(start_paused = true)]
async fn a_search_asks_for_at_most_five_more_pages() {
    let mut bench = Bench::new();
    let mut search = bench.start(1, phrase("alpha")).await;
    assert!(matches!(
        bench.next_sent().await,
        Ed2kCommand::Search { .. }
    ));
    bench.answer_page(vec![row(0, "alpha-0.iso")], true).await;
    assert_eq!(news(&mut search.leg).await, None);
    for page in 1..=MORE_RESULTS_ASKS {
        let mut leg = bench.more(1).await;
        assert_eq!(bench.next_sent().await, Ed2kCommand::QueryMoreResults);
        bench.answer_page(vec![row(page, "alpha.iso")], true).await;
        assert_eq!(news(&mut leg).await, None);
    }
    assert_eq!(bench.pager(), pager(1, 0));
    let mut refused = bench.more(1).await;
    assert_eq!(
        refused.next_event().await,
        Some(ServerSearchEvent::MoreNotOffered)
    );
}

/// A request the server drops leaves an answer owed that never comes (ADR-0034,
/// "Owed answers lapse"): until it lapses no answer names a pager, and once it
/// has, places are trusted again.
#[tokio::test(start_paused = true)]
async fn an_owed_answer_lapses_and_an_answer_names_its_pager_again() {
    let mut bench = Bench::new();
    let mut dropped = bench.start(1, phrase("alpha")).await;
    assert!(matches!(
        bench.next_sent().await,
        Ed2kCommand::Search { .. }
    ));
    assert_eq!(
        news(&mut dropped.leg).await,
        None,
        "its answer wait ran out"
    );

    let mut owed = bench.start(2, phrase("beta")).await;
    assert!(matches!(
        bench.next_sent().await,
        Ed2kCommand::Search { .. }
    ));
    bench.answer_page(vec![row(2, "beta-1.iso")], true).await;
    assert_eq!(news(&mut owed.leg).await, None);
    assert_eq!(bench.pager(), None, "an answer is owed: no owner");

    tokio::time::sleep(super::super::answer_order::OWED_LAPSE).await;
    let mut lapsed = bench.start(3, phrase("gamma")).await;
    assert!(matches!(
        bench.next_sent().await,
        Ed2kCommand::Search { .. }
    ));
    bench.answer_page(vec![row(3, "gamma-1.iso")], true).await;
    assert_eq!(news(&mut lapsed.leg).await, None);
    assert_eq!(bench.pager(), pager(3, MORE_RESULTS_ASKS));
}
