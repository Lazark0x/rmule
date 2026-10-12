//! More results at the core seam (ADR-0036): a server answer
//! that says it holds more names the search on the diagnostics level; the
//! operator's `MoreResults` puts `OP_QUERY_MORE_RESULT` on the link; the page
//! joins the same **Search Result Set**, and the search completes again. The
//! more-results byte the loopback server writes is derived (ed2k-server
//! `search.rs:186-187`), not captured.

use std::time::Duration;

use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, MORE_RESULTS_ASKS, SearchCommand, SearchEvent,
    SearchId, ServerMoreResults,
};
use rmule_ed2k::Opcode;
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

async fn completed_with(core: &mut Core, search_id: SearchId, total: usize) {
    next_expected(core, "the search to complete", |event| {
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchCompleted { search_id: id, total_results })
                if *id == search_id && *total_results == total
        )
    })
    .await;
}

async fn more(core: &Core, search_id: SearchId) {
    core.send(CoreCommand::Search(SearchCommand::MoreResults {
        search_id,
    }))
    .await
    .unwrap();
}

#[tokio::test]
async fn the_next_page_joins_the_same_result_set() {
    let mut server = LoopbackSearchServer::start().await;
    let mut core = Core::builder(
        CoreConfig {
            search_quiet_timeout: Duration::from_millis(150),
            ..CoreConfig::default()
        },
        rmule_testkit::memory_store(),
    )
    .settings(rmule_core::CoreSettings::default())
    .build();
    let search_id = SearchId::mint();
    rmule_testkit::connect_to(&core, &server.endpoint).await;
    core.send(CoreCommand::Search(SearchCommand::StartSearch {
        search_id,
        query: search_query("linux").into(),
    }))
    .await
    .unwrap();
    server.wait_for_search_request().await;
    server.send_page(vec![row(1, "linux-1.iso")], true).await;
    completed_with(&mut core, search_id, 1).await;
    assert_eq!(
        core.diagnostics_snapshot().search_more_results,
        Some(ServerMoreResults {
            search_id,
            asks_left: MORE_RESULTS_ASKS
        })
    );

    more(&core, search_id).await;
    next_expected(&mut core, "the request for more", |event| {
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchMoreRequested { search_id: id }) if *id == search_id
        )
    })
    .await;
    server.wait_for_client_opcode(Opcode::QueryMoreResult).await;
    server.send_page(vec![row(2, "linux-2.iso")], false).await;
    let whole = next_expected(&mut core, "the page joining the set", |event| {
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchResultsReceived { search_id: id, .. }) if *id == search_id
        )
    })
    .await;
    let CoreEvent::Search(SearchEvent::SearchResultsReceived { results, .. }) = whole else {
        unreachable!()
    };
    let names: Vec<String> = results
        .iter()
        .map(|row| row.primary_name().to_display_string())
        .collect();
    assert_eq!(names, ["linux-1.iso", "linux-2.iso"]);
    completed_with(&mut core, search_id, 2).await;
    assert_eq!(core.diagnostics_snapshot().search_more_results, None);

    // The last page said no more: nothing is left to ask for.
    more(&core, search_id).await;
    next_expected(&mut core, "the refusal", |event| {
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchMoreRefused { search_id: id }) if *id == search_id
        )
    })
    .await;
}
