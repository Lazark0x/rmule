//! The session's search requests over the fake link (ADR-0034): every request
//! goes out in turn, the search spacing after the last, each answer is the
//! oldest unanswered request's — its owner — and its rows reach the owner and
//! every other live search they prove, through **Search Attribution**. After
//! an answer wait runs out, places are not trusted until the owed answer is
//! paid back.

use std::time::Duration;

use rmule_ed2k::{Ed2kCommand, Ed2kEvent, SearchResultSkipReason};
use rmule_primitives::{Ed2kText, KeywordQuery, PeerSource, SearchQuery, SearchResult};
use tokio::sync::mpsc;

use super::super::super::tests::{FakeLink, client_id, test_sinks};
use super::super::*;
use crate::diagnostics::DiagnosticsState;
use crate::own_identity::SharedOwnIdentity;
use crate::search::{AttributedRows, LiveSearches};

/// The server's answer wait (amule-kno `SERVER_ANSWER_TIMEOUT_MS`).
const ANSWER_WAIT: Duration = Duration::from_secs(12);

pub(super) fn phrase(text: &str) -> SearchQuery {
    KeywordQuery::new(Ed2kText::from_utf8(text)).unwrap().into()
}

pub(super) fn row(hash: u8, name: &str) -> SearchResult {
    SearchResult::new(
        FileHash::from_bytes([hash; FileHash::BYTE_LEN]),
        1024,
        vec![Ed2kText::from_utf8(name)],
        vec![PeerSource::new(client_id(), 4662)],
    )
    .unwrap()
}

/// The leg's next event past the spacing's own news: what these tests
/// read is the answer, the skip or the close.
pub(super) async fn news(leg: &mut SearchStream) -> Option<ServerSearchEvent> {
    loop {
        match leg.next_event().await {
            Some(ServerSearchEvent::WaitingForTurn { .. } | ServerSearchEvent::SentToServer) => {}
            other => return other,
        }
    }
}

fn names(rows: &[SearchResult]) -> Vec<String> {
    rows.iter()
        .map(|row| row.primary_name().to_display_string())
        .collect()
}

/// A fresh session over a fake link, the registry its searches live in, and
/// the diagnostics that count what reached nobody.
pub(super) struct Bench {
    handle: ServerSessionHandle,
    server: mpsc::Sender<Ed2kEvent>,
    pub(super) sent: mpsc::Receiver<Ed2kCommand>,
    live: LiveSearches,
    diagnostics: DiagnosticsState,
}

/// One search as the actor holds it: its server leg and its attributed rows.
pub(super) struct Search {
    pub(super) leg: SearchStream,
    pub(super) rows: AttributedRows,
}

impl Bench {
    pub(super) fn new() -> Self {
        let (server, evt_rx) = mpsc::channel(8);
        let (cmd_tx, sent) = mpsc::channel(8);
        let handle = ServerSession::spawn(
            FakeLink {
                events: evt_rx,
                sent: cmd_tx,
            },
            client_id(),
            test_sinks(SharedOwnIdentity::default()),
        );
        let diagnostics = DiagnosticsState::default();
        Self {
            handle,
            server,
            sent,
            live: LiveSearches::new(diagnostics.clone()),
            diagnostics,
        }
    }

    pub(super) async fn start(&self, id: u64, query: SearchQuery) -> Search {
        let search_id = SearchId::from_u64(id);
        let rows = self.live.register(search_id, query.clone());
        let leg = self
            .handle
            .start_search(search_id, query, ANSWER_WAIT, self.live.clone())
            .await
            .unwrap();
        Search { leg, rows }
    }

    async fn sent_phrase(&mut self) -> String {
        match self.sent.recv().await.unwrap() {
            Ed2kCommand::Search {
                query: SearchQuery::Keywords(query),
            } => query.phrase().to_display_string(),
            other => panic!("expected a search request, got {other:?}"),
        }
    }

    async fn answer(&self, rows: Vec<SearchResult>) {
        self.answer_page(rows, false).await;
    }

    /// An answer that says whether the server holds more.
    pub(super) async fn answer_page(&self, rows: Vec<SearchResult>, more_available: bool) {
        self.server
            .send(Ed2kEvent::SearchResultsFound {
                skipped: Vec::new(),
                results: rows,
                more_available,
            })
            .await
            .unwrap();
    }

    /// The next command the session put on the link.
    pub(super) async fn next_sent(&mut self) -> Ed2kCommand {
        self.sent.recv().await.unwrap()
    }

    /// Ask for `id`'s next page.
    pub(super) async fn more(&self, id: u64) -> SearchStream {
        self.handle
            .more_results(SearchId::from_u64(id), ANSWER_WAIT, self.live.clone())
            .await
            .unwrap()
    }

    /// The search the session says its server holds more rows for.
    pub(super) fn pager(&self) -> Option<crate::search::ServerMoreResults> {
        *self.live.watch_more().borrow()
    }

    fn unattributed(&self) -> u64 {
        self.diagnostics
            .snapshot()
            .session
            .search_rows_unattributed_total
    }
}

/// Three searches started together go out in turn, the search spacing apart
/// (Lugdunum's spacing, ADR-0035), and answers land each row in
/// exactly the searches it answers: its owner's, whole, and every other live
/// search it proves.
#[tokio::test(start_paused = true)]
async fn three_searches_go_out_in_turn_and_each_row_lands_where_it_belongs() {
    let mut bench = Bench::new();
    let mut ubuntu = bench.start(1, phrase("ubuntu")).await;
    let mut debian = bench.start(2, phrase("debian")).await;
    let mut desktop = bench.start(3, phrase("ubuntu desktop")).await;
    let start = tokio::time::Instant::now();
    assert_eq!(bench.sent_phrase().await, "ubuntu");
    assert_eq!(bench.sent_phrase().await, "debian");
    assert_eq!(start.elapsed(), answer_order::SEARCH_SPACING);
    assert_eq!(bench.sent_phrase().await, "ubuntu desktop");
    assert_eq!(start.elapsed(), 2 * answer_order::SEARCH_SPACING);

    // Ubuntu's answer: the server's verdict stands for its owner — a row
    // whose name shows no query word still answers it — while the desktop
    // search takes only the row that proves its own query.
    bench
        .answer(vec![
            row(1, "ubuntu-desktop.iso"),
            row(2, "ubuntu-server.iso"),
            row(3, "matched-on-a-tag.bin"),
        ])
        .await;
    assert_eq!(news(&mut ubuntu.leg).await, None, "its answer settles it");
    assert_eq!(
        names(&ubuntu.rows.drain()),
        [
            "ubuntu-desktop.iso",
            "ubuntu-server.iso",
            "matched-on-a-tag.bin"
        ]
    );
    assert_eq!(names(&desktop.rows.drain()), ["ubuntu-desktop.iso"]);
    assert!(debian.rows.drain().is_empty());

    bench.answer(vec![row(4, "debian-12.iso")]).await;
    assert_eq!(news(&mut debian.leg).await, None);
    assert_eq!(names(&debian.rows.drain()), ["debian-12.iso"]);
    assert!(ubuntu.rows.drain().is_empty());
    assert!(desktop.rows.drain().is_empty());

    bench.answer(vec![row(5, "Ubuntu Desktop 24.iso")]).await;
    assert_eq!(news(&mut desktop.leg).await, None);
    assert_eq!(names(&desktop.rows.drain()), ["Ubuntu Desktop 24.iso"]);
    assert_eq!(
        names(&ubuntu.rows.drain()),
        ["Ubuntu Desktop 24.iso"],
        "a later answer's row that proves an earlier search is that search's too"
    );
    assert_eq!(bench.unattributed(), 0);
}

/// The owner keeps what the server matched on fields it cannot see, but a
/// field the row carries can still overrule the server (ed2k-server ignores
/// the availability floor outright).
#[tokio::test]
async fn the_owner_drops_only_rows_a_carried_field_contradicts() {
    let bench = Bench::new();
    let floor: SearchQuery = KeywordQuery::new(Ed2kText::from_utf8("live"))
        .unwrap()
        .with_min_availability(5)
        .into();
    let mut search = bench.start(1, floor).await;
    bench
        .answer(vec![
            row(1, "live-a.mp3"),
            row(2, "live-b.mp3").with_reported_availability(2),
            row(3, "live-c.mp3").with_reported_availability(9),
        ])
        .await;
    assert_eq!(news(&mut search.leg).await, None);
    assert_eq!(names(&search.rows.drain()), ["live-a.mp3", "live-c.mp3"]);
    assert_eq!(bench.unattributed(), 1);
}

/// An answer whose search has ended is shown nowhere it does not belong:
/// its rows reach the live searches they prove, and the rest are counted.
#[tokio::test]
async fn an_answer_after_its_search_ended_is_counted_not_shown() {
    let bench = Bench::new();
    let ended = bench.start(1, phrase("ubuntu")).await;
    let mut other = bench.start(2, phrase("debian")).await;
    drop(ended);

    bench
        .answer(vec![row(1, "ubuntu.iso"), row(2, "debian-on-ubuntu.iso")])
        .await;
    bench.answer(vec![]).await;
    assert_eq!(news(&mut other.leg).await, None);
    assert_eq!(names(&other.rows.drain()), ["debian-on-ubuntu.iso"]);
    assert_eq!(bench.unattributed(), 1);
}

#[tokio::test(start_paused = true)]
async fn an_undecodable_answer_takes_its_place_and_tells_its_owner() {
    let mut bench = Bench::new();
    let mut first = bench.start(1, phrase("alpha")).await;
    let mut second = bench.start(2, phrase("beta")).await;
    assert_eq!(bench.sent_phrase().await, "alpha");
    assert_eq!(bench.sent_phrase().await, "beta");
    bench
        .server
        .send(Ed2kEvent::SearchResultSkipped {
            reason: SearchResultSkipReason::MalformedPayload,
        })
        .await
        .unwrap();
    assert_eq!(
        news(&mut first.leg).await,
        Some(ServerSearchEvent::Skipped {
            reason: SearchResultSkipReason::MalformedPayload
        })
    );
    assert_eq!(news(&mut first.leg).await, None);
    bench.answer(vec![row(1, "whatever.bin")]).await;
    assert_eq!(news(&mut second.leg).await, None);
    assert_eq!(names(&second.rows.drain()), ["whatever.bin"]);
}

/// Each row an answer skipped is told to that answer's owner, by its reason,
/// before its leg settles; the rows that stood reach it all the same.
#[tokio::test(start_paused = true)]
async fn an_answer_tells_its_owner_each_row_it_skipped() {
    let mut bench = Bench::new();
    let mut first = bench.start(1, phrase("gamma")).await;
    assert_eq!(bench.sent_phrase().await, "gamma");
    bench
        .server
        .send(Ed2kEvent::SearchResultsFound {
            results: vec![row(1, "gamma.iso")],
            skipped: vec![
                SearchResultSkipReason::FileSizeAboveLimit,
                SearchResultSkipReason::MissingFileName,
            ],
            more_available: false,
        })
        .await
        .unwrap();
    for reason in [
        SearchResultSkipReason::FileSizeAboveLimit,
        SearchResultSkipReason::MissingFileName,
    ] {
        assert_eq!(
            news(&mut first.leg).await,
            Some(ServerSearchEvent::Skipped { reason })
        );
    }
    assert_eq!(news(&mut first.leg).await, None);
    assert_eq!(names(&first.rows.drain()), ["gamma.iso"]);
}

/// A server that never answers one request delays nobody else: that leg
/// closes after its own answer wait, and the answer then owed makes places
/// untrusted — rows go only where they prove a query — until an answer
/// arrives with nothing outstanding and pays it back.
#[tokio::test(start_paused = true)]
async fn an_unanswered_request_delays_no_one_and_suspends_places_until_paid_back() {
    let mut bench = Bench::new();
    let mut silent = bench.start(1, phrase("alpha")).await;
    let start = tokio::time::Instant::now();
    assert_eq!(news(&mut silent.leg).await, None);
    assert_eq!(start.elapsed(), ANSWER_WAIT, "closed by its own wait");

    // An answer is owed: the next answer has no trusted owner.
    let mut beta = bench.start(2, phrase("beta")).await;
    let _ = bench.sent_phrase().await;
    let _ = bench.sent_phrase().await;
    bench
        .answer(vec![row(1, "beta.iso"), row(2, "unrelated.bin")])
        .await;
    assert_eq!(
        news(&mut beta.leg).await,
        None,
        "its place still settles it"
    );
    assert_eq!(names(&beta.rows.drain()), ["beta.iso"]);
    assert_eq!(bench.unattributed(), 1);

    // The late answer arrives with nothing outstanding: debt paid. It still
    // reaches its live search, by what it contains.
    bench.answer(vec![row(3, "alpha.iso")]).await;
    let late = silent.rows.recv().await.expect("registered");
    assert_eq!(names(&late.rows), ["alpha.iso"]);
    let mut gamma = bench.start(3, phrase("gamma")).await;
    assert_eq!(bench.sent_phrase().await, "gamma");
    bench.answer(vec![row(4, "matched-on-a-tag.bin")]).await;
    assert_eq!(news(&mut gamma.leg).await, None);
    assert_eq!(
        names(&gamma.rows.drain()),
        ["matched-on-a-tag.bin"],
        "places are trusted again"
    );
}

#[tokio::test]
async fn a_dropped_link_tells_every_request_out() {
    let bench = Bench::new();
    let mut first = bench.start(1, phrase("alpha")).await;
    let mut second = bench.start(2, phrase("beta")).await;
    drop(bench.server);
    for leg in [&mut first.leg, &mut second.leg] {
        assert!(matches!(
            news(leg).await,
            Some(ServerSearchEvent::Disconnected) | None
        ));
    }
}

/// A request held back by the spacing tells its search so, with the wait, and
/// again when it goes on the link — the operator is never left with a
/// silent lag.
#[tokio::test(start_paused = true)]
async fn a_search_held_for_its_turn_hears_the_wait_and_the_send() {
    let mut bench = Bench::new();
    let _first = bench.start(1, phrase("alpha")).await;
    let mut second = bench.start(2, phrase("beta")).await;
    assert_eq!(
        second.leg.next_event().await,
        Some(ServerSearchEvent::WaitingForTurn {
            send_in: answer_order::SEARCH_SPACING
        })
    );
    assert_eq!(bench.sent_phrase().await, "alpha");
    assert_eq!(bench.sent_phrase().await, "beta");
    assert_eq!(
        second.leg.next_event().await,
        Some(ServerSearchEvent::SentToServer)
    );
}

/// The spacing counts from the last send, not from the ask: a search asked
/// 1.5 s after the last one went out waits the half second left, then goes out
/// two seconds after it — two whole seconds of the server's clock, so Lugdunum
/// neither answers it empty nor counts it a strike (ADR-0035).
#[tokio::test(start_paused = true)]
async fn a_search_asked_soon_after_the_last_one_goes_out_two_seconds_after_its_send() {
    let mut bench = Bench::new();
    let _first = bench.start(1, phrase("alpha")).await;
    let first_sent = tokio::time::Instant::now();
    assert_eq!(bench.sent_phrase().await, "alpha");
    tokio::time::advance(Duration::from_millis(1500)).await;
    let mut second = bench.start(2, phrase("beta")).await;
    assert_eq!(
        second.leg.next_event().await,
        Some(ServerSearchEvent::WaitingForTurn {
            send_in: Duration::from_millis(500)
        })
    );
    assert_eq!(bench.sent_phrase().await, "beta");
    assert_eq!(first_sent.elapsed(), Duration::from_millis(2000));
}
