//! The **Related-Files Search** inside the session loop: a grant withdrawn
//! between the actor's gate and the send fails that search alone and leaves
//! the session up, a mid-session `OP_IDCHANGE` moves the grant level a menu
//! reads, and — its results sharing no words with its query — its answer is
//! known by its place on the link alone (ADR-0037).

use rmule_ed2k::{CommandRejectReason, Ed2kCommandKind, ServerCapability, ServerTcpFlags};
use rmule_primitives::{Ed2kText, RelatedFilesQuery};

use super::super::super::tests::{FakeLink, client_id, connected, test_sinks};
use super::super::*;
use crate::RelatedSearchRefusal;
use crate::search::LiveSearches;

/// The server's answer wait (amule-kno `SERVER_ANSWER_TIMEOUT_MS`).
const ANSWER_WAIT: std::time::Duration = std::time::Duration::from_secs(12);

fn related() -> SearchQuery {
    RelatedFilesQuery::new(
        FileHash::from_bytes([0x5A; FileHash::BYTE_LEN]),
        Ed2kText::from_utf8("a.avi"),
    )
    .into()
}

#[tokio::test(start_paused = true)]
async fn a_withdrawn_grant_fails_the_related_search_and_keeps_the_session() {
    let (evt_tx, evt_rx) = mpsc::channel(8);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
    let handle = ServerSession::spawn(
        FakeLink {
            events: evt_rx,
            sent: cmd_tx,
        },
        client_id(),
        test_sinks(SharedOwnIdentity::default()),
    );
    let mut stream = handle
        .start_search(
            SearchId::from_u64(1),
            related(),
            ANSWER_WAIT,
            LiveSearches::default(),
        )
        .await
        .unwrap();
    assert!(matches!(
        cmd_rx.recv().await.unwrap(),
        Ed2kCommand::Search { .. }
    ));

    evt_tx
        .send(Ed2kEvent::CommandRejected {
            command: Ed2kCommandKind::Search,
            reason: CommandRejectReason::UnsupportedServerCapability {
                capability: ServerCapability::RelatedSearch,
            },
        })
        .await
        .unwrap();

    assert_eq!(
        stream.next_event().await,
        Some(ServerSearchEvent::RelatedSearchNotOffered)
    );
    assert!(handle.is_alive(), "the session outlives the refusal");
    // Held for the spacing, then sent — while its search still listens.
    let _second = handle
        .start_search(
            SearchId::from_u64(2),
            related(),
            ANSWER_WAIT,
            LiveSearches::default(),
        )
        .await
        .expect("the session still takes searches");
    assert!(matches!(
        cmd_rx.recv().await.unwrap(),
        Ed2kCommand::Search { .. }
    ));
}

#[tokio::test]
async fn a_mid_session_idchange_moves_the_grant_level() {
    let (evt_tx, evt_rx) = mpsc::channel(8);
    let (cmd_tx, _cmd_rx) = mpsc::channel(8);
    let (facts, diagnostics) = crate::server_list::test_facts(&[connected()]);
    diagnostics.set_connected_server(Some((connected(), rmule_ed2k::ServerGrants::default())));
    let _handle = ServerSession::spawn(
        FakeLink {
            events: evt_rx,
            sent: cmd_tx,
        },
        client_id(),
        SessionSinks {
            facts,
            ..test_sinks(SharedOwnIdentity::default())
        },
    );

    evt_tx
        .send(Ed2kEvent::LoginAccepted {
            client_id: client_id(),
            tcp_flags: Some(ServerTcpFlags::from_bits(ServerTcpFlags::RELATEDSEARCH)),
            facts: rmule_ed2k::ServerAssignedFacts::default(),
        })
        .await
        .unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while diagnostics.snapshot().related_search_refusal().is_some() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the re-assignment's grant reached the level within 2s");

    evt_tx
        .send(Ed2kEvent::LoginAccepted {
            client_id: client_id(),
            tcp_flags: None,
            facts: rmule_ed2k::ServerAssignedFacts::default(),
        })
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while diagnostics.snapshot().related_search_refusal()
            != Some(RelatedSearchRefusal::NotOffered)
        {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("a flagless re-assignment withdrew the grant within 2s");
}

fn row(hash: u8, name: &str) -> rmule_primitives::SearchResult {
    rmule_primitives::SearchResult::new(
        FileHash::from_bytes([hash; FileHash::BYTE_LEN]),
        1024,
        vec![Ed2kText::from_utf8(name)],
        Vec::new(),
    )
    .unwrap()
}

fn keywords(text: &str) -> SearchQuery {
    rmule_primitives::KeywordQuery::new(Ed2kText::from_utf8(text))
        .unwrap()
        .into()
}

/// A related search beside keyword searches, and a second related search:
/// each related answer is the one in its place, whole; its rows also reach the
/// keyword searches they prove, and nothing of a keyword answer reaches a
/// related search.
#[tokio::test(start_paused = true)]
async fn a_related_answer_is_known_by_its_place() {
    let (evt_tx, evt_rx) = mpsc::channel(8);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
    let handle = ServerSession::spawn(
        FakeLink {
            events: evt_rx,
            sent: cmd_tx,
        },
        client_id(),
        test_sinks(SharedOwnIdentity::default()),
    );
    let live = LiveSearches::default();
    let mut legs = Vec::new();
    let mut rows = Vec::new();
    for (id, query) in [(1, related()), (2, keywords("holiday")), (3, related())] {
        let search_id = SearchId::from_u64(id);
        rows.push(live.register(search_id, query.clone()));
        legs.push(
            handle
                .start_search(search_id, query, ANSWER_WAIT, live.clone())
                .await
                .unwrap(),
        );
    }
    let answer = |results| Ed2kEvent::SearchResultsFound {
        skipped: Vec::new(),
        results,
        more_available: false,
    };
    // Each answer follows its request on the link; the session spaces them.
    for _ in 0..3 {
        cmd_rx.recv().await.expect("a request on the link");
    }

    evt_tx
        .send(answer(vec![row(1, "beach.avi"), row(2, "holiday-2.avi")]))
        .await
        .unwrap();
    assert_eq!(super::search::news(&mut legs[0]).await, None);
    evt_tx
        .send(answer(vec![row(3, "holiday.iso"), row(4, "cake.jpg")]))
        .await
        .unwrap();
    assert_eq!(super::search::news(&mut legs[1]).await, None);
    evt_tx
        .send(answer(vec![row(5, "sunset.avi")]))
        .await
        .unwrap();
    assert_eq!(super::search::news(&mut legs[2]).await, None);

    let seen = |rows: &mut crate::search::AttributedRows| -> Vec<String> {
        rows.drain()
            .iter()
            .map(|row| row.primary_name().to_display_string())
            .collect()
    };
    assert_eq!(seen(&mut rows[0]), ["beach.avi", "holiday-2.avi"]);
    assert_eq!(
        seen(&mut rows[1]),
        ["holiday-2.avi", "holiday.iso", "cake.jpg"]
    );
    assert_eq!(seen(&mut rows[2]), ["sunset.avi"]);
}

/// With an answer owed, the answer in a related search's place may be that
/// late one: nothing in it is shown as the related search's, and it says so.
#[tokio::test(start_paused = true)]
async fn a_related_answer_while_an_answer_is_owed_is_not_shown() {
    let (evt_tx, evt_rx) = mpsc::channel(8);
    let (cmd_tx, _cmd_rx) = mpsc::channel(8);
    let handle = ServerSession::spawn(
        FakeLink {
            events: evt_rx,
            sent: cmd_tx,
        },
        client_id(),
        test_sinks(SharedOwnIdentity::default()),
    );
    let live = LiveSearches::default();
    let mut silent = handle
        .start_search(
            SearchId::from_u64(1),
            keywords("alpha"),
            ANSWER_WAIT,
            live.clone(),
        )
        .await
        .unwrap();
    assert_eq!(silent.next_event().await, None, "its wait ran out");

    let mut rows = live.register(SearchId::from_u64(2), related());
    let mut leg = handle
        .start_search(SearchId::from_u64(2), related(), ANSWER_WAIT, live.clone())
        .await
        .unwrap();
    evt_tx
        .send(Ed2kEvent::SearchResultsFound {
            skipped: Vec::new(),
            results: vec![row(1, "alpha.iso")],
            more_available: false,
        })
        .await
        .unwrap();
    assert_eq!(
        leg.next_event().await,
        Some(ServerSearchEvent::RelatedAnswerUnattributable)
    );
    assert!(rows.drain().is_empty());
}

fn refusal() -> Ed2kEvent {
    Ed2kEvent::CommandRejected {
        command: Ed2kCommandKind::Search,
        reason: CommandRejectReason::UnsupportedServerCapability {
            capability: ServerCapability::RelatedSearch,
        },
    }
}

/// Two related searches, one on the link and one waiting its turn,
/// and the grant withdrawn between them. The one sent keeps its place and its
/// answer; the one waiting is refused by its own id and never sent; no answer
/// changes owner.
#[tokio::test(start_paused = true)]
async fn a_withdrawn_grant_refuses_the_waiting_related_search_and_the_sent_one_keeps_its_answer() {
    let (evt_tx, evt_rx) = mpsc::channel(8);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
    let handle = ServerSession::spawn(
        FakeLink {
            events: evt_rx,
            sent: cmd_tx,
        },
        client_id(),
        test_sinks(SharedOwnIdentity::default()),
    );
    let live = LiveSearches::default();
    let (sent_id, waiting_id) = (SearchId::from_u64(1), SearchId::from_u64(2));
    let mut sent_rows = live.register(sent_id, related());
    let mut waiting_rows = live.register(waiting_id, related());
    let mut sent_leg = handle
        .start_search(sent_id, related(), ANSWER_WAIT, live.clone())
        .await
        .unwrap();
    cmd_rx.recv().await.expect("the first goes on the link");
    let mut waiting_leg = handle
        .start_search(waiting_id, related(), ANSWER_WAIT, live.clone())
        .await
        .unwrap();
    assert!(matches!(
        waiting_leg.next_event().await,
        Some(ServerSearchEvent::WaitingForTurn { .. })
    ));

    evt_tx
        .send(Ed2kEvent::LoginAccepted {
            client_id: client_id(),
            tcp_flags: None,
            facts: rmule_ed2k::ServerAssignedFacts::default(),
        })
        .await
        .unwrap();
    assert_eq!(
        waiting_leg.next_event().await,
        Some(ServerSearchEvent::RelatedSearchNotOffered),
        "the waiting one is refused, by its own leg"
    );

    evt_tx
        .send(Ed2kEvent::SearchResultsFound {
            skipped: Vec::new(),
            results: vec![row(1, "beach.avi")],
            more_available: false,
        })
        .await
        .unwrap();
    assert_eq!(super::search::news(&mut sent_leg).await, None);
    assert_eq!(sent_rows.drain().len(), 1, "the sent one keeps its answer");
    assert!(waiting_rows.drain().is_empty());
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    assert!(cmd_rx.try_recv().is_err(), "the refused one never left");
}

/// The residual race: a related request put on the link before the session
/// heard the withdrawal, refused by the eD2k session. The refusal is the newest
/// related request's; the older one, which reached the server, keeps its answer.
#[tokio::test(start_paused = true)]
async fn an_ed2k_refusal_is_the_newest_related_request_on_the_link() {
    let (evt_tx, evt_rx) = mpsc::channel(8);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
    let handle = ServerSession::spawn(
        FakeLink {
            events: evt_rx,
            sent: cmd_tx,
        },
        client_id(),
        test_sinks(SharedOwnIdentity::default()),
    );
    let live = LiveSearches::default();
    let (older, newer) = (SearchId::from_u64(1), SearchId::from_u64(2));
    let mut older_rows = live.register(older, related());
    let mut newer_rows = live.register(newer, related());
    let mut older_leg = handle
        .start_search(older, related(), ANSWER_WAIT, live.clone())
        .await
        .unwrap();
    let mut newer_leg = handle
        .start_search(newer, related(), ANSWER_WAIT, live.clone())
        .await
        .unwrap();
    for _ in 0..2 {
        cmd_rx.recv().await.expect("a request on the link");
    }

    evt_tx
        .send(Ed2kEvent::LoginAccepted {
            client_id: client_id(),
            tcp_flags: None,
            facts: rmule_ed2k::ServerAssignedFacts::default(),
        })
        .await
        .unwrap();
    evt_tx.send(refusal()).await.unwrap();
    assert_eq!(
        super::search::news(&mut newer_leg).await,
        Some(ServerSearchEvent::RelatedSearchNotOffered)
    );
    evt_tx
        .send(Ed2kEvent::SearchResultsFound {
            skipped: Vec::new(),
            results: vec![row(1, "beach.avi")],
            more_available: false,
        })
        .await
        .unwrap();
    assert_eq!(super::search::news(&mut older_leg).await, None);
    assert_eq!(older_rows.drain().len(), 1);
    assert!(newer_rows.drain().is_empty());
}

/// A related request the eD2k session refused never reached the server, so it
/// gives back its place: the keyword search sent before it is still the newest
/// on the link, and its answer that says more names it the pager.
#[tokio::test(start_paused = true)]
async fn a_refused_related_request_leaves_the_search_before_it_the_pager() {
    let (evt_tx, evt_rx) = mpsc::channel(8);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
    let handle = ServerSession::spawn(
        FakeLink {
            events: evt_rx,
            sent: cmd_tx,
        },
        client_id(),
        test_sinks(SharedOwnIdentity::default()),
    );
    let live = LiveSearches::default();
    let (search, refused) = (SearchId::from_u64(1), SearchId::from_u64(2));
    let _search_rows = live.register(search, keywords("linux"));
    let _refused_rows = live.register(refused, related());
    let mut search_leg = handle
        .start_search(search, keywords("linux"), ANSWER_WAIT, live.clone())
        .await
        .unwrap();
    let mut refused_leg = handle
        .start_search(refused, related(), ANSWER_WAIT, live.clone())
        .await
        .unwrap();
    for _ in 0..2 {
        cmd_rx.recv().await.expect("a request on the link");
    }

    evt_tx
        .send(Ed2kEvent::LoginAccepted {
            client_id: client_id(),
            tcp_flags: None,
            facts: rmule_ed2k::ServerAssignedFacts::default(),
        })
        .await
        .unwrap();
    evt_tx.send(refusal()).await.unwrap();
    assert_eq!(
        super::search::news(&mut refused_leg).await,
        Some(ServerSearchEvent::RelatedSearchNotOffered)
    );
    evt_tx
        .send(Ed2kEvent::SearchResultsFound {
            skipped: Vec::new(),
            results: vec![row(1, "linux.iso")],
            more_available: true,
        })
        .await
        .unwrap();
    assert_eq!(super::search::news(&mut search_leg).await, None);
    assert_eq!(
        live.watch_more().borrow().map(|more| more.search_id),
        Some(search)
    );
}

/// A refused related request that went out after the pager was named names it
/// again: the server never saw a request that would replace its kept pages.
#[tokio::test(start_paused = true)]
async fn a_refused_related_request_names_the_pager_it_ended_again() {
    let (evt_tx, evt_rx) = mpsc::channel(8);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
    let handle = ServerSession::spawn(
        FakeLink {
            events: evt_rx,
            sent: cmd_tx,
        },
        client_id(),
        test_sinks(SharedOwnIdentity::default()),
    );
    let live = LiveSearches::default();
    let (search, refused) = (SearchId::from_u64(1), SearchId::from_u64(2));
    let _search_rows = live.register(search, keywords("linux"));
    let _refused_rows = live.register(refused, related());
    let mut search_leg = handle
        .start_search(search, keywords("linux"), ANSWER_WAIT, live.clone())
        .await
        .unwrap();
    cmd_rx.recv().await.expect("the search on the link");
    evt_tx
        .send(Ed2kEvent::SearchResultsFound {
            skipped: Vec::new(),
            results: vec![row(1, "linux.iso")],
            more_available: true,
        })
        .await
        .unwrap();
    assert_eq!(super::search::news(&mut search_leg).await, None);
    let pager = || live.watch_more().borrow().map(|more| more.search_id);
    assert_eq!(pager(), Some(search));

    let mut refused_leg = handle
        .start_search(refused, related(), ANSWER_WAIT, live.clone())
        .await
        .unwrap();
    cmd_rx
        .recv()
        .await
        .expect("the related request on the link");
    assert_eq!(pager(), None, "a request on the link ends the pager");
    evt_tx
        .send(Ed2kEvent::LoginAccepted {
            client_id: client_id(),
            tcp_flags: None,
            facts: rmule_ed2k::ServerAssignedFacts::default(),
        })
        .await
        .unwrap();
    evt_tx.send(refusal()).await.unwrap();
    assert_eq!(
        super::search::news(&mut refused_leg).await,
        Some(ServerSearchEvent::RelatedSearchNotOffered)
    );
    assert_eq!(pager(), Some(search));
}

/// An answer that says more, arriving after a related request went out and
/// before the eD2k session refused it, names its search the pager once the
/// refusal gives the request's place back: the server never saw a request
/// that would replace the pages it kept.
#[tokio::test(start_paused = true)]
async fn an_answer_between_a_related_request_and_its_refusal_names_the_pager_after_it() {
    let (evt_tx, evt_rx) = mpsc::channel(8);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
    let handle = ServerSession::spawn(
        FakeLink {
            events: evt_rx,
            sent: cmd_tx,
        },
        client_id(),
        test_sinks(SharedOwnIdentity::default()),
    );
    let live = LiveSearches::default();
    let (search, refused) = (SearchId::from_u64(1), SearchId::from_u64(2));
    let _search_rows = live.register(search, keywords("linux"));
    let _refused_rows = live.register(refused, related());
    let mut search_leg = handle
        .start_search(search, keywords("linux"), ANSWER_WAIT, live.clone())
        .await
        .unwrap();
    let mut refused_leg = handle
        .start_search(refused, related(), ANSWER_WAIT, live.clone())
        .await
        .unwrap();
    for _ in 0..2 {
        cmd_rx.recv().await.expect("a request on the link");
    }
    let pager = || live.watch_more().borrow().map(|more| more.search_id);

    evt_tx
        .send(Ed2kEvent::SearchResultsFound {
            skipped: Vec::new(),
            results: vec![row(1, "linux.iso")],
            more_available: true,
        })
        .await
        .unwrap();
    assert_eq!(super::search::news(&mut search_leg).await, None);
    assert_eq!(pager(), None, "a later request is on the link");

    evt_tx
        .send(Ed2kEvent::LoginAccepted {
            client_id: client_id(),
            tcp_flags: None,
            facts: rmule_ed2k::ServerAssignedFacts::default(),
        })
        .await
        .unwrap();
    evt_tx.send(refusal()).await.unwrap();
    assert_eq!(
        super::search::news(&mut refused_leg).await,
        Some(ServerSearchEvent::RelatedSearchNotOffered)
    );
    assert_eq!(pager(), Some(search));
}
