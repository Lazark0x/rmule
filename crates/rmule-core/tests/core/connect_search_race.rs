//! A search must never race the eager `ConnectToServer` for
//! the session slot. A `StartSearch` processed while the spawned connect task
//! has not yet locked the slot must not establish its **own** session — the
//! connect would kill it (`Disconnected` → `SearchFailed`) before dialing the
//! server again, so the first search after connect returned nothing and the
//! retry worked. The operator's connect claims establishment authority
//! synchronously at command accept, and a search waits for a live claim to
//! resolve and rides its session (ADR-0034 amendment). Since ADR-0093's
//! "Connecting is the operator's act" a search never dials at all: with no
//! session it waits for the operator's connect.
//!
//! The fake server's login delay models the real Lugdunum Back-Connect-Probe
//! window: `OP_IDCHANGE` lands well after `OP_LOGINREQUEST`, so
//! the login is genuinely in flight when the search command arrives.

use rmule_testkit::HANG_GUARD;
use std::time::Duration;

use crate::fixture::search_config;
use crate::fixture::search_query;
use rmule_core::{
    Core, CoreCommand, CoreEvent, ManagedServer, SearchCommand, SearchEvent, ServerConnectionEvent,
    ServerListCommand,
};
use rmule_primitives::{ClientId, Ed2kText, FileHash, PeerSource, SearchResult, ServerEndpoint};
use rmule_testkit::FakeEd2kServer;
use tokio::time::{Instant, timeout, timeout_at};

fn scripted_result() -> SearchResult {
    SearchResult::new(
        FileHash::from_bytes([0xAA; FileHash::BYTE_LEN]),
        1024,
        vec![Ed2kText::from_utf8("linux.iso")],
        vec![PeerSource::new(ClientId::from_u32(0x0100_007F), 4662)],
    )
    .expect("a valid result")
}

async fn login_delayed_server() -> (FakeEd2kServer, ServerEndpoint) {
    let server = FakeEd2kServer::start_scripted().await;
    // A wide login window on purpose: the legs of this binary run in
    // parallel, and a race test that sends its search 100 ms in needs the
    // window to still be open on a loaded machine.
    server.set_login_delay(Duration::from_secs(1)).await;
    server.set_search_results(vec![scripted_result()]).await;
    let endpoint = server.endpoint();
    (server, endpoint)
}

async fn add_server(core: &mut Core, endpoint: &ServerEndpoint) {
    core.send(CoreCommand::ServerList(ServerListCommand::AddServer {
        server: ManagedServer::listed(endpoint.clone()),
    }))
    .await
    .expect("core accepts the command");
}

async fn connect_cmd(endpoint: &ServerEndpoint) -> CoreCommand {
    CoreCommand::ConnectToServer {
        server: endpoint.clone(),
    }
}

fn search_cmd() -> CoreCommand {
    CoreCommand::Search(SearchCommand::StartSearch {
        search_id: rmule_core::SearchId::mint(),
        query: search_query("linux").into(),
    })
}

/// Collect every event until the search completes (or fails/toes a 5 s line),
/// so the assertions read the one whole trail rather than racing the bus.
async fn trail_until_search_settles(core: &mut Core) -> Vec<CoreEvent> {
    let mut trail = Vec::new();
    timeout(HANG_GUARD, async {
        loop {
            let event = core.next_event().await.expect("core is alive");
            let settled = matches!(
                event,
                CoreEvent::Search(
                    SearchEvent::SearchCompleted { .. } | SearchEvent::SearchFailed { .. }
                )
            );
            trail.push(event);
            if settled {
                return;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no search settlement; trail so far: {trail:#?}"));
    trail
}

/// The whole-trail contract shared by both racing orders: exactly one
/// establishment (the operator's), no session death, and the strict
/// `Connecting → Connected → SearchStarted → results → completed` order.
fn assert_single_session_search_trail(trail: &[CoreEvent]) {
    let disconnects = trail
        .iter()
        .filter(|event| {
            matches!(
                event,
                CoreEvent::ServerConnection(ServerConnectionEvent::Disconnected { .. })
            )
        })
        .count();
    assert_eq!(
        disconnects, 0,
        "no session dies between connect and first-search results; trail: {trail:#?}"
    );
    let connectings = trail
        .iter()
        .filter(|event| {
            matches!(
                event,
                CoreEvent::ServerConnection(ServerConnectionEvent::Connecting { .. })
            )
        })
        .count();
    assert_eq!(
        connectings, 1,
        "the operator's connect is the only establishment — the search must not \
         dial a rival session; trail: {trail:#?}"
    );
    assert!(
        !trail
            .iter()
            .any(|event| matches!(event, CoreEvent::Search(SearchEvent::SearchFailed { .. }))),
        "the first search survives the eager connect; trail: {trail:#?}"
    );

    // Trail ordering: Connecting strictly before Connected,
    // Connected strictly before SearchStarted, then results, then completion.
    let position = |pred: &dyn Fn(&CoreEvent) -> bool, label: &str| -> usize {
        trail
            .iter()
            .position(pred)
            .unwrap_or_else(|| panic!("no {label} in trail: {trail:#?}"))
    };
    let connecting = position(
        &|e| {
            matches!(
                e,
                CoreEvent::ServerConnection(ServerConnectionEvent::Connecting { .. })
            )
        },
        "Connecting",
    );
    let connected = position(
        &|e| {
            matches!(
                e,
                CoreEvent::ServerConnection(ServerConnectionEvent::Connected { .. })
            )
        },
        "Connected",
    );
    let started = position(
        &|e| matches!(e, CoreEvent::Search(SearchEvent::SearchStarted { .. })),
        "SearchStarted",
    );
    let results = position(
        &|e| {
            matches!(
                e,
                CoreEvent::Search(SearchEvent::SearchResultsReceived { .. })
            )
        },
        "SearchResultsReceived",
    );
    let completed = position(
        &|e| {
            matches!(
                e,
                CoreEvent::Search(SearchEvent::SearchCompleted {
                    total_results: 1,
                    ..
                })
            )
        },
        "SearchCompleted(total 1)",
    );
    assert!(
        connecting < connected && connected < started && started < results && results < completed,
        "expected Connecting({connecting}) → Connected({connected}) → \
         SearchStarted({started}) → results({results}) → completed({completed}); \
         trail: {trail:#?}"
    );
}

/// The manual repro's race: `ConnectToServer` and `StartSearch`
/// arrive back-to-back, so the search is processed before the spawned connect
/// task has even locked the slot. The search must wait for the operator's
/// connect and ride its session — one login, no kill, results on the first try.
#[tokio::test]
async fn a_search_racing_the_eager_connect_rides_its_session() {
    let (server, endpoint) = login_delayed_server().await;
    let mut core = Core::builder(search_config(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();
    add_server(&mut core, &endpoint).await;

    core.send(connect_cmd(&endpoint).await)
        .await
        .expect("connect accepted");
    core.send(search_cmd()).await.expect("search accepted");

    let trail = trail_until_search_settles(&mut core).await;
    assert_single_session_search_trail(&trail);
    assert_eq!(
        server.search_phrases().await,
        vec!["linux".to_string()],
        "exactly one OP_SEARCHREQUEST reached the server"
    );
}

/// The same race caught mid-login: the search arrives while the connect's
/// `OP_IDCHANGE` is still outstanding (the Lugdunum probe window). Identical
/// contract — the login-in-flight session is the search's session.
#[tokio::test]
async fn a_search_arriving_mid_login_rides_the_connecting_session() {
    let (server, endpoint) = login_delayed_server().await;
    let mut core = Core::builder(search_config(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();
    add_server(&mut core, &endpoint).await;

    core.send(connect_cmd(&endpoint).await)
        .await
        .expect("connect accepted");
    // Inside the login window, well past the connect task's spawn.
    tokio::time::sleep(Duration::from_millis(100)).await;
    core.send(search_cmd()).await.expect("search accepted");

    let trail = trail_until_search_settles(&mut core).await;
    assert_single_session_search_trail(&trail);
    assert_eq!(server.search_phrases().await, vec!["linux".to_string()]);
}

/// A cold search dials nothing (ADR-0095, "Connecting is the operator's act"):
/// with no session it says it waits, no login reaches the server, and the
/// operator's connect — the one establishment — sends it, with the same trail
/// as a search that raced the connect.
#[tokio::test]
async fn a_cold_search_waits_for_the_operators_connect_and_is_sent_on_it() {
    let (server, endpoint) = login_delayed_server().await;
    let mut core = Core::builder(search_config(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();

    core.send(search_cmd()).await.expect("search accepted");
    crate::fixture::next_expected(&mut core, "the search to say it waits", |event| {
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchWaitingForConnection { .. })
        )
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        server.assigned_ids().await.is_empty(),
        "a search logs nobody in"
    );

    add_server(&mut core, &endpoint).await;
    core.send(connect_cmd(&endpoint).await)
        .await
        .expect("connect accepted");
    let trail = trail_until_search_settles(&mut core).await;
    assert_single_session_search_trail(&trail);
    assert_eq!(server.search_phrases().await, vec!["linux".to_string()]);
}

/// A search queued behind a connect that never logs in keeps waiting and
/// dials nothing of its own: the operator is told `ConnectFailed`, the search
/// says it waits for a connection, and no second dial follows.
#[tokio::test]
async fn a_search_behind_a_failing_connect_waits_and_dials_nothing_of_its_own() {
    // A listener bound then dropped: the port refuses the dial.
    let dead = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a throwaway port");
    let addr = dead.local_addr().expect("read the throwaway port");
    drop(dead);
    let endpoint = ServerEndpoint::new(addr.ip().to_string(), addr.port()).expect("endpoint");
    let mut core = Core::builder(search_config(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();
    add_server(&mut core, &endpoint).await;

    core.send(connect_cmd(&endpoint).await)
        .await
        .expect("connect accepted");
    core.send(search_cmd()).await.expect("search accepted");

    // The watch runs until the refusal lands, then as long again for a second
    // dial. The refusal is instant on Linux and macOS; Windows re-sends the
    // SYN twice before it reports one, about 2 s even on loopback, which the
    // eD2k connect timeout (10 s) still covers.
    let mut connectings = 0;
    let mut saw_connect_failed = false;
    let mut saw_waiting = false;
    let mut watch_until = Instant::now() + Duration::from_secs(10);
    while let Ok(event) = timeout_at(watch_until, core.next_event()).await {
        match event.expect("core is alive") {
            CoreEvent::ServerConnection(ServerConnectionEvent::Connecting { .. }) => {
                connectings += 1;
            }
            CoreEvent::ServerConnection(ServerConnectionEvent::ConnectFailed { .. }) => {
                saw_connect_failed = true;
                watch_until = Instant::now() + Duration::from_secs(2);
            }
            CoreEvent::Search(SearchEvent::SearchWaitingForConnection { .. }) => {
                saw_waiting = true;
            }
            CoreEvent::Search(SearchEvent::SearchFailed { .. }) => {
                panic!("a search with no connection waits; it does not fail")
            }
            _ => {}
        }
    }
    assert!(
        saw_connect_failed,
        "the operator is told the connect failed"
    );
    assert!(saw_waiting, "the search says it waits for a connection");
    assert_eq!(connectings, 1, "the operator's dial is the only one");
}
