//! Connect-to-selected (ADR-0080 amendment): the operator picks a
//! listed server, rmule ends whatever session it held, dials the picked one,
//! and every later activity rides *that* server — whatever endpoint the
//! front-end's startup config still names in its commands.
//!
//! Everything here drives a real `Core` over real loopback sockets, because
//! the contract is about what happens on the wire and which of two servers a
//! command reaches. The session loop's own request handling is pinned sans-I/O
//! in `server_session.rs`.

use rmule_testkit::HANG_GUARD;
use std::time::Duration;

use crate::fixture::search_query;
use crate::fixture::{connect_server, list_server};
use rmule_core::{
    Core, CoreCommand, CoreCommandRejectReason, CoreConfig, CoreEvent, ManagedServer,
    SearchCommand, SearchEvent, ServerConnectFailure, ServerConnectionEvent, ServerListCommand,
};
use rmule_primitives::ServerEndpoint;
use rmule_testkit::FakeEd2kServer;
use tokio::net::TcpListener;
use tokio::time::timeout;

// --- fixtures ---------------------------------------------------------------

/// A core whose status-ping sweep is parked. These tests assert the failure
/// tally a *connect* moves, and the sweep is the other legitimate writer of
/// exactly that number (ADR-0080 amendment) — one writer per assertion.
fn connect_only() -> CoreConfig {
    CoreConfig {
        status_ping_tick: Duration::from_secs(3600),
        // A search must stay open long enough for a switch to land on it; the
        // tests that need it to end drive that themselves.
        search_quiet_timeout: Duration::from_secs(3600),
        ..CoreConfig::default()
    }
}

/// A bound-then-released loopback port: a connect to it is refused at once, so
/// a failed dial needs no timeout to be deterministic.
async fn refused_endpoint() -> ServerEndpoint {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    ServerEndpoint::new("127.0.0.1", addr.port()).expect("a loopback endpoint")
}

/// The next session-lifecycle edge or rejection, whichever comes first; every
/// other cross-activity fact is walked past.
async fn next_answer(core: &mut Core) -> CoreEvent {
    timeout(HANG_GUARD, async {
        loop {
            match core.next_event().await.expect("core is alive") {
                event @ (CoreEvent::ServerConnection(_) | CoreEvent::CommandRejected { .. }) => {
                    return event;
                }
                _ => continue,
            }
        }
    })
    .await
    .expect("an answer within the deadline")
}

async fn next_edge(core: &mut Core) -> ServerConnectionEvent {
    match next_answer(core).await {
        CoreEvent::ServerConnection(event) => event,
        other => panic!("expected a session edge, got {other:?}"),
    }
}

/// Walk the trail until the connect settles, returning the terminal edge.
async fn settle_connect(core: &mut Core) -> ServerConnectionEvent {
    loop {
        match next_edge(core).await {
            event @ (ServerConnectionEvent::Connected { .. }
            | ServerConnectionEvent::ConnectFailed { .. }) => return event,
            _ => continue,
        }
    }
}

fn fail_count(core: &Core, server: &ServerEndpoint) -> u32 {
    core.diagnostics_snapshot()
        .servers
        .into_iter()
        .find(|row| &row.server.endpoint == server)
        .expect("a listed row")
        .server
        .fail_count
}

// --- the connect arc --------------------------------------------------------

/// The happy path an operator sees: the trail names the server it is dialing,
/// then the one it reached, and the connected marker names that server alone.
#[tokio::test]
async fn a_connect_reports_its_trail_and_raises_the_connected_marker() {
    let server = FakeEd2kServer::start_scripted().await;
    let endpoint = server.endpoint();
    let mut core = Core::builder(connect_only(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();
    list_server(&core, &endpoint).await;

    assert_eq!(core.diagnostics_snapshot().connected_server, None);
    connect_server(&core, &endpoint).await;

    assert_eq!(
        next_edge(&mut core).await,
        ServerConnectionEvent::Connecting {
            server: endpoint.clone(),
            leaving: None,
        }
    );
    let ServerConnectionEvent::Connected {
        server: connected,
        client_id,
    } = next_edge(&mut core).await
    else {
        panic!("expected the login to be accepted");
    };
    assert_eq!(connected, endpoint);
    assert!(client_id.is_high_id(), "the scripted server grants High-ID");
    assert_eq!(
        core.diagnostics_snapshot().connected_server,
        Some(endpoint.clone())
    );
}

/// A switch is two halves in one order: the old session goes down *before* the
/// new one is dialed, so the marker is never briefly the wrong server and the
/// trail never interleaves.
#[tokio::test]
async fn a_switch_ends_the_old_session_before_dialing_the_new_one() {
    let first = FakeEd2kServer::start_scripted().await;
    let second = FakeEd2kServer::start_scripted().await;
    let (a, b) = (first.endpoint(), second.endpoint());
    let mut core = Core::builder(connect_only(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();
    list_server(&core, &a).await;
    list_server(&core, &b).await;

    connect_server(&core, &a).await;
    settle_connect(&mut core).await;
    assert_eq!(
        core.diagnostics_snapshot().connected_server,
        Some(a.clone())
    );

    connect_server(&core, &b).await;
    assert_eq!(
        next_edge(&mut core).await,
        ServerConnectionEvent::Disconnected { server: a.clone() }
    );
    assert_eq!(
        next_edge(&mut core).await,
        ServerConnectionEvent::Connecting {
            server: b.clone(),
            leaving: Some(a),
        },
        "the connect names the session it ended"
    );
    assert!(matches!(
        next_edge(&mut core).await,
        ServerConnectionEvent::Connected { server, .. } if server == b
    ));
    assert_eq!(core.diagnostics_snapshot().connected_server, Some(b));
}

/// The connected marker reports a session that exists, never an intent: a
/// switch away from a live server to one that refuses leaves it down.
#[tokio::test]
async fn a_refused_switch_leaves_the_marker_down_and_counts_a_failure() {
    let live = FakeEd2kServer::start_scripted().await;
    let reachable = live.endpoint();
    let refused = refused_endpoint().await;
    let mut core = Core::builder(connect_only(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();
    list_server(&core, &reachable).await;
    list_server(&core, &refused).await;

    connect_server(&core, &reachable).await;
    settle_connect(&mut core).await;

    connect_server(&core, &refused).await;
    assert_eq!(
        next_edge(&mut core).await,
        ServerConnectionEvent::Disconnected {
            server: reachable.clone()
        }
    );
    assert_eq!(
        next_edge(&mut core).await,
        ServerConnectionEvent::Connecting {
            server: refused.clone(),
            leaving: Some(reachable),
        }
    );
    assert_eq!(
        next_edge(&mut core).await,
        ServerConnectionEvent::ConnectFailed {
            server: refused.clone(),
            reason: ServerConnectFailure::Unreachable,
        }
    );
    assert_eq!(core.diagnostics_snapshot().connected_server, None);
    assert_eq!(fail_count(&core, &refused), 1, "aMule's AddFailedCount");
}

/// A server that is *up* and mute is its own fault. The deadline
/// belongs to the eD2k session — `login_deadline_elapsed`, ADR-0044 — so the
/// link closes itself with `CloseReason::LoginTimeout` and the trail reports
/// `LoginTimedOut`, never the `Unreachable` a refused dial earns. Without the
/// distinction a caller cannot tell "the server ignored me" from "I never
/// reached it", which is the whole reason the variant exists.
#[tokio::test]
async fn a_mute_server_fails_the_login_with_the_typed_timeout() {
    let (mute, _held) = crate::fixture::mute_server().await;
    let config = CoreConfig {
        server_login_timeout: Duration::from_millis(300),
        ..connect_only()
    };
    let mut core = Core::builder(config, rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();
    list_server(&core, &mute).await;

    connect_server(&core, &mute).await;
    assert_eq!(
        next_edge(&mut core).await,
        ServerConnectionEvent::Connecting {
            server: mute.clone(),
            leaving: None,
        }
    );
    assert_eq!(
        settle_connect(&mut core).await,
        ServerConnectionEvent::ConnectFailed {
            server: mute.clone(),
            reason: ServerConnectFailure::LoginTimedOut,
        }
    );
    assert_eq!(core.diagnostics_snapshot().connected_server, None);
    assert_eq!(
        fail_count(&core, &mute),
        1,
        "silence counts against the server exactly as a refusal does"
    );
}

/// A server that accepts the link and closes it before answering the login
/// is not one that could not be reached: the first connect after a
/// start failed in 140 ms as "login failed", and nothing said which.
#[tokio::test]
async fn a_server_that_hangs_up_before_answering_is_named_apart_from_an_unreachable_one() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local addr").port();
    let hang_up = ServerEndpoint::new("127.0.0.1", port).expect("a loopback endpoint");
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            drop(stream);
        }
    });
    let mut core = Core::builder(connect_only(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();
    list_server(&core, &hang_up).await;

    connect_server(&core, &hang_up).await;
    assert_eq!(
        settle_connect(&mut core).await,
        ServerConnectionEvent::ConnectFailed {
            server: hang_up.clone(),
            reason: ServerConnectFailure::ClosedBeforeAnswer,
        }
    );
    assert_eq!(fail_count(&core, &hang_up), 1);
}

/// aMule's absolve: a login that lands clears the tally the failed reaches
/// built up — the same number an unanswered ping climbs.
#[tokio::test]
async fn an_accepted_login_absolves_the_failure_tally() {
    let server = FakeEd2kServer::start_scripted().await;
    let endpoint = server.endpoint();
    let mut core = Core::builder(connect_only(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();
    core.send(CoreCommand::ServerList(ServerListCommand::AddServer {
        server: ManagedServer {
            fail_count: 7,
            ..ManagedServer::listed(endpoint.clone())
        },
    }))
    .await
    .expect("core accepts the command");

    connect_server(&core, &endpoint).await;
    settle_connect(&mut core).await;

    assert_eq!(fail_count(&core, &endpoint), 0, "aMule's ResetFailedCount");
}

/// A server that is not listed is not a server the operator could have picked.
#[tokio::test]
async fn an_unlisted_endpoint_is_refused_without_dialing() {
    let server = FakeEd2kServer::start_scripted().await;
    let endpoint = server.endpoint();
    let mut core = Core::builder(connect_only(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();

    connect_server(&core, &endpoint).await;

    assert!(matches!(
        next_answer(&mut core).await,
        CoreEvent::CommandRejected {
            reason: CoreCommandRejectReason::UnknownServer
        }
    ));
    assert_eq!(core.diagnostics_snapshot().connected_server, None);
    assert!(server.assigned_ids().await.is_empty(), "nothing was dialed");
}

// --- the re-target ----------------------------------------------------------

/// The minimum contract: after a connect, an activity command that still names
/// the *old* server rides the picked one. The front-end's startup config does
/// not undo the operator's choice.
#[tokio::test]
async fn a_later_activity_rides_the_picked_server_not_the_one_it_named() {
    let picked = FakeEd2kServer::start_scripted().await;
    let stale = FakeEd2kServer::start_scripted().await;
    let (picked_endpoint, stale_endpoint) = (picked.endpoint(), stale.endpoint());
    let mut core = Core::builder(connect_only(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();
    list_server(&core, &picked_endpoint).await;
    list_server(&core, &stale_endpoint).await;

    connect_server(&core, &picked_endpoint).await;
    settle_connect(&mut core).await;

    core.send(CoreCommand::Search(SearchCommand::StartSearch {
        search_id: rmule_core::SearchId::mint(),
        query: search_query("ubuntu").into(),
    }))
    .await
    .expect("core accepts the command");

    timeout(HANG_GUARD, async {
        while picked.search_phrases().await.is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the picked server was asked");
    assert!(
        stale.search_phrases().await.is_empty(),
        "the named-but-not-picked server was never asked"
    );
}

/// A failed connect leaves no session, and a later activity dials nothing to
/// make one (ADR-0095, "Connecting is the operator's act"): a search whose
/// command names a reachable server waits for the operator's next connect,
/// and that server is never dialed behind the operator's back.
#[tokio::test]
async fn after_a_failed_connect_a_search_waits_and_dials_nothing() {
    let live = FakeEd2kServer::start_scripted().await;
    let reachable = live.endpoint();
    let refused = refused_endpoint().await;
    let mut core = Core::builder(connect_only(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();
    list_server(&core, &reachable).await;
    list_server(&core, &refused).await;

    connect_server(&core, &refused).await;
    assert!(matches!(
        settle_connect(&mut core).await,
        ServerConnectionEvent::ConnectFailed { .. }
    ));

    core.send(CoreCommand::Search(SearchCommand::StartSearch {
        search_id: rmule_core::SearchId::mint(),
        query: search_query("ubuntu").into(),
    }))
    .await
    .expect("core accepts the command");

    timeout(HANG_GUARD, async {
        loop {
            if let CoreEvent::Search(SearchEvent::SearchWaitingForConnection { .. }) =
                core.next_event().await.expect("core is alive")
            {
                return;
            }
        }
    })
    .await
    .expect("the search says it waits");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        live.assigned_ids().await.is_empty(),
        "the reachable server the command named was never dialed"
    );
}

// --- survival ---------------------------------------------------------------

/// A search the server already answered survives a switch: the server's one
/// `OP_SEARCHRESULT` ends its server leg (aMule `ServerSocket.cpp:421-431`
/// ends the local search on it), so the session going away takes nothing from
/// it — it stays held, and ends when the operator says so. A search whose
/// answer was still due fails instead (the session's search-queue tests).
#[tokio::test]
async fn an_answered_search_survives_its_session_being_switched_out() {
    let first = FakeEd2kServer::start_scripted().await;
    let second = FakeEd2kServer::start_scripted().await;
    let (a, b) = (first.endpoint(), second.endpoint());
    let mut core = Core::builder(connect_only(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();
    list_server(&core, &a).await;
    list_server(&core, &b).await;

    connect_server(&core, &a).await;
    settle_connect(&mut core).await;
    core.send(CoreCommand::Search(SearchCommand::StartSearch {
        search_id: rmule_core::SearchId::mint(),
        query: search_query("ubuntu").into(),
    }))
    .await
    .expect("core accepts the command");
    timeout(HANG_GUARD, async {
        while first.search_phrases().await.is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the search is running");

    let search_id = timeout(HANG_GUARD, async {
        loop {
            if let CoreEvent::Search(SearchEvent::SearchStarted { search_id }) =
                core.next_event().await.expect("core is alive")
            {
                return search_id;
            }
        }
    })
    .await
    .expect("the search started");

    connect_server(&core, &b).await;
    core.send(CoreCommand::Search(SearchCommand::CancelSearch {
        search_id,
    }))
    .await
    .expect("core accepts the command");

    let ended = timeout(HANG_GUARD, async {
        loop {
            if let CoreEvent::Search(
                event @ (SearchEvent::SearchFailed { .. } | SearchEvent::SearchCancelled { .. }),
            ) = core.next_event().await.expect("core is alive")
            {
                return event;
            }
        }
    })
    .await
    .expect("the search ends");
    assert!(
        matches!(ended, SearchEvent::SearchCancelled { search_id: id } if id == search_id),
        "the answered search is cancelled, not failed: {ended:?}"
    );
}
