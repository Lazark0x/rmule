//! A lost session is re-made (ADR-0096, "A lost session is re-made"):
//! the operator's connect is an intent — stay connected to this server — that
//! outlives the link. A session the server drops is dialed again through the
//! one establishment, after a delay that grows to a ceiling and then repeats
//! at it — without end unless a bound is configured — and only to the server
//! the operator chose; the operator's
//! disconnect or a connect elsewhere ends the intent, and a restart carries
//! none. The delays are the core's config, set short here.

use rmule_testkit::HANG_GUARD;
use std::time::Duration;

use rmule_core::{Core, CoreCommand, CoreConfig, CoreEvent, ReconnectEnd, ServerConnectionEvent};
use rmule_testkit::FakeEd2kServer;
use tokio::time::timeout;

use crate::fixture::{free_port, next_expected};

/// Short delays; every re-made session counts as held at once, so each loss
/// starts the count over unless a leg sets `server_session_holds` itself.
fn reconnect_config(first: Duration, ceiling: Duration) -> CoreConfig {
    CoreConfig {
        status_ping_tick: Duration::from_secs(3600),
        server_reconnect_first: first,
        server_reconnect_ceiling: ceiling,
        server_session_holds: Duration::ZERO,
        ..CoreConfig::default()
    }
}

/// The operator's connect, and its landing.
async fn operator_connects(core: &mut Core, server: &FakeEd2kServer) {
    rmule_testkit::connect_to(core, &server.endpoint()).await;
    let endpoint = server.endpoint();
    next_expected(core, "the operator's connect", |event| {
        matches!(
            event,
            CoreEvent::ServerConnection(ServerConnectionEvent::Connected { server, .. })
                if *server == endpoint
        )
    })
    .await;
}

/// Every server-connection edge until `stop` matches one, in order.
async fn edges_until(
    core: &mut Core,
    stop: impl Fn(&ServerConnectionEvent) -> bool,
) -> Vec<ServerConnectionEvent> {
    let mut edges = Vec::new();
    timeout(HANG_GUARD, async {
        loop {
            if let CoreEvent::ServerConnection(edge) =
                core.next_event().await.expect("core is alive")
            {
                let done = stop(&edge);
                edges.push(edge);
                if done {
                    return;
                }
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the awaited edge never came; saw {edges:?}"));
    edges
}

/// No server-connection edge arrives once the core has drained what was
/// queued for it (a diagnostics dump answered in order proves that) and the
/// clock has then run `window` past the retry delay. The clock is paused
/// here, so `window` is virtual time: an armed retry timer fires within it
/// however loaded the machine is, and a timer that was never armed cannot.
async fn quiet_through(core: &mut Core, window: Duration, what: &str) {
    core.send(CoreCommand::DumpDiagnostics).await.unwrap();
    loop {
        match core.next_event().await.expect("core is alive") {
            CoreEvent::ServerConnection(edge) => panic!("{what}: {edge:?}"),
            CoreEvent::DiagnosticsSnapshot { .. } => break,
            _ => {}
        }
    }
    tokio::time::pause();
    let _ = timeout(window, async {
        loop {
            if let CoreEvent::ServerConnection(edge) =
                core.next_event().await.expect("core is alive")
            {
                panic!("{what}: {edge:?}");
            }
        }
    })
    .await;
}

#[tokio::test]
async fn a_dropped_session_is_re_made_through_the_one_establishment() {
    // Not scripted: the server's port check dials our listener, so a High ID
    // on the re-made session proves the listener was up at its login.
    let server = FakeEd2kServer::start().await;
    let port = free_port().await;
    let mut core = Core::builder(
        reconnect_config(Duration::from_millis(20), Duration::from_millis(80)),
        rmule_testkit::memory_store(),
    )
    .settings(crate::fixture::settings_on(port))
    .build();
    operator_connects(&mut core, &server).await;

    server.hang_up_all().await;
    let edges = edges_until(&mut core, |edge| {
        matches!(edge, ServerConnectionEvent::Connected { .. })
    })
    .await;
    let endpoint = server.endpoint();
    assert!(
        matches!(
            edges.as_slice(),
            [
                ServerConnectionEvent::Disconnected { server: lost },
                ServerConnectionEvent::Reconnecting { server: again, attempt: 1, next_in, .. },
                ServerConnectionEvent::Connecting { .. },
                ServerConnectionEvent::Connected { client_id, .. },
            ] if *lost == endpoint && *again == endpoint
                && *next_in == Duration::from_millis(20) && client_id.is_high_id()
        ),
        "{edges:?}"
    );
    let logins = server.assigned_ids().await;
    assert_eq!(logins.len(), 2);
    assert!(logins.iter().all(|id| id.is_high_id()));

    // Re-made, the intent stands: a second loss is re-made the same way,
    // its count starting over.
    server.hang_up_all().await;
    let edges = edges_until(&mut core, |edge| {
        matches!(edge, ServerConnectionEvent::Connected { .. })
    })
    .await;
    assert!(
        edges
            .iter()
            .any(|edge| matches!(edge, ServerConnectionEvent::Reconnecting { attempt: 1, .. })),
        "{edges:?}"
    );
}

/// A re-made session the server drops before it has held does not start the
/// count over: the next try is the next attempt, its delay doubled, so a
/// server that accepts the login and then hangs up is dialed ever less often.
#[tokio::test]
async fn a_session_dropped_before_it_holds_continues_the_count() {
    let server = FakeEd2kServer::start_scripted().await;
    let port = free_port().await;
    let mut core = Core::builder(
        CoreConfig {
            server_session_holds: Duration::from_secs(3600),
            ..reconnect_config(Duration::from_millis(20), Duration::from_millis(80))
        },
        rmule_testkit::memory_store(),
    )
    .settings(crate::fixture::settings_on(port))
    .build();
    operator_connects(&mut core, &server).await;

    let mut tries = Vec::new();
    for _ in 0..3 {
        server.hang_up_all().await;
        let edges = edges_until(&mut core, |edge| {
            matches!(edge, ServerConnectionEvent::Connected { .. })
        })
        .await;
        tries.extend(edges.iter().filter_map(|edge| match edge {
            ServerConnectionEvent::Reconnecting {
                attempt, next_in, ..
            } => Some((*attempt, next_in.as_millis())),
            _ => None,
        }));
    }
    assert_eq!(tries, [(1, 20), (2, 40), (3, 80)]);
}

/// With no bound (the default) the tries never end while the intent
/// stands: past the ceiling each one waits the ceiling, said as steady, and the
/// count keeps climbing.
#[tokio::test]
async fn with_no_bound_the_tries_go_on_at_the_ceiling() {
    let server = FakeEd2kServer::start_scripted().await;
    let port = free_port().await;
    let mut core = Core::builder(
        reconnect_config(Duration::from_millis(2), Duration::from_millis(4)),
        rmule_testkit::memory_store(),
    )
    .settings(crate::fixture::settings_on(port))
    .build();
    operator_connects(&mut core, &server).await;

    server.set_refusing(true).await;
    server.hang_up_all().await;
    let edges = edges_until(&mut core, |edge| {
        matches!(
            edge,
            ServerConnectionEvent::Reconnecting { attempt: 20, .. }
        )
    })
    .await;
    assert!(
        !edges
            .iter()
            .any(|edge| matches!(edge, ServerConnectionEvent::ReconnectEnded { .. })),
        "{edges:?}"
    );
    let steps: Vec<(u32, Option<u32>, bool)> = edges
        .iter()
        .filter_map(|edge| match edge {
            ServerConnectionEvent::Reconnecting {
                attempt,
                bound,
                steady,
                ..
            } => Some((*attempt, *bound, *steady)),
            _ => None,
        })
        .collect();
    let expected: Vec<(u32, Option<u32>, bool)> = (1..=20)
        .map(|attempt| (attempt, None, attempt >= 2))
        .collect();
    assert_eq!(steps, expected, "2 ms, then 4 ms from the second on");
    core.send(CoreCommand::DisconnectFromServer).await.unwrap();
    let edges = edges_until(&mut core, |edge| {
        matches!(edge, ServerConnectionEvent::ReconnectEnded { .. })
    })
    .await;
    assert!(
        matches!(
            edges.last(),
            Some(ServerConnectionEvent::ReconnectEnded {
                reason: ReconnectEnd::OperatorDisconnected,
                ..
            })
        ),
        "only the operator ends it: {edges:?}"
    );
}

/// Core hands the time of the next attempt, not only the delay: the front
/// end counts the wait down against it. The deadline lies a `next_in` after
/// the instant the session was lost, and no later than a `next_in` after the
/// event reached the operator.
#[tokio::test]
async fn a_reconnect_hands_the_time_of_the_next_attempt() {
    let server = FakeEd2kServer::start_scripted().await;
    let port = free_port().await;
    let mut core = Core::builder(
        reconnect_config(Duration::from_millis(700), Duration::from_millis(700)),
        rmule_testkit::memory_store(),
    )
    .settings(crate::fixture::settings_on(port))
    .build();
    operator_connects(&mut core, &server).await;

    let before = std::time::Instant::now();
    server.hang_up_all().await;
    let edges = edges_until(&mut core, |edge| {
        matches!(edge, ServerConnectionEvent::Reconnecting { .. })
    })
    .await;
    let after = std::time::Instant::now();
    let Some(ServerConnectionEvent::Reconnecting { next_in, at, .. }) = edges.last() else {
        panic!("the wait is said: {edges:?}");
    };
    assert_eq!(*next_in, Duration::from_millis(700));
    assert!(*at >= before + *next_in, "the deadline follows the loss");
    assert!(
        *at <= after + *next_in,
        "and precedes the event's arrival by no more than the delay"
    );
}

/// The bound, when configured, ends the tries.
#[tokio::test]
async fn the_delay_grows_to_its_ceiling_and_a_configured_bound_ends_the_tries() {
    const ATTEMPTS: u32 = 6;
    let server = FakeEd2kServer::start_scripted().await;
    let port = free_port().await;
    let mut core = Core::builder(
        CoreConfig {
            server_reconnect_attempts: Some(ATTEMPTS),
            ..reconnect_config(Duration::from_millis(5), Duration::from_millis(20))
        },
        rmule_testkit::memory_store(),
    )
    .settings(crate::fixture::settings_on(port))
    .build();
    operator_connects(&mut core, &server).await;

    server.set_refusing(true).await;
    server.hang_up_all().await;
    let edges = edges_until(&mut core, |edge| {
        matches!(edge, ServerConnectionEvent::ReconnectEnded { .. })
    })
    .await;
    let delays: Vec<(u32, u64)> = edges
        .iter()
        .filter_map(|edge| match edge {
            ServerConnectionEvent::Reconnecting {
                attempt, next_in, ..
            } => Some((*attempt, u64::try_from(next_in.as_millis()).unwrap())),
            _ => None,
        })
        .collect();
    let expected: Vec<(u32, u64)> = (1..=ATTEMPTS)
        .map(|attempt| (attempt, (5_u64 << (attempt - 1).min(16)).min(20)))
        .collect();
    assert_eq!(delays, expected, "5, 10, 20, then 20 — {ATTEMPTS} tries");
    assert!(
        matches!(
            edges.last(),
            Some(ServerConnectionEvent::ReconnectEnded {
                reason: ReconnectEnd::AttemptsSpent { attempts: ATTEMPTS },
                ..
            })
        ),
        "{edges:?}"
    );
    let failed = edges
        .iter()
        .filter(|edge| matches!(edge, ServerConnectionEvent::ConnectFailed { .. }))
        .count();
    assert_eq!(
        failed,
        usize::try_from(ATTEMPTS).unwrap(),
        "every attempt dialed the chosen server"
    );
    quiet_through(
        &mut core,
        Duration::from_millis(200),
        "nothing dials after the last try",
    )
    .await;
}

#[tokio::test]
async fn the_operators_disconnect_during_a_retry_ends_the_intent() {
    let server = FakeEd2kServer::start_scripted().await;
    let port = free_port().await;
    let mut core = Core::builder(
        reconnect_config(Duration::from_millis(300), Duration::from_millis(300)),
        rmule_testkit::memory_store(),
    )
    .settings(crate::fixture::settings_on(port))
    .build();
    operator_connects(&mut core, &server).await;

    server.hang_up_all().await;
    edges_until(&mut core, |edge| {
        matches!(edge, ServerConnectionEvent::Reconnecting { .. })
    })
    .await;
    core.send(CoreCommand::DisconnectFromServer).await.unwrap();
    let edges = edges_until(&mut core, |edge| {
        matches!(edge, ServerConnectionEvent::ReconnectEnded { .. })
    })
    .await;
    assert!(
        matches!(
            edges.as_slice(),
            [ServerConnectionEvent::ReconnectEnded {
                reason: ReconnectEnd::OperatorDisconnected,
                ..
            }]
        ),
        "{edges:?}"
    );
    quiet_through(
        &mut core,
        Duration::from_millis(600),
        "the dropped retry dialed",
    )
    .await;
    assert_eq!(server.assigned_ids().await.len(), 1);
}

#[tokio::test]
async fn the_operators_disconnect_hangs_up_the_session_and_nothing_re_makes_it() {
    let server = FakeEd2kServer::start_scripted().await;
    let port = free_port().await;
    let mut core = Core::builder(
        reconnect_config(Duration::from_millis(20), Duration::from_millis(20)),
        rmule_testkit::memory_store(),
    )
    .settings(crate::fixture::settings_on(port))
    .build();
    operator_connects(&mut core, &server).await;

    core.send(CoreCommand::DisconnectFromServer).await.unwrap();
    let edges = edges_until(&mut core, |edge| {
        matches!(edge, ServerConnectionEvent::Disconnected { .. })
    })
    .await;
    assert_eq!(edges.len(), 1, "{edges:?}");
    quiet_through(
        &mut core,
        Duration::from_millis(300),
        "a disconnected session was re-made",
    )
    .await;
    assert_eq!(server.assigned_ids().await.len(), 1);
}

#[tokio::test]
async fn connecting_elsewhere_replaces_the_intent() {
    let first = FakeEd2kServer::start_scripted().await;
    let second = FakeEd2kServer::start_scripted().await;
    let port = free_port().await;
    let mut core = Core::builder(
        reconnect_config(Duration::from_millis(300), Duration::from_millis(300)),
        rmule_testkit::memory_store(),
    )
    .settings(crate::fixture::settings_on(port))
    .build();
    operator_connects(&mut core, &first).await;
    first.hang_up_all().await;
    edges_until(&mut core, |edge| {
        matches!(edge, ServerConnectionEvent::Reconnecting { .. })
    })
    .await;

    rmule_testkit::connect_to(&core, &second.endpoint()).await;
    let edges = edges_until(&mut core, |edge| {
        matches!(edge, ServerConnectionEvent::Connected { .. })
    })
    .await;
    assert!(
        matches!(
            edges.first(),
            Some(ServerConnectionEvent::ReconnectEnded {
                server,
                reason: ReconnectEnd::Replaced,
            }) if *server == first.endpoint()
        ),
        "the replaced reconnect is said: {edges:?}"
    );
    quiet_through(
        &mut core,
        Duration::from_millis(600),
        "the replaced intent's retry dialed",
    )
    .await;
    assert_eq!(
        first.assigned_ids().await.len(),
        1,
        "the first server is not re-dialed"
    );
    assert_eq!(second.assigned_ids().await.len(), 1);
}

#[tokio::test]
async fn a_restart_carries_no_intent_and_dials_nothing() {
    let server = FakeEd2kServer::start_scripted().await;
    let port = free_port().await;
    let dir = tempfile::tempdir().unwrap();
    let store = rmule_core::open_durable_store(dir.path()).unwrap();
    let mut core = Core::builder(
        reconnect_config(Duration::from_millis(20), Duration::from_millis(20)),
        std::sync::Arc::clone(&store),
    )
    .settings(crate::fixture::settings_on(port))
    .build();
    operator_connects(&mut core, &server).await;
    core.shutdown().await;

    let mut restarted = Core::builder(
        reconnect_config(Duration::from_millis(20), Duration::from_millis(20)),
        store,
    )
    .settings(crate::fixture::settings_on(port))
    .restore_at_attach()
    .build();
    quiet_through(
        &mut restarted,
        Duration::from_millis(500),
        "a restart dialed the last server",
    )
    .await;
    assert_eq!(server.assigned_ids().await.len(), 1);
}
