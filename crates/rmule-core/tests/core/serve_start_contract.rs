//! The serve-start contract over the production adapter:
//! `ServingStarted` is the **bind** fact and nothing else, a serve start dials
//! no server (ADR-0095, "Connecting is the operator's act"), an operator's
//! connect that fails leaves the serve up, and every `StartServing` is
//! answered — a retry after a failure included. And its second half
//! The activity that ends gives the adapter back, so a start
//! after a stop is a first start — a fresh bind, under the identity that start
//! named.
//!
//! Everything here runs a real `Core::new` over real loopback sockets, because
//! the whole claim is about what a listener does while a server is doing
//! nothing. The fake-adapter lifecycle legs live in `serve_lifecycle`.

use rmule_testkit::HANG_GUARD;
use std::net::{Ipv4Addr, SocketAddrV4};

use crate::fixture::{mute_server, next_expected, serving_started};
use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, ServeCommand, ServeEvent, ServeStartFailure,
    ServeStopReason, ServerConnectFailure, ServerConnectionEvent,
};
use rmule_net::peer::{ConnectOptions, Connection};
use rmule_peer::{ConnectionEvent, PeerEvent, PeerIdentity};
use rmule_primitives::{Ipv4Endpoint, PeerEndpoint};
use rmule_testkit::test_handshake_ctx;
use tokio::net::TcpListener;
use tokio::time::{Duration, timeout};

/// A core whose login deadline is short enough to observe inside a test, with
/// the status-ping sweep parked so the only server traffic is the login.
fn quick_login() -> CoreConfig {
    CoreConfig {
        server_login_timeout: Duration::from_secs(2),
        status_ping_tick: Duration::from_secs(3600),
        ..CoreConfig::default()
    }
}

async fn start_serving(core: &Core, listen_addr: SocketAddrV4) {
    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr,
    }))
    .await
    .expect("core accepts the command");
}

/// Stop the serve activity and return the reason it reports. `ServingStopped`
/// is the actor's word, emitted only once the adapter is back in the wiring
/// So a leg that sees it may start again without racing anything.
async fn stop_serving(core: &mut Core) -> ServeStopReason {
    core.send(CoreCommand::Serve(ServeCommand::StopServing))
        .await
        .expect("core accepts the command");
    let event = next_expected(core, "the serve activity's ServingStopped", |event| {
        matches!(event, CoreEvent::Serve(ServeEvent::ServingStopped { .. }))
    })
    .await;
    let CoreEvent::Serve(ServeEvent::ServingStopped { reason }) = event else {
        unreachable!("the predicate admits only ServingStopped")
    };
    reason
}

/// Dial the bound listener as an ordinary inbound peer and drive the hello to
/// completion. Identification is the proof that a peer is *served*: the
/// accepted connection got a real `OP_HELLOANSWER` out of the serve side — and
/// the identity it returns is the one the serve side answered under.
async fn identify_against(bound: SocketAddrV4) -> PeerIdentity {
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(*bound.ip(), bound.port()));
    let mut conn = Connection::connect(
        peer,
        test_handshake_ctx(0x07, "rmule-serve-start"),
        ConnectOptions::default(),
    )
    .await
    .expect("the serve listener accepts a dial");
    timeout(HANG_GUARD, async {
        while let Some(event) = conn.next_event().await {
            if let PeerEvent::Connection(ConnectionEvent::Identified { identity }) = event {
                return identity;
            }
        }
        panic!("the connection ended before the serve side answered the hello");
    })
    .await
    .expect("an inbound peer is identified")
}

/// A serve start binds and dials nothing (ADR-0095): the bind is announced, an
/// inbound peer is served, and no session edge ever follows — the login is
/// the operator's to make.
#[tokio::test]
async fn a_serve_start_binds_and_dials_no_server() {
    let mut core = Core::builder(quick_login(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();
    start_serving(&core, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await;
    let bound = serving_started(&mut core).await;
    identify_against(bound).await;
    let edge = timeout(Duration::from_millis(500), async {
        loop {
            match core.next_event().await {
                Some(CoreEvent::ServerConnection(edge)) => return Some(edge),
                Some(_) => {}
                None => return None,
            }
        }
    })
    .await;
    assert!(edge.is_err(), "a serve start opened a session: {edge:?}");
}

/// The operator's connect to a mute server ends under its own name and takes
/// nothing with it: the listener is still accepting after the login deadline
/// fires, and no `ServingStopped` is ever emitted.
#[tokio::test]
async fn an_operator_login_that_is_never_answered_times_out_without_stopping_the_serve() {
    let (mute, _held) = mute_server().await;
    let mut core = Core::builder(quick_login(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();
    start_serving(&core, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await;
    let bound = serving_started(&mut core).await;
    rmule_testkit::connect_to(&core, &mute).await;

    let settled = next_expected(&mut core, "the login's own verdict", |e| {
        matches!(
            e,
            CoreEvent::ServerConnection(ServerConnectionEvent::ConnectFailed { .. })
                | CoreEvent::Serve(ServeEvent::ServingStopped { .. })
        )
    })
    .await;
    let CoreEvent::ServerConnection(edge) = settled else {
        panic!("the serve stopped instead of the login failing");
    };
    assert_eq!(
        edge,
        ServerConnectionEvent::ConnectFailed {
            server: mute,
            reason: ServerConnectFailure::LoginTimedOut,
        },
        "a mute server fails the login, not the serve",
    );

    identify_against(bound).await;
}

/// A bind failure names the bind, a retry against the still-held port is
/// answered again rather than swallowed, and the retry that follows the port
/// being freed binds it. The adapter survives all three, which is the second
/// half of the contract.
#[tokio::test]
async fn a_held_port_fails_the_start_by_name_until_it_is_freed() {
    let holder = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let held = holder.local_addr().expect("local addr").port();
    let mut core = Core::builder(quick_login(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();
    let listen_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, held);

    for attempt in 1..=2 {
        start_serving(&core, listen_addr).await;
        let refused = next_expected(&mut core, "the serve start's verdict", |e| {
            matches!(e, CoreEvent::Serve(_))
        })
        .await;
        let CoreEvent::Serve(event) = refused else {
            unreachable!("the predicate admits only serve events")
        };
        assert_eq!(
            event,
            ServeEvent::ServingFailed {
                reason: ServeStartFailure::Bind(std::io::ErrorKind::AddrInUse),
            },
            "attempt {attempt} must name the bind, and the second must be answered at all",
        );
    }

    drop(holder);
    start_serving(&core, listen_addr).await;
    assert_eq!(
        serving_started(&mut core).await.port(),
        held,
        "the retry after the port is freed binds exactly that port",
    );
}

/// A second start is a first start: the activity that ended gave
/// its adapter back, so the next `StartServing` binds again — the very port the
/// first one released, which it could not do if that listener were still up —
/// and serves an inbound peer on it.
#[tokio::test]
async fn a_stopped_serve_starts_again_on_the_port_it_released() {
    let mut core = Core::builder(quick_login(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();
    start_serving(&core, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await;
    let bound = serving_started(&mut core).await;
    identify_against(bound).await;

    assert_eq!(
        stop_serving(&mut core).await,
        ServeStopReason::Requested,
        "an operator's stop is named as one",
    );

    start_serving(&core, bound).await;
    assert_eq!(
        serving_started(&mut core).await,
        bound,
        "the second start binds the port the first activity gave up",
    );
    identify_against(bound).await;
}

/// The node's User Hash is fixed at build time (ADR-0048 "Identity ownership"):
/// credentials carry only a nickname, a port and a version — there is no
/// field a command or a setting could name another hash in (the
/// `ClientCredentials` doc's `compile_fail` block) — and the hello a peer
/// reads carries the hash the builder was given, under the Core Settings'
/// nickname.
#[tokio::test]
async fn a_started_node_s_hello_carries_the_build_time_user_hash() {
    let node_hash = rmule_primitives::UserHash::from_bytes([0x5E; 16]);
    let mut core = Core::builder(quick_login(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings {
            nickname: "rmule-projected".to_owned(),
            ..rmule_core::CoreSettings::default()
        })
        .user_hash(node_hash)
        .build();
    start_serving(&core, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await;
    let bound = serving_started(&mut core).await;
    let hello = identify_against(bound).await;
    assert_eq!(hello.user_hash(), node_hash);
    assert_eq!(
        hello.nickname(),
        Some(&rmule_primitives::Ed2kText::from_utf8("rmule-projected"))
    );
}
