//! The steps of a login between its session edges (ADR-0075, Run Log): what
//! rmule claimed about itself, what the server answered, and why a dial never
//! came up, each a typed event a reachability diagnosis reads.

use std::net::Ipv4Addr;
use std::time::Duration;

use rmule_core::{
    AssignedAddress, Core, CoreConfig, CoreEvent, DialFailure, LoginStep, PortTestAdmission,
    PortTestEnd, ServerConnectFailure, ServerConnectionEvent,
};
use rmule_primitives::{AddressFamily, ServerEndpoint};
use rmule_testkit::FakeEd2kServer;
use tokio::net::TcpListener;
use tokio::time::timeout;

use crate::fixture::{connect_server_as, free_port, identity_with_port, list_server};

fn connect_only() -> CoreConfig {
    CoreConfig {
        status_ping_tick: Duration::from_secs(3600),
        ..CoreConfig::default()
    }
}

/// Every login step and session edge up to the one that settles the connect.
async fn trail_until_settled(core: &mut Core) -> Vec<CoreEvent> {
    timeout(Duration::from_secs(5), async {
        let mut trail = Vec::new();
        loop {
            let event = core.next_event().await.expect("core is alive");
            let settled = matches!(
                event,
                CoreEvent::ServerConnection(
                    ServerConnectionEvent::Connected { .. }
                        | ServerConnectionEvent::ConnectFailed { .. }
                )
            );
            if matches!(
                event,
                CoreEvent::ServerLogin { .. } | CoreEvent::ServerConnection(_)
            ) {
                trail.push(event);
            }
            if settled {
                return trail;
            }
        }
    })
    .await
    .expect("the connect settles within the deadline")
}

fn steps(trail: &[CoreEvent]) -> Vec<LoginStep> {
    trail
        .iter()
        .filter_map(|event| match event {
            CoreEvent::ServerLogin { step, .. } => Some(*step),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn an_answered_login_reports_what_it_claimed_and_what_the_server_named_us() {
    let server = FakeEd2kServer::start_scripted().await;
    let endpoint = server.endpoint();
    let mut core = Core::builder(connect_only(), rmule_testkit::memory_store()).build();
    list_server(&core, &endpoint).await;
    let port = free_port().await;
    connect_server_as(&core, &endpoint, identity_with_port(port).into()).await;

    let trail = trail_until_settled(&mut core).await;
    let steps = steps(&trail);
    let [
        LoginStep::PortTestAwaited,
        LoginStep::LoginSent { claim },
        LoginStep::Answered { assignment },
        LoginStep::PortTestWindowClosed { arrived: false },
    ] = steps.as_slice()
    else {
        panic!("a login sent, then answered, and no port test from a scripted server: {trail:?}");
    };
    assert_eq!(claim.tcp_port, port, "the listen port the login advertised");
    assert_eq!(claim.family, Some(AddressFamily::V4));
    assert!(assignment.client_id.is_high_id());
    assert_eq!(
        assignment.address,
        AssignedAddress::Ours(Ipv4Addr::LOCALHOST),
        "a High id is the address the server reached"
    );
    assert!(
        matches!(
            trail.last(),
            Some(CoreEvent::ServerConnection(
                ServerConnectionEvent::Connected { .. }
            ))
        ),
        "the steps come before the edge: {trail:?}"
    );
}

#[tokio::test]
async fn a_refused_dial_names_the_os_cause_before_the_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let refused = ServerEndpoint::new("127.0.0.1", listener.local_addr().expect("addr").port())
        .expect("a loopback endpoint");
    drop(listener);
    let mut core = Core::builder(connect_only(), rmule_testkit::memory_store()).build();
    list_server(&core, &refused).await;
    connect_server_as(
        &core,
        &refused,
        identity_with_port(free_port().await).into(),
    )
    .await;

    let trail = trail_until_settled(&mut core).await;
    assert!(
        matches!(
            steps(&trail).as_slice(),
            [LoginStep::DialFailed {
                cause: DialFailure::Os {
                    kind: std::io::ErrorKind::ConnectionRefused,
                    ..
                }
            }]
        ),
        "{trail:?}"
    );
    assert!(
        matches!(
            trail.last(),
            Some(CoreEvent::ServerConnection(
                ServerConnectionEvent::ConnectFailed {
                    reason: ServerConnectFailure::Unreachable,
                    ..
                }
            ))
        ),
        "{trail:?}"
    );
}

/// A server that probes the advertised port dials in while its login is
/// unanswered: the arrival lands inside the window, before the answer, and
/// the window closes saying it came. rmule's listener is up by the login, and
/// the default crypt policy admits the plain dial as a peer — whose end is
/// reported too, once the server hangs up its test.
#[tokio::test]
async fn a_servers_port_test_dialling_in_is_reported_inside_its_window() {
    let server = FakeEd2kServer::start().await;
    let endpoint = server.endpoint();
    let mut core = Core::builder(connect_only(), rmule_testkit::memory_store()).build();
    list_server(&core, &endpoint).await;
    connect_server_as(
        &core,
        &endpoint,
        identity_with_port(free_port().await).into(),
    )
    .await;

    let trail = trail_until_settled(&mut core).await;
    let ended = LoginStep::PortTestEnded {
        end: PortTestEnd::PeerConnectionEnded {
            closed_by: rmule_core::PortTestClosedBy::Peer,
        },
    };
    // The server hangs up its test as it answers the login, so the end may
    // land on either side of the answer.
    let mut steps = steps(&trail);
    let ended_in_trail = steps.contains(&ended);
    steps.retain(|step| *step != ended);
    if !ended_in_trail {
        timeout(Duration::from_secs(5), async {
            while let Some(event) = core.next_event().await {
                if matches!(event, CoreEvent::ServerLogin { step, .. } if step == ended) {
                    return;
                }
            }
            panic!("the core closed before the test's end was reported");
        })
        .await
        .expect("the test's end is reported once the server hangs up");
    }
    let [
        LoginStep::PortTestAwaited,
        LoginStep::LoginSent { .. },
        LoginStep::PortTestArrived {
            admission: PortTestAdmission::Peer,
        },
        LoginStep::Answered { assignment },
        LoginStep::PortTestWindowClosed { arrived: true },
    ] = steps.as_slice()
    else {
        panic!("the server's test arrives inside its window: {trail:?}");
    };
    assert!(assignment.client_id.is_high_id(), "the port test passed");
}
