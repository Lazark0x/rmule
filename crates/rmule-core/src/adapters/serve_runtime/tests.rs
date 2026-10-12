//! Accept-side tests: a cancelled accept must not drop a peer mid-handshake,
//! and a banned or IP-filtered address is refused at the listener.

use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use rmule_net::peer::ObfuscationPolicy;
use rmule_primitives::{Ipv4Endpoint, PeerEndpoint};
use tokio::time::timeout;

use crate::adapters::tests::{dialed_serve_ctx, loopback_blocking_ip_filter};
use crate::ban_store::SharedBanStore;
use crate::ip_filter::SharedIpFilter;

use super::*;
use rmule_peer::{ConnectionEvent, SideCommand};

/// Found on the interop bench: a peer that has completed the TCP
/// handshake but not yet sent its hello must survive `accept()` being
/// cancelled. With obfuscation armed the listener peeks byte 0 to tell a
/// plaintext hello from an obfuscated one, and that peek awaits while
/// holding the accepted socket — so an `accept()` future cancelled by the
/// serve runner's `select!` (any other branch waking first) would drop
/// the stream, FINning a peer that had done nothing wrong. A stock aMule
/// hit exactly this: its source dial was reset before its hello, and it
/// dead-listed rmule for the whole run.
///
/// Cancel `accept()` while a silent client is mid-handshake, then call it
/// again: the client must still be connected, and its hello must still be
/// served. With the accept inside the cancelled future the first
/// assertion fails — the peek is cancelled and the socket dropped.
#[tokio::test]
async fn a_cancelled_accept_does_not_drop_a_peer_that_is_mid_handshake() {
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    // Crypt armed: this is what puts the byte-0 peek on the accept path.
    let mut serve =
        RuntimeServeRuntimeService::new().with_hello_adverts(crate::adapters::HelloAdverts {
            obfuscation: crate::obfuscation_policy::SharedObfuscationPolicy::new(Some(
                ObfuscationPolicy::Supported,
            )),
            ..crate::adapters::HelloAdverts::default()
        });
    let credentials = dialed_serve_ctx().identity;
    let bound = serve
        .start(credentials, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();

    // A client that connects and then stays silent, exactly as aMule is
    // between its SYN and its hello.
    let mut client = TcpStream::connect(SocketAddr::V4(bound)).await.unwrap();

    // Cancel an `accept()` while that client is mid-handshake.
    assert!(
        timeout(Duration::from_millis(200), serve.accept())
            .await
            .is_err(),
        "a silent peer must not resolve accept()",
    );

    // The peer is still connected: nothing was dropped under it. A read
    // that times out means the socket is open and simply idle; `Ok(0)`
    // would mean rmule closed it.
    assert!(
        timeout(Duration::from_millis(200), client.read(&mut [0u8; 1]))
            .await
            .is_err(),
        "the mid-handshake peer was dropped by the cancelled accept",
    );

    // And it is still servable: its hello now completes the accept.
    client
        .write_all(&plaintext_hello_bytes())
        .await
        .expect("write the peer hello");
    let accepted = timeout(Duration::from_secs(5), serve.accept())
        .await
        .expect("the surviving peer's hello resolves accept()")
        .expect("a ServeConnection surfaced");
    drop(accepted);
}

/// ADR-0064, peer-TCP enforcement: `accept()` silently refuses a
/// connection from a banned IP — never surfacing it as a `ServeConnection`
/// and closing the underlying socket — while the *same* running instance
/// keeps serving ordinary connections. Refusal must never look like
/// "listener closed" to the caller (which would wind the whole serve
/// activity down).
#[tokio::test]
async fn accept_refuses_a_connection_from_a_banned_ip() {
    use std::net::SocketAddr;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpStream;

    // An unreachable "server": bind then drop for a free port whose
    // connect fails fast (mirrors `runtime_adapters.rs`); a failed login
    // never fails the serve activity — only binding the listener does.

    let ban_store: SharedBanStore = SharedBanStore::default();
    let mut serve = RuntimeServeRuntimeService::new().with_ban_store(ban_store.clone());
    let credentials = dialed_serve_ctx().identity;
    let bound = serve
        .start(credentials, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();

    // Positive control: not yet banned, an ordinary dial is accepted.
    let _control_client = TcpStream::connect(SocketAddr::V4(bound)).await.unwrap();
    let accepted = timeout(Duration::from_secs(2), serve.accept())
        .await
        .expect("accept resolves for an unbanned dial")
        .expect("a ServeConnection surfaced");
    drop(accepted);

    // Ban the loopback address (the only address a test can dial from),
    // then dial again on the same running instance.
    ban_store
        .lock()
        .await
        .ban(IpAddr::V4(Ipv4Addr::LOCALHOST), std::time::Instant::now());
    let mut banned_client = TcpStream::connect(SocketAddr::V4(bound)).await.unwrap();

    // `accept()` never surfaces a connection for the banned dial — it
    // keeps looping internally rather than returning `None` (which would
    // mean "listener closed").
    assert!(
        timeout(Duration::from_millis(300), serve.accept())
            .await
            .is_err(),
        "a banned IP's connection never becomes a ServeConnection"
    );

    // The client side observes its connection closed, not merely ignored.
    let mut buf = [0u8; 1];
    let read = timeout(Duration::from_secs(2), banned_client.read(&mut buf))
        .await
        .expect("the refused socket closes within 2s");
    assert_eq!(
        read.unwrap(),
        0,
        "the banned connection is closed, not left open"
    );
}

/// The IP filter's accept gate (aMule `CClientTCPSocket::InitNetworkData`):
/// `accept()` silently refuses a connection from an IP-filtered address on
/// the same running instance that accepted an ordinary one moments before
/// — proving both the gate and that a table swapped into the shared handle
/// (the future reload path) takes effect on live surfaces.
#[tokio::test]
async fn accept_refuses_a_connection_from_an_ip_filtered_address() {
    use std::net::SocketAddr;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpStream;

    let ip_filter = SharedIpFilter::default();
    let mut serve = RuntimeServeRuntimeService::new().with_ip_filter(ip_filter.clone());
    let credentials = dialed_serve_ctx().identity;
    let bound = serve
        .start(credentials, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();

    // Positive control: the empty filter admits an ordinary dial.
    let _control_client = TcpStream::connect(SocketAddr::V4(bound)).await.unwrap();
    let accepted = timeout(Duration::from_secs(2), serve.accept())
        .await
        .expect("accept resolves while the filter table is empty")
        .expect("a ServeConnection surfaced");
    drop(accepted);

    // Swap in a table blocking loopback, then dial again.
    *ip_filter.write().expect("ip filter lock") = loopback_blocking_ip_filter();
    let mut filtered_client = TcpStream::connect(SocketAddr::V4(bound)).await.unwrap();

    assert!(
        timeout(Duration::from_millis(300), serve.accept())
            .await
            .is_err(),
        "an IP-filtered connection never becomes a ServeConnection"
    );

    // The client side observes its connection closed, not merely ignored.
    let mut buf = [0u8; 1];
    let read = timeout(Duration::from_secs(2), filtered_client.read(&mut buf))
        .await
        .expect("the refused socket closes within 2s");
    assert_eq!(
        read.unwrap(),
        0,
        "the filtered connection is closed, not left open"
    );
}

/// A burst of refused peers is drained **off** the accept path.
///
/// Three IP-filtered peers arrive at once. One `accept()` call — cancelled,
/// exactly as the serve runner's `select!` cancels it — drains all three, and
/// every one of them is still closed afterwards: their `shutdown()` runs in a
/// task of its own, so neither the drain nor the close is gated on the other.
/// Inline, the cancellation would have dropped whichever refusal was mid-close
/// and left the rest queued behind it.
///
/// The backlog the accept gauge reports is asserted on the way past, since it
/// is the same fact from the other side: three peers queued is a depth of
/// three.
#[tokio::test]
async fn a_burst_of_refused_peers_is_drained_and_closed_off_the_accept_path() {
    use std::net::SocketAddr;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpStream;

    let ip_filter = SharedIpFilter::default();
    *ip_filter.write().expect("ip filter lock") = loopback_blocking_ip_filter();
    let mut serve = RuntimeServeRuntimeService::new().with_ip_filter(ip_filter);
    let credentials = dialed_serve_ctx().identity;
    let bound = serve
        .start(credentials, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();

    let mut refused = Vec::new();
    for _ in 0..3 {
        refused.push(TcpStream::connect(SocketAddr::V4(bound)).await.unwrap());
    }

    // Wait for all three to reach the channel, so the drain below really is
    // one accept over a burst rather than three accepts over a trickle.
    timeout(Duration::from_secs(5), async {
        while serve.accept_backlog() != Some(3) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the pump admits all three within 5s");

    assert!(
        timeout(Duration::from_millis(300), serve.accept())
            .await
            .is_err(),
        "no filtered peer becomes a ServeConnection"
    );
    assert_eq!(
        serve.accept_backlog(),
        Some(0),
        "one cancelled accept drained the whole burst"
    );

    for (nth, mut client) in refused.into_iter().enumerate() {
        let mut buf = [0u8; 1];
        let read = timeout(Duration::from_secs(2), client.read(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("refused peer {nth} closes within 2s"));
        assert_eq!(
            read.unwrap(),
            0,
            "refused peer {nth} is closed, not ignored"
        );
    }
}

/// A minimal plaintext `OP_HELLO` (`0xE3`), enough for the listener's
/// byte-0 discrimination to route this connection down the plaintext path
/// and for the driver to answer it.
fn plaintext_hello_bytes() -> Vec<u8> {
    use rmule_peer::PeerSession;
    use rmule_primitives::SessionOutput;

    let ctx = dialed_serve_ctx();
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4662));
    let mut session = PeerSession::new_outbound(peer, ctx);
    session.start();
    let mut bytes = Vec::new();
    while let Some(output) = session.poll_output() {
        if let SessionOutput::Write(frame) = output {
            bytes.extend_from_slice(&frame);
        }
    }
    assert_eq!(bytes.first(), Some(&0xE3), "a plaintext peer hello");
    bytes
}

/// A serve runtime injected through
/// `CoreBuilder::serve_runtime` holds the builder's one Peer Roster — the
/// instance the actor's serve task and the Kad requester gate share — not a
/// copy. Before, the trait's `peer_roster()` default handed back a fresh,
/// unshared roster.
#[test]
fn an_injected_serve_runtime_shares_the_builder_s_peer_roster() {
    let builder = crate::Core::builder(crate::CoreConfig::default(), rmule_testkit::memory_store())
        .settings(crate::CoreSettings::default())
        .serve_runtime(RuntimeServeRuntimeService::new());
    let peer = rmule_primitives::Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 7), 4662);
    builder
        .shared_peer_roster()
        .mark_known(crate::peer_roster::PeerRelation::Upload, peer);
    assert!(
        builder.installed_serve_runtime().peer_roster.knows(peer.ip),
        "the injected runtime reads the node's one roster"
    );
}

/// A serve runtime under `Required`, bound on loopback, logging in to a
/// server that is not there (the login fails on its own; the listener stays).
async fn required_serve() -> (RuntimeServeRuntimeService, SocketAddrV4) {
    let mut serve =
        RuntimeServeRuntimeService::new().with_hello_adverts(crate::adapters::HelloAdverts {
            obfuscation: crate::obfuscation_policy::SharedObfuscationPolicy::new(Some(
                ObfuscationPolicy::Required,
            )),
            ..crate::adapters::HelloAdverts::default()
        });
    let bound = serve
        .start(
            dialed_serve_ctx().identity,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        )
        .await
        .unwrap();
    (serve, bound)
}

/// Dial `bound` plain and send a hello, as a server's port test and a Kad
/// helper's connect-back do; returns the stream and the opcode of the first
/// frame it is answered with, `None` when it is closed instead.
async fn plain_test_dial(bound: SocketAddrV4) -> (tokio::net::TcpStream, Option<u8>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut tester = tokio::net::TcpStream::connect(std::net::SocketAddr::V4(bound))
        .await
        .unwrap();
    tester
        .write_all(&rmule_testkit::wire::hello_bytes(
            rmule_primitives::UserHash::from_bytes([0x33; 16]),
            "tester",
        ))
        .await
        .unwrap();
    let mut head = [0u8; 6];
    let answered = timeout(Duration::from_secs(2), tester.read_exact(&mut head))
        .await
        .expect("answered or closed within 2s");
    if answered.is_err() {
        return (tester, None);
    }
    let len = u32::from_le_bytes([head[1], head[2], head[3], head[4]]) as usize;
    let mut body = vec![0u8; len - 1];
    tester.read_exact(&mut body).await.unwrap();
    (tester, Some(head[5]))
}

/// Whether the peer closed `stream` within 2 s.
async fn closed_by_us(stream: &mut tokio::net::TcpStream) -> bool {
    use tokio::io::AsyncReadExt;
    let mut sink = [0u8; 256];
    loop {
        match timeout(Duration::from_secs(2), stream.read(&mut sink)).await {
            Ok(Ok(0) | Err(_)) => return true,
            Ok(Ok(_)) => {}
            Err(_) => return false,
        }
    }
}

/// The login to a loopback server whose port test is awaited, and where its
/// steps are reported.
fn awaiting_loopback_login(
    serve: &RuntimeServeRuntimeService,
    events: &mpsc::Sender<crate::CoreEvent>,
) -> crate::awaited_testers::AwaitingLogin {
    serve
        .session
        .own_identity()
        .awaited_testers()
        .awaiting_login_from(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            rmule_primitives::ServerEndpoint::new("127.0.0.1", 4661).expect("endpoint"),
            crate::server_list::ServerFacts::reporting_to(events),
        )
}

/// The next port test step reported, within 2 s.
async fn port_test_step(events: &mut mpsc::Receiver<crate::CoreEvent>) -> crate::LoginStep {
    match timeout(Duration::from_secs(2), events.recv()).await {
        Ok(Some(crate::CoreEvent::ServerLogin { step, .. })) => step,
        other => panic!("no login step reported: {other:?}"),
    }
}

/// Under `Required`, the server a login answer is awaited from
/// dials its High-ID port test plain. The test is answered — the hello
/// exchange is all it needs — and served nothing: a file request closes it,
/// and it never becomes a serve connection. Its arrival and its end are
/// reported as steps of the login.
#[tokio::test]
async fn under_required_the_awaited_servers_plain_test_is_answered_and_served_nothing() {
    use tokio::io::AsyncWriteExt;
    let (mut serve, bound) = required_serve().await;
    let (events_tx, mut events) = mpsc::channel(8);
    let awaiting = awaiting_loopback_login(&serve, &events_tx);

    let (mut tester, answer) = plain_test_dial(bound).await;
    assert_eq!(answer, Some(rmule_peer::PeerOpcode::HelloAnswer.as_u8()));

    // OP_SETREQFILEID: a request to be served.
    let mut ask = vec![
        0xE3,
        17,
        0,
        0,
        0,
        rmule_peer::PeerOpcode::SetReqFileId.as_u8(),
    ];
    ask.extend_from_slice(&[0x11; 16]);
    tester.write_all(&ask).await.unwrap();
    // The serve loop's accept runs the gates and hands the test off; it
    // never yields it as a serve connection.
    assert!(
        timeout(Duration::from_millis(300), serve.accept())
            .await
            .is_err(),
        "a Test Connection never reaches the serve pipeline"
    );
    assert!(
        closed_by_us(&mut tester).await,
        "a test asking to be served is closed"
    );
    assert_eq!(
        port_test_step(&mut events).await,
        crate::LoginStep::PortTestArrived {
            admission: crate::PortTestAdmission::TestConnection
        }
    );
    assert_eq!(
        port_test_step(&mut events).await,
        crate::LoginStep::PortTestEnded {
            end: crate::PortTestEnd::AskedToBeServed
        }
    );
    assert!(awaiting.close(), "the window saw the server's test arrive");
}

/// The window closes with the login's answer: the same plain dial is then
/// refused before any hello is answered — and, being the server's, reported
/// as its port test come late rather than lost among strangers.
#[tokio::test]
async fn under_required_a_plain_dial_after_the_login_was_answered_is_refused_and_reported_late() {
    let (serve, bound) = required_serve().await;
    let (events_tx, mut events) = mpsc::channel(8);
    drop(awaiting_loopback_login(&serve, &events_tx));

    let (_tester, answer) = plain_test_dial(bound).await;
    assert_eq!(answer, None, "no test is awaited: plain is refused");
    let crate::LoginStep::PortTestLate { late_by, admission } = port_test_step(&mut events).await
    else {
        panic!("the refused late test is reported as late");
    };
    assert_eq!(admission, crate::PortTestLateAdmission::Refused);
    assert!(late_by < crate::awaited_testers::LATE_TEST_MEMORY);
}

/// The obfuscation policy changes live (ADR-0046): the accept reads it as
/// each connection arrives, so a change to `Required` refuses the very next
/// plain dial before any hello is answered, while the plain link admitted
/// before the change keeps what it agreed and stays up.
#[tokio::test]
async fn a_live_policy_change_reaches_the_next_accept_and_spares_the_link_already_in() {
    let policy = crate::obfuscation_policy::SharedObfuscationPolicy::default();
    let mut serve =
        RuntimeServeRuntimeService::new().with_hello_adverts(crate::adapters::HelloAdverts {
            obfuscation: policy.clone(),
            ..crate::adapters::HelloAdverts::default()
        });
    let bound = serve
        .start(
            dialed_serve_ctx().identity,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        )
        .await
        .unwrap();

    let before = tokio::spawn(plain_test_dial(bound));
    let served = timeout(Duration::from_secs(2), serve.accept())
        .await
        .expect("the plain dial reaches the serve pipeline")
        .expect("as a serve connection");
    let (mut before, answer) = before.await.unwrap();
    assert_eq!(answer, Some(rmule_peer::PeerOpcode::HelloAnswer.as_u8()));

    policy.set(Some(ObfuscationPolicy::Required));
    let (_after, refused) = plain_test_dial(bound).await;
    assert_eq!(refused, None, "the next plain dial meets Required");
    assert!(
        !closed_by_us(&mut before).await,
        "the plain link admitted before the change stays up"
    );
    drop(served);
}

/// Outside `Required` the server's plain test is let in like any peer, so
/// nothing tells it from one — but its arrival is the login's step, and the
/// end of its peer connection is reported too, naming the peer as the side
/// that closed it.
#[tokio::test]
async fn outside_required_the_awaited_servers_test_is_served_as_a_peer_and_its_end_reported() {
    let mut serve = RuntimeServeRuntimeService::new();
    let bound = serve
        .start(
            dialed_serve_ctx().identity,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        )
        .await
        .unwrap();
    let (events_tx, mut events) = mpsc::channel(8);
    let awaiting = awaiting_loopback_login(&serve, &events_tx);

    let tester = tokio::spawn(plain_test_dial(bound));
    let served = timeout(Duration::from_secs(2), serve.accept())
        .await
        .expect("the test reaches the serve pipeline")
        .expect("as a serve connection");
    let (tester, answer) = tester.await.unwrap();
    assert_eq!(answer, Some(rmule_peer::PeerOpcode::HelloAnswer.as_u8()));
    assert_eq!(
        port_test_step(&mut events).await,
        crate::LoginStep::PortTestArrived {
            admission: crate::PortTestAdmission::Peer
        }
    );
    drop(tester);
    assert_eq!(
        port_test_step(&mut events).await,
        crate::LoginStep::PortTestEnded {
            end: crate::PortTestEnd::PeerConnectionEnded {
                closed_by: crate::PortTestClosedBy::Peer
            }
        }
    );
    drop(served);
    assert!(awaiting.close(), "the window saw the server's test arrive");
}

/// The same test served as a peer and let go by core first: its end names
/// rmule as the side that closed it.
#[tokio::test]
async fn a_port_test_served_as_a_peer_and_let_go_by_core_names_rmule_as_the_closer() {
    let mut serve = RuntimeServeRuntimeService::new();
    let bound = serve
        .start(
            dialed_serve_ctx().identity,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        )
        .await
        .unwrap();
    let (events_tx, mut events) = mpsc::channel(8);
    let _awaiting = awaiting_loopback_login(&serve, &events_tx);

    let tester = tokio::spawn(plain_test_dial(bound));
    let served = timeout(Duration::from_secs(2), serve.accept())
        .await
        .expect("the test reaches the serve pipeline")
        .expect("as a serve connection");
    let (_tester, _) = tester.await.unwrap();
    assert!(matches!(
        port_test_step(&mut events).await,
        crate::LoginStep::PortTestArrived { .. }
    ));
    drop(served);
    assert_eq!(
        port_test_step(&mut events).await,
        crate::LoginStep::PortTestEnded {
            end: crate::PortTestEnd::PeerConnectionEnded {
                closed_by: crate::PortTestClosedBy::Us
            }
        }
    );
}

/// A Kad helper whose check window was dropped (a recheck started) connects
/// back plain under `Required`: refused, and reported as a late Kad helper
/// test rather than lost among strangers.
#[tokio::test]
async fn under_required_a_kad_helpers_plain_connect_back_after_its_window_is_refused_and_reported_late()
 {
    let (serve, bound) = required_serve().await;
    let (events_tx, mut events) = mpsc::channel(8);
    let awaited = serve.session.own_identity().awaited_testers();
    awaited.install_events(events_tx.downgrade());
    let window = (
        Ipv4Addr::LOCALHOST,
        Instant::now() + Duration::from_secs(180),
    );
    awaited.kad_check_asked(window.0, window.1);
    awaited.kad_checks_dropped(&[window]);

    let (_helper, answer) = plain_test_dial(bound).await;
    assert_eq!(answer, None, "no test is awaited: plain is refused");
    let Ok(Some(crate::CoreEvent::KadHelperTestLate {
        helper,
        late_by,
        admission,
    })) = timeout(Duration::from_secs(2), events.recv()).await
    else {
        panic!("the refused late helper test is reported");
    };
    assert_eq!(helper, Ipv4Addr::LOCALHOST);
    assert_eq!(admission, crate::PortTestLateAdmission::Refused);
    assert!(late_by < crate::awaited_testers::LATE_TEST_MEMORY);
}

/// A Kad helper asked for a TCP firewall check connects back plain; its
/// `OP_KAD_FWTCPCHECK_ACK` after the hello is what proves us reachable, so it
/// must reach the Kad requester cycle.
#[tokio::test]
async fn under_required_an_asked_kad_helpers_plain_connect_back_delivers_its_ack() {
    use tokio::io::AsyncWriteExt;
    let (mut serve, bound) = required_serve().await;
    let (pump_tx, mut pump_rx) = mpsc::channel(4);
    serve.kad_pump.install_for_good(pump_tx);
    serve
        .session
        .own_identity()
        .awaited_testers()
        .kad_check_asked(
            Ipv4Addr::LOCALHOST,
            Instant::now() + Duration::from_secs(180),
        );

    let (mut helper, answer) = plain_test_dial(bound).await;
    assert_eq!(answer, Some(rmule_peer::PeerOpcode::HelloAnswer.as_u8()));
    // OP_KAD_FWTCPCHECK_ACK: eMule-extended, empty body.
    helper
        .write_all(&[
            0xC5,
            1,
            0,
            0,
            0,
            rmule_peer::PeerOpcode::KadFwTcpCheckAck.as_u8(),
        ])
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_millis(300), serve.accept())
            .await
            .is_err()
    );
    let delivered = timeout(Duration::from_secs(2), pump_rx.recv())
        .await
        .expect("the ack reaches the Kad pump within 2s");
    assert!(matches!(
        delivered,
        Some(crate::adapters::kad_runtime::KadPumpCommand::TcpFirewallAck(ip))
            if ip == Ipv4Addr::LOCALHOST
    ));
}

/// Under `Required`, an aMule helper connects back
/// plain, and its hello is followed by Secure User Identification (aMule's
/// `InfoPacketsReceived` → `SendSecIdentStatePacket`, `BaseClient.cpp:3255-3265`)
/// before its `OP_KAD_FWTCPCHECK_ACK`, which its client-list timer sends
/// (`ClientList.cpp:734-746`). The identity proof is not a request to be
/// served: the Test Connection must stay up for the ack. Closed at the proof,
/// the ack never counted and Kad TCP never read Open under `Required`.
#[tokio::test]
async fn under_required_a_helper_that_proves_its_identity_before_its_ack_is_still_counted() {
    use rmule_peer::{PeerCommand, PeerEvent};
    let mut serve =
        RuntimeServeRuntimeService::new().with_hello_adverts(crate::adapters::HelloAdverts {
            obfuscation: crate::obfuscation_policy::SharedObfuscationPolicy::new(Some(
                ObfuscationPolicy::Required,
            )),
            secure_ident: Some(std::sync::Arc::new(
                rmule_primitives::SecureIdentKey::generate().expect("a SUI keypair"),
            )),
            ..crate::adapters::HelloAdverts::default()
        });
    let bound = serve
        .start(
            dialed_serve_ctx().identity,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        )
        .await
        .unwrap();
    let (pump_tx, mut pump_rx) = mpsc::channel(4);
    serve.kad_pump.install_for_good(pump_tx);
    serve
        .session
        .own_identity()
        .awaited_testers()
        .kad_check_asked(
            Ipv4Addr::LOCALHOST,
            Instant::now() + Duration::from_secs(180),
        );

    // The helper: plain (our request named no crypt it could key), SUI on.
    let helper_adverts = crate::adapters::HelloAdverts {
        secure_ident: Some(std::sync::Arc::new(
            rmule_primitives::SecureIdentKey::generate().expect("a SUI keypair"),
        )),
        ..crate::adapters::HelloAdverts::default()
    };
    let mut helper_ctx = dialed_serve_ctx();
    helper_ctx.identity = rmule_primitives::ClientIdentity::new(
        rmule_primitives::UserHash::from_bytes([0x44; 16]),
        rmule_primitives::Ed2kText::from_utf8("helper"),
        4662,
        60,
    );
    let (mut helper, _) = rmule_net::peer::Connection::connect_identified(
        PeerEndpoint::V4(Ipv4Endpoint::new(*bound.ip(), bound.port())),
        helper_ctx,
        helper_adverts.connect_options(rmule_primitives::PeerCrypt::unknown()),
    )
    .await
    .expect("the plain test dial is admitted");
    // The serve loop hands the Test Connection off; it is never served.
    assert!(
        timeout(Duration::from_millis(300), serve.accept())
            .await
            .is_err()
    );
    timeout(Duration::from_secs(2), async {
        while let Some(event) = helper.next_event().await {
            if matches!(
                event,
                PeerEvent::Connection(ConnectionEvent::IdentityVerified { .. })
            ) {
                return;
            }
        }
        panic!("the helper's link ended before the identity exchange");
    })
    .await
    .expect("Secure User Identification completes within 2s");
    helper
        .send(PeerCommand::Side(SideCommand::SendKadFirewallAck))
        .await
        .expect("the ack goes out");
    let delivered = timeout(Duration::from_secs(2), pump_rx.recv())
        .await
        .expect("the ack reaches the Kad pump within 2s");
    assert!(matches!(
        delivered,
        Some(crate::adapters::kad_runtime::KadPumpCommand::TcpFirewallAck(ip))
            if ip == Ipv4Addr::LOCALHOST
    ));
}
