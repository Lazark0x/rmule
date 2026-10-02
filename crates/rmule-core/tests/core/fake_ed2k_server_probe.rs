//! Probe-unit tests for `FakeEd2kServer`'s High-ID **Back-Connect Probe**
//! (ADR-0040 Correctness Tier), capture-corrected to the bench Lugdunum 17.15
//! semantics: the check is a protocol exchange — the server
//! back-connects the advertised port, sends `OP_HELLO`, and grants High-ID
//! only when an `OP_HELLOANSWER` with the login's user hash comes back within
//! the window. A merely-accepted (mute) port fails the check, exactly as the
//! real server does ("WARNING : No answer from your <port> port"). Includes
//! the serve-adapter regression: `RuntimeServeRuntimeService::start` must
//! answer the check *during* the login (accepting concurrently), or the login
//! lands Low-ID.

use std::net::{Ipv4Addr, SocketAddrV4};

use crate::fixture::identity_with_port;
use crate::fixture::login_and_read_id;
use crate::fixture::{dead_port, free_port};
use rmule_core::{RuntimeServeRuntimeService, ServeRuntimeService};
use rmule_testkit::{FakeEd2kServer, spawn_check_answering_listener};
use tokio::net::TcpListener;

#[tokio::test]
async fn probe_answered_check_grants_high_id() {
    let server = FakeEd2kServer::start().await;

    // A listener that answers the check `OP_HELLO` as the logging-in identity:
    // the exchange completes, so the login earns High-ID.
    let (p, listener) = spawn_check_answering_listener(identity_with_port(0)).await;

    let id = login_and_read_id(server.local_addr(), p).await;
    assert!(
        id.is_high_id(),
        "an answered port check must grant High-ID, got {id:?}"
    );
    listener.abort();
}

#[tokio::test]
async fn probe_mute_accepted_port_assigns_low_id() {
    let server = FakeEd2kServer::start().await;

    // Bind a listener on P that accepts but never answers the check `OP_HELLO`
    // — rmule's posture before its serve listener answered the back-connect.
    // The real Lugdunum fails this check ("No answer from your <port> port"),
    // so the fake must too.
    let peer_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = peer_listener.local_addr().unwrap().port();
    let listener = tokio::spawn(async move { while peer_listener.accept().await.is_ok() {} });

    let id = login_and_read_id(server.local_addr(), p).await;
    assert!(
        id.is_low_id(),
        "a mute (accepted, unanswered) port must assign Low-ID, got {id:?}"
    );
    listener.abort();
}

#[tokio::test]
async fn probe_unreachable_advertised_port_assigns_low_id() {
    let server = FakeEd2kServer::start().await;

    // Advertise a port nothing listens on: the back-connect is refused.
    let p = dead_port().await;

    let id = login_and_read_id(server.local_addr(), p).await;
    assert!(
        id.is_low_id(),
        "an unreachable advertised port must assign Low-ID, got {id:?}"
    );
}

/// The serve adapter's `start` binds the listener and keeps
/// accepting from its own pump, so a server's port-check `OP_HELLO` arriving
/// while a login is in flight is answered inside the check window and the
/// login earns High-ID. The serve dials no server itself (ADR-0095); the
/// login here is the operator's, made on a raw connection advertising the
/// listener's port.
#[tokio::test]
async fn a_started_serve_answers_the_port_check_of_a_login_in_flight() {
    let server = FakeEd2kServer::start().await;

    // A fixed port with identity.tcp_port == listen port, as production binds
    // (the serve CLI aligns them; see ADR-0040).
    let p = free_port().await;
    let mut serve = RuntimeServeRuntimeService::new();
    let bound = serve
        .start(
            identity_with_port(p),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, p),
        )
        .await
        .expect("serve start");
    assert_eq!(bound.port(), p, "serve bound the requested port");
    assert!(
        server.assigned_ids().await.is_empty(),
        "a serve start logs nobody in"
    );

    let id = login_and_read_id(server.local_addr(), p).await;
    assert!(
        id.is_high_id(),
        "the listener must answer the port check during the login and earn High-ID, got {id:?}"
    );
}
