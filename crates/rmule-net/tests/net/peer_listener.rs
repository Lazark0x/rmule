//! Inbound `PeerListener` loopbacks (Correctness Tier, ADR-0040) over the
//! testkit `FakeDialer`: bind reporting, the accept-side handshake invariant
//! (reply `OP_HELLOANSWER`, never a premature `OP_HELLO`), and the inbound
//! hello timeout against a dialer that never speaks.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use rmule_net::peer::ConnectOptions;
use rmule_net::peer::PeerListener;
use rmule_peer::PeerCloseReason;
use rmule_peer::PeerEvent;
use rmule_primitives::{Ed2kText, UserHash};
use rmule_testkit::FakeDialer;
use rmule_testkit::peer_session::loopback_ctx;

#[tokio::test]
async fn bind_reports_real_local_port() {
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let local = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_port());
    assert_ne!(
        local.port(),
        0,
        "OS-assigned port must be resolved to a real port"
    );
    assert_eq!(local.ip(), &Ipv4Addr::LOCALHOST);
}

#[tokio::test]
async fn accept_identifies_dialer_and_replies_hello_answer() {
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let bound = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_port());
    let user_hash = UserHash::from_bytes([0xBE; UserHash::BYTE_LEN]);

    // The dialer asserts our reply is HELLOANSWER — proving the inbound
    // session waits and replies, never sending a premature OP_HELLO.
    let dialer = FakeDialer::spawn(bound, user_hash, "dialing-peer");

    let mut conn = listener
        .accept(loopback_ctx(), ConnectOptions::default())
        .await
        .expect("accept");

    let mut identity = None;
    while let Some(event) = conn.next_event().await {
        if let PeerEvent::PeerIdentified { identity: id } = event {
            identity = Some(id);
            break;
        }
    }
    let identity = identity.expect("PeerIdentified arrived");
    assert_eq!(identity.user_hash(), user_hash);
    assert_eq!(
        identity.nickname().map(Ed2kText::to_display_string),
        Some("dialing-peer".to_owned())
    );

    conn.shutdown().await.expect("shutdown");
    let _ = dialer.await;
}

#[tokio::test]
async fn inbound_hello_timeout_closes_when_dialer_silent() {
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let bound = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_port());

    let silent = FakeDialer::spawn_silent(bound, Duration::from_millis(500));

    let options = ConnectOptions {
        hello_timeout: Duration::from_millis(50),
        ..Default::default()
    };
    let mut conn = listener
        .accept(loopback_ctx(), options)
        .await
        .expect("accept");

    let mut saw_timeout = false;
    while let Some(event) = conn.next_event().await {
        if let PeerEvent::Disconnected { reason } = event {
            saw_timeout = matches!(reason, PeerCloseReason::HelloTimeout);
            break;
        }
    }
    assert!(saw_timeout, "inbound silence must close with HelloTimeout");
    conn.shutdown().await.expect("shutdown");
    let _ = silent.await;
}
