//! Dial-out `Connection` handshake loopbacks (Correctness Tier, ADR-0040)
//! over the testkit `FakePeer`: identified handshake with capture artifacts,
//! and the hello-timeout close against a peer that never answers.

use std::time::Duration;

use crate::fixture::peer_endpoint;
use rmule_net::peer::{ConnectOptions, Connection};
use rmule_peer::{ConnectionEvent, PeerEvent};
use rmule_primitives::{Ed2kText, UserHash};
use rmule_testkit::peer_session::loopback_ctx;
use rmule_testkit::{FakePeer, PeerScript};
use tempfile::TempDir;

#[tokio::test]
async fn connection_handshake_round_trips_with_loopback_peer() {
    let peer = FakePeer::bind().await;
    let endpoint = peer_endpoint(peer.addr());
    let user_hash = UserHash::from_bytes([0xBE; UserHash::BYTE_LEN]);
    let peer_task = peer.spawn(PeerScript::hello_only(user_hash, "loopback-peer"));

    let capture_dir = TempDir::new().unwrap();
    let options = ConnectOptions {
        connect_timeout: Duration::from_secs(2),
        hello_timeout: Duration::from_secs(5),
        capture_dir: Some(capture_dir.path().to_path_buf()),
        ..Default::default()
    };
    let mut conn = Connection::connect(endpoint, loopback_ctx(), options)
        .await
        .expect("connect");

    assert_eq!(conn.peer_endpoint(), endpoint);

    let mut identity = None;
    while let Some(event) = conn.next_event().await {
        if let PeerEvent::Connection(ConnectionEvent::Identified { identity: id }) = event {
            identity = Some(id);
            break;
        }
    }
    let identity = identity.expect("Identified arrived");
    assert_eq!(identity.user_hash(), user_hash);
    assert_eq!(
        identity.nickname().map(Ed2kText::to_display_string),
        Some("loopback-peer".to_owned())
    );

    conn.shutdown().await.expect("shutdown");
    let _ = peer_task.await;

    for name in ["inbound.bin", "outbound.bin", "meta.toml", "events.toml"] {
        let path = capture_dir.path().join(name);
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        assert!(!bytes.is_empty(), "{name} should not be empty");
    }
}

#[tokio::test]
async fn hello_timeout_closes_session_when_remote_silent() {
    let peer = FakePeer::bind().await;
    let endpoint = peer_endpoint(peer.addr());
    let silent_peer = peer.spawn_silent();

    let options = ConnectOptions {
        connect_timeout: Duration::from_secs(2),
        hello_timeout: Duration::from_millis(50),
        capture_dir: None,
        ..Default::default()
    };
    let mut conn = Connection::connect(endpoint, loopback_ctx(), options)
        .await
        .expect("connect");

    let mut saw_timeout = false;
    while let Some(event) = conn.next_event().await {
        if let PeerEvent::Connection(ConnectionEvent::Disconnected { reason }) = event {
            saw_timeout = matches!(reason, rmule_peer::PeerCloseReason::HelloTimeout);
            break;
        }
    }
    assert!(saw_timeout, "expected HelloTimeout disconnect");
    conn.shutdown().await.expect("shutdown");
    silent_peer.abort();
}
