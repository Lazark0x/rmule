//! The reusable peer-TCP **dial-back surface** (`Connection::connect_identified`,
//! ADR-0058 responder) over the testkit `FakePeer`: a Kad firewall-check
//! dial-back that connects, completes the eD2k handshake, delivers the null
//! `OP_KAD_FWTCPCHECK_ACK` (`0xA8`), and closes — and the silent-refusal path a
//! peer that never finishes its hello takes.
//!
//! Beside it the **callback** dial-back seam (`Connection::dial_stream`, ADR-0061 routes 2/4):
//! the undriven stream a `0x95`/`0x99`
//! verdict opens, plaintext or obfuscated toward the requester's User Hash.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use crate::fixture::{RESPONDER_HASH, bound_v4, options, peer_endpoint};
use rmule_net::peer::{
    ConnectOptions, Connection, ObfuscationConfig, ObfuscationPolicy, PeerListener, PeerNetError,
    PeerStreamRole,
};
use rmule_peer::{ConnectionEvent, PeerCommand, PeerEvent, SideCommand};
use rmule_primitives::{UserHash, is_plaintext_marker};
use rmule_testkit::peer_session::serverless_ctx;
use rmule_testkit::{FakePeer, PeerScript};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

/// The load-bearing enactment: a firewalled requester that answers our hello
/// must receive the `OP_KAD_FWTCPCHECK_ACK` (`0xA8`) our dial-back sends — that
/// arrival is the whole proof its TCP port is reachable. If the ack still
/// carried the old wrong byte (`0xA9`), the requester would never count it, so
/// this pins both the dial surface and the opcode.
#[tokio::test]
async fn dial_back_delivers_the_firewall_ack_once_the_requester_identifies() {
    let peer = FakePeer::bind().await;
    let endpoint = peer_endpoint(peer.addr());
    let requester_hash = UserHash::from_bytes([0xBE; UserHash::BYTE_LEN]);
    let peer_task = peer.spawn(PeerScript::hello_only(requester_hash, "fw-check-requester"));

    let (conn, identity) = Connection::connect_identified(endpoint, serverless_ctx(), options())
        .await
        .expect("dial-back completes the handshake");
    assert_eq!(
        identity.user_hash(),
        requester_hash,
        "the dial surface hands back the requester's proven identity",
    );

    conn.send(PeerCommand::Side(SideCommand::SendKadFirewallAck))
        .await
        .expect("queue the connect-back ack");
    conn.shutdown().await.expect("close after the ack flushes");

    let stats = peer_task.await.expect("requester script");
    assert!(
        stats.kad_fw_tcp_check_ack,
        "the requester must receive OP_KAD_FWTCPCHECK_ACK (0xA8) after the dial-back handshake",
    );
}

/// aMule's `RequestTCP` refused dial-back is silent. A requester that accepts
/// the TCP connect but never finishes its hello yields `HandshakeIncomplete`,
/// which the core broker drops rather than reacting to — no ack, no panic.
#[tokio::test]
async fn dial_back_reports_handshake_incomplete_when_the_requester_never_identifies() {
    let peer = FakePeer::bind().await;
    let endpoint = peer_endpoint(peer.addr());
    let silent = peer.spawn_silent();

    let options = ConnectOptions {
        hello_timeout: Duration::from_millis(50),
        ..options()
    };
    match Connection::connect_identified(endpoint, serverless_ctx(), options).await {
        Err(PeerNetError::HandshakeIncomplete(_)) => {}
        Err(other) => panic!("expected HandshakeIncomplete, got {other:?}"),
        Ok(_) => panic!("a hello that never completes must not yield an identified dial-back"),
    }

    silent.abort();
}

/// The callback dial-back's own identity — distinct from the requester's, so
/// each side identifying the other is a real reading and not a coincidence.
const CALLBACK_DIALER_HASH: [u8; 16] = [0xC5; 16];

/// Our side of a callback dial-back: no server behind us (the `0x95` route is
/// serverless), under a hash the requester can tell apart from its own.
fn callback_ctx() -> rmule_peer::PeerHandshakeContext {
    let mut ctx = serverless_ctx();
    ctx.identity = rmule_primitives::ClientIdentity::new(
        UserHash::from_bytes(CALLBACK_DIALER_HASH),
        rmule_primitives::Ed2kText::from_utf8("rmule-callback"),
        4662,
        0x3C,
    );
    ctx
}

/// Drive a connection to the peer's proven identity, or `None` if it dropped.
async fn identified_hash(conn: &mut Connection) -> Option<UserHash> {
    while let Some(event) = conn.next_event().await {
        match event {
            PeerEvent::Connection(ConnectionEvent::Identified { identity }) => {
                return Some(identity.user_hash());
            }
            PeerEvent::Connection(ConnectionEvent::Disconnected { .. }) => return None,
            _ => {}
        }
    }
    None
}

/// The obfuscated dial-back leg at the transport tier: a dial-back opened with
/// an obfuscation target reaches a requester that *requires* obfuscation — a
/// plaintext dial-back would be refused outright — and a real `PeerSession`
/// hello completes in both directions over the `CryptStream`.
///
/// The key is the **requester's** User Hash, the one its own `0x95` body
/// carried: the responder derives from `ctx.identity.user_hash()`, so a dialer
/// that keyed on anything else would never sync.
#[tokio::test]
async fn an_obfuscated_callback_dial_back_carries_a_real_hello_both_ways() {
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the requester");
    let bound = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_port());

    let requester = tokio::spawn(async move {
        let opts = ConnectOptions {
            obfuscation: Some(ObfuscationConfig {
                policy: ObfuscationPolicy::Required,
            }),
            ..options()
        };
        let mut conn = listener
            .accept(serverless_ctx(), opts)
            .await
            .expect("the dial-back arrives obfuscated");
        let seen = identified_hash(&mut conn).await;
        conn.shutdown().await.ok();
        seen
    });

    let endpoint = peer_endpoint(bound);
    let stream = Connection::dial_stream(
        endpoint,
        Duration::from_secs(2),
        Some(UserHash::from_bytes(RESPONDER_HASH)),
    )
    .await
    .expect("the obfuscated dial-back opens");
    // Exactly what the serve pipeline's admit seam does with it: the dialer's
    // side of an ordinary peer conversation, over whatever stream it was given.
    let mut conn = Connection::over_stream(
        stream,
        endpoint,
        PeerStreamRole::Dialer,
        callback_ctx(),
        options(),
    );
    let dialer_saw = identified_hash(&mut conn).await;
    conn.shutdown().await.ok();

    assert_eq!(
        dialer_saw,
        Some(UserHash::from_bytes(RESPONDER_HASH)),
        "the dial-back identifies the requester through the crypt layer"
    );
    assert_eq!(
        requester.await.expect("requester task"),
        Some(UserHash::from_bytes(CALLBACK_DIALER_HASH)),
        "the requester identifies us through the crypt layer"
    );
}

/// Transport Probe (ADR-0040): the first wire byte of each dial-back, and the
/// absence of a retry. With a target the opening is an obfuscated
/// `[marker][random key]` — never a plaintext protocol marker — and a requester
/// that then answers in plaintext fails the dial outright: as with
/// `Connection::connect` there is no plaintext re-dial, and here the requester
/// itself named the stance we are honouring.
#[tokio::test]
async fn a_targeted_dial_back_opens_obfuscated_and_never_retries_in_plaintext() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = bound_v4(&listener);

    let probe = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("the dial-back arrives");
        let mut buf = [0u8; 64];
        let read = sock.read(&mut buf).await.expect("the opening");
        assert!(read > 0, "the dial-back sent its opening");
        drop(sock); // answer nothing: the crypt handshake cannot complete
        let retried = tokio::time::timeout(Duration::from_millis(300), listener.accept())
            .await
            .is_ok();
        (buf[0], retried)
    });

    let dialed = Connection::dial_stream(
        peer_endpoint(addr),
        Duration::from_secs(2),
        Some(UserHash::from_bytes(RESPONDER_HASH)),
    )
    .await;
    assert!(
        dialed.is_err(),
        "an unanswered crypt handshake fails the dial-back"
    );

    let (first_byte, retried) = probe.await.expect("probe task");
    assert!(
        !is_plaintext_marker(first_byte),
        "the obfuscated opening is no protocol marker (first byte {first_byte:#04x})"
    );
    assert!(!retried, "a callback dial-back never re-dials in plaintext");
}
