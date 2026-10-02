//! Outbound obfuscated peer dial (ADR-0042): rmule *initiates* an
//! RC4-obfuscated peer connection through `Connection::connect`, keyed on the
//! target's User Hash threaded from a source-exchange candidate. Covers the
//! rmule<->rmule loopback against rmule's own accept, the absence of a
//! plaintext retry after a failed handshake (required or merely requested),
//! the no-target plaintext dial (a server-lookup source), and the
//! peer's own stance meeting ours by aMule's outbound rule (ADR-0049).

use std::net::{Ipv4Addr, SocketAddrV4};

use crate::fixture::{RESPONDER_HASH, bound_v4, peer_endpoint};
use rmule_net::peer::{
    ConnectOptions, Connection, ObfuscationConfig, ObfuscationPolicy, PeerListener, PeerNetError,
};
use rmule_peer::{PeerEvent, PeerHandshakeContext};
use rmule_primitives::{
    ClientId, ClientIdentity, Ed2kText, Ipv4Endpoint, PeerCrypt, SourceCryptOptions, UserHash,
    is_plaintext_marker,
};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

const DIALER_HASH: [u8; 16] = [0xBE; 16];

fn ctx(user_hash: [u8; 16], nick: &str, client_id: u32) -> PeerHandshakeContext {
    PeerHandshakeContext {
        identity: ClientIdentity::new(
            UserHash::from_bytes(user_hash),
            Ed2kText::from_utf8(nick),
            4662,
            0x3C,
        ),
        client_id: ClientId::from_u32(client_id),
        connected_server: Some(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4661)),
    }
}

fn dialer_ctx() -> PeerHandshakeContext {
    ctx(DIALER_HASH, "rmule-dialer", 0x2000_0002)
}

/// Drive a connection to its first identity (or `None` on disconnect).
async fn identified_hash(conn: &mut Connection) -> Option<UserHash> {
    while let Some(event) = conn.next_event().await {
        match event {
            PeerEvent::PeerIdentified { identity } => return Some(identity.user_hash()),
            PeerEvent::Disconnected { .. } => return None,
            _ => {}
        }
    }
    None
}

/// A dial under our `policy` (`None` = obfuscation off) toward a peer whose
/// record stated the connect-options byte `options` and the hash `target`.
fn dial_options(
    policy: Option<ObfuscationPolicy>,
    options: u8,
    target: [u8; 16],
) -> ConnectOptions {
    ConnectOptions {
        obfuscation: policy.map(|policy| ObfuscationConfig { policy }),
        peer_crypt: PeerCrypt::from_record(
            Some(SourceCryptOptions::from_byte(options)),
            Some(UserHash::from_bytes(target)),
        ),
        ..Default::default()
    }
}

/// Our `Requested` policy toward a peer that stated crypt support.
fn requested_toward(target: [u8; 16]) -> ConnectOptions {
    dial_options(Some(ObfuscationPolicy::Requested), 0x01, target)
}

/// An rmule accept that *requires* obfuscation, answering as the responder:
/// only a genuinely obfuscated dial keyed on `RESPONDER_HASH` identifies.
async fn required_responder() -> (SocketAddrV4, tokio::task::JoinHandle<Option<UserHash>>) {
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let bound = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_port());
    let responder = tokio::spawn(async move {
        let opts = ConnectOptions {
            obfuscation: Some(ObfuscationConfig {
                policy: ObfuscationPolicy::Required,
            }),
            ..Default::default()
        };
        let mut conn = listener
            .accept(ctx(RESPONDER_HASH, "rmule-responder", 0x1000_0001), opts)
            .await
            .expect("accept the obfuscated dial");
        let seen = identified_hash(&mut conn).await;
        conn.shutdown().await.ok();
        seen
    });
    (bound, responder)
}

#[tokio::test]
async fn dials_obfuscated_against_required_accept_and_both_identify() {
    // Responder: rmule's own accept, *requiring* obfuscation — so a
    // plaintext dial is refused and only a genuinely obfuscated dial identifies.
    let (bound, responder) = required_responder().await;

    // Dialer: the real connect API obfuscates, keyed on the responder's User
    // Hash (as it would be threaded from a source-exchange candidate).
    let mut conn = Connection::connect(
        peer_endpoint(bound),
        dialer_ctx(),
        requested_toward(RESPONDER_HASH),
    )
    .await
    .expect("obfuscated dial connects");
    let dialer_saw = identified_hash(&mut conn).await;
    conn.shutdown().await.ok();

    let responder_saw = responder.await.unwrap();
    assert_eq!(
        dialer_saw,
        Some(UserHash::from_bytes(RESPONDER_HASH)),
        "dialer identifies the responder through the crypt layer"
    );
    assert_eq!(
        responder_saw,
        Some(UserHash::from_bytes(DIALER_HASH)),
        "responder identifies the dialer through the crypt layer"
    );
}

/// A raw peer that reads the dialer's opening and closes, failing the crypt
/// handshake, then reports whether a second connection — a plaintext retry —
/// arrives within 300 ms.
async fn handshake_refuser() -> (SocketAddrV4, tokio::task::JoinHandle<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = bound_v4(&listener);
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 256];
        let _ = s.read(&mut buf).await;
        drop(s);
        tokio::time::timeout(std::time::Duration::from_millis(300), listener.accept())
            .await
            .is_ok()
    });
    (addr, server)
}

#[tokio::test]
async fn a_failed_obfuscated_handshake_is_never_retried_in_plaintext() {
    // Transport Probe (ADR-0040): a raw socket asserting the *absence* of a
    // retry connection — a connection-count invariant no scripted testkit
    // counterparty can express, so it stays hand-rolled.
    // The peer refuses the obfuscated handshake. Whether a side requires the
    // obfuscation (our `Required`) or only asks for it (our `Requested`
    // toward a peer that merely supports it), the failure ends the dial:
    // aMule's `Connect` configures the socket once and a crypt error
    // disconnects it (ADR-0049).
    for policy in [ObfuscationPolicy::Required, ObfuscationPolicy::Requested] {
        let (addr, server) = handshake_refuser().await;
        let opts = dial_options(Some(policy), 0x01, RESPONDER_HASH);
        let result = Connection::connect(peer_endpoint(addr), dialer_ctx(), opts).await;
        assert!(
            result.is_err(),
            "{policy:?}: the failed obfuscated handshake is the end of the dial"
        );
        assert!(
            !server.await.unwrap(),
            "{policy:?}: no plaintext retry connection is opened"
        );
    }
}

#[tokio::test]
async fn no_target_dials_plaintext_even_under_requested() {
    // Transport Probe (ADR-0040): a raw socket inspecting the first wire byte of
    // the dial — a raw-byte invariant off testkit by design.
    // Policy `Requested` but no target hash (a server-lookup source with no User
    // Hash): the dial must be plaintext — the first byte on the wire is a protocol
    // marker, never an obfuscated `[marker][random key]` opening.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = bound_v4(&listener);

    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 8];
        let n = s.read(&mut buf).await.unwrap();
        assert!(n > 0, "dial sent bytes");
        buf[0]
    });

    let opts = ConnectOptions {
        obfuscation: Some(ObfuscationConfig {
            policy: ObfuscationPolicy::Requested,
        }),
        peer_crypt: PeerCrypt::unknown(), // server-lookup source: no User Hash
        ..Default::default()
    };
    let conn = Connection::connect(peer_endpoint(addr), dialer_ctx(), opts)
        .await
        .expect("plaintext dial connects");

    let first_byte = server.await.unwrap();
    assert!(
        is_plaintext_marker(first_byte),
        "no target ⇒ plaintext dial (first byte {first_byte:#04x})"
    );
    conn.shutdown().await.ok();
}

#[tokio::test]
async fn a_peer_that_requires_is_dialed_obfuscated_toward_its_hash_under_our_supported_policy() {
    // Our policy only *supports* obfuscation — alone it never initiates — but
    // the peer's record says it requires it: aMule's `Connect` obfuscates when
    // either side requests, so the dial runs the crypt handshake keyed on the
    // peer's hash. The responder refuses plaintext, so identifying at all
    // proves the stream is a `CryptStream` toward `RESPONDER_HASH`.
    let (bound, responder) = required_responder().await;

    let mut conn = Connection::connect(
        peer_endpoint(bound),
        dialer_ctx(),
        dial_options(Some(ObfuscationPolicy::Supported), 0x07, RESPONDER_HASH),
    )
    .await
    .expect("a requiring peer is dialed obfuscated");
    let dialer_saw = identified_hash(&mut conn).await;
    conn.shutdown().await.ok();

    assert_eq!(dialer_saw, Some(UserHash::from_bytes(RESPONDER_HASH)));
    assert_eq!(
        responder.await.unwrap(),
        Some(UserHash::from_bytes(DIALER_HASH)),
        "the requiring responder accepted the dial, so it arrived obfuscated"
    );
}

#[tokio::test]
async fn a_peer_that_only_supports_is_dialed_plaintext_under_our_supported_policy() {
    // Transport Probe (ADR-0040): the dial's first wire byte. Both sides
    // support obfuscation, neither asks for it — someone has to ask, so the
    // dial is plaintext even though the peer's hash is in hand.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = bound_v4(&listener);
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 8];
        let n = s.read(&mut buf).await.unwrap();
        assert!(n > 0, "dial sent bytes");
        buf[0]
    });

    let conn = Connection::connect(
        peer_endpoint(addr),
        dialer_ctx(),
        dial_options(Some(ObfuscationPolicy::Supported), 0x01, RESPONDER_HASH),
    )
    .await
    .expect("plaintext dial connects");

    let first_byte = server.await.unwrap();
    assert!(
        is_plaintext_marker(first_byte),
        "support met by support ⇒ plaintext (first byte {first_byte:#04x})"
    );
    conn.shutdown().await.ok();
}

#[tokio::test]
async fn a_peer_that_requires_with_no_hash_is_refused_before_any_socket() {
    // Transport Probe (ADR-0040): a listener asserting the *absence* of any
    // connection. The peer requires obfuscation and ours supports it, but its
    // record carried no User Hash — no key. aMule would dial it plaintext
    // (`HasValidHash()` gates `Connect` first) and the peer would cut the
    // opening; rmule refuses the doomed dial instead.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = bound_v4(&listener);
    let opts = ConnectOptions {
        obfuscation: Some(ObfuscationConfig {
            policy: ObfuscationPolicy::Supported,
        }),
        peer_crypt: PeerCrypt::from_record(Some(SourceCryptOptions::from_byte(0x07)), None),
        ..Default::default()
    };

    let result = Connection::connect(peer_endpoint(addr), dialer_ctx(), opts).await;
    assert!(
        matches!(result, Err(PeerNetError::CryptIncompatible)),
        "a required obfuscation with no key is refused"
    );
    let dialed = tokio::time::timeout(std::time::Duration::from_millis(300), listener.accept())
        .await
        .is_ok();
    assert!(!dialed, "a refused dial opens no socket");
}

#[tokio::test]
async fn a_peer_that_requires_is_refused_before_any_socket_when_our_layer_is_off() {
    // Transport Probe (ADR-0040): a listener asserting the *absence* of any
    // connection. The peer requires obfuscation and ours is off: aMule's
    // contact precondition refuses the pair, so no TCP dial is ever made.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = bound_v4(&listener);

    let result = Connection::connect(
        peer_endpoint(addr),
        dialer_ctx(),
        dial_options(None, 0x07, RESPONDER_HASH),
    )
    .await;
    assert!(
        matches!(result, Err(PeerNetError::CryptIncompatible)),
        "the dial is refused for incompatible crypt stances"
    );
    let dialed = tokio::time::timeout(std::time::Duration::from_millis(300), listener.accept())
        .await
        .is_ok();
    assert!(!dialed, "a refused dial opens no socket");
}
