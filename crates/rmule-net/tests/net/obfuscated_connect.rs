//! Server obfuscation connect wiring (ADR-0042): rmule dials a server's
//! obfuscation port, completes the DH handshake, and its login flows through
//! the crypt layer — and a server that does not take obfuscation there fails
//! the one attempt, leaving the plaintext fallback to the caller's policy.
//! The counterparty is the testkit [`FakeEd2kServer`], whose obfuscated
//! accept byte-0-discriminates exactly like a real crypt-capable server.

use rmule_ed2k::Ed2kEvent;
use rmule_net::driver::{ObfuscationConfig, ObfuscationPolicy};
use rmule_net::ed2k::{ConnectOptions, Connection, Ed2kNetError};
use rmule_primitives::{ClientIdentity, Ed2kText, UserHash};
use rmule_testkit::FakeEd2kServer;

fn identity() -> ClientIdentity {
    ClientIdentity::new(
        UserHash::from_bytes([0; UserHash::BYTE_LEN]),
        Ed2kText::from_utf8("rmule-test"),
        4662,
        60,
    )
}

/// A `Requested` dial of the obfuscation port `port`.
fn obfuscated_at(port: u16) -> ConnectOptions {
    ConnectOptions {
        obfuscation: Some(ObfuscationConfig {
            policy: ObfuscationPolicy::Requested,
        }),
        obfuscated_port: Some(port),
        ..Default::default()
    }
}

/// Drain events until the login resolves: the fake answers a decoded login
/// with `OP_IDCHANGE`, so `LoginAccepted` proves the login round-tripped the
/// transport intact in both directions.
async fn login_accepted(conn: &mut Connection) -> bool {
    while let Some(event) = conn.next_event().await {
        match event {
            Ed2kEvent::LoginAccepted { .. } => return true,
            Ed2kEvent::LoginRejected | Ed2kEvent::Disconnected { .. } => return false,
            _ => {}
        }
    }
    false
}

#[tokio::test]
async fn obfuscated_connect_completes_and_login_flows_through_crypt() {
    let server = FakeEd2kServer::start_obfuscated().await;
    let port = server.local_addr().port();

    let mut conn =
        Connection::connect_with_options(server.endpoint(), identity(), obfuscated_at(port))
            .await
            .expect("obfuscated connect completes the DH handshake");

    // The fake only sees the login if the crypt layer decrypted it, and rmule
    // only sees the id-change reply if it decrypts the encrypted response:
    // one assertion, both directions of the RC4 stream.
    assert!(
        login_accepted(&mut conn).await,
        "login round-tripped through the crypt layer"
    );
    conn.shutdown().await.ok();
}

#[tokio::test]
async fn an_obfuscated_dial_to_a_plain_server_fails_its_one_attempt() {
    // A fake without obfuscated accept: rmule's opening `[marker][G^A]` is not
    // eD2k framing, so the fake drops the connection and the handshake fails.
    // The dial does not fall back on its own — the policy that might allow it
    // is the caller's.
    let server = FakeEd2kServer::start_scripted().await;
    let port = server.local_addr().port();

    let failed =
        Connection::connect_with_options(server.endpoint(), identity(), obfuscated_at(port)).await;

    assert!(
        matches!(failed, Err(Ed2kNetError::CryptHandshake(_))),
        "a server that does not take obfuscation fails the handshake, not the login"
    );
}

#[tokio::test]
async fn plaintext_client_logs_in_against_obfuscation_enabled_fake() {
    // Byte-0 discrimination on the fake's accept: a client with no obfuscation
    // config opens with a plaintext protocol marker and must be served as-is.
    let server = FakeEd2kServer::start_obfuscated().await;

    let mut conn =
        Connection::connect_with_options(server.endpoint(), identity(), ConnectOptions::default())
            .await
            .expect("plaintext connect");

    assert!(
        login_accepted(&mut conn).await,
        "the obfuscation-enabled fake served the plaintext login"
    );
    conn.shutdown().await.ok();
}
