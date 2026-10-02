//! Server obfuscation connect wiring (ADR-0042): rmule dials a
//! server with an obfuscation policy, completes the DH handshake, and its login
//! flows through the crypt layer — plus the `Requested` plaintext fallback when
//! the server does not speak obfuscation. The counterparty is the testkit
//! [`FakeEd2kServer`], whose obfuscated accept byte-0-discriminates exactly
//! like a real crypt-capable server.

use rmule_ed2k::Ed2kEvent;
use rmule_net::driver::{ObfuscationConfig, ObfuscationPolicy};
use rmule_net::ed2k::{ConnectOptions, Connection};
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

fn requested() -> ConnectOptions {
    ConnectOptions {
        obfuscation: Some(ObfuscationConfig {
            policy: ObfuscationPolicy::Requested,
        }),
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

    let mut conn = Connection::connect_with_options(server.endpoint(), identity(), requested())
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
async fn requested_falls_back_to_plaintext_when_server_is_not_obfs() {
    // A fake without obfuscated accept: rmule's opening `[marker][G^A]` is not
    // eD2k framing, so the fake drops that connection, failing the crypt
    // handshake; `Requested` then reconnects in plaintext.
    let server = FakeEd2kServer::start_scripted().await;

    let mut conn = Connection::connect_with_options(server.endpoint(), identity(), requested())
        .await
        .expect("Requested falls back to a plaintext connect");

    assert!(
        login_accepted(&mut conn).await,
        "the fallback connection carried a working plaintext login"
    );
    conn.shutdown().await.ok();
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
