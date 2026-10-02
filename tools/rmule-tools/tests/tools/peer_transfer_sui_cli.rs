//! Offline CLI tests for `ed2k peer transfer capture --secure-ident`:
//! the flag dials with a fresh SUI keypair and the run only succeeds if
//! the exchange completes. The counterparty is a real accepted `Connection`
//! with its own keypair (FakePeer is byte-scripted and cannot answer an RSA
//! challenge), holding the socket open without answering the file probe — SUI
//! completes during the hello phase, the probe stalls, and `--max-seconds`
//! ends the run.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use assert_cmd::Command;
use rmule_net::peer::{ConnectOptions, PeerListener};
use rmule_peer::{PeerEvent, PeerHandshakeContext, SecureIdentConfig};
use rmule_primitives::{ClientId, ClientIdentity, Ed2kText, SecureIdentKey, UserHash};

const FILE_LINK: &str = "ed2k://|file|sui.bin|40|55555555555555555555555555555555|/";

async fn accept_and_hold(listener: PeerListener, secure_ident: Option<SecureIdentConfig>) {
    let ctx = PeerHandshakeContext {
        identity: ClientIdentity::new(
            UserHash::from_bytes([0x0B; UserHash::BYTE_LEN]),
            Ed2kText::from_utf8("sui-cli-peer"),
            4662,
            60,
        ),
        client_id: ClientId::from_u32(0x0100_007F),
        connected_server: None,
    };
    let options = ConnectOptions {
        secure_ident,
        ..ConnectOptions::default()
    };
    let Ok(mut conn) = listener.accept(ctx, options).await else {
        return;
    };
    while let Some(event) = conn.next_event().await {
        if matches!(event, PeerEvent::Disconnected { .. }) {
            break;
        }
    }
}

fn capture_command(peer_port: u16, output_dir: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args([
        "ed2k",
        "peer",
        "transfer",
        "capture",
        "--peer",
        &format!("127.0.0.1:{peer_port}"),
        "--file",
        FILE_LINK,
        "--output-dir",
        output_dir.to_str().unwrap(),
        "--max-seconds",
        "5",
        "--secure-ident",
    ]);
    cmd
}

#[tokio::test(flavor = "current_thread")]
async fn secure_ident_flag_succeeds_against_a_sui_peer() {
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let port = listener.local_port();
    let key = Arc::new(SecureIdentKey::generate().unwrap());
    let peer_task = tokio::spawn(accept_and_hold(
        listener,
        Some(SecureIdentConfig {
            key,
            challenge: 0xB00B_0005,
        }),
    ));

    let dir = tempfile::tempdir().unwrap();
    let output_dir = dir.path().to_path_buf();
    let out = tokio::task::spawn_blocking(move || {
        capture_command(port, &output_dir)
            .timeout(Duration::from_secs(60))
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "expected success against a SUI peer; stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("peer identity_verified user_hash=0B0B"),
        "stdout reports the verified peer identity:\n{stdout}"
    );
    peer_task.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn secure_ident_flag_fails_when_the_peer_cannot_prove_itself() {
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let port = listener.local_port();
    // The peer has no keypair: it never advertises SUI, nothing is verified.
    let peer_task = tokio::spawn(accept_and_hold(listener, None));

    let dir = tempfile::tempdir().unwrap();
    let output_dir = dir.path().to_path_buf();
    let out = tokio::task::spawn_blocking(move || {
        capture_command(port, &output_dir)
            .timeout(Duration::from_secs(60))
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    assert!(
        !out.status.success(),
        "a --secure-ident run without a completed exchange must fail"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("identification"),
        "stderr names the missing identification:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    peer_task.abort();
}
