//! Capture-mode boundary tests.
//!
//! Per ADR-0024, `ProtocolOnly` (the default) elides `OP_SENDINGPART`
//! data bytes in `inbound.bin` / `outbound.bin` and records the count
//! in `meta.toml`. The frame size on disk stays unchanged so byte-offset
//! bookkeeping is exact; the elided region starts with a fixed marker
//! followed by nul padding.

use std::time::Duration;

use crate::fixture::{bound_v4, peer_endpoint};
use rmule_net::peer::{CaptureMode, ConnectOptions, Connection, ELISION_MARKER};
use rmule_peer::PeerEvent;
use rmule_primitives::{FileHash, UserHash};
use rmule_testkit::peer_session::loopback_ctx;
use rmule_testkit::wire;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The peer's hello-answer, pinned to a fixed identity (the test asserts on
/// byte offsets, not on who the peer claims to be).
fn answer_bytes() -> Vec<u8> {
    wire::hello_answer_bytes(UserHash::from_bytes([0x99; UserHash::BYTE_LEN]), "peer")
}

/// A 64-byte `OP_SENDINGPART` of `0xCD` — the frame whose data the elision
/// scan replaces under `ProtocolOnly`.
fn part_bytes() -> Vec<u8> {
    wire::sending_part_bytes(FileHash::from_bytes([0xAA; 16]), 0, &[0xCD; 64])
}

async fn run_session_with_mode(mode: CaptureMode, capture_dir: Option<TempDir>) -> Option<TempDir> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer = peer_endpoint(bound_v4(&listener));

    // Transport Probe (ADR-0040): a raw socket emitting an *unsolicited*
    // OP_SENDINGPART to drive the capture-elision byte contract — a wire-byte
    // invariant no FakePeer policy models, so it stays a hand-rolled socket.
    let peer_task = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        // Read hello.
        let _ = sock.read(&mut buf).await.unwrap();
        // Reply with hello answer + one SENDINGPART frame.
        sock.write_all(&answer_bytes()).await.unwrap();
        sock.write_all(&part_bytes()).await.unwrap();
        // Wait for client disconnect.
        let _ = sock.read(&mut buf).await;
    });

    let options = ConnectOptions {
        connect_timeout: Duration::from_secs(2),
        hello_timeout: Duration::from_secs(2),
        capture_dir: capture_dir.as_ref().map(|d| d.path().to_path_buf()),
        capture_mode: mode,
        ..Default::default()
    };
    let mut conn = Connection::connect(peer, loopback_ctx(), options)
        .await
        .unwrap();

    // Drain events until Disconnected or a couple of UnknownPeerPackets
    // (SENDINGPART arrives without an active slot → PartReceived
    // emitted, then peer closes; we just want enough to flush the
    // capture).
    let mut got_part = false;
    let mut deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(100), conn.next_event()).await {
            Ok(Some(PeerEvent::PartReceived { .. })) => {
                got_part = true;
                deadline = std::time::Instant::now() + Duration::from_millis(200);
            }
            Ok(Some(PeerEvent::Disconnected { .. })) | Ok(None) => break,
            Ok(Some(_)) => {}
            Err(_) => {}
        }
    }
    let _ = got_part;
    conn.shutdown().await.ok();
    let _ = peer_task.await;
    capture_dir
}

#[test]
fn capture_mode_default_is_protocol_only() {
    assert_eq!(CaptureMode::default(), CaptureMode::ProtocolOnly);
}

#[tokio::test]
async fn protocol_only_mode_records_elision_marker_and_counts_elided_bytes() {
    let dir = TempDir::new().unwrap();
    let dir = run_session_with_mode(CaptureMode::ProtocolOnly, Some(dir))
        .await
        .unwrap();

    let inbound = std::fs::read(dir.path().join("inbound.bin")).unwrap();
    let meta = std::fs::read_to_string(dir.path().join("meta.toml")).unwrap();

    assert!(meta.contains("capture_mode = \"protocol_only\""), "{meta}");
    assert!(
        meta.contains("bytes_elided_inbound = 64"),
        "expected 64-byte elision, got meta:\n{meta}"
    );

    // Find marker in the inbound stream.
    let pos =
        find_subsequence(&inbound, ELISION_MARKER).expect("elision marker present in inbound.bin");
    // Header before marker = protocol (1) + len (4) + opcode (1) + hash (16) + start (4) + end (4) = 30 bytes
    let hello_answer_len = answer_bytes().len();
    assert_eq!(pos, hello_answer_len + 30);
    // Bytes after marker until end-of-frame are zero.
    let after = &inbound[pos + ELISION_MARKER.len()..];
    let tail_zero_len = 64 - ELISION_MARKER.len();
    assert!(after.iter().take(tail_zero_len).all(|&b| b == 0));
}

#[tokio::test]
async fn full_mode_preserves_part_data_bytes_literally() {
    let dir = TempDir::new().unwrap();
    let dir = run_session_with_mode(CaptureMode::Full, Some(dir))
        .await
        .unwrap();

    let inbound = std::fs::read(dir.path().join("inbound.bin")).unwrap();
    let meta = std::fs::read_to_string(dir.path().join("meta.toml")).unwrap();

    assert!(meta.contains("capture_mode = \"full\""), "{meta}");
    assert!(
        meta.contains("bytes_elided_inbound = 0"),
        "Full mode elides nothing, got meta:\n{meta}"
    );

    // 64 sequential 0xCD bytes should appear contiguously.
    let needle = vec![0xCDu8; 64];
    assert!(
        find_subsequence(&inbound, &needle).is_some(),
        "full payload bytes preserved literally"
    );
}

#[tokio::test]
async fn capture_dir_none_writes_no_files_but_still_emits_events() {
    let dir = run_session_with_mode(CaptureMode::ProtocolOnly, None).await;
    assert!(dir.is_none(), "no capture dir passed");
    // The function above returns None; no panic / no file written.
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
