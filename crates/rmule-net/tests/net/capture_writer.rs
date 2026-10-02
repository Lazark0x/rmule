//! Capture artifacts written while a real eD2k `Connection` runs: a clean
//! shutdown finalizes them byte for byte against the captured welcome burst,
//! and a compressed frame the session skips is still recorded as an event.

use std::fs;
use std::time::Duration;

use crate::fixture::{ed2k_fixture, test_session};
use rmule_ed2k::Ed2kEvent;
use rmule_net::ed2k::{ConnectOptions, Connection};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

#[tokio::test(flavor = "current_thread")]
async fn clean_shutdown_finalizes_capture_artifacts_byte_for_byte() {
    let dir = tempdir().unwrap();
    let capture_dir = dir.path().to_path_buf();
    let (client_io, mut server_io) = duplex(64 * 1024);

    let options = ConnectOptions {
        capture_dir: Some(capture_dir.clone()),
        ..ConnectOptions::default()
    };
    let mut conn = Connection::spawn_with_options(test_session(), client_io, options);

    // Capture what the driver writes c2s (the LoginRequest) by reading it
    // off the server side of the duplex.
    let mut login_bytes = vec![0u8; 1024];
    let n = server_io.read(&mut login_bytes).await.unwrap();
    let expected_c2s = login_bytes[..n].to_vec();

    // Server pushes IdChange + ServerMessage. Both must show up in
    // s2c.bin byte-for-byte.
    let mut expected_s2c = Vec::new();
    expected_s2c.extend_from_slice(&ed2k_fixture("login/id_change_with_tcp_flags.bin"));
    expected_s2c.extend_from_slice(&ed2k_fixture("server/server_message.bin"));
    server_io.write_all(&expected_s2c).await.unwrap();

    // Drain a few events so the session is past login.
    assert!(matches!(
        conn.next_event().await,
        Some(Ed2kEvent::LoginRequested { .. })
    ));
    assert!(matches!(
        conn.next_event().await,
        Some(Ed2kEvent::LoginAccepted { .. })
    ));
    assert!(matches!(
        conn.next_event().await,
        Some(Ed2kEvent::ServerMessageReceived { .. })
    ));

    conn.shutdown().await.unwrap();

    // Wait briefly for the capture task's finalize rename to settle.
    for _ in 0..50 {
        if capture_dir.join("s2c.bin").exists() && capture_dir.join("c2s.bin").exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let s2c = fs::read(capture_dir.join("s2c.bin")).expect("s2c.bin");
    assert_eq!(s2c, expected_s2c, "s2c.bin must match server-side bytes");

    let c2s = fs::read(capture_dir.join("c2s.bin")).expect("c2s.bin");
    assert_eq!(
        c2s, expected_c2s,
        "c2s.bin must match what the driver wrote"
    );

    let meta_text = fs::read_to_string(capture_dir.join("meta.toml")).expect("meta.toml");
    let meta: toml::Value = toml::from_str(&meta_text).expect("meta.toml parses");
    assert_eq!(
        meta["endpoint"].as_str(),
        Some("example.invalid:4661"),
        "endpoint recorded in meta"
    );

    let events_text = fs::read_to_string(capture_dir.join("events.toml")).expect("events.toml");
    let events: toml::Value = toml::from_str(&events_text).expect("events.toml parses");
    let arr = events["event"].as_array().expect("event array");
    assert!(
        arr.iter()
            .any(|e| e.get("type").and_then(|t| t.as_str()) == Some("LoginRequested")),
        "events.toml records LoginRequested"
    );
    assert!(
        arr.iter()
            .any(|e| e.get("type").and_then(|t| t.as_str()) == Some("LoginAccepted")),
        "events.toml records LoginAccepted"
    );
    assert!(
        arr.iter()
            .any(|e| e.get("type").and_then(|t| t.as_str()) == Some("Disconnected")),
        "events.toml records Disconnected"
    );

    // No .partial files survive a clean shutdown.
    assert!(!capture_dir.join("s2c.bin.partial").exists());
    assert!(!capture_dir.join("c2s.bin.partial").exists());
}

#[tokio::test(flavor = "current_thread")]
async fn capture_records_compressed_frame_skipped_event() {
    let dir = tempdir().unwrap();
    let capture_dir = dir.path().to_path_buf();
    let (client_io, mut server_io) = duplex(64 * 1024);

    let options = ConnectOptions {
        capture_dir: Some(capture_dir.clone()),
        ..ConnectOptions::default()
    };
    let mut conn = Connection::spawn_with_options(test_session(), client_io, options);

    // Drain the LoginRequest off the server side so the driver's outbound
    // capture frame completes before we feed s2c bytes.
    let mut login_bytes = vec![0u8; 1024];
    let _ = server_io.read(&mut login_bytes).await.unwrap();

    assert!(matches!(
        conn.next_event().await,
        Some(Ed2kEvent::LoginRequested { .. })
    ));

    // 0xD4 + length=3 + opcode=OP_SERVERMESSAGE + invalid zlib payload [0, 1].
    server_io
        .write_all(&[0xD4, 0x03, 0, 0, 0, 0x38, 0, 1])
        .await
        .unwrap();

    let skipped = conn.next_event().await;
    assert!(
        matches!(
            skipped,
            Some(Ed2kEvent::CompressedFrameSkipped {
                opcode: 0x38,
                compressed_len: 2,
                ..
            })
        ),
        "expected CompressedFrameSkipped, got {skipped:?}",
    );

    conn.shutdown().await.unwrap();

    for _ in 0..50 {
        if capture_dir.join("events.toml").exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let events_text = fs::read_to_string(capture_dir.join("events.toml")).expect("events.toml");
    let events: toml::Value = toml::from_str(&events_text).expect("events.toml parses");
    let arr = events["event"].as_array().expect("event array");
    let skipped_event = arr
        .iter()
        .find(|e| e.get("type").and_then(|t| t.as_str()) == Some("CompressedFrameSkipped"))
        .expect("events.toml records CompressedFrameSkipped");
    assert_eq!(skipped_event["opcode"].as_integer(), Some(56));
    assert_eq!(skipped_event["compressed_len"].as_integer(), Some(2));
    assert_eq!(
        skipped_event["reason"].as_str(),
        Some("InflateFailed"),
        "reason label"
    );
    assert!(
        skipped_event.get("limit").is_none(),
        "InflateFailed must not carry a limit field"
    );
}
