//! Offline CLI test for `rmule-tools ed2k peer transfer capture`.
//! The testkit `FakePeer` serves the full probe → request → part flow, and
//! the binary is driven via assert_cmd. The protocol-level variant of this
//! scenario lives in `peer_transfer_replay.rs`; this test specifically
//! exercises the CLI's staged probe → request dispatch, `peer_event_label`
//! printing, capture-dir wiring, and `--max-seconds` watchdog through the
//! binary.

use std::time::Duration;

use crate::fixture::FILE_HASH;
use assert_cmd::Command;
use rmule_primitives::FileHash;
use rmule_testkit::{FakePeer, PeerScript};

fn hex_upper(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        write!(s, "{:02X}", b).unwrap();
    }
    s
}

#[tokio::test(flavor = "current_thread")]
async fn peer_transfer_capture_cli_completes_against_mock_peer() {
    let part_data: Vec<u8> = (0..40u8).collect();

    let fake = FakePeer::bind().await;
    let bound = fake.addr();
    let mock = fake.spawn(PeerScript {
        file_name: "cli-replay.bin".into(),
        hello_nickname: "mock".into(),
        ..PeerScript::serving(FileHash::from_bytes(FILE_HASH), part_data.clone())
    });

    let link = format!(
        "ed2k://|file|cli-replay.bin|{}|{}|/",
        part_data.len(),
        hex_upper(&FILE_HASH)
    );
    let dir = tempfile::tempdir().unwrap();
    let peer_arg = format!("127.0.0.1:{}", bound.port());
    let output_dir = dir.path().to_path_buf();

    let out = tokio::task::spawn_blocking(move || {
        Command::cargo_bin("rmule-tools")
            .unwrap()
            .args([
                "ed2k",
                "peer",
                "transfer",
                "capture",
                "--peer",
                &peer_arg,
                "--file",
                &link,
                "--output-dir",
                output_dir.to_str().unwrap(),
                "--max-seconds",
                "8",
            ])
            .timeout(Duration::from_secs(15))
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stderr: {stderr}\nstdout: {stdout}");
    assert!(
        stdout.contains("peer identified"),
        "stdout missing 'peer identified':\n{stdout}"
    );
    assert!(
        stdout.contains("file_probed"),
        "stdout missing 'file_probed':\n{stdout}"
    );
    assert!(
        stdout.contains("slot_released: DownloadComplete"),
        "stdout missing 'slot_released: DownloadComplete':\n{stdout}"
    );
    let _ = mock.await;
}
