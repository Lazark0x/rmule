//! Hermetic CLI coverage for `rmule-tools natt buddy-rendezvous`: the target
//! body run as a real process against the testkit `FakeEd2kServer`, so the
//! server it names is a counterparty that records whether it was logged in to.

use std::time::Duration;

use assert_cmd::Command;
use rmule_testkit::FakeEd2kServer;

/// `--login` puts the target on the server it names before the recruit, and
/// the row carries the id that server granted — the posture an open aMule
/// keeps as a buddy.
#[tokio::test(flavor = "current_thread")]
async fn the_target_logs_in_to_the_server_it_names() {
    let server = FakeEd2kServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let share = dir.path().join("shared.bin");
    std::fs::write(&share, vec![0x42_u8; 4096]).unwrap();
    let row = dir.path().join("row.toml");

    let server_arg = server.local_addr().to_string();
    let share_arg = share.to_str().unwrap().to_owned();
    let row_arg = row.to_str().unwrap().to_owned();
    let out = tokio::task::spawn_blocking(move || {
        Command::cargo_bin("rmule-tools")
            .unwrap()
            .args([
                "natt",
                "buddy-rendezvous",
                "--role",
                "target",
                "--server",
                &server_arg,
                "--login",
                "--listen",
                "127.0.0.1:0",
                "--udp-port",
                "0",
                "--share",
                &share_arg,
                "--user-hash",
                "8e302db5b806a25c9385fc23f21062d2",
                "--buddy-timeout",
                "1",
                "--window",
                "1",
                "--out",
                &row_arg,
            ])
            // A hang guard, not a latency budget: the child links and drives a
            // whole core.
            .timeout(Duration::from_secs(120))
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stderr: {stderr}\nstdout: {stdout}");
    let granted = server.assigned_ids().await;
    assert_eq!(
        granted.len(),
        1,
        "one login reached the server: {granted:?}"
    );
    let text = std::fs::read_to_string(&row).unwrap();
    assert!(text.contains("connected = true"), "{text}");
    assert!(
        text.contains(&format!("client_id = {}", granted[0].as_u32())),
        "the row names the id the server granted, {:?}: {text}",
        granted[0]
    );
}
