//! Env-gated CLI live test for `rmule-tools ed2k server welcome live`.
//! Skips silently when `RMULE_LIVE_ED2K_ENDPOINT` is unset; runs with
//! `cargo test -- --ignored` when set. The protocol-level guarantees
//! live in `crates/rmule-net/tests/net/live_welcome.rs`; this test is
//! deliberately a CLI-binary test that exercises clap parsing, the
//! `print_event` printer, and capture-file wiring through the binary.

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
#[ignore = "requires RMULE_LIVE_ED2K_ENDPOINT and a reachable eD2k server"]
fn welcome_live_against_real_server_produces_capture_and_login_accepted() {
    let Ok(endpoint) = std::env::var("RMULE_LIVE_ED2K_ENDPOINT") else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();

    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args([
        "ed2k",
        "server",
        "welcome",
        "live",
        &endpoint,
        "--out",
        dir.path().to_str().unwrap(),
        "--connect-timeout",
        "10",
        "--login-timeout",
        "15",
        "--max-seconds",
        "12",
    ])
    .timeout(std::time::Duration::from_secs(40));

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("login_accepted client_id="));

    for name in ["s2c.bin", "c2s.bin", "meta.toml", "events.toml"] {
        let path = dir.path().join(name);
        assert!(
            path.is_file(),
            "{} should exist after capture",
            path.display()
        );
    }
    let meta = std::fs::read_to_string(dir.path().join("meta.toml")).unwrap();
    assert!(meta.contains("endpoint = "), "meta.toml endpoint missing");
    assert!(
        !meta.contains("ProtocolViolation"),
        "extended OP_IDCHANGE must not regress to ProtocolViolation"
    );
}
