//! `ed2k server welcome`: the slicer cutting a recorded stream into one file
//! per decoded packet without re-encoding a byte, and the `live` operand the
//! command refuses to run without.

use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;

use super::{login_fixture_path, server_fixture_path};

#[test]
fn welcome_slice_writes_one_file_per_decoded_packet() {
    let dir = tempfile::tempdir().unwrap();

    // Seed s2c.bin with three real synthetic welcome frames so the slicer
    // walks Packet::decode three times and produces three artefacts.
    let mut s2c = Vec::new();
    s2c.extend_from_slice(
        &std::fs::read(login_fixture_path("id_change_with_tcp_flags.bin")).unwrap(),
    );
    s2c.extend_from_slice(&std::fs::read(server_fixture_path("server_message.bin")).unwrap());
    s2c.extend_from_slice(&std::fs::read(server_fixture_path("server_status.bin")).unwrap());
    std::fs::write(dir.path().join("s2c.bin"), &s2c).unwrap();

    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args([
        "ed2k",
        "server",
        "welcome",
        "slice",
        dir.path().to_str().unwrap(),
    ]);
    cmd.assert().success();

    assert!(dir.path().join("01_id_change.bin").is_file());
    assert!(dir.path().join("02_server_message.bin").is_file());
    assert!(dir.path().join("03_server_status.bin").is_file());

    // Slice files are byte-for-byte the original frame, not re-encoded.
    let sliced = std::fs::read(dir.path().join("02_server_message.bin")).unwrap();
    let original = std::fs::read(server_fixture_path("server_message.bin")).unwrap();
    assert_eq!(sliced, original);
}

#[test]
fn welcome_slice_names_packed_server_message_frame() {
    // Captured `04_undecoded_tail.bin` is a 0xD4 packed server frame
    // carrying an inflated OP_SERVERMESSAGE payload. After A3 the slicer
    // recognises the frame and names the slice by the logical packet kind
    // (`server_message`), without re-encoding — the on-disk bytes stay
    // byte-faithful to the captured wire bytes.
    let dir = tempfile::tempdir().unwrap();
    let captured = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../crates/rmule-ed2k/tests/fixtures/server/captured/welcome-burst-2026-05-17/04_undecoded_tail.bin",
        ),
    )
    .unwrap();
    std::fs::write(dir.path().join("s2c.bin"), &captured).unwrap();

    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args([
        "ed2k",
        "server",
        "welcome",
        "slice",
        dir.path().to_str().unwrap(),
    ]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("01_server_message.bin"));

    let sliced = std::fs::read(dir.path().join("01_server_message.bin")).unwrap();
    assert_eq!(
        sliced, captured,
        "slice file preserves the compressed wire bytes exactly"
    );
}

#[test]
fn welcome_live_rejects_missing_out_flag() {
    // `live <endpoint>` without `--out` is a hard error from clap.
    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args(["ed2k", "server", "welcome", "live", "127.0.0.1:1234"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("--out"));
}
