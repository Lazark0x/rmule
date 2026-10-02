//! The command line as a contract: subcommands listed, flags validated before
//! a run dir exists, the resolved config written first — checked against the
//! `true` fake runtime, never a container.

use assert_cmd::Command;
use predicates::prelude::*;

use crate::fixture::{fake_hash_command, unused_local_port};

#[test]
fn help_lists_interop_flows() {
    Command::cargo_bin("rmule-interop-harness")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("amule-serves-rmule-downloads"))
        .stdout(predicate::str::contains("amule-serves-rmule-searches"))
        .stdout(predicate::str::contains("rmule-serves-amule-downloads"));
}

#[test]
fn build_images_requires_existing_server_build_context() {
    let amule_context = tempfile::tempdir().unwrap();
    let run_root = tempfile::tempdir().unwrap();
    let missing_server_context = amule_context.path().join("missing-server-context");

    Command::cargo_bin("rmule-interop-harness")
        .unwrap()
        .arg("amule-serves-rmule-downloads")
        .arg("--build-images")
        .arg("--server-build-context")
        .arg(&missing_server_context)
        .arg("--amule-build-context")
        .arg(amule_context.path())
        .arg("--container-runtime")
        .arg("true")
        .arg("--run-root")
        .arg(run_root.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "server build context does not exist or is not a directory",
        ));

    assert!(
        std::fs::read_dir(run_root.path()).unwrap().next().is_none(),
        "build context validation should happen before creating a run directory",
    );
}

#[test]
fn build_images_rejects_file_server_build_context() {
    let server_context_file = tempfile::NamedTempFile::new().unwrap();
    let amule_context = tempfile::tempdir().unwrap();
    let run_root = tempfile::tempdir().unwrap();

    Command::cargo_bin("rmule-interop-harness")
        .unwrap()
        .arg("amule-serves-rmule-downloads")
        .arg("--build-images")
        .arg("--server-build-context")
        .arg(server_context_file.path())
        .arg("--amule-build-context")
        .arg(amule_context.path())
        .arg("--container-runtime")
        .arg("true")
        .arg("--run-root")
        .arg(run_root.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "server build context does not exist or is not a directory",
        ));

    assert!(
        std::fs::read_dir(run_root.path()).unwrap().next().is_none(),
        "build context validation should happen before creating a run directory",
    );
}

#[test]
fn build_images_and_skip_build_are_mutually_exclusive() {
    Command::cargo_bin("rmule-interop-harness")
        .unwrap()
        .args([
            "amule-serves-rmule-downloads",
            "--build-images",
            "--skip-build",
            "--container-runtime",
            "true",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--build-images and --skip-build are mutually exclusive",
        ));
}

#[test]
fn zero_server_host_port_is_rejected() {
    Command::cargo_bin("rmule-interop-harness")
        .unwrap()
        .args([
            "amule-serves-rmule-downloads",
            "--container-runtime",
            "true",
            "--server-host-port",
            "0",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--server-host-port must be non-zero",
        ));
}

#[test]
fn default_image_build_contexts_are_checked_in() {
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");

    for path in [
        "tools/interop-harness/images/server/Dockerfile",
        "tools/interop-harness/images/amule/Dockerfile",
    ] {
        assert!(workspace_root.join(path).is_file(), "{path} missing");
    }
}

#[test]
fn missing_container_runtime_fails_before_creating_a_run_directory() {
    let dir = tempfile::tempdir().unwrap();

    Command::cargo_bin("rmule-interop-harness")
        .unwrap()
        .args([
            "amule-serves-rmule-downloads",
            "--server-image",
            "example/server:local",
            "--amule-image",
            "example/amule:local",
            "--container-runtime",
            "definitely-not-a-real-container-runtime",
            "--run-root",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "container runtime `definitely-not-a-real-container-runtime` is not available",
        ));

    assert!(
        std::fs::read_dir(dir.path()).unwrap().next().is_none(),
        "runtime validation should happen before creating a run directory",
    );
}

#[test]
fn flow_writes_resolved_config_then_stops_at_orchestration_boundary() {
    let dir = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let hash_command = fake_hash_command(fake_bin.path(), 1024);
    let closed_port = unused_local_port();
    let closed_port_num = closed_port.port();
    let mut command = Command::cargo_bin("rmule-interop-harness").unwrap();
    command.args([
        "amule-serves-rmule-downloads",
        "--container-runtime",
        "true",
        "--ed2k-hash-command",
        hash_command.to_str().unwrap(),
        "--run-root",
        dir.path().to_str().unwrap(),
        "--file-size",
        "1024",
        "--timeout",
        "1",
        "--server-host-port",
        &closed_port_num.to_string(),
        "--server-env",
        "SERVER_DEBUG=1",
        "--amule-env",
        "AMULE_DEBUG=1",
    ]);
    // Dropped before the run so the port genuinely answers nothing — a held
    // listener would still complete the handshake this asserts times out.
    drop(closed_port);

    command
        .assert()
        .failure()
        .stdout(predicate::str::contains("run_dir="))
        .stderr(predicate::str::contains("server readiness timed out"));

    let runs = std::fs::read_dir(dir.path())
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(runs.len(), 1, "one retained run directory is created");

    let config = std::fs::read_to_string(runs[0].path().join("resolved-config.toml")).unwrap();
    assert!(config.contains("scenario = \"amule-serves-rmule-downloads\""));
    assert!(config.contains("build_images = false"));
    assert!(config.contains("skip_build = false"));
    assert!(config.contains("server_image = \"rmule/interop-eserver:local\""));
    assert!(config.contains("amule_image = \"rmule/interop-amule:local\""));
    assert!(config.contains("server_build_context = \"tools/interop-harness/images/server\""));
    assert!(config.contains("amule_build_context = \"tools/interop-harness/images/amule\""));
    assert!(config.contains("keep_containers = false"));
    assert!(config.contains("container_runtime = \"true\""));
    assert!(config.contains("file_size = 1024"));
    assert!(config.contains("timeout_secs = 1"));
    assert!(config.contains(&format!("server_host_port = {closed_port_num}")));
    assert!(config.contains("\"SERVER_DEBUG=1\""));
    assert!(config.contains("\"AMULE_DEBUG=1\""));
    assert!(config.contains("amule_ready_log_pattern = \"rmule-amule-ready\""));

    let shared = std::fs::read(runs[0].path().join("synthetic/shared.bin")).unwrap();
    assert_eq!(shared.len(), 1024);
    assert_eq!(shared[0], 0);
    assert_eq!(shared[250], 250);
    assert_eq!(shared[251], 0);
    let ed2k = std::fs::read_to_string(runs[0].path().join("synthetic/shared.ed2k.txt")).unwrap();
    assert_eq!(
        ed2k, "ed2k://|file|shared.bin|1024|fakehash|/\n",
        "canonical ED2K link artifact should be retained"
    );
    assert!(runs[0].path().join("rmule").is_dir());
    assert!(
        runs[0]
            .path()
            .join("rmule/output.bin")
            .parent()
            .unwrap()
            .is_dir()
    );
    assert!(runs[0].path().join("logs/server").is_dir());
    assert!(runs[0].path().join("logs/amule").is_dir());
    assert!(runs[0].path().join("logs/rmule").is_dir());
}

#[test]
fn help_lists_kad_source_lookup_capture() {
    Command::cargo_bin("rmule-interop-harness")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("kad-source-lookup-capture"));
}

#[test]
fn kad_capture_defaults_to_patched_amule_image() {
    Command::cargo_bin("rmule-interop-harness")
        .unwrap()
        .args(["kad-source-lookup-capture", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "rmule/interop-amule-kad-patched:local",
        ))
        .stdout(predicate::str::contains(
            "tools/interop-harness/images/amule-kad-patched",
        ));
}

#[test]
fn patched_kad_amule_build_context_is_checked_in() {
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    assert!(
        workspace_root
            .join("tools/interop-harness/images/amule-kad-patched/Dockerfile")
            .is_file(),
        "patched Kad aMule Dockerfile missing"
    );
}

#[test]
fn kad_capture_has_no_public_kad_flag() {
    Command::cargo_bin("rmule-interop-harness")
        .unwrap()
        .args(["kad-source-lookup-capture", "--public-kad"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--public-kad"));
}

#[test]
fn kad_capture_build_images_and_skip_build_are_mutually_exclusive() {
    Command::cargo_bin("rmule-interop-harness")
        .unwrap()
        .args([
            "kad-source-lookup-capture",
            "--build-images",
            "--skip-build",
            "--container-runtime",
            "true",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--build-images and --skip-build are mutually exclusive",
        ));
}

#[test]
fn kad_capture_rejects_routing_nodes_below_phase_two_minimum() {
    for routing_nodes in ["1", "2"] {
        Command::cargo_bin("rmule-interop-harness")
            .unwrap()
            .args([
                "kad-source-lookup-capture",
                "--container-runtime",
                "true",
                "--routing-nodes",
                routing_nodes,
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains("--routing-nodes must be 0"));
    }
}

#[test]
fn kad_capture_build_images_requires_existing_capture_build_context() {
    let amule_context = tempfile::tempdir().unwrap();
    let run_root = tempfile::tempdir().unwrap();
    let missing_capture_context = run_root.path().join("missing-capture-context");

    Command::cargo_bin("rmule-interop-harness")
        .unwrap()
        .args([
            "kad-source-lookup-capture",
            "--build-images",
            "--amule-build-context",
            amule_context.path().to_str().unwrap(),
            "--capture-build-context",
            missing_capture_context.to_str().unwrap(),
            "--container-runtime",
            "true",
            "--run-root",
            run_root.path().to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "capture build context does not exist or is not a directory",
        ));

    assert!(
        std::fs::read_dir(run_root.path()).unwrap().next().is_none(),
        "build context validation should happen before creating a run directory",
    );
}

#[test]
fn kad_capture_default_resolved_config_records_phase_one() {
    let dir = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let hash_command = fake_hash_command(fake_bin.path(), 1024);

    Command::cargo_bin("rmule-interop-harness")
        .unwrap()
        .args([
            "kad-source-lookup-capture",
            "--container-runtime",
            "true",
            "--ed2k-hash-command",
            hash_command.to_str().unwrap(),
            "--run-root",
            dir.path().to_str().unwrap(),
            // Short timeout: the resolved config is written before orchestration,
            // which then fails fast against the `true` fake runtime.
            "--timeout",
            "1",
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("run_dir="));

    let runs = std::fs::read_dir(dir.path())
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(runs.len(), 1, "one retained run directory is created");

    let config = std::fs::read_to_string(runs[0].path().join("resolved-config.toml")).unwrap();
    assert!(config.contains("scenario = \"kad-source-lookup-capture\""));
    assert!(config.contains("routing_nodes = 0"));
    assert!(config.contains("public_kad_used = false"));
    // The Kad flow defaults to the LAN-patched aMule image and its context.
    assert!(config.contains("amule_image = \"rmule/interop-amule-kad-patched:local\""));
    assert!(
        config.contains("amule_build_context = \"tools/interop-harness/images/amule-kad-patched\"")
    );
    assert!(config.contains("capture_image = \"rmule/interop-capture:local\""));
    assert!(config.contains("capture_build_context = \"tools/interop-harness/images/capture\""));
    assert!(config.contains("kad_udp_port_base = 4672"));
    assert!(config.contains("kad_udp_port_span = 10"));
    assert!(config.contains("file_size = 65536"));

    // Phase 1 still creates the source-lookup-target synthetic artifacts.
    assert!(runs[0].path().join("synthetic/shared.bin").is_file());
    assert!(runs[0].path().join("synthetic/shared.ed2k.txt").is_file());
}

#[test]
fn kad_capture_accepts_three_routing_nodes() {
    let dir = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let hash_command = fake_hash_command(fake_bin.path(), 1024);

    Command::cargo_bin("rmule-interop-harness")
        .unwrap()
        .args([
            "kad-source-lookup-capture",
            "--container-runtime",
            "true",
            "--ed2k-hash-command",
            hash_command.to_str().unwrap(),
            "--run-root",
            dir.path().to_str().unwrap(),
            "--routing-nodes",
            "3",
            "--timeout",
            "1",
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("run_dir="));

    let runs = std::fs::read_dir(dir.path())
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(runs.len(), 1);
    let config = std::fs::read_to_string(runs[0].path().join("resolved-config.toml")).unwrap();
    assert!(config.contains("routing_nodes = 3"));
}
