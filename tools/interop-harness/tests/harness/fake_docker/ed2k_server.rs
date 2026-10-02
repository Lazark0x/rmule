//! Orchestration order the eD2k server legs stand up in: images built before a
//! container, readiness gated before the next boundary, and the bench smoke
//! probe writing its capability summary.

use std::net::TcpListener;

use assert_cmd::Command;
use predicates::prelude::*;

use crate::fake_docker::script::fake_docker;
use crate::fixture::fake_hash_command;
use crate::fixture::{assert_ordered, base_command, run_dirs, unused_local_port, workspace_root};

#[test]
fn build_images_and_server_container_are_orchestrated_before_readiness_failure() {
    let run_root = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let docker_log = run_root.path().join("docker.log");
    let docker = fake_docker(fake_bin.path(), &docker_log);
    let hash_command = fake_hash_command(fake_bin.path(), 65536);
    let closed_port = unused_local_port();
    let server_context = workspace_root().join("tools/interop-harness/images/server");
    let amule_context = workspace_root().join("tools/interop-harness/images/amule");

    let mut command = Command::cargo_bin("rmule-interop-harness").unwrap();
    command.args([
        "amule-serves-rmule-downloads",
        "--build-images",
        "--server-build-context",
        server_context.to_str().unwrap(),
        "--amule-build-context",
        amule_context.to_str().unwrap(),
        "--container-runtime",
        docker.to_str().unwrap(),
        "--ed2k-hash-command",
        hash_command.to_str().unwrap(),
        "--run-root",
        run_root.path().to_str().unwrap(),
        "--timeout",
        "0",
        "--server-host-port",
        &closed_port.port().to_string(),
    ]);
    // Dropped before the run so the port genuinely answers nothing — a held
    // listener would still complete the handshake this asserts times out.
    drop(closed_port);

    command
        .assert()
        .failure()
        .stderr(predicate::str::contains("server readiness timed out"));

    let log = std::fs::read_to_string(&docker_log).unwrap();
    let expected_server_build = format!(
        "build -t rmule/interop-eserver:local {}",
        server_context.display()
    );
    let expected_amule_build = format!(
        "build -t rmule/interop-amule:local {}",
        amule_context.display()
    );
    assert_ordered(
        &log,
        &[
            "--version".to_owned(),
            expected_server_build,
            expected_amule_build,
            "network create rmule-interop-".to_owned(),
            "run --detach --name rmule-interop-server-".to_owned(),
            "logs rmule-interop-server-".to_owned(),
            "rm -f rmule-interop-server-".to_owned(),
            "network rm rmule-interop-".to_owned(),
        ],
    );

    let runs = run_dirs(run_root.path());
    assert_eq!(runs.len(), 1, "one retained run directory is created");
    assert!(runs[0].join("docker/network-id.txt").is_file());
    assert!(runs[0].join("docker/server-container-id.txt").is_file());
}

#[test]
fn server_readiness_success_reaches_next_orchestration_boundary() {
    let run_root = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let docker_log = run_root.path().join("docker.log");
    let docker = fake_docker(fake_bin.path(), &docker_log);
    let hash_command = fake_hash_command(fake_bin.path(), 65536);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();

    let mut command = base_command(&docker, &hash_command, run_root.path());
    command.args(["--server-host-port", &port]);
    command
        .assert()
        .failure()
        .stderr(predicate::str::contains("aMule log pattern"));

    let log = std::fs::read_to_string(&docker_log).unwrap();
    assert_ordered(
        &log,
        &[
            format!("-p {port}:4661/tcp"),
            "logs rmule-interop-server-".to_owned(),
            "run --detach --name rmule-interop-amule-".to_owned(),
            "-v ".to_owned(),
            ":/incoming".to_owned(),
            "-e ED2K_SERVER_HOST=rmule-interop-server-".to_owned(),
            "-e ED2K_SERVER_PORT=4661".to_owned(),
            "-e AMULE_SHARED_DIR=/incoming".to_owned(),
            "logs rmule-interop-amule-".to_owned(),
            "rm -f rmule-interop-amule-".to_owned(),
            "rm -f rmule-interop-server-".to_owned(),
            "network rm rmule-interop-".to_owned(),
        ],
    );

    let runs = run_dirs(run_root.path());
    assert_eq!(runs.len(), 1, "one retained run directory is created");
    assert!(runs[0].join("docker/amule-container-id.txt").is_file());
}

#[test]
fn bench_smoke_probes_server_and_writes_capability_summary() {
    let run_root = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let docker_log = run_root.path().join("docker.log");
    let docker = fake_docker(fake_bin.path(), &docker_log);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();

    let mut command = Command::cargo_bin("rmule-interop-harness").unwrap();
    command.args([
        "bench-smoke",
        "--container-runtime",
        docker.to_str().unwrap(),
        "--run-root",
        run_root.path().to_str().unwrap(),
        "--timeout",
        "5",
        "--server-host-port",
        &port,
    ]);
    command
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "bench-smoke: compression_advert=YES",
        ))
        .stdout(predicate::str::contains("bench-smoke: crypt_advert=NO"));

    let log = std::fs::read_to_string(&docker_log).unwrap();
    assert_ordered(
        &log,
        &[
            "network create rmule-interop-".to_owned(),
            "run --detach --name rmule-interop-server-".to_owned(),
            "logs rmule-interop-server-".to_owned(),
            // The probe runs in the interop network via rmule-tools.
            "run --rm --network rmule-interop-".to_owned(),
            "cargo run -p rmule-tools -- ed2k server probe rmule-interop-server-".to_owned(),
            "rm -f rmule-interop-server-".to_owned(),
            "network rm rmule-interop-".to_owned(),
        ],
    );

    // No aMule is ever started — this is a server-only wire smoke.
    assert!(
        !log.contains("rmule-interop-amule-"),
        "bench-smoke starts no aMule:\n{log}"
    );

    let runs = run_dirs(run_root.path());
    assert_eq!(runs.len(), 1);
    let summary = std::fs::read_to_string(runs[0].join("bench-smoke-summary.toml")).unwrap();
    assert!(summary.contains("scenario = \"bench-smoke\""), "{summary}");
    assert!(
        summary.contains("compression_advert = \"YES\""),
        "{summary}"
    );
    assert!(summary.contains("crypt_advert = \"NO\""), "{summary}");
    assert!(summary.contains("tcp_flags = \"0x00000003\""), "{summary}");
    assert!(summary.contains("udp_flags = \"0x00000123\""), "{summary}");
    // The raw probe report is retained for the record.
    assert!(runs[0].join("probe/stdout.log").is_file());
}
