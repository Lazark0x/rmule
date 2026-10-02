//! rmule driven as the client of the bench: the counterparty env a flow passes
//! through, and the download and search runs that follow readiness — each
//! inside the interop network.

use std::net::TcpListener;

use predicates::prelude::*;

use crate::fake_docker::script::{fake_docker, fake_docker_with_mode, fake_rmule_tools};
use crate::fixture::fake_hash_command;
use crate::fixture::{assert_ordered, base_command, base_command_for, run_dirs};

#[test]
fn amule_env_overrides_are_passed_to_container() {
    let run_root = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let docker_log = run_root.path().join("docker.log");
    let docker = fake_docker(fake_bin.path(), &docker_log);
    let hash_command = fake_hash_command(fake_bin.path(), 65536);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();

    let mut command = base_command(&docker, &hash_command, run_root.path());
    command.args(["--server-host-port", &port, "--amule-env", "AMULE_DEBUG=1"]);
    command
        .assert()
        .failure()
        .stderr(predicate::str::contains("aMule log pattern"));

    let log = std::fs::read_to_string(&docker_log).unwrap();
    assert!(log.contains("-e AMULE_DEBUG=1"), "{log}");
}

#[test]
fn amule_readiness_success_runs_rmule_download_and_cleans_up() {
    let run_root = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let docker_log = run_root.path().join("docker.log");
    let docker = fake_docker_with_mode(fake_bin.path(), &docker_log, "amule-ready");
    let hash_command = fake_hash_command(fake_bin.path(), 65536);
    let rmule = fake_rmule_tools(fake_bin.path());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();

    let mut command = base_command(&docker, &hash_command, run_root.path());
    command.args([
        "--server-host-port",
        &port,
        "--amule-ready-log-pattern",
        "custom-amule-ready",
        "--rmule-tools-command",
        rmule.to_str().unwrap(),
    ]);
    command.assert().success();

    let log = std::fs::read_to_string(&docker_log).unwrap();
    assert_ordered(
        &log,
        &[
            "run --detach --name rmule-interop-amule-".to_owned(),
            "logs rmule-interop-amule-".to_owned(),
            "rm -f rmule-interop-amule-".to_owned(),
            "rm -f rmule-interop-server-".to_owned(),
            "network rm rmule-interop-".to_owned(),
        ],
    );

    let runs = run_dirs(run_root.path());
    assert_eq!(runs.len(), 1, "one retained run directory is created");
    assert!(runs[0].join("rmule/stdout.log").is_file());
    assert_eq!(
        std::fs::read(runs[0].join("synthetic/shared.bin")).unwrap(),
        std::fs::read(runs[0].join("rmule/output.bin")).unwrap()
    );
}

#[test]
fn default_rmule_client_runs_inside_interop_network() {
    let run_root = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let docker_log = run_root.path().join("docker.log");
    let docker = fake_docker_with_mode(fake_bin.path(), &docker_log, "amule-ready");
    let hash_command = fake_hash_command(fake_bin.path(), 65536);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();

    let mut command = base_command(&docker, &hash_command, run_root.path());
    command.args([
        "--server-host-port",
        &port,
        "--amule-ready-log-pattern",
        "custom-amule-ready",
    ]);
    command.assert().success();

    let log = std::fs::read_to_string(&docker_log).unwrap();
    assert_ordered(
        &log,
        &[
            "run --detach --name rmule-interop-amule-".to_owned(),
            "logs rmule-interop-amule-".to_owned(),
            "run --rm --network rmule-interop-".to_owned(),
            "-w /workspace".to_owned(),
            "rust:1.94.0-bookworm cargo run -p rmule-tools -- ed2k download start".to_owned(),
            "--server rmule-interop-server-".to_owned(),
            ":4661".to_owned(),
            "rm -f rmule-interop-amule-".to_owned(),
            "rm -f rmule-interop-server-".to_owned(),
            "network rm rmule-interop-".to_owned(),
        ],
    );

    let runs = run_dirs(run_root.path());
    assert_eq!(runs.len(), 1, "one retained run directory is created");
    assert!(runs[0].join("rmule/stdout.log").is_file());
    assert_eq!(
        std::fs::read(runs[0].join("synthetic/shared.bin")).unwrap(),
        std::fs::read(runs[0].join("rmule/output.bin")).unwrap()
    );
}

#[test]
fn search_flow_runs_rmule_search_inside_interop_network() {
    let run_root = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let docker_log = run_root.path().join("docker.log");
    let docker = fake_docker_with_mode(fake_bin.path(), &docker_log, "amule-ready");
    let hash_command = fake_hash_command(fake_bin.path(), 65536);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();

    let mut command = base_command_for(
        "amule-serves-rmule-searches",
        &docker,
        &hash_command,
        run_root.path(),
    );
    command.args([
        "--server-host-port",
        &port,
        "--amule-ready-log-pattern",
        "custom-amule-ready",
    ]);
    command.assert().success();

    let log = std::fs::read_to_string(&docker_log).unwrap();
    assert_ordered(
        &log,
        &[
            "run --detach --name rmule-interop-amule-".to_owned(),
            "logs rmule-interop-amule-".to_owned(),
            "run --rm --network rmule-interop-".to_owned(),
            "cargo run -p rmule-tools -- ed2k search".to_owned(),
            "--server rmule-interop-server-".to_owned(),
            ":4661 --query shared.bin".to_owned(),
            "rm -f rmule-interop-amule-".to_owned(),
            "rm -f rmule-interop-server-".to_owned(),
            "network rm rmule-interop-".to_owned(),
        ],
    );

    let runs = run_dirs(run_root.path());
    assert_eq!(runs.len(), 1, "one retained run directory is created");
    let stdout = std::fs::read_to_string(runs[0].join("rmule/stdout.log")).unwrap();
    assert!(stdout.contains("shared.bin"), "{stdout}");
}
