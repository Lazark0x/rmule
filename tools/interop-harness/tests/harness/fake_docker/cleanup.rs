//! What the bench tears down, and what it keeps: `--keep-containers`, and the
//! four failure paths where cleanup must still run and the primary error must
//! still surface.

use std::net::TcpListener;
use std::path::Path;

use predicates::prelude::*;
use rmule_interop_harness::artifacts::RunLayout;
use rmule_interop_harness::flow::RmuleClientAction;
use rmule_interop_harness::flow::{ServerSkeletonOptions, run_server_skeleton};
use rmule_interop_harness::rmule::{RmuleClientContainer, RmuleServeContainer, RmuleToolsCommand};

use crate::fake_docker::script::{fake_docker, fake_docker_with_mode, fake_rmule_tools};
use crate::fixture::fake_hash_command;
use crate::fixture::{assert_ordered, base_command, unused_local_port, workspace_root};

#[test]
fn keep_containers_skips_cleanup_and_prints_retained_resources() {
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
        "--keep-containers",
    ]);
    command
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "kept_container=rmule-interop-amule-",
        ))
        .stdout(predicate::str::contains(
            "kept_container=rmule-interop-server-",
        ))
        .stdout(predicate::str::contains("kept_network=rmule-interop-"));

    let log = std::fs::read_to_string(&docker_log).unwrap();
    assert!(!log.lines().any(|line| line.starts_with("rm -f ")), "{log}");
    assert!(
        !log.lines().any(|line| line.starts_with("network rm ")),
        "{log}"
    );
}

#[test]
fn failed_server_run_removes_the_server_container_and_the_network() {
    let run_root = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let docker_log = run_root.path().join("docker.log");
    let docker = fake_docker_with_mode(fake_bin.path(), &docker_log, "run-fails");
    let hash_command = fake_hash_command(fake_bin.path(), 65536);

    base_command(&docker, &hash_command, run_root.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("run server container"));

    let log = std::fs::read_to_string(&docker_log).unwrap();
    assert_ordered(
        &log,
        &[
            "network create rmule-interop-".to_owned(),
            "run --detach --name rmule-interop-server-".to_owned(),
            // A refused `run` can still have created the container.
            "rm -f rmule-interop-server-".to_owned(),
            "network rm rmule-interop-".to_owned(),
        ],
    );
}

#[test]
fn failed_log_collection_reports_log_error_and_cleans_up_resources() {
    let run_root = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let docker_log = run_root.path().join("docker.log");
    let docker = fake_docker_with_mode(fake_bin.path(), &docker_log, "logs-fail");
    let hash_command = fake_hash_command(fake_bin.path(), 65536);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();

    let mut command = base_command(&docker, &hash_command, run_root.path());
    command.args(["--server-host-port", &port]);
    command
        .assert()
        .failure()
        .stderr(predicate::str::contains("collect server container logs"));

    let log = std::fs::read_to_string(&docker_log).unwrap();
    assert_ordered(
        &log,
        &[
            "run --detach --name rmule-interop-server-".to_owned(),
            "logs rmule-interop-server-".to_owned(),
            "rm -f rmule-interop-server-".to_owned(),
            "network rm rmule-interop-".to_owned(),
        ],
    );
}

/// The two stderr messages this asserts are never a race between
/// themselves — `wait_for_tcp_ready` (`readiness.rs`) is an `Instant`
/// deadline loop that always reports "timed out" once it elapses regardless
/// of scheduler delay, and log collection is only attempted afterward, in
/// the same control-flow chain, once the readiness `Result` is already an
/// `Err`. The `logs-fail` fake docker script fails unconditionally and
/// immediately (no timing of its own), so both messages are guaranteed once
/// readiness fails at all. The one observed flake is
/// unexplained by anything in that chain; the suspected root cause
/// ("1-second timeout under load") does not hold up against the
/// deadline-based implementation, which cannot mis-fire under scheduler
/// pressure — only run longer wall-clock time before it does. **Fixed**:
/// `closed_port` used to come from `unused_local_port()`'s
/// plain `:0` bind-then-drop, and a sibling test's own bind-then-drop could
/// in principle reclaim the freed port before this process's first connect
/// attempt, which would make readiness succeed instead of time out.
/// `unused_local_port()` now draws off a dedicated, never-repeating cursor
/// (`fixture::ReservedPort`), so no other call in this binary can ever be
/// handed the same number.
#[test]
fn readiness_timeout_remains_primary_when_log_collection_also_fails() {
    let run_root = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let docker_log = run_root.path().join("docker.log");
    let docker = fake_docker_with_mode(fake_bin.path(), &docker_log, "logs-fail");
    let hash_command = fake_hash_command(fake_bin.path(), 65536);
    let closed_port = unused_local_port();

    let mut command = base_command(&docker, &hash_command, run_root.path());
    command.args(["--server-host-port", &closed_port.port().to_string()]);
    // Dropped before the run so the port genuinely answers nothing — a held
    // listener would still complete the handshake this asserts times out.
    drop(closed_port);

    command
        .assert()
        .failure()
        .stderr(predicate::str::contains("server readiness timed out"))
        .stderr(predicate::str::contains(
            "failed to collect server logs after readiness failure",
        ));
}

#[test]
fn failed_network_id_write_cleans_up_created_network() {
    let run_root = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let docker_log = run_root.path().join("docker.log");
    let docker = fake_docker(fake_bin.path(), &docker_log);
    let layout = RunLayout::create(run_root.path().join("run")).unwrap();
    std::fs::create_dir(layout.network_id_file()).unwrap();

    let result = run_server_skeleton(ServerSkeletonOptions {
        layout: &layout,
        container_runtime: docker.to_str().unwrap(),
        build_images: false,
        server_image: "rmule/interop-eserver:local",
        amule_image: "rmule/interop-amule:local",
        server_build_context: Path::new("unused-server-context"),
        amule_build_context: Path::new("unused-amule-context"),
        keep_containers: false,
        timeout_secs: 1,
        server_host_port: 4661,
        server_env: &[],
        amule_env: &[],
        amule_ready_log_pattern: "rmule-amule-ready",
        rmule_tools_command: Some(&RmuleToolsCommand::new("unused-rmule-tools")),
        rmule_client_container: &RmuleClientContainer::new("rust:1-bookworm", workspace_root()),
        rmule_serve_container: &RmuleServeContainer::new("rust:1-bookworm", workspace_root()),
        amule_low_id: false,
        rmule_serve: false,
        rmule_peer_crypt: None,
        rmule_peer_crypt_flip: &[],
        rmule_client_action: RmuleClientAction::Download,
    });

    assert!(result.is_err());
    let log = std::fs::read_to_string(&docker_log).unwrap();
    assert_ordered(
        &log,
        &[
            "network create rmule-interop-run".to_owned(),
            "network rm rmule-interop-run".to_owned(),
        ],
    );
}
