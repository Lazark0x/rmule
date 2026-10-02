//! Container-runtime argv composition where the ORDER is the contract:
//! `--subnet`/`--internal` before the network name, run options in docker's
//! order, `container:path` joined for `cp`, and exec argv after the name.

use std::ffi::{OsStr, OsString};

use rmule_interop_harness::docker::{Docker, RunContainer, is_retriable_build_export_failure};

fn assert_program(cmd: &rmule_interop_harness::docker::DockerCommand, program: &str) {
    assert_eq!(cmd.program(), OsStr::new(program));
}

fn assert_args(cmd: &rmule_interop_harness::docker::DockerCommand, expected: &[&str]) {
    let expected = expected.iter().map(OsString::from).collect::<Vec<_>>();
    assert_eq!(cmd.args(), expected.as_slice());
}

#[test]
fn create_network_with_subnet_passes_subnet_before_name() {
    let docker = Docker::new("docker");

    let cmd = docker.create_network_with_subnet("rmule-interop-kad-123", "172.30.0.0/24");

    assert_program(&cmd, "docker");
    assert_args(
        &cmd,
        &[
            "network",
            "create",
            "--subnet",
            "172.30.0.0/24",
            "rmule-interop-kad-123",
        ],
    );
}

#[test]
fn prune_bench_stage_images_scopes_to_the_bench_stage_label_and_dangling() {
    let docker = Docker::new("docker");

    let cmd = docker.prune_bench_stage_images();

    assert_program(&cmd, "docker");
    assert_args(
        &cmd,
        &[
            "image",
            "prune",
            "-f",
            "--filter",
            "label=org.rmule.bench.stage=1",
            "--filter",
            "dangling=true",
        ],
    );
}

#[test]
fn create_internal_network_with_subnet_passes_internal_before_subnet() {
    let docker = Docker::new("docker");

    let cmd = docker.create_internal_network_with_subnet("rmule-interop-kad-123", "203.0.113.0/24");

    assert_program(&cmd, "docker");
    assert_args(
        &cmd,
        &[
            "network",
            "create",
            "--internal",
            "--subnet",
            "203.0.113.0/24",
            "rmule-interop-kad-123",
        ],
    );
}

#[test]
fn run_container_static_ip_follows_network() {
    let docker = Docker::new("docker");
    let container = RunContainer::new("rmule/interop-amule-kad-patched:local")
        .name("rmule-interop-kad-storer")
        .detach()
        .network("rmule-interop-kad-123")
        .ip("172.30.0.4");

    let cmd = docker.run_container(container);

    assert_args(
        &cmd,
        &[
            "run",
            "--detach",
            "--name",
            "rmule-interop-kad-storer",
            "--network",
            "rmule-interop-kad-123",
            "--ip",
            "172.30.0.4",
            "rmule/interop-amule-kad-patched:local",
        ],
    );
}

#[test]
fn run_container_command_includes_runtime_options_in_docker_order() {
    let docker = Docker::new("docker");
    let container = RunContainer::new("rmule/interop-amule:local")
        .name("rmule-amule")
        .detach()
        .remove_after_exit()
        .network("rmule-interop-123")
        .workdir("/workspace")
        .publish("4711", "4711/tcp")
        .volume("/tmp/rmule/incoming", "/incoming")
        .env("AMULE_DEBUG", "1");

    let cmd = docker.run_container(container);

    assert_program(&cmd, "docker");
    assert_args(
        &cmd,
        &[
            "run",
            "--detach",
            "--rm",
            "--name",
            "rmule-amule",
            "--network",
            "rmule-interop-123",
            "-w",
            "/workspace",
            "-p",
            "4711:4711/tcp",
            "-v",
            "/tmp/rmule/incoming:/incoming",
            "-e",
            "AMULE_DEBUG=1",
            "rmule/interop-amule:local",
        ],
    );
}

#[test]
fn run_container_renders_capture_sidecar_caps_after_network() {
    let docker = Docker::new("docker");
    let container = RunContainer::new("rmule/interop-capture:local")
        .name("rmule-interop-kad-capture")
        .detach()
        .network("container:rmule-interop-kad-requester")
        .cap_add("NET_RAW")
        .cap_add("NET_ADMIN")
        .volume("/tmp/run/capture/kad", "/capture")
        .arg("tcpdump")
        .arg("-i")
        .arg("eth0")
        .arg("-U")
        .arg("-w")
        .arg("/capture/kad.pcap")
        .arg("--")
        .arg("udp")
        .arg("and")
        .arg("(")
        .arg("port")
        .arg("4672")
        .arg("or")
        .arg("portrange")
        .arg("4672-4682")
        .arg(")");

    let cmd = docker.run_container(container);

    assert_program(&cmd, "docker");
    assert_args(
        &cmd,
        &[
            "run",
            "--detach",
            "--name",
            "rmule-interop-kad-capture",
            "--network",
            "container:rmule-interop-kad-requester",
            "--cap-add",
            "NET_RAW",
            "--cap-add",
            "NET_ADMIN",
            "-v",
            "/tmp/run/capture/kad:/capture",
            "rmule/interop-capture:local",
            "tcpdump",
            "-i",
            "eth0",
            "-U",
            "-w",
            "/capture/kad.pcap",
            "--",
            "udp",
            "and",
            "(",
            "port",
            "4672",
            "or",
            "portrange",
            "4672-4682",
            ")",
        ],
    );
}

#[test]
fn exec_command_uses_container_name_and_command_args() {
    let docker = Docker::new("docker");

    let cmd = docker.exec(
        "rmule-amule",
        [
            OsString::from("sh"),
            OsString::from("-lc"),
            OsString::from("amulecmd -P rmule -c Status"),
        ],
    );

    assert_program(&cmd, "docker");
    assert_args(
        &cmd,
        &[
            "exec",
            "rmule-amule",
            "sh",
            "-lc",
            "amulecmd -P rmule -c Status",
        ],
    );
}

#[test]
fn is_retriable_build_export_failure_matches_the_three_signatures_only() {
    // The three containerd content-store races observed twice in one bench
    // window (paraphrased; digests/refs elided as "…").
    assert!(is_retriable_build_export_failure(
        "failed to export layer sha256:abc123: content digest sha256:def456: not found"
    ));
    assert!(is_retriable_build_export_failure(
        "failed commit on ref \"layer-sha256:abc\": \"blob sha256:def\": ingest rename: no such file or directory"
    ));
    assert!(is_retriable_build_export_failure(
        "failed to prepare extraction snapshot sha256:abc123: not found"
    ));
    // A real compile error must never be retried.
    assert!(!is_retriable_build_export_failure(
        "error[E0433]: failed to resolve: use of undeclared crate or module `rmule_tools`"
    ));
}

#[test]
fn copy_from_container_joins_container_and_path_with_colon() {
    let docker = Docker::new("docker");

    let cmd = docker.copy_from_container(
        "rmule-interop-amule-1",
        "/root/.aMule/server.met",
        "/tmp/run/golden/server.met",
    );

    assert_program(&cmd, "docker");
    assert_args(
        &cmd,
        &[
            "cp",
            "rmule-interop-amule-1:/root/.aMule/server.met",
            "/tmp/run/golden/server.met",
        ],
    );
}
