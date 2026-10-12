//! rmule driven as the serving side: the reverse flow a counterparty downloads
//! from, the golden-author flush that copies its files out, and the eserver-
//! login retry that gives up clearly instead of hanging.

use std::net::TcpListener;
use std::time::Duration;

use rmule_interop_harness::artifacts::RunLayout;
use rmule_interop_harness::rmule::{BenchStaging, RmuleServeContainer, ServeKnobs};

use crate::fake_docker::script::{
    fake_docker_with_mode, fake_flush_docker, fake_login_retry_docker,
};
use crate::fixture::fake_hash_command;
use crate::fixture::{assert_ordered, base_command_for, run_dirs};

#[test]
fn reverse_default_runs_rmule_serve_and_amule_download_inside_interop_network() {
    let run_root = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let docker_log = run_root.path().join("docker.log");
    let docker = fake_docker_with_mode(fake_bin.path(), &docker_log, "reverse-ready");
    let hash_command = fake_hash_command(fake_bin.path(), 65536);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();

    let mut command = base_command_for(
        "rmule-serves-amule-downloads",
        &docker,
        &hash_command,
        run_root.path(),
    );
    command.args(["--server-host-port", &port]);
    command.assert().success();

    let log = std::fs::read_to_string(&docker_log).unwrap();
    assert_ordered(
        &log,
        &[
            "cargo build -p rmule-tools".to_owned(),
            "run --detach --name rmule-interop-rmule-".to_owned(),
            "/tmp/rmule-target/debug/rmule-tools ed2k serve start".to_owned(),
            "--server rmule-interop-server-".to_owned(),
            ":4661 --listen 0.0.0.0:4663".to_owned(),
            "logs rmule-interop-rmule-".to_owned(),
            "inspect --format {{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}} rmule-interop-rmule-"
                .to_owned(),
            "run --detach --name rmule-interop-amule-".to_owned(),
            "-e AMULE_DOWNLOAD_LINK=ed2k://|file|shared.bin|65536|fakehash|/|sources,172.18.0.3:4663|/"
                .to_owned(),
            "-e AMULE_EXPECTED_SIZE=65536".to_owned(),
            "logs rmule-interop-amule-".to_owned(),
            "rm -f rmule-interop-amule-".to_owned(),
            "rm -f rmule-interop-rmule-".to_owned(),
            "rm -f rmule-interop-server-".to_owned(),
            "network rm rmule-interop-".to_owned(),
        ],
    );

    let runs = run_dirs(run_root.path());
    assert_eq!(runs.len(), 1, "one retained run directory is created");
    assert!(runs[0].join("rmule/stdout.log").is_file());
    assert!(runs[0].join("amule/shared.bin").is_file());
    assert_eq!(
        std::fs::read(runs[0].join("synthetic/shared.bin")).unwrap(),
        std::fs::read(runs[0].join("amule/shared.bin")).unwrap()
    );
}

#[test]
fn flush_golden_files_shuts_down_then_copies_server_met_and_nodes_dat() {
    let fake_bin = tempfile::tempdir().unwrap();
    let dest = tempfile::tempdir().unwrap();
    let docker_log = fake_bin.path().join("docker.log");
    let docker_path = fake_flush_docker(fake_bin.path(), &docker_log);
    let docker = rmule_interop_harness::docker::Docker::new(docker_path.to_str().unwrap());

    let copied = rmule_interop_harness::flow::flush_golden_files(
        &docker,
        "rmule-interop-amule-x",
        "/root/.aMule",
        dest.path(),
    )
    .unwrap();

    let log = std::fs::read_to_string(&docker_log).unwrap();
    // Clean shutdown, then WAIT for amuled to finish its write_safe rename, then
    // a cp per golden — the wait is what stops the cp racing the rename.
    assert_ordered(
        &log,
        &[
            "exec rmule-interop-amule-x amulecmd -P rmule -c Shutdown".to_owned(),
            "wait rmule-interop-amule-x".to_owned(),
            "cp rmule-interop-amule-x:/root/.aMule/server.met".to_owned(),
            "cp rmule-interop-amule-x:/root/.aMule/nodes.dat".to_owned(),
        ],
    );
    assert_eq!(copied.len(), 2, "both goldens copied when cp succeeds");
}

/// The eserver-login retry: `docker logs` never contains
/// `files_announced`, so every attempt's `wait_for_rmule_ready` genuinely
/// times out — the give-up-after-N path, proving a truly-stuck login still
/// fails clearly instead of hanging forever.
#[test]
fn rmule_serve_login_retry_restarts_the_stalled_container_then_gives_up_clearly() {
    let fake_bin = tempfile::tempdir().unwrap();
    let run_root = tempfile::tempdir().unwrap();
    let docker_log = fake_bin.path().join("docker.log");
    let docker_path = fake_login_retry_docker(fake_bin.path(), &docker_log);
    let docker = rmule_interop_harness::docker::Docker::new(docker_path.to_str().unwrap());
    let layout = RunLayout::create(run_root.path().join("run")).unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let serve_container = RmuleServeContainer::new("rust:1.94.0-bookworm", workspace.path());

    let error = rmule_interop_harness::flow::start_rmule_serve_with_login_retry(
        BenchStaging {
            docker: &docker,
            layout: &layout,
            network: "rmule-net",
        },
        &serve_container,
        "rmule-interop-rmule-login-retry",
        "rmule-server:4661",
        ServeKnobs::default(),
        Duration::from_millis(200),
    )
    .unwrap_err();

    // Bounded: the context names the attempt budget, and the chained cause is
    // the real per-attempt timeout — a genuinely-down counterparty still
    // fails clearly, the cause is not swallowed.
    let message = format!("{error:#}");
    assert!(
        message.contains("after 3 eserver-login attempts"),
        "{message}"
    );
    assert!(message.contains("readiness timed out"), "{message}");

    let log = std::fs::read_to_string(&docker_log).unwrap();
    assert_eq!(
        log.matches("run --detach --name rmule-interop-rmule-login-retry")
            .count(),
        3,
        "3 login attempts, each a fresh container start:\n{log}"
    );
    assert_eq!(
        log.matches("rm -f rmule-interop-rmule-login-retry").count(),
        2,
        "torn down between attempts (2x), but not after the last one — the \
         stalled container is left for failure-log collection:\n{log}"
    );
}
