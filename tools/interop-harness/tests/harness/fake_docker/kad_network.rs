//! The stock-aMule Kad smoke: two nodes on the fake-public swarm, each
//! reporting Kad started, polled until `amulecmd Status` says connected.

use assert_cmd::Command;
use predicates::prelude::*;

use crate::fake_docker::script::fake_kad_smoke_docker;
use crate::fixture::{assert_ordered, run_dirs};

#[test]
fn kad_smoke_starts_two_stock_nodes_on_fake_public_and_reports_connected() {
    let run_root = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let docker_log = run_root.path().join("docker.log");
    let docker = fake_kad_smoke_docker(fake_bin.path(), &docker_log);

    let mut command = Command::cargo_bin("rmule-interop-harness").unwrap();
    command.args([
        "kad-smoke",
        "--skip-build",
        "--container-runtime",
        docker.to_str().unwrap(),
        "--run-root",
        run_root.path().to_str().unwrap(),
        "--timeout",
        "5",
        "--connect-deadline",
        "10",
    ]);
    command
        .assert()
        .success()
        .stdout(predicate::str::contains("kad_connected=true"));

    let log = std::fs::read_to_string(&docker_log).unwrap();
    assert_ordered(
        &log,
        &[
            "network create --internal --subnet 203.0.113.0/24 rmule-interop-kad-".to_owned(),
            // Seed (storer container) starts and reports Kad-started first.
            "run --detach --name rmule-interop-kad-storer-".to_owned(),
            "logs rmule-interop-kad-storer-".to_owned(),
            // Then the joiner (requester container).
            "run --detach --name rmule-interop-kad-requester-".to_owned(),
            "logs rmule-interop-kad-requester-".to_owned(),
            // amulecmd Status poll, then teardown.
            "exec rmule-interop-kad-".to_owned(),
            "network rm rmule-interop-kad-".to_owned(),
        ],
    );
    // Deterministic fake-public static IPs (Config A): .1 is the gateway.
    assert!(log.contains("--ip 203.0.113.2"), "seed on .2:\n{log}");
    assert!(log.contains("--ip 203.0.113.3"), "joiner on .3:\n{log}");
    // Config A forces FilterLanIPs=1 so the stock node stays out of LAN mode.
    assert!(
        log.contains("-e AMULE_KAD_FILTER_LAN_IPS=1"),
        "Config A must force FilterLanIPs=1:\n{log}"
    );
    // Stock image, never the patched one.
    assert!(
        !log.contains("amule-kad-patched"),
        "kad-smoke must use the stock image:\n{log}"
    );

    let runs = run_dirs(run_root.path());
    assert_eq!(runs.len(), 1);
    let verdict = std::fs::read_to_string(runs[0].join("kad/kad-smoke-verdict.txt")).unwrap();
    assert!(verdict.contains("kad_connected = true"), "{verdict}");
    assert!(verdict.contains("stock_amule = true"), "{verdict}");
    assert!(verdict.contains("subnet = \"203.0.113.0/24\""), "{verdict}");
}
