//! The NAT-family build plan: `natgw` and `natprobe` must rebuild on
//! every run — they carry hand-edited recipes (`entrypoint.sh`,
//! `natgw-proof.sh`) a stale image would silently ship — while the heavier,
//! project-owned bodies stay gated behind `--build-images`. Each test drives a
//! real subcommand against the **Fake Build Log Docker**, which answers every
//! **Bench Doctor** probe with no capability at all, so the flow takes the
//! graceful `SKIPPED` path right after `build_images` runs and before any
//! network or container orchestration — cheap, and it never mistakes a
//! skipped flow for a built one.

use std::path::Path;

use assert_cmd::Command;

use crate::fake_docker::script::fake_build_log_docker;
use crate::fixture::run_dir_from;

/// Every context a NAT flow's `--*-build-context` flags must resolve to
/// absolutely: the CLI's defaults are repo-root-relative and this binary runs
/// from the harness package root, one directory too deep.
fn image_dir(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("images")
        .join(name)
        .to_str()
        .unwrap()
        .to_owned()
}

#[test]
fn natgw_selfproof_rebuilds_natgw_and_natprobe_without_build_images() {
    let run_root = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let docker_log = run_root.path().join("docker.log");
    let docker = fake_build_log_docker(fake_bin.path(), &docker_log);
    let (natgw, natprobe) = (image_dir("natgw"), image_dir("natprobe"));

    let assert = Command::cargo_bin("rmule-interop-harness")
        .unwrap()
        .args([
            "natgw-selfproof",
            "--skip-build",
            "--container-runtime",
            docker.to_str().unwrap(),
            "--run-root",
            run_root.path().to_str().unwrap(),
            "--natgw-build-context",
            &natgw,
            "--natprobe-build-context",
            &natprobe,
        ])
        .assert()
        .success();
    let run_dir = run_dir_from(&assert.get_output().stdout);
    let verdict = std::fs::read_to_string(run_dir.join("natgw-selfproof-verdict.toml")).unwrap();
    assert!(
        verdict.contains("verdict = \"SKIPPED\""),
        "the fake doctor reports no capability, so the flow must skip:\n{verdict}"
    );

    let log = std::fs::read_to_string(&docker_log).unwrap();
    assert!(
        log.contains("-t rmule/interop-natgw:local"),
        "natgw must rebuild without --build-images:\n{log}"
    );
    assert!(
        log.contains("-t rmule/interop-natprobe:local"),
        "natprobe must rebuild without --build-images:\n{log}"
    );
    assert!(
        !log.contains("-t rmule/interop-capture:local"),
        "capture stays gated behind --build-images:\n{log}"
    );
}

#[test]
fn natt_buddy_rendezvous_rebuilds_natgw_and_natprobe_without_build_images() {
    let run_root = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let docker_log = run_root.path().join("docker.log");
    let docker = fake_build_log_docker(fake_bin.path(), &docker_log);
    let (natgw, natprobe) = (image_dir("natgw"), image_dir("natprobe"));

    let assert = Command::cargo_bin("rmule-interop-harness")
        .unwrap()
        .args([
            "natt",
            "natt-buddy-rendezvous-restricted",
            "--skip-build",
            "--container-runtime",
            docker.to_str().unwrap(),
            "--run-root",
            run_root.path().to_str().unwrap(),
            "--natgw-build-context",
            &natgw,
            "--natprobe-build-context",
            &natprobe,
        ])
        .assert()
        .success();
    let run_dir = run_dir_from(&assert.get_output().stdout);
    let verdict =
        std::fs::read_to_string(run_dir.join("natt-buddy-rendezvous-restricted-verdict.toml"))
            .unwrap();
    assert!(
        verdict.contains("verdict = \"SKIPPED\""),
        "the fake doctor reports no capability, so the flow must skip:\n{verdict}"
    );

    let log = std::fs::read_to_string(&docker_log).unwrap();
    assert!(
        log.contains("-t rmule/interop-natgw:local"),
        "natgw must rebuild without --build-images:\n{log}"
    );
    assert!(
        log.contains("-t rmule/interop-natprobe:local"),
        "natprobe must rebuild without --build-images:\n{log}"
    );
    assert!(
        !log.contains("-t rmule/interop-capture:local"),
        "capture stays gated behind --build-images:\n{log}"
    );
    assert!(
        !log.contains("-t rmule/interop-amule-kno:local"),
        "amule-kno stays gated behind --build-images:\n{log}"
    );
}

#[test]
fn ipv6_net_accept_rebuilds_natprobe_without_build_images() {
    let run_root = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let docker_log = run_root.path().join("docker.log");
    let docker = fake_build_log_docker(fake_bin.path(), &docker_log);
    let natprobe = image_dir("natprobe");

    let assert = Command::cargo_bin("rmule-interop-harness")
        .unwrap()
        .args([
            "ipv6-net-accept",
            "--skip-build",
            "--skip-amule-kno",
            "--skip-emuleqt",
            "--container-runtime",
            docker.to_str().unwrap(),
            "--run-root",
            run_root.path().to_str().unwrap(),
            "--natprobe-build-context",
            &natprobe,
        ])
        .assert()
        .success();
    let run_dir = run_dir_from(&assert.get_output().stdout);
    let verdict = std::fs::read_to_string(run_dir.join("ipv6-net-accept-verdict.toml")).unwrap();
    assert!(
        verdict.contains("verdict = \"OBSERVED\""),
        "the fake doctor grants daemon-ipv6, and both bodies are skipped, \
         so an empty body list is neither a pass nor a skip:\n{verdict}"
    );

    let log = std::fs::read_to_string(&docker_log).unwrap();
    assert!(
        log.contains("-t rmule/interop-natprobe:local"),
        "natprobe must rebuild without --build-images:\n{log}"
    );
    assert!(
        !log.contains("-t rmule/interop-amule-kno:local"),
        "amule-kno stays gated behind --build-images:\n{log}"
    );
    assert!(
        !log.contains("-t rmule/interop-emuleqt:local"),
        "emuleqt stays gated behind --build-images:\n{log}"
    );
}

#[test]
fn portmap_rebuilds_natprobe_without_build_images() {
    let run_root = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let docker_log = run_root.path().join("docker.log");
    let docker = fake_build_log_docker(fake_bin.path(), &docker_log);
    let natprobe = image_dir("natprobe");

    let assert = Command::cargo_bin("rmule-interop-harness")
        .unwrap()
        .args([
            "portmap",
            "portmap-highid",
            "--skip-build",
            "--container-runtime",
            docker.to_str().unwrap(),
            "--run-root",
            run_root.path().to_str().unwrap(),
            "--natprobe-build-context",
            &natprobe,
        ])
        .assert()
        .success();
    let run_dir = run_dir_from(&assert.get_output().stdout);
    let verdict = std::fs::read_to_string(run_dir.join("portmap-highid-verdict.toml")).unwrap();
    assert!(
        verdict.contains("verdict = \"SKIPPED\""),
        "the fake doctor reports no capability, so the flow must skip:\n{verdict}"
    );

    let log = std::fs::read_to_string(&docker_log).unwrap();
    assert!(
        log.contains("-t rmule/interop-natprobe:local"),
        "natprobe must rebuild without --build-images:\n{log}"
    );
    assert!(
        !log.contains("-t rmule/interop-miniupnpd:local"),
        "miniupnpd stays gated behind --build-images:\n{log}"
    );
    assert!(
        !log.contains("-t rmule/interop-capture:local"),
        "capture stays gated behind --build-images:\n{log}"
    );
}
