//! The NAT-family build plan: the **Bench Doctor** runs first, on the one image
//! it probes with, and a flow builds nothing else until its capabilities are
//! there. `natprobe` and the `rmule-tools` driver image then rebuild on every
//! run that goes on — they carry hand-edited recipes and workspace code a stale
//! image would silently ship — while the heavier, project-owned bodies stay
//! gated behind `--build-images`. Each test drives a real subcommand against
//! the **Fake Build Log Docker**, which answers every Bench Doctor probe with no
//! capability at all, so the flow takes the graceful `SKIPPED` path right after
//! the doctor and before any network or container orchestration — cheap, and it
//! never mistakes a skipped flow for a built one.

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

/// Run `args` (a NAT-family subcommand) against the Fake Build Log Docker, which
/// reports no capability, and return its docker log and the verdict file named
/// `verdict_file`.
fn run_skipped(args: &[&str], verdict_file: &str, contexts: &[(&str, String)]) -> (String, String) {
    let run_root = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let docker_log = run_root.path().join("docker.log");
    let docker = fake_build_log_docker(fake_bin.path(), &docker_log);

    let mut command = Command::cargo_bin("rmule-interop-harness").unwrap();
    command
        .args(args)
        .args(["--skip-build", "--container-runtime"])
        .arg(&docker)
        .arg("--run-root")
        .arg(run_root.path());
    for (flag, dir) in contexts {
        command.arg(flag).arg(dir);
    }
    let assert = command.assert().success();
    let run_dir = run_dir_from(&assert.get_output().stdout);
    let verdict = std::fs::read_to_string(run_dir.join(verdict_file)).unwrap();
    (std::fs::read_to_string(&docker_log).unwrap(), verdict)
}

/// One skipping flow: its argv, its verdict file, the doctor's image and the
/// build contexts it needs.
type SkippedCase<'a> = (&'a [&'a str], &'a str, &'a str, Vec<(&'a str, String)>);

/// A run the host cannot carry is written down as skipped after the doctor's own
/// image alone: no `natprobe`, no capture, no compile of `rmule-tools` (no
/// prebuild container, no driver image), and no counterparty.
#[test]
fn a_skipped_nat_run_builds_only_the_doctors_image() {
    let (natgw, natprobe, miniupnpd) = (
        image_dir("natgw"),
        image_dir("natprobe"),
        image_dir("miniupnpd"),
    );
    let gateway_contexts = [
        ("--natgw-build-context", natgw.clone()),
        ("--natprobe-build-context", natprobe.clone()),
    ];
    let cases: [SkippedCase; 3] = [
        (
            &["natgw-selfproof"],
            "natgw-selfproof-verdict.toml",
            "rmule/interop-natgw:local",
            gateway_contexts.to_vec(),
        ),
        (
            &["natt", "natt-buddy-rendezvous-restricted"],
            "natt-buddy-rendezvous-restricted-verdict.toml",
            "rmule/interop-natgw:local",
            gateway_contexts.to_vec(),
        ),
        (
            &["portmap", "portmap-highid"],
            "portmap-highid-verdict.toml",
            "rmule/interop-miniupnpd:local",
            vec![
                ("--miniupnpd-build-context", miniupnpd),
                ("--natprobe-build-context", natprobe),
            ],
        ),
    ];
    for (args, verdict_file, doctor_image, contexts) in cases {
        let (log, verdict) = run_skipped(args, verdict_file, &contexts);
        let flow = args.join(" ");
        assert!(
            verdict.contains("verdict = \"SKIPPED\""),
            "{flow}: the fake doctor reports no capability, so the flow must skip:\n{verdict}"
        );
        assert!(
            log.contains(&format!("-t {doctor_image}")),
            "{flow}: the doctor's image is built first:\n{log}"
        );
        for later in [
            "-t rmule/interop-natprobe:local",
            "-t rmule/interop-rmule-tools:local",
            "-t rmule/interop-capture:local",
            "-t rmule/interop-amule-kno:local",
            "-t rmule/interop-ed2ksrv:local",
            "cargo build",
        ] {
            assert!(
                !log.contains(later),
                "{flow}: a skipped run must not reach `{later}`:\n{log}"
            );
        }
    }
}

#[test]
fn ipv6_net_accept_builds_natgw_then_rebuilds_natprobe_without_build_images() {
    let run_root = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let docker_log = run_root.path().join("docker.log");
    let docker = fake_build_log_docker(fake_bin.path(), &docker_log);
    let (natgw, natprobe) = (image_dir("natgw"), image_dir("natprobe"));

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
            "--natgw-build-context",
            &natgw,
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
    let at = |needle: &str| {
        log.find(needle)
            .unwrap_or_else(|| panic!("no `{needle}`:\n{log}"))
    };
    assert!(
        at("-t rmule/interop-natgw:local") < at("-t rmule/interop-natprobe:local"),
        "the doctor's image comes before natprobe, which rebuilds without --build-images:\n{log}"
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

/// Drive `ipv6-net-accept` with kno's aMule as its one body against the Fake
/// Build Log Docker, whose images carry no label. `kno_recipe` is the kno build
/// context; returns the command's result and the docker log.
fn run_net_accept_with_kno(
    run_root: &Path,
    kno_recipe: &Path,
    extra: &[&str],
    envs: &[(&str, &str)],
) -> (assert_cmd::assert::Assert, String) {
    let fake_bin = tempfile::tempdir().unwrap();
    let docker_log = run_root.join("docker.log");
    let docker = fake_build_log_docker(fake_bin.path(), &docker_log);
    let mut command = Command::cargo_bin("rmule-interop-harness").unwrap();
    command
        .args([
            "ipv6-net-accept",
            "--skip-emuleqt",
            "--timeout",
            "2",
            "--settle",
            "0",
        ])
        .args(extra)
        .arg("--container-runtime")
        .arg(&docker)
        .arg("--run-root")
        .arg(run_root)
        .arg("--amule-kno-build-context")
        .arg(kno_recipe)
        .args(["--natgw-build-context", &image_dir("natgw")])
        .args(["--natprobe-build-context", &image_dir("natprobe")])
        .envs(envs.iter().copied());
    let assert = command.assert();
    let log = std::fs::read_to_string(&docker_log).unwrap();
    (assert, log)
}

/// `--build-images` builds kno's aMule only through the recipe's own
/// `build.sh` (which verifies the pin and stamps the labels): it is handed the
/// image tag, and the harness never runs a bare `docker build` of the recipe's
/// Dockerfile, whose compile stage only that script makes.
#[test]
fn build_images_builds_kno_through_the_recipes_build_script() {
    let recipe = tempfile::tempdir().unwrap();
    let marker = recipe.path().join("ran");
    let script = recipe.path().join("build.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/bash\nprintf '%s' \"$AMULE_KNO_RUNTIME_TAG\" > {}\n",
            marker.display()
        ),
    )
    .unwrap();

    // Off the pin on purpose: the stub stamps no label, and this test is about
    // how the image is built, not about starting it.
    let run_root = tempfile::tempdir().unwrap();
    let (_, log) = run_net_accept_with_kno(
        run_root.path(),
        recipe.path(),
        &["--build-images"],
        &[("RMULE_BENCH_AMULE_KNO_OFF_PIN", "1")],
    );
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap(),
        "rmule/interop-amule-kno:local",
        "build.sh ran with the tag to build:\n{log}"
    );
    assert!(
        !log.lines()
            .any(|line| line.starts_with("build") && line.contains("amule-kno")),
        "no bare docker build of the kno recipe:\n{log}"
    );
}

/// A kno image whose commit label is not the pin is refused before any
/// container starts, and the refusal names the script that rebuilds it.
#[test]
fn a_kno_image_off_the_pin_is_refused_before_it_starts() {
    let recipe = tempfile::tempdir().unwrap();
    let run_root = tempfile::tempdir().unwrap();
    let (assert, log) =
        run_net_accept_with_kno(run_root.path(), recipe.path(), &["--skip-build"], &[]);
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
    assert!(
        stderr.contains("org.rmule.amule_kno.commit") && stderr.contains("amule-kno/build.sh"),
        "the refusal names the label and the rebuild script:\n{stderr}"
    );
    assert!(
        !log.lines()
            .any(|line| line.starts_with("run") && line.contains("amule-kno")),
        "kno's container never started:\n{log}"
    );
}

/// Every run leaves a `run.toml` the harness wrote itself: the commit it was
/// built from, and the end of the run — written although the flow failed.
#[test]
fn a_failed_run_still_leaves_its_run_record() {
    let recipe = tempfile::tempdir().unwrap();
    let run_root = tempfile::tempdir().unwrap();
    let (assert, _) =
        run_net_accept_with_kno(run_root.path(), recipe.path(), &["--skip-build"], &[]);
    assert.failure();

    let run_dir = std::fs::read_dir(run_root.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.join("run.toml").is_file())
        .expect("a run dir holding run.toml");
    let record: toml::Table = std::fs::read_to_string(run_dir.join("run.toml"))
        .unwrap()
        .parse()
        .unwrap();
    let head = std::process::Command::new("git")
        .args(["-C", env!("CARGO_MANIFEST_DIR"), "rev-parse", "HEAD"])
        .output()
        .unwrap();
    assert_eq!(
        record["harness_commit"].as_str().unwrap(),
        String::from_utf8_lossy(&head.stdout).trim()
    );
    assert_eq!(record["outcome"].as_str(), Some("error"));
    assert!(record["duration_ms"].as_integer().is_some(), "{record:?}");
}
