//! The rmule container contract: the exact argv the client and serve
//! containers compose (mounts, caches, trace env, the serve port), so a flow
//! can rely on where another container's artifacts land.

use std::ffi::{OsStr, OsString};

use rmule_interop_harness::artifacts::RunLayout;
use rmule_interop_harness::docker::Docker;
use rmule_interop_harness::rmule::{BenchStaging, RmuleClientContainer, RmuleServeContainer};

fn assert_args(cmd: &rmule_interop_harness::docker::DockerCommand, expected: &[&str]) {
    let expected = expected.iter().map(OsString::from).collect::<Vec<_>>();
    assert_eq!(cmd.args(), expected.as_slice());
}

#[test]
fn container_download_command_runs_rmule_inside_interop_network() {
    let run_root = tempfile::tempdir().unwrap();
    let layout = RunLayout::create(run_root.path().join("run")).unwrap();
    let docker = Docker::new("docker");
    let workspace = tempfile::tempdir().unwrap();
    let client = RmuleClientContainer::new("rust:1-bookworm", workspace.path());

    let command = client
        .download_start_command(
            BenchStaging {
                docker: &docker,
                layout: &layout,
                network: "rmule-net",
            },
            "rmule-server:4661",
            "ed2k://|file|shared.bin|1|hash|/",
            false,
            None,
        )
        .unwrap();
    let run_volume = format!("{}:/interop-run", layout.root().display());
    let workspace_volume = format!("{}:/workspace", workspace.path().display());
    let target_volume = format!(
        "{}:/tmp/rmule-target",
        workspace
            .path()
            .join(".scratch/interop-target-cache")
            .display()
    );

    assert_eq!(command.program(), OsStr::new("docker"));
    assert_args(
        &command,
        &[
            "run",
            "--rm",
            "--network",
            "rmule-net",
            "-w",
            "/workspace",
            "-v",
            &workspace_volume,
            "-v",
            &run_volume,
            "-v",
            &target_volume,
            "-e",
            // Serve-side trace knob wired into the downloading rmule too, so the
            // Low-ID callback flow can surface the callback frames;
            // RMULE_SERVE_LOG overrides it, else info.
            "RMULE_LOG=info",
            "rust:1-bookworm",
            "/tmp/rmule-target/debug/rmule-tools",
            "ed2k",
            "download",
            "start",
            "--data-dir",
            "/interop-run/rmule",
            "--server",
            "rmule-server:4661",
            "--file",
            "ed2k://|file|shared.bin|1|hash|/",
            "--out",
            "/interop-run/rmule/output.bin",
            "--tcp-port",
            "4663",
        ],
    );
}

#[test]
fn container_download_command_appends_serve_when_requested() {
    let run_root = tempfile::tempdir().unwrap();
    let layout = RunLayout::create(run_root.path().join("run")).unwrap();
    let docker = Docker::new("docker");
    let workspace = tempfile::tempdir().unwrap();
    let client = RmuleClientContainer::new("rust:1-bookworm", workspace.path());

    let command = client
        .download_start_command(
            BenchStaging {
                docker: &docker,
                layout: &layout,
                network: "rmule-net",
            },
            "rmule-server:4661",
            "ed2k://|file|shared.bin|1|hash|/",
            true,
            None,
        )
        .unwrap();

    // `--serve` makes rmule bind the inbound listener (High-ID + callback-capable,
    // ADR-0039); with no bounded-run deadline it is appended last, after `--tcp-port`.
    assert_eq!(command.args().last(), Some(&OsString::from("--serve")));
}

#[test]
fn container_serve_command_runs_rmule_serve_inside_interop_network() {
    let run_root = tempfile::tempdir().unwrap();
    let layout = RunLayout::create(run_root.path().join("run")).unwrap();
    let docker = Docker::new("docker");
    let workspace = tempfile::tempdir().unwrap();
    let server = RmuleServeContainer::new("rust:1.94.0-bookworm", workspace.path());

    let command = server
        .start_command(
            BenchStaging {
                docker: &docker,
                layout: &layout,
                network: "rmule-net",
            },
            "rmule-serve",
            "rmule-server:4661",
        )
        .unwrap();
    let run_volume = format!("{}:/interop-run", layout.root().display());
    let workspace_volume = format!("{}:/workspace", workspace.path().display());
    let target_volume = format!(
        "{}:/tmp/rmule-target",
        workspace
            .path()
            .join(".scratch/interop-target-cache")
            .display()
    );

    assert_eq!(command.program(), OsStr::new("docker"));
    assert_args(
        &command,
        &[
            "run",
            "--detach",
            "--name",
            "rmule-serve",
            "--network",
            "rmule-net",
            "-w",
            "/workspace",
            "-v",
            &workspace_volume,
            "-v",
            &run_volume,
            "-v",
            &target_volume,
            "-e",
            // Default serve-side trace level; RMULE_SERVE_LOG overrides it for
            // reverse-download wire diagnosis.
            "RMULE_LOG=info",
            "rust:1.94.0-bookworm",
            "/tmp/rmule-target/debug/rmule-tools",
            "ed2k",
            "serve",
            "start",
            "--file",
            "/interop-run/synthetic/shared.bin",
            "--server",
            "rmule-server:4661",
            "--listen",
            "0.0.0.0:4663",
        ],
    );
}
