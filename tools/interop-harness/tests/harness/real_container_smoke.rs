//! Live smokes against a real container runtime and the checked-in image
//! recipes: `#[ignore]`d, run explicitly when Docker and the images are present.

use crate::fixture::{run_dir_from, unused_local_port};

#[test]
#[ignore = "requires Docker-compatible runtime and interop images/artifacts"]
fn amule_serves_rmule_downloads_real_containers() {
    let _ = run_real_flow("amule-serves-rmule-downloads", &[]);
}

#[test]
#[ignore = "requires Docker-compatible runtime and interop images/artifacts"]
fn amule_serves_rmule_searches_real_containers() {
    let run_dir = run_real_flow("amule-serves-rmule-searches", &[]);
    let stdout = std::fs::read_to_string(run_dir.join("rmule/stdout.log")).unwrap();
    assert!(
        stdout.contains("search_completed "),
        "search smoke should complete:\n{stdout}"
    );
    assert!(
        stdout.contains("shared.bin"),
        "search smoke should find the synthetic shared file:\n{stdout}"
    );
}

#[test]
#[ignore = "requires Docker-compatible runtime and interop images/artifacts"]
fn amule_serves_rmule_downloads_large_file_real_containers() {
    let run_dir = run_real_flow(
        "amule-serves-rmule-downloads",
        &["--file-size", "9728001", "--timeout", "420"],
    );
    let stdout = std::fs::read_to_string(run_dir.join("rmule/stdout.log")).unwrap();
    assert!(
        stdout.contains("download.part_verified "),
        "large file should use part hashes and emit part_verified:\n{stdout}"
    );
}

#[test]
#[ignore = "requires Docker-compatible runtime and interop images/artifacts"]
fn rmule_serves_amule_downloads_large_file_real_containers() {
    let run_dir = run_real_flow(
        "rmule-serves-amule-downloads",
        &["--file-size", "9728001", "--timeout", "420"],
    );
    assert_eq!(
        std::fs::read(run_dir.join("synthetic/shared.bin")).unwrap(),
        std::fs::read(run_dir.join("amule/shared.bin")).unwrap()
    );
}

#[test]
#[ignore = "requires Docker-compatible runtime and interop images/artifacts"]
fn amule_low_id_callback_real_containers() {
    // The aMule sharer is forced to Low-ID, so rmule has no dialable source; a
    // byte-for-byte output therefore proves rmule requested a server-relayed
    // callback and adopted the called-back peer as a download worker (ADR-0039).
    // The callback round-trip needs more time than a direct dial.
    let run_dir = run_real_flow("amule-low-id-callback", &["--timeout", "420"]);
    assert_eq!(
        std::fs::read(run_dir.join("synthetic/shared.bin")).unwrap(),
        std::fs::read(run_dir.join("rmule/output.bin")).unwrap()
    );
}

#[test]
#[ignore = "requires Docker-compatible runtime and working private aMule Kad bootstrap"]
fn kad_source_lookup_capture_phase1_real_containers() {
    let run_dir = run_real_kad_flow(&[]);
    assert!(run_dir.join("capture/kad/kad.pcap").is_file());
    assert!(run_dir.join("kad/candidate-summary.toml").is_file());
}

fn run_real_kad_flow(extra_args: &[&str]) -> std::path::PathBuf {
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let amule_context = workspace_root.join("tools/interop-harness/images/amule");
    let capture_context = workspace_root.join("tools/interop-harness/images/capture");
    let mut cmd = assert_cmd::Command::cargo_bin("rmule-interop-harness").unwrap();
    // The Kad flow owns no eD2k server: never pass --server-build-context
    // or --server-host-port here.
    let assert = cmd
        .arg("kad-source-lookup-capture")
        .arg("--build-images")
        .arg("--amule-build-context")
        .arg(amule_context)
        .arg("--capture-build-context")
        .arg(capture_context)
        .args(extra_args)
        .assert()
        .success();
    run_dir_from(&assert.get_output().stdout)
}

fn run_real_flow(flow: &str, extra_args: &[&str]) -> std::path::PathBuf {
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let server_context = workspace_root.join("tools/interop-harness/images/server");
    let amule_context = workspace_root.join("tools/interop-harness/images/amule");
    let server_host_port = unused_local_port();
    let mut cmd = assert_cmd::Command::cargo_bin("rmule-interop-harness").unwrap();
    cmd.arg(flow)
        .arg("--build-images")
        .arg("--server-build-context")
        .arg(server_context)
        .arg("--amule-build-context")
        .arg(amule_context)
        .arg("--server-host-port")
        .arg(server_host_port.port().to_string())
        .args(extra_args);
    // Dropped before the run so the container's own host-port publish can
    // bind this exact number — a held listener would refuse it the bind.
    drop(server_host_port);
    let assert = cmd.assert().success();
    run_dir_from(&assert.get_output().stdout)
}
