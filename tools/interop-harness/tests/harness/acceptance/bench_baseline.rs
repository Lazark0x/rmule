//! ADR-0092's baseline rows: NAT gateway self-proof, IPv6 net accept, sentinel sources.

use super::{bench_enabled, bench_run_root, read_string, run_flow};
use std::path::{Path, PathBuf};
use std::process::Command;

/// **`natgw-selfproof` — NAT gateway self-proof.** Every `NAT_TYPE` the `natgw` image builds
/// is stood up in turn and the RFC 5780 reflector probe measures it from inside
/// the gateway's LAN. `PASS` means all four probed the RFC 4787 pair their knob
/// claims; `OBSERVED` is the honest partial — a gateway that built something
/// else, which is a real finding about the bench and not a test failure.
///
/// `--run-root` is taken from `RMULE_BENCH_RUN_ROOT` when set: a container
/// runtime in a VM can only bind-mount host paths the VM actually mounts, and
/// the run dir is where the NAT Type Proof lands.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn natgw_selfproof() {
    if !bench_enabled("natgw-selfproof") {
        return;
    }
    // The wrapper runs the binary from the crate directory, so the flow's
    // repo-relative defaults for the rmule-tools driver image would resolve
    // against `tools/interop-harness/`. Same reason flow K passes them.
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let dockerfile = repo_root.join("tools/interop-harness/images/rmule-tools/Dockerfile");
    let (repo_root, dockerfile) = (
        repo_root.to_str().unwrap().to_string(),
        dockerfile.to_str().unwrap().to_string(),
    );
    let mut args = vec![
        "--skip-build",
        "--timeout",
        "120",
        "--rmule-tools-dockerfile",
        &dockerfile,
        "--rmule-tools-build-context",
        &repo_root,
    ];
    let run_root = bench_run_root();
    if let Some(root) = &run_root {
        args.extend_from_slice(&["--run-root", root]);
    }
    let run_dir = run_flow("natgw-selfproof", &args);
    let verdict = read_string(&run_dir, "natgw-selfproof-verdict.toml");
    // `PASS` alone: a leg whose gateway probed as another type, or could not
    // forward its pinned port, is `FAIL`, and no leg at all is `OBSERVED`.
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "natgw-selfproof: every gateway leg must build the type it claims:\n{verdict}",
    );
    // A leg with no NAT Type Proof is the fabricated row ADR-0045 forbids, so
    // the artifacts are asserted, not just the verdict line. The `peer/` half
    // is the **Pinned-Pair Reach** leg's second gateway and carries the same
    // record: two gateways of one type toward each other is an arrangement
    // neither the reflector nor a single gateway's dump can speak for.
    let nat_types = [
        "port-restricted",
        "restricted",
        "full-cone-pinned",
        "symmetric",
    ];
    for nat_type in nat_types {
        for artifact in [
            "nat-type.toml",
            "nat-probe.toml",
            "nft-ruleset.txt",
            "conntrack.txt",
            "peer-reach.toml",
            "peer/peer-reach.toml",
            "peer/nft-ruleset.txt",
            "peer/conntrack.txt",
            "peer/tap-wan.pcap",
            "peer/tap-lan.pcap",
        ] {
            let path = format!("nat/{nat_type}/{artifact}");
            assert!(
                run_dir.join(&path).is_file(),
                "natgw-selfproof: {nat_type} leg is missing its {artifact}",
            );
        }
    }
    // The pinned pair is asserted harder than the RFC 4787 axes above, and
    // deliberately. A gateway that measures a different mapping behaviour than
    // its knob claims is a finding about the kernel; a gateway that cannot pass
    // a punch between two of its own kind is a bench no NAT-traversal flow can run on
    // And `OBSERVED` must not launder it.
    assert_eq!(
        verdict.matches("as_expected = true").count(),
        nat_types.len(),
        "natgw-selfproof: every leg's pinned pair must behave as its type demands — \
         crossing on the three that can, silent on symmetric:\n{verdict}",
    );
}

/// **`ipv6-net-accept` — IPv6 prefix acceptance.** Each IPv6-speaking body starts on a
/// `3fff::/20` address and its own log is read back. `OBSERVED` is accepted
/// because a body that *rejects* the prefix is the measurement, not a failure;
/// what is asserted is that every body was actually classified from a log the
/// run dir retains.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn ipv6_net_accept() {
    if !bench_enabled("ipv6-net-accept") {
        return;
    }
    let mut args = vec!["--skip-build", "--timeout", "120", "--settle", "20"];
    let run_root = bench_run_root();
    if let Some(root) = &run_root {
        args.extend_from_slice(&["--run-root", root]);
    }
    let run_dir = run_flow("ipv6-net-accept", &args);
    let verdict = read_string(&run_dir, "ipv6-net-accept-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\"") || verdict.contains("verdict = \"OBSERVED\""),
        "ipv6-net-accept: every body must be stood up on the prefix and classified:\n{verdict}",
    );
    for body in ["amule-kno", "emuleqt"] {
        assert!(
            run_dir.join(format!("ipv6/{body}.log")).is_file(),
            "ipv6-net-accept: {body} was classified without its log retained",
        );
    }
}

/// Build `rmule-tools` and return its binary's absolute path, so the
/// sentinel-reader probe below can point `--sentinel-reader-probe` at a
/// **hyphen-free** argv (`<path> ed2k sentinel-probe`) — `sentinel-reader-probe`
/// is `num_args = 1..` and stops collecting at the first `-`-prefixed token, so
/// an argv built from `cargo run -p rmule-tools -- ...` parses wrong (its own
/// `-p` reads as a new, unrecognised flag).
fn built_rmule_tools_binary() -> PathBuf {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let status = Command::new("cargo")
        .args(["build", "--package", "rmule-tools", "--bin", "rmule-tools"])
        .current_dir(&repo_root)
        .status()
        .expect("spawn cargo build -p rmule-tools");
    assert!(status.success(), "cargo build -p rmule-tools failed");
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_root.join("target"));
    // Matches the profile a plain `cargo build`/`cargo test` invocation uses.
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let binary = target_dir.join(profile).join("rmule-tools");
    assert!(
        binary.is_file(),
        "built rmule-tools binary not found at {}",
        binary.display()
    );
    binary
}

/// **`sentinel-sources-legacy` — sentinel legacy safety.** Both halves of ADR-0092's sentinel row,
/// as amended to drive it with rmule as the stimulus. rmule's half is the reader gate:
/// `--sentinel-reader-probe` points at `rmule-tools ed2k sentinel-probe`, which
/// decodes ed2k-server#12's documented sentinel-source payload through the
/// compiled reader. aMule's half is `--drive-legacy`: an rmule-authored
/// stimulus hands a sentinel-bearing `OP_FOUNDSOURCES` to a **stock aMule
/// 2.3.3** and the flow judges aMule alone — it must dial the records either
/// side of the Sentinel Source at their own ports, dial nothing at the
/// sentinel's port or at the `255.255.255.255` its id unpacks to, and keep its
/// session. The emission fires on the harness's trigger file, which is what
/// puts it after the tap; the wrapper asserts that too, because a `PASS` whose
/// list went out before the capture started would be unwitnessed.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn sentinel_sources_legacy() {
    if !bench_enabled("sentinel-sources-legacy") {
        return;
    }
    let binary = built_rmule_tools_binary();
    let binary_str = binary.to_str().unwrap().to_string();
    // The wrapper runs the binary from the crate directory, so the flow's
    // repo-relative defaults for the rmule-tools driver image would resolve
    // against `tools/interop-harness/`. Same reason `natgw-selfproof` passes them.
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let dockerfile = repo_root.join("tools/interop-harness/images/rmule-tools/Dockerfile");
    let (repo_root, dockerfile) = (
        repo_root.to_str().unwrap().to_string(),
        dockerfile.to_str().unwrap().to_string(),
    );
    let mut args = vec![
        "--drive-legacy",
        "--skip-build",
        "--timeout",
        "240",
        "--window",
        "60",
        "--rmule-tools-dockerfile",
        &dockerfile,
        "--rmule-tools-build-context",
        &repo_root,
    ];
    let run_root = bench_run_root();
    if let Some(root) = &run_root {
        args.extend_from_slice(&["--run-root", root]);
    }
    // `--sentinel-reader-probe` is `num_args = 1..`, so its argv goes last.
    args.extend_from_slice(&[
        "--sentinel-reader-probe",
        binary_str.as_str(),
        "ed2k",
        "sentinel-probe",
    ]);
    let run_dir = run_flow("sentinel-sources-legacy", &args);
    let verdict = read_string(&run_dir, "sentinel-sources-legacy-verdict.toml");
    for expected in [
        "verdict = \"PASS\"",
        "sentinel_reader_present = true",
        "legacy_leg = \"PASS\"",
        "legacy_emit_trigger = \"trigger-file\"",
        "amule_dialled_before_sentinel = true",
        "amule_dialled_after_sentinel = true",
        "amule_dialled_sentinel_port = 0",
        "amule_dialled_broadcast_id = 0",
        "legacy_session_survived = true",
    ] {
        assert!(
            verdict.contains(expected),
            "sentinel-sources-legacy: {expected} missing from the verdict:\n{verdict}",
        );
    }
    // Both recording surfaces have to survive the run: the counterparty's dials
    // are read off the stimulus journal and corroborated on its own netns pcap.
    for artifact in ["stimulus/stimulus.toml", "capture/amule.pcap"] {
        assert!(
            run_dir.join(artifact).is_file(),
            "sentinel-sources-legacy: the legacy leg passed without retaining {artifact}",
        );
    }
}
