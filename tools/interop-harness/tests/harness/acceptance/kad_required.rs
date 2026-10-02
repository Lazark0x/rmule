//! Kad under Required (flow R): a Core-pumped rmule runs
//! its live firewall self-checks against two open stock aMule helpers, under
//! `--peer-crypt required` and under `requested` as the control. **The gate is
//! the TCP check** (scored on run `1790704014`): every helper's dial-back
//! authenticates and rmule's own diagnostics read TCP open.
//! The UDP verdict is recorded in the verdict file and not gated, because the
//! bench cannot show it: the UDP check engages only a helper outside rmule's
//! routing zone, and in a swarm of two to four nodes every helper is already a
//! contact, so it reads Unverified under either policy. The UDP check under
//! `Required` is proven live, by hand (Kad UDP Open 0.66 s after the
//! connect, 2026-09-29; ADR-0046).

use std::path::Path;

use rmule_interop_harness::flow::RequiredCheckVerdict;

use super::{bench_enabled, bench_run_root, read_string, run_flow};

fn run_flow_r(peer_crypt: &str) -> String {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let images = repo_root.join("tools/interop-harness/images");
    let at = |relative: &str| images.join(relative).to_str().unwrap().to_string();
    let (amule, capture) = (at("amule"), at("capture"));
    let mut args = vec![
        "--amule-build-context",
        &amule,
        "--capture-build-context",
        &capture,
        "--helpers",
        "2",
        "--window",
        "900",
        "--peer-crypt",
        peer_crypt,
    ];
    let run_root = bench_run_root();
    if let Some(root) = &run_root {
        args.extend_from_slice(&["--run-root", root]);
    }
    let run_dir = run_flow("kad-required-check", &args);
    read_string(&run_dir, "kad/kad-required-check-verdict.toml")
}

fn assert_tcp_open(verdict: &str) {
    assert!(
        RequiredCheckVerdict::from_verdict_file(verdict)
            .is_some_and(RequiredCheckVerdict::tcp_open),
        "flow R: rmule's TCP self-check must read open:\n{verdict}",
    );
    assert!(
        verdict.contains("rmule_last_verdicts = \"rmule-kad-verdicts tcp=open"),
        "flow R: rmule's own diagnostics must say TCP is open:\n{verdict}",
    );
}

/// **Flow R — `kad-required-check`, the TCP check.** rmule's TCP verdict, read
/// from its own diagnostics, reaches Open under Required: every helper's
/// obfuscated dial-back authenticates against the user hash rmule's `0x53`
/// named. Says nothing of the UDP check.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn kad_required_tcp_check_reaches_open() {
    if !bench_enabled("R") {
        return;
    }
    assert_tcp_open(&run_flow_r("required"));
}

/// **Flow R's control** — the same swarm under `requested`. If its TCP check
/// does not reach Open either, the flow is wrong, not rmule's `Required` handling.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn kad_requested_control_tcp_check_reaches_open() {
    if !bench_enabled("R") {
        return;
    }
    assert_tcp_open(&run_flow_r("requested"));
}
