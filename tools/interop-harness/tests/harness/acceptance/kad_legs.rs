//! The two Kad legs of flow K's `kad-firewalled-buddy` subcommand.

use super::{bench_enabled, read_string, run_flow};
use std::path::Path;

/// **Kad firewall self-check — requester leg (ADR-0058).** The
/// mirror of flow K's responder direction: rmule joins a NON-firewalled stock
/// aMule with its OWN firewall self-check armed, emits its `0x53`
/// `KADEMLIA_FIREWALLED2_REQ`, and captures the aMule's `0x58`
/// `KADEMLIA_FIREWALLED_RES` reply (which pinned the low-octet-first observed-IP
/// byte order). PASS = rmule emitted its check and the aMule answered; the
/// fixture + decode test promote the capture (ADR-0045). (Adopts
/// `kad-firewalled-buddy --requester-capture`.)
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn flow_kad_firewall_selfcheck() {
    if !bench_enabled("firewall-selfcheck") {
        return;
    }
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let dockerfile = repo_root.join("tools/interop-harness/images/rmule-node/Dockerfile");
    let (repo_root, dockerfile) = (
        repo_root.to_str().unwrap().to_string(),
        dockerfile.to_str().unwrap().to_string(),
    );
    let run_dir = run_flow(
        "kad-firewalled-buddy",
        &[
            "--skip-build",
            "--requester-capture",
            "--timeout",
            "300",
            "--window",
            "180",
            "--rmule-dockerfile",
            &dockerfile,
            "--rmule-build-context",
            &repo_root,
        ],
    );
    let verdict = read_string(&run_dir, "kad/kad-firewall-selfcheck-verdict.toml");
    // OBSERVED accepted: one-sided emit gate — counterparty silence degrades
    // the artifact, it does not red the suite (see flow K's note).
    assert!(
        verdict.contains("verdict = \"PASS\"") || verdict.contains("verdict = \"OBSERVED\""),
        "requester leg: rmule must emit its own 0x53 check toward the open aMule \
         (PASS on a captured 0x58 reply, else OBSERVED):\n{verdict}",
    );
}

/// **Kad buddy recruit — recruiter leg (ADR-0061).** rmule joins an
/// open stock aMule with its OWN buddy recruiter armed, emits its `0x51`
/// `KADEMLIA_FINDBUDDY_REQ` toward it, and captures any `0x5A`
/// `KADEMLIA_FINDBUDDY_RES` the aMule answers. PASS = rmule emitted its recruit
/// and the aMule answered; OBSERVED = the recruit emitted but no `0x5A` landed
/// (the documented reachability-convergence wall — a lone open aMule that cannot
/// self-verify open silently refuses to serve as a buddy). (Adopts
/// `kad-firewalled-buddy --recruit-buddy`.)
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn flow_kad_buddy_recruit() {
    if !bench_enabled("buddy-recruit") {
        return;
    }
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let dockerfile = repo_root.join("tools/interop-harness/images/rmule-node/Dockerfile");
    let (repo_root, dockerfile) = (
        repo_root.to_str().unwrap().to_string(),
        dockerfile.to_str().unwrap().to_string(),
    );
    let run_dir = run_flow(
        "kad-firewalled-buddy",
        &[
            "--skip-build",
            "--recruit-buddy",
            "--timeout",
            "300",
            "--window",
            "180",
            "--rmule-dockerfile",
            &dockerfile,
            "--rmule-build-context",
            &repo_root,
        ],
    );
    let verdict = read_string(&run_dir, "kad/kad-buddy-recruit-verdict.toml");
    // OBSERVED accepted: one-sided emit gate — counterparty silence degrades
    // the artifact, it does not red the suite (see flow K's note).
    assert!(
        verdict.contains("verdict = \"PASS\"") || verdict.contains("verdict = \"OBSERVED\""),
        "recruit leg: rmule must emit its own 0x51 toward the open aMule \
         (PASS on a captured 0x5A reply, else OBSERVED):\n{verdict}",
    );
}
