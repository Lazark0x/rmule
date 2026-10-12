//! A Kad TCP check through a link rmule dialed (flow S): a Core downloading
//! from a stock aMule helper asks that helper for its TCP check, and the helper
//! acks on the live link rather than connecting back. The gate is the chain:
//! the helper's `0xA8` on the dialed link, no connect-back from it, and
//! rmule's trace showing the ack reach its Kad node.

use std::path::Path;

use rmule_interop_harness::flow::DialedLinkVerdict;

use super::{bench_enabled, bench_run_root, read_string, run_flow};

/// The debug build of the pinned aMule body, whose trail names the ack it sent.
const AMULE_DEBUG_IMAGE: &str = "rmule/interop-amule-debug:local";

/// **Flow S — `kad-dialed-link`.**
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn kad_tcp_check_concludes_through_the_dialed_link() {
    if !bench_enabled("S") {
        return;
    }
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let images = repo_root.join("tools/interop-harness/images");
    let at = |relative: &str| images.join(relative).to_str().unwrap().to_string();
    let (amule, capture) = (at("amule"), at("capture"));
    let amule_image =
        std::env::var("RMULE_BENCH_AMULE_IMAGE").unwrap_or_else(|_| AMULE_DEBUG_IMAGE.to_owned());
    let mut args = vec![
        "--skip-build",
        "--amule-image",
        &amule_image,
        "--amule-build-context",
        &amule,
        "--capture-build-context",
        &capture,
    ];
    // The operator's own tag, when one is set: `:local` is shared by every
    // worktree on the bench and may be rebuilt from another tip mid-run.
    let tools_image = std::env::var("RMULE_BENCH_RMULE_TOOLS_IMAGE").ok();
    if let Some(image) = &tools_image {
        args.extend_from_slice(&["--rmule-tools-image", image]);
    }
    let run_root = bench_run_root();
    if let Some(root) = &run_root {
        args.extend_from_slice(&["--run-root", root]);
    }
    let run_dir = run_flow("kad-dialed-link", &args);
    let verdict = read_string(&run_dir, "kad/kad-dialed-link-verdict.toml");
    assert_eq!(
        DialedLinkVerdict::from_verdict_file(&verdict),
        Some(DialedLinkVerdict::Pass),
        "flow S: the ack must ride the dialed link and be acted on:\n{verdict}",
    );
}
