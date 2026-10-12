//! The Low-ID callback re-ask (`peer-lowid-callback-reask`): a queued rmule
//! pings a called-back Low-ID stock aMule at the address it called in from,
//! `FILEREASKTIME` less 20 s after its rank; the sharer answers with its rank,
//! so no second `OP_CALLBACKREQUEST` comes, and rmule never dials the sharer.
//!
//! A run waits out rmule's 1300 s reask period, so the wrapper is meant to
//! score a retained run: drive the subcommand once in the foreground, then
//! point `RMULE_BENCH_VERDICT_DIR` at its run dir (or at
//! `peer-lowid-callback-reask-score`'s output for an archived one).

use super::{bench_enabled, read_string, run_flow};

/// Every claim the flow's verdict makes.
const CLAIMS: [&str; 9] = [
    "the-sharer-logged-in-low-id",
    "the-server-relayed-rmules-callback",
    "the-sharer-dialed-rmule-back",
    "the-sharer-queued-rmule-on-the-callback-link",
    "the-sharer-answered-rmules-source-ask",
    "rmule-pinged-the-called-back-sharer-at-the-reask-window",
    "the-sharer-answered-the-ping-with-its-rank",
    "rmule-asked-for-no-second-callback-while-its-standing-was-fresh",
    "rmule-dialed-no-endpoint-of-the-sharer",
];

#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1; ~30 min, score a retained run with RMULE_BENCH_VERDICT_DIR"]
fn peer_lowid_callback_reask() {
    if !bench_enabled("lowid-callback-reask") {
        return;
    }
    let run_dir = run_flow("peer-lowid-callback-reask", &[]);
    let verdict = read_string(&run_dir, "peer-lowid-callback-reask-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "every claim must hold:\n{verdict}",
    );
    for claim in CLAIMS {
        assert!(
            verdict.contains(&format!("name = \"{claim}\"")),
            "{claim} missing from the verdict:\n{verdict}",
        );
    }
}
