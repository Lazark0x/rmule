//! The buddy-callback row against a live aMule: ADR-0061
//! route 4 driven by a real download, with the firewalled target a stock
//! aMule 2.3.3 on the debug image. Its topology is flow M's (`kad-core-buddy`),
//! so the wrappers drive that subcommand with the third party switched on —
//! an rmule downloader (`--callback-downloader`) or a second stock aMule
//! (`--amule-requester`).

use std::path::Path;

use super::{bench_enabled, bench_run_root, read_string, run_flow};

/// The debug build of the pinned aMule body. Pre-built by hand —
/// `--skip-build` below is load-bearing, since the harness's own build would
/// retag a release image under this name.
const AMULE_DEBUG_IMAGE: &str = "rmule/interop-amule-debug:local";

/// **`kad-core-buddy --callback-downloader`.** A High-ID rmule
/// downloader handed only the ed2k link finds the firewalled aMule's type-3
/// buddy row over Kad, sends the plaintext `0x52` to the rmule buddy the row
/// names, the buddy relays `OP_CALLBACK` over the link aMule holds, and aMule
/// dials the downloader back and serves the file byte-equal. Every claim is
/// asserted by name: a completed file with no relayed callback behind it would
/// be some other road's.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn kad_buddy_callback_against_amule() {
    if !bench_enabled("kad-core-buddy --callback-downloader") {
        return;
    }
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let images = repo_root.join("tools/interop-harness/images");
    let at = |relative: &str| images.join(relative).to_str().unwrap().to_string();
    let (amule, capture) = (at("amule"), at("capture"));
    // The operator's own tag of the same debug build, when one is set.
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
        "--publish-source",
        "--mesh-members",
        "3",
        "--callback-downloader",
        "--callback-walk",
        // One part, on purpose: a one-part file's connect-time source ask
        // once went out as a standalone 19-byte `OP_REQUESTSOURCES2`, which
        // aMule 2.3.3's standalone arm refuses (`size != 16`) and disconnects
        // on (run `1790153981`). It now rides aMule's own one-part bundle
        // And this size keeps that road under test.
        "--file-size",
        "4194304",
        // aMule's recruit lands near +10 min, its first ping (and with it the
        // buddy status the publish waits on) ten minutes later; the gate this
        // bounds usually opens near +21 min.
        "--window",
        "1800",
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
    let run_dir = run_flow("kad-core-buddy", &args);
    let verdict = read_string(&run_dir, "kad/kad-buddy-callback-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "kad-core-buddy --callback-downloader: every claim of the buddy callback must hold:\n{verdict}",
    );
    for claim in [
        "the-firewalled-amule-published-its-buddy-row-to-the-placed-storer",
        "the-download-routed-the-buddy-callback-from-the-kad-row",
        "the-0x52-left-the-downloader-for-the-buddy",
        "the-0x52-reached-the-rmule-buddy",
        "the-buddy-relayed-op-callback-to-amule-on-the-held-link",
        "amule-dialed-back-the-downloaders-listener",
        "amule-said-hello-on-the-dial-back",
        "the-file-completed-byte-equal-over-the-dial-back",
    ] {
        assert!(
            verdict.contains(&format!("\"{claim}\" = true")),
            "kad-core-buddy --callback-downloader: {claim} must hold:\n{verdict}",
        );
    }
    // The ID-only fold-in: a Callback Walk's obfuscated `0x52` reaches
    // aMule, and aMule relays it over the buddy link it holds.
    let walk = read_string(&run_dir, "kad/kad-buddy-callback-walk-verdict.toml");
    assert!(
        walk.contains("verdict = \"PASS\""),
        "kad-core-buddy --callback-walk: every claim must hold:\n{walk}",
    );
    for claim in [
        "the-walk-asked-a-contact-within-tolerance",
        "the-walk-0x52-reached-amule-obfuscated",
        "amule-relayed-op-callback-over-its-buddy-link",
        "amules-relay-names-the-walker-and-echoes-the-walk",
    ] {
        assert!(
            walk.contains(&format!("\"{claim}\" = true")),
            "kad-core-buddy --callback-walk: {claim} must hold:\n{walk}",
        );
    }
}

/// **`kad-core-buddy --amule-requester`.**
/// `kad-core-buddy --callback-downloader`'s topology with the third party a
/// second stock aMule, handed only the ed2k link: it reads Kad-open, its `FILE`
/// search draws the firewalled aMule's type-3 row from the placed rmule storer,
/// and it sends **its own** `0x52` to the rmule buddy the row names, which
/// relays `OP_CALLBACK` to the firewalled aMule over the held link. The field
/// claims pin both bodies to the row and the link; the firewalled aMule's
/// dial-back is the relay's consumption.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn kad_buddy_amule_requester() {
    if !bench_enabled("kad-core-buddy --amule-requester") {
        return;
    }
    let verdict = run_amule_requester(&[]);
    assert_claims(
        "kad-core-buddy --amule-requester",
        &verdict,
        &[
            "the-amule-requester-read-kad-open-before-the-link",
            "the-placed-storer-answered-the-requesters-source-search",
            "the-0x52-left-the-amule-requester-for-the-buddy",
            "the-0x52-reached-the-rmule-buddy",
            "the-0x52-names-the-rows-buddy-the-links-file-and-the-requesters-port",
            "the-buddy-relayed-op-callback-to-the-firewalled-amule",
            "the-0x99-repeats-the-0x52-and-names-the-requester-host-order",
            "the-firewalled-amule-dialed-the-requester-back",
        ],
    );
}

/// **`kad-core-buddy --amule-requester --omit-buddy-endpoint`.**
/// `kad-core-buddy --amule-requester` with the row ID-only: an rmule publisher names the
/// buddy by `TAG_BUDDYHASH` alone, so the stock aMule requester cannot address
/// it and takes aMule's `FINDSOURCE` road — a Kad walk toward the buddy ID and
/// the `0x52` sent to the rmule buddy that answers at distance 0. The relay
/// and dial-back are recorded, not asserted: the firewalled aMule shares
/// nothing under this variant.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn kad_buddy_amule_requester_id_only_row() {
    if !bench_enabled("kad-core-buddy --amule-requester --omit-buddy-endpoint") {
        return;
    }
    let verdict = run_amule_requester(&["--omit-buddy-endpoint"]);
    assert_claims(
        "kad-core-buddy --amule-requester --omit-buddy-endpoint",
        &verdict,
        &[
            "the-amule-requester-read-kad-open-before-the-link",
            "the-placed-storer-answered-the-requesters-source-search",
            "the-0x52-left-the-amule-requester-for-the-buddy",
            "the-0x52-reached-the-rmule-buddy",
            "the-0x52-names-the-rows-buddy-the-links-file-and-the-requesters-port",
            "the-storers-row-names-the-buddy-by-id-alone",
            "the-requester-searched-for-the-buddy-not-its-endpoint",
            "the-requester-walked-toward-the-buddy-id",
        ],
    );
}

/// **`kad-core-buddy --amule-requester --omit-buddy-endpoint --requester-kad-crypt`.**
/// The requester runs aMule's crypt layer, so its `FINDSOURCE` `0x52`
/// leaves keyed on the buddy's Kad ID (`Search.cpp:1103-1110`, kno
/// `ab483654`); the rmule buddy must decrypt it under its own ID and
/// relay it.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn kad_buddy_amule_requester_keyed_findsource() {
    if !bench_enabled(
        "kad-core-buddy --amule-requester --omit-buddy-endpoint --requester-kad-crypt",
    ) {
        return;
    }
    let verdict = run_amule_requester(&["--omit-buddy-endpoint", "--requester-kad-crypt"]);
    assert_claims(
        "kad-core-buddy --amule-requester --omit-buddy-endpoint --requester-kad-crypt",
        &verdict,
        &[
            "the-amule-requester-read-kad-open-before-the-link",
            "the-placed-storer-answered-the-requesters-source-search",
            "the-0x52-left-the-amule-requester-for-the-buddy",
            "the-0x52-reached-the-rmule-buddy",
            "the-0x52-names-the-rows-buddy-the-links-file-and-the-requesters-port",
            "the-storers-row-names-the-buddy-by-id-alone",
            "the-requester-searched-for-the-buddy-not-its-endpoint",
            "the-requester-walked-toward-the-buddy-id",
            "the-0x52-reached-the-buddy-keyed-on-its-kad-id",
            "the-rmule-buddy-decoded-the-keyed-0x52-and-relayed-it",
        ],
    );
}

/// **`kad-core-buddy --amule-requester --omit-buddy-endpoint --findsource-transfer`.**
/// The `FINDSOURCE` road carried to a file: the firewalled aMule shares it
/// under a pinned user hash, the ID-only row goes out under that hash after
/// aMule's own row, and the requester adopts the ID-only one — so the
/// relayed `0x99` ends in a dial-back from a body that serves the file.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn kad_buddy_amule_requester_findsource_transfer() {
    if !bench_enabled(
        "kad-core-buddy --amule-requester --omit-buddy-endpoint --findsource-transfer",
    ) {
        return;
    }
    let verdict = run_amule_requester(&["--omit-buddy-endpoint", "--findsource-transfer"]);
    assert_claims(
        "kad-core-buddy --amule-requester --omit-buddy-endpoint --findsource-transfer",
        &verdict,
        &[
            "the-storers-row-names-the-buddy-by-id-alone",
            "the-requester-searched-for-the-buddy-not-its-endpoint",
            "the-requester-walked-toward-the-buddy-id",
            "the-buddy-relayed-op-callback-to-the-firewalled-amule",
            "the-0x99-repeats-the-0x52-and-names-the-requester-host-order",
            "the-firewalled-amule-dialed-the-requester-back",
            "the-adopted-row-carries-the-firewalled-amules-user-hash",
            "the-requester-completed-the-file-byte-equal",
        ],
    );
}

/// Run flow M with the stock aMule requester (plus `extra` flags) and return
/// its verdict file.
fn run_amule_requester(extra: &[&str]) -> String {
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
        "--publish-source",
        "--mesh-members",
        "3",
        "--amule-requester",
        "--file-size",
        "4194304",
        "--window",
        "1800",
    ];
    args.extend_from_slice(extra);
    let tools_image = std::env::var("RMULE_BENCH_RMULE_TOOLS_IMAGE").ok();
    if let Some(image) = &tools_image {
        args.extend_from_slice(&["--rmule-tools-image", image]);
    }
    let run_root = bench_run_root();
    if let Some(root) = &run_root {
        args.extend_from_slice(&["--run-root", root]);
    }
    let run_dir = run_flow("kad-core-buddy", &args);
    read_string(&run_dir, "kad/kad-amule-requester-verdict.toml")
}

/// The verdict passed and every named claim holds.
fn assert_claims(row: &str, verdict: &str, claims: &[&str]) {
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "{row}: every claim of the aMule requester must hold:\n{verdict}",
    );
    for claim in claims {
        assert!(
            verdict.contains(&format!("\"{claim}\" = true")),
            "{row}: {claim} must hold:\n{verdict}",
        );
    }
}
