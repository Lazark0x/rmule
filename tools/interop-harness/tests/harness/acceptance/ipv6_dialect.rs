//! ADR-0092's **Bench Tier** wrappers for the IPv6-dialect flows
//! (ADR-0087).
//!
//! Each wrapper asserts the *label its row is supposed to reach* rather than
//! merely "not FAIL": `PASS` where the pins this repo carries can settle the
//! row, `OBSERVED` where a claim is blocked and names what blocks it. A run
//! that turned an `OBSERVED` into a `PASS` would mean a blocked claim had been
//! quietly dropped, which is the one regression a verdict file cannot show on
//! its own.

use std::path::{Path, PathBuf};

use super::{bench_enabled, bench_run_root, read_string, run_flow};

/// Drive one IPv6-dialect flow through its CLI subcommand with every build context
/// resolved absolutely, and hand back its run dir.
fn run_ipv6_dialect_flow(flow: &str) -> PathBuf {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let dockerfile = repo_root.join("tools/interop-harness/images/rmule-tools/Dockerfile");
    let amule_kno = repo_root.join("tools/interop-harness/images/amule-kno");
    let emuleqt = repo_root.join("tools/interop-harness/images/emuleqt");
    let amule = repo_root.join("tools/interop-harness/images/amule");
    let capture = repo_root.join("tools/interop-harness/images/capture");
    let (repo_root, dockerfile, amule_kno, emuleqt, amule, capture) = (
        repo_root.to_str().unwrap().to_string(),
        dockerfile.to_str().unwrap().to_string(),
        amule_kno.to_str().unwrap().to_string(),
        emuleqt.to_str().unwrap().to_string(),
        amule.to_str().unwrap().to_string(),
        capture.to_str().unwrap().to_string(),
    );
    let mut args = vec![
        flow,
        "--skip-build",
        "--timeout",
        "180",
        "--amule-kno-build-context",
        &amule_kno,
        "--emuleqt-build-context",
        &emuleqt,
        "--amule-build-context",
        &amule,
        "--capture-build-context",
        &capture,
        "--rmule-tools-dockerfile",
        &dockerfile,
        "--rmule-tools-build-context",
        &repo_root,
    ];
    // The operator's own driver tag, when one is set: `:local` is shared by
    // every worktree on the bench and may be rebuilt from another tip mid-run.
    let tools_image = std::env::var("RMULE_BENCH_RMULE_TOOLS_IMAGE").ok();
    if let Some(image) = &tools_image {
        args.extend_from_slice(&["--rmule-tools-image", image]);
    }
    // Same reason for kno's runtime image: its entrypoint is the recipe under
    // test in `ipv6-kad-tags`.
    let kno_image = std::env::var("RMULE_BENCH_AMULE_KNO_IMAGE").ok();
    if let Some(image) = &kno_image {
        args.extend_from_slice(&["--amule-kno-image", image]);
    }
    // And for emule-qt's runtime image, whose entrypoint drives the `kad-node`
    // scenario in `ipv6-kad-tags`.
    let emuleqt_image = std::env::var("RMULE_BENCH_EMULEQT_IMAGE").ok();
    if let Some(image) = &emuleqt_image {
        args.extend_from_slice(&["--emuleqt-image", image]);
    }
    // And for the stock aMule `ipv6-extsx-core` asks: any 2.3.3 build serves.
    let amule_image = std::env::var("RMULE_BENCH_AMULE_IMAGE").ok();
    if let Some(image) = &amule_image {
        args.extend_from_slice(&["--amule-image", image]);
    }
    let run_root = bench_run_root();
    if let Some(root) = &run_root {
        args.extend_from_slice(&["--run-root", root]);
    }
    run_flow("ipv6-dialect", &args)
}

/// **`ipv6-hello-tags`.** The `0xAA` **Static Capability Claim** and the
/// `CT_MOD_IP_V6` round trip off two independent oracles, plus the
/// legacy-safety leg: stock aMule 2.3.3 receives the same hello and ignores
/// every new tag, with the three legacy hazards (an unknown tag type, a new
/// TCP protocol byte, a hello suffix) asserted absent.
///
/// The `amule-kno` half is an **Exemption** and is asserted as one: the fork
/// counts `CT_MOD_IP_V6` and never writes it, so its answer is malformed for
/// every strict reader and only emule-qt can carry the tag row. A run that
/// stopped naming that claim would mean the defect had been quietly dropped.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn ipv6_hello_tags() {
    if !bench_enabled("ipv6-hello-tags") {
        return;
    }
    let run_dir = run_ipv6_dialect_flow("ipv6-hello-tags");
    let verdict = read_string(&run_dir, "ipv6-hello-tags-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "ipv6-hello-tags: every driveable claim must hold:\n{verdict}",
    );
    for expected in [
        "emuleqt-names-its-own-ipv6",
        "emuleqt-answer-is-usable-by-a-strict-reader",
        "amule-kno-claims-0xaa-ipv6",
        "amule-kno-counts-a-tag-it-does-not-write",
        "legacy-answered-the-dialect-hello",
        "legacy-ignored-the-dialect-tags",
        "legacy-session-held-on-0xe3",
    ] {
        assert!(
            verdict.contains(expected),
            "ipv6-hello-tags: {expected} missing from the verdict:\n{verdict}",
        );
    }
}

/// **`ipv6-udp-key`.** The 35-byte client-UDP key (ADR-0087): emule-qt
/// answers an obfuscated `OP_REASKFILEPING` that arrived over IPv6, which it
/// could only have read by deriving the key from our v6 source address at that
/// width. kno's documented refusal of the same datagram is recorded beside it.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn ipv6_udp_key() {
    if !bench_enabled("ipv6-udp-key") {
        return;
    }
    let run_dir = run_ipv6_dialect_flow("ipv6-udp-key");
    let verdict = read_string(&run_dir, "ipv6-udp-key-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "ipv6-udp-key: the 35-byte key row must hold:\n{verdict}",
    );
    for expected in [
        "key-material-is-35-bytes-both-ways",
        "emuleqt-parsed-our-35-byte-keyed-v6-datagram",
        "reply-is-op-filenotfound",
        "amule-kno-does-not-decrypt-a-native-v6-datagram",
    ] {
        assert!(
            verdict.contains(expected),
            "ipv6-udp-key: {expected} missing from the verdict:\n{verdict}",
        );
    }
}

/// **`ipv6-direct-dial-lowid`.** Rung 0 of the ADR-0061 route tree: a
/// Low-ID peer that named an IPv6 is dialled directly while this node holds
/// one, and falls back to the server callback when it binds IPv4 only.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn ipv6_direct_dial_lowid() {
    if !bench_enabled("ipv6-direct-dial-lowid") {
        return;
    }
    let run_dir = run_ipv6_dialect_flow("ipv6-direct-dial-lowid");
    let verdict = read_string(&run_dir, "ipv6-direct-dial-lowid-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "ipv6-direct-dial-lowid: rung 0 and its control must both hold:\n{verdict}",
    );
    for expected in [
        "rung-zero-outranks-every-callback",
        "control-without-our-ipv6-falls-back-to-the-server-callback",
        "the-counterparty-logged-the-inbound-ipv6-connection",
    ] {
        assert!(
            verdict.contains(expected),
            "ipv6-direct-dial-lowid: {expected} missing from the verdict:\n{verdict}",
        );
    }
}

/// **`ipv6-extsx`.** `PASS`: emule-qt's claim bits, and the carrier
/// half — a queued requester that named its IPv6 in its hello holds a slot on
/// emule-qt's shared file, and emule-qt's answer to a second requester's
/// bundled source ask is an ExtSX record carrying that IPv6.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn ipv6_extsx() {
    if !bench_enabled("ipv6-extsx") {
        return;
    }
    let run_dir = run_ipv6_dialect_flow("ipv6-extsx");
    let verdict = read_string(&run_dir, "ipv6-extsx-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "ipv6-extsx: emule-qt must answer with an ExtSX record carrying the queued IPv6:\n{verdict}",
    );
    for expected in [
        "emuleqt-claims-extsx",
        "emuleqt-claims-extsx-skiptags",
        "a-queued-requester-named-its-ipv6-and-holds-a-slot",
        "emuleqt-answered-the-bundled-source-ask",
        "an-extsx-record-carrying-a-v6-source",
        "rmule-surfaces-the-extsx-ipv6-source",
    ] {
        assert!(
            verdict.contains(expected),
            "ipv6-extsx: {expected} missing from the verdict:\n{verdict}",
        );
    }
}

/// **`ipv6-extsx-kno`.** `PASS` on a **Documented Absence**: the same
/// source ask put to kno's aMule, ADR-0087's second ExtSX oracle. kno claims
/// no `EXTXS` and answers with a classic record naming the dual-stack queued
/// requester by its IPv4 alone — the IPv6 its hello named has nowhere to go.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn ipv6_extsx_kno() {
    if !bench_enabled("ipv6-extsx-kno") {
        return;
    }
    let run_dir = run_ipv6_dialect_flow("ipv6-extsx-kno");
    let verdict = read_string(&run_dir, "ipv6-extsx-kno-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "ipv6-extsx-kno: kno must answer, and without an ExtSX record:\n{verdict}",
    );
    for expected in [
        "amule-kno-claims-no-extsx",
        "a-dual-stack-requester-named-its-ipv6-and-holds-a-slot",
        "amule-kno-answered-the-bundled-source-ask",
        "amule-kno-writes-no-extsx-record",
        "rmule-surfaces-the-classic-source",
    ] {
        assert!(
            verdict.contains(expected),
            "ipv6-extsx-kno: {expected} missing from the verdict:\n{verdict}",
        );
    }
}

/// **`ipv6-extsx-core`.** `PASS`: rmule's production downloader,
/// finding stock aMule 2.3.3 through `ed2ksrv`, opens a complete file with a
/// bundle whose `0x58` sub carries its part status, and aMule
/// answers with a source record naming the queued requester — the answer a
/// v0 claim never drew.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn ipv6_extsx_core() {
    if !bench_enabled("ipv6-extsx-core") {
        return;
    }
    let run_dir = run_ipv6_dialect_flow("ipv6-extsx-core");
    let verdict = read_string(&run_dir, "ipv6-extsx-core-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "ipv6-extsx-core: stock aMule must answer rmule's downloader:\n{verdict}",
    );
    for expected in [
        "a-v0-requester-holds-a-slot-on-stock-amule",
        "rmule-core-asks-with-its-part-status",
        "stock-amule-answers-rmule-core-for-a-complete-file",
        "the-answer-names-the-queued-requester",
        "rmule-core-decodes-the-answer",
    ] {
        assert!(
            verdict.contains(expected),
            "ipv6-extsx-core: {expected} missing from the verdict:\n{verdict}",
        );
    }
}

/// **`ipv6-extsx-emit`.** `PASS`: the roles swapped. rmule serves the
/// file and holds a requester queued over IPv6 with no server session; emule-qt
/// downloads it, asks rmule for sources, reads rmule's ExtSX record (Low-ID
/// placeholder `1`, `CT_MOD_IP_V6`) and dials the IPv6 it names. A second,
/// dual-stack requester queued over IPv4 goes out as one record with both
/// addresses, which emule-qt admits as a High ID and dials over IPv4.
/// A third requester that says it holds no part is left out of that answer:
/// rmule's needed-part filter reads emule-qt's own status. A fourth
/// requester names an IPv6 no bench network routes, and an rmule download
/// whose dial of that half fails dials the source's IPv4 next.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn ipv6_extsx_emit() {
    if !bench_enabled("ipv6-extsx-emit") {
        return;
    }
    let run_dir = run_ipv6_dialect_flow("ipv6-extsx-emit");
    let verdict = read_string(&run_dir, "ipv6-extsx-emit-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "ipv6-extsx-emit: emule-qt must admit rmule's ExtSX records and dial them:\n{verdict}",
    );
    for expected in [
        "a-queued-requester-named-its-ipv6-and-holds-a-slot-on-rmule",
        "rmule-answered-emuleqts-source-ask",
        "emuleqt-dialled-the-extsx-ipv6-source",
        "a-dual-stack-requester-holds-a-place-on-rmule-over-ipv4",
        "rmule-wrote-the-dual-stack-source-with-both-addresses",
        "emuleqt-admitted-the-dual-stack-record-and-dialled-its-ipv4-half",
        "a-requester-holding-no-part-holds-a-place-on-rmule",
        "rmule-left-the-holds-nothing-source-out-of-emuleqts-answer",
        "a-dual-stack-requester-with-an-unroutable-ipv6-holds-a-place-on-rmule",
        "a-failed-ipv6-dial-fell-to-the-ipv4-half",
    ] {
        assert!(
            verdict.contains(expected),
            "ipv6-extsx-emit: {expected} missing from the verdict:\n{verdict}",
        );
    }
}

/// **`ipv6-download-rung0`.** A real rmule download takes rung 0
/// Emule-qt describes a Low-ID requester that named its IPv6 and our
/// server, and rmule's download puts a worker on that IPv6 half before its
/// server callback — and, the dial refused, falls to that callback.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn ipv6_download_rung0() {
    if !bench_enabled("ipv6-download-rung0") {
        return;
    }
    let run_dir = run_ipv6_dialect_flow("ipv6-download-rung0");
    let verdict = read_string(&run_dir, "ipv6-download-rung0-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "ipv6-download-rung0: rmule's download must dial the Low-ID source's IPv6 half:\n{verdict}",
    );
    for expected in [
        "a-low-id-requester-named-its-ipv6-and-server-and-holds-a-slot-on-emuleqt",
        "rmule-download-dialled-the-low-id-sources-ipv6-half-first",
        "rung-0-fell-through-to-the-callback-road",
    ] {
        assert!(
            verdict.contains(expected),
            "ipv6-download-rung0: {expected} missing from the verdict:\n{verdict}",
        );
    }
}

/// **`ipv6-server-sentinel`.** A **Documented Absence** naming the
/// missing pin, in the verdict's own `note`. No pinnable `ed2ksrv` build
/// speaks the dialect yet, so no server can emit a **Sentinel
/// Source** to a capable session. The flow lifts itself with no code change the
/// moment `server_claims_ipv6` reads true.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn ipv6_server_sentinel() {
    if !bench_enabled("ipv6-server-sentinel") {
        return;
    }
    let run_dir = run_ipv6_dialect_flow("ipv6-server-sentinel");
    let verdict = read_string(&run_dir, "ipv6-server-sentinel-verdict.toml");
    assert!(
        verdict.contains("verdict = \"OBSERVED\""),
        "ipv6-server-sentinel: the row must stay a documented absence until a pinnable ed2k-server build carries IPv6:\n{verdict}",
    );
    for expected in ["no pinnable ed2k-server build", "note = "] {
        assert!(
            verdict.contains(expected),
            "ipv6-server-sentinel: {expected} missing from the verdict:\n{verdict}",
        );
    }
}

/// **`ipv6-kad-tags`.** Both directions against kno's aMule, placed in
/// a private Kad mesh by **Seeded Bootstrap**: kno stores rmule's `ip6` and
/// hands it back in its `0x3B`, and kno — IPv6 verified by an inbound dial,
/// High ID from `ed2ksrv` — publishes its own `ip6`, which rmule reads and
/// indexes. A firewalled rmule publishes the buddy row closed with `bi6`,
/// kno returns it verbatim, rmule reads it back into the row's buddy contact,
/// and kno's own publish carries none. rmule then dials kno's
/// file off that row alone, in the family the Dial Chooser picked; the
/// transfer stops at kno's over-counted hello answer, measured as that stop.
/// emule-qt, a Kad node sharing a third file, publishes its `ip6` in
/// lower-case to a rmule storer, and rmule downloads that file off the row the
/// storer re-serves, over IPv6, byte-equal. Seventeen claims.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn ipv6_kad_tags() {
    if !bench_enabled("ipv6-kad-tags") {
        return;
    }
    let run_dir = run_ipv6_dialect_flow("ipv6-kad-tags");
    let verdict = read_string(&run_dir, "ipv6-kad-tags-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "ipv6-kad-tags: both directions must hold:\n{verdict}",
    );
    for expected in [
        "amule-kno-verified-its-ipv6-on-an-inbound-v6-dial",
        "amule-kno-stores-and-returns-the-ip6-tag",
        "a-search-result-row-parsed-back-with-its-ipv6-endpoint",
        "amule-kno-publishes-its-own-ip6-tag",
        "rmule-reads-amule-knos-ip6-and-indexes-the-row",
        "amule-kno-stores-and-returns-the-bi6-tag",
        "a-buddy-row-parsed-back-with-its-bi6",
        "amule-kno-writes-no-bi6",
        "rmule-dialled-knos-kad-row-in-the-family-the-dial-chooser-picked",
        "amule-kno-over-counted-hello-answer-ends-the-download",
        "amule-kno-searches-rmules-storer-for-the-bi6-row",
        "rmule-storer-re-serves-the-stored-bi6",
        "amule-kno-calls-back-through-the-rows-ipv4-buddy-trio",
        "amule-kno-sends-nothing-to-the-bi6-address",
        "emule-qt-published-a-lower-case-ip6",
        "rmule-re-served-emule-qts-ip6-and-dialled-it",
        "the-file-arrived-byte-equal-off-emule-qts-kad-row",
    ] {
        assert!(
            verdict.contains(expected),
            "ipv6-kad-tags: {expected} missing from the verdict:\n{verdict}",
        );
    }
}

/// **`peer-hello-surface`.** Each bench client's own `OP_HELLOANSWER`
/// and `OP_HELLO`, its reaction to rmule's hello (which ends in
/// `CT_MOD_VERSION`), Secure User Identification and a part each
/// way; and one rmule naming another. Borrows the IPv6-dialect bench's bodies.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn peer_hello_surface() {
    if !bench_enabled("peer-hello-surface") {
        return;
    }
    let run_dir = run_ipv6_dialect_flow("peer-hello-surface");
    let text = read_string(&run_dir, "peer-hello-surface-verdict.toml");
    let verdict: toml::Table = toml::from_str(&text)
        .unwrap_or_else(|error| panic!("peer-hello-surface: the verdict does not parse: {error}"));
    // The three `log-names-rmule` rows are blocked (no client's own log is
    // reachable from the bench), so the label is `OBSERVED`; a `PASS` would
    // mean a blocked claim had been quietly dropped.
    assert_eq!(
        verdict.get("verdict").and_then(toml::Value::as_str),
        Some("OBSERVED"),
        "peer-hello-surface: the flow's label:\n{text}",
    );
    let outcome = |name: &str| {
        verdict
            .get("claim")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .find(|row| row.get("name").and_then(toml::Value::as_str) == Some(name))
            .and_then(|row| row.get("outcome"))
            .and_then(toml::Value::as_str)
    };
    for client in ["amule-233", "amule-kno", "emuleqt"] {
        for claim in [
            "hello-read-by-the-strict-reader",
            "took-rmule-for-a-mule",
            "held-the-link-after-rmule-named-itself",
            "sends-its-op-hello-to-rmule",
            "runs-secure-identification-with-rmule",
            "pulls-a-part-from-rmule",
            "serves-rmule-a-part",
            "sends-rmule-no-emule-info",
        ] {
            let name = format!("{client}-{claim}");
            assert_eq!(
                outcome(&name),
                Some("held"),
                "peer-hello-surface: {name} must be a held row:\n{text}",
            );
        }
        let name = format!("{client}-log-names-rmule");
        assert_eq!(
            outcome(&name),
            Some("blocked"),
            "peer-hello-surface: {name} must be the blocked row:\n{text}",
        );
    }
    for claim in [
        "serving-rmule-names-the-downloading-rmule",
        "downloading-rmule-names-the-serving-rmule",
        "amule-kno-dials-rmule-with-an-over-counted-hello",
        "rmule-refuses-knos-over-counted-hello-inbound",
    ] {
        assert_eq!(
            outcome(claim),
            Some("held"),
            "peer-hello-surface: {claim} must be a held row:\n{text}",
        );
    }
}
