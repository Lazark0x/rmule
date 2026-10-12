//! ADR-0092's **Bench Tier** wrappers for the NAT-traversal flows
//! (ADR-0091).
//!
//! Each wrapper asserts the *label its row is supposed to reach* **and every
//! decisive claim by name**. Asserting the label alone would be reachable by
//! dropping a claim: a flow that stopped probing CAPS altogether would still
//! read `PASS`, and the whole point of the CAPS row is that its zero is a
//! measured one.

use std::path::{Path, PathBuf};

use super::{bench_enabled, bench_run_root, read_string, run_flow};

/// Drive one NAT-traversal flow through its CLI subcommand with every build context
/// resolved absolutely, and hand back its run dir.
///
/// **Every path the flow reads, not only the ones it builds from.** The
/// subcommand's defaults are repo-root-relative and a `cargo test` runs from
/// the harness *package* root, so a default left in place resolves one
/// directory too deep. The coordinator's `config.toml` is the one that bites
/// even under `--skip-build`: it is bind-mounted, not built, so a wrapper that
/// passed only the build contexts died before standing anything up.
fn run_natt_flow(flow: &str) -> PathBuf {
    run_natt_flow_with(flow, &[])
}

/// [`run_natt_flow`] with the flow's own knobs appended.
fn run_natt_flow_with(flow: &str, extra: &[&str]) -> PathBuf {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let images = repo_root.join("tools/interop-harness/images");
    let at = |relative: &str| images.join(relative).to_str().unwrap().to_string();
    let (dockerfile, amule_kno, capture, ed2ksrv, ed2ksrv_config, natgw, natprobe) = (
        at("rmule-tools/Dockerfile"),
        at("amule-kno"),
        at("capture"),
        at("ed2ksrv"),
        at("ed2ksrv/config.toml"),
        at("natgw"),
        at("natprobe"),
    );
    let repo_root = repo_root.to_str().unwrap().to_string();
    let mut args = vec![
        flow,
        "--skip-build",
        "--timeout",
        "180",
        "--amule-kno-build-context",
        &amule_kno,
        "--capture-build-context",
        &capture,
        "--ed2ksrv-build-context",
        &ed2ksrv,
        "--ed2ksrv-config",
        &ed2ksrv_config,
        "--natgw-build-context",
        &natgw,
        "--natprobe-build-context",
        &natprobe,
        "--rmule-tools-dockerfile",
        &dockerfile,
        "--rmule-tools-build-context",
        &repo_root,
    ];
    args.extend_from_slice(extra);
    // The operator's own image tags, when set: `:local` is shared by
    // every worktree on the bench and may be rebuilt from another tip
    // mid-run (the same convention `kad_buddy_callback_against_amule` uses).
    let amule_image = std::env::var("RMULE_BENCH_AMULE_IMAGE").ok();
    if let Some(image) = &amule_image {
        args.extend_from_slice(&["--amule-image", image]);
    }
    let tools_image = std::env::var("RMULE_BENCH_RMULE_TOOLS_IMAGE").ok();
    if let Some(image) = &tools_image {
        args.extend_from_slice(&["--rmule-tools-image", image]);
    }
    let run_root = bench_run_root();
    if let Some(root) = &run_root {
        args.extend_from_slice(&["--run-root", root]);
    }
    run_flow("natt", &args)
}

/// **`natt-caps-utp`.** The dialect's three opening frames against kno's
/// aMule at its Fork Pin: the uTP `ST_SYN` is answered and a Tunnel rises, and
/// the CAPS and KEY halves are **Documented Absences** the fork's own `0xB2`
/// demux explains.
///
/// The two absences are asserted by name beside the positive row, and so is the
/// wire row that makes each of them a *measurement*: without
/// `the-caps-probe-reached-the-counterparty` the CAPS zero would be
/// indistinguishable from a probe that never left.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn natt_caps_utp() {
    if !bench_enabled("natt-caps-utp") {
        return;
    }
    let run_dir = run_natt_flow("natt-caps-utp");
    let verdict = read_string(&run_dir, "natt-caps-utp-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "natt-caps-utp: every driveable claim must hold:\n{verdict}",
    );
    for expected in [
        "amule-kno-claims-natt-in-its-hello",
        "a-utp-tunnel-rose-over-the-advertised-client-udp-bind",
        "the-utp-answer-left-the-port-the-hello-named",
        "the-counterparty-answered-the-utp-syn",
        "the-caps-probe-reached-the-counterparty",
        "the-key-frame-rode-the-opening-packet",
        "amule-kno-negotiates-no-caps-at-this-pin",
        "amule-kno-adopts-no-key-frame-at-this-pin",
        "no-caps-ack-crossed-the-wire",
    ] {
        assert!(
            verdict.contains(expected),
            "natt-caps-utp: {expected} missing from the verdict:\n{verdict}",
        );
    }
}

/// **`natt-server-punch-cone`.** ADR-0091's second Rendezvous
/// coordinator, end to end: an `ed2ksrv` introduces two rmule peers that each
/// sit behind their own `full-cone-pinned` **NAT Gateway**, both burst at the
/// endpoint the server observed, and a uTP Tunnel rises over the pinhole.
///
/// Withheld at first on purpose — a wrapper asserting `PASS` would have been a red
/// gate for a defect nobody had attributed yet. It is written now because the
/// row passes, and every claim is asserted by name: the label alone is reachable
/// by dropping the Tunnel claim, which is the one claim this row exists for.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn natt_server_punch_cone() {
    if !bench_enabled("natt-server-punch-cone") {
        return;
    }
    let run_dir = run_natt_flow("natt-server-punch-cone");
    let verdict = read_string(&run_dir, "natt-server-punch-cone-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "natt-server-punch-cone: every claim of the server-coordinated punch must hold:\n{verdict}",
    );
    for expected in [
        "both-peers-earned-a-low-id-behind-their-own-gateway",
        "the-requester-routed-through-the-server-coordinator",
        "a-tunnel-rose-between-the-two-firewalled-peers",
        "the-server-received-one-holepunch-request",
        "the-server-introduced-both-peers",
        "the-keepalive-reached-the-server-udp-port",
        "both-peers-burst-at-the-endpoint-the-server-named",
        // Added 2026-09-22 with the pinned-port leg: the RFC 5780
        // tests never address the pinned port, so without this claim a gateway
        // that hairpinned every punch would still reach the label.
        "each-lan-reached-the-wan-on-the-pinned-port",
        "each-gateway-probed-as-its-claimed-nat-type",
    ] {
        assert!(
            verdict.contains(expected),
            "natt-server-punch-cone: {expected} missing from the verdict:\n{verdict}",
        );
    }
    // The **NAT Type Proof** each gateway's verdict cites, and the driver rows
    // the `rmule-only` claims are read off. A claim with no artifact behind it
    // is the fabricated row ADR-0045 forbids.
    for artifact in punch_artifacts("natt-server-punch-cone") {
        assert!(
            run_dir.join(&artifact).is_file(),
            "natt-server-punch-cone: the run is missing its {artifact}",
        );
    }
}

/// The **NAT Type Proof** and driver artifacts every gateway-bearing NAT-traversal
/// row must have written, by flow name. A claim with no artifact behind it is
/// the fabricated row ADR-0045 forbids, so the wrappers assert the files as
/// well as the claim names.
fn punch_artifacts(flow: &str) -> Vec<String> {
    let mut artifacts = vec![format!("nat/{flow}/tap-server.pcap")];
    for peer in ["peer-a", "peer-b"] {
        for file in [
            "nft-ruleset.txt",
            "conntrack.txt",
            "nat-probe.toml",
            "nat-type.toml",
            "punch.toml",
            "tap-wan.pcap",
            "tap-lan.pcap",
        ] {
            artifacts.push(format!("nat/{flow}/{peer}/{file}"));
        }
    }
    artifacts
}

/// Assert one peer's gateway *observed* the symmetric mapping and agreed with
/// its claim, read as fields off its `nat-type.toml`. A text search would
/// also match the row's *claimed* fields, which name the same behaviour.
fn assert_probed_symmetric(run_dir: &Path, flow: &str, peer: &str, row: &str) {
    let path = format!("nat/{flow}/{peer}/nat-type.toml");
    let proof: toml::Table = toml::from_str(&read_string(run_dir, &path))
        .unwrap_or_else(|error| panic!("{row}: {path} does not parse: {error}"));
    assert_eq!(
        proof.get("observed_mapping").and_then(toml::Value::as_str),
        Some("address-and-port-dependent"),
        "{row}: {peer}'s gateway did not probe address-and-port-dependent:\n{proof}",
    );
    assert_eq!(
        proof.get("agrees").and_then(toml::Value::as_bool),
        Some(true),
        "{row}: {peer}'s gateway disagreed with its own claim:\n{proof}",
    );
}

/// **`natt-server-punch-symmetric`.** The honest negative: the same two
/// rmule peers, the same coordinator, two **symmetric** gateways, and no
/// Tunnel.
///
/// ADR-0045 makes a punch-failure row evidence only with four things in the
/// *same run*, and each is asserted here by name rather than by the label: both
/// gateways' **NAT Type Proof** (including the pinned-port leg, so the zero is
/// not a gateway that forwards nothing), the RFC 5780 **Reflector Probe**
/// beside their claim, the outbound conntrack mappings showing the punch was
/// fired and translated, and the counterparty's own zero read on **both** the
/// LAN and the WAN taps. Its positive control is `natt-server-punch-cone`
/// above; a green `natt-server-punch-symmetric` with a red
/// `natt-server-punch-cone` would prove nothing about NAT type.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn natt_server_punch_symmetric() {
    if !bench_enabled("natt-server-punch-symmetric") {
        return;
    }
    let run_dir = run_natt_flow("natt-server-punch-symmetric");
    let verdict = read_string(&run_dir, "natt-server-punch-symmetric-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "natt-server-punch-symmetric: the negative and its whole evidence kit must hold:\n{verdict}",
    );
    for expected in [
        "each-lan-reached-the-wan-on-the-pinned-port",
        "each-gateway-probed-as-its-claimed-nat-type",
        "both-peers-earned-a-low-id-behind-their-own-gateway",
        "the-requester-routed-through-the-server-coordinator",
        "no-tunnel-rose-behind-symmetric-gateways",
        "the-outbound-punch-mapping-exists-in-each-gateways-conntrack",
        "the-openers-left-the-lan-behind-symmetric-gateways",
        "no-transport-frame-arrived-at-either-peer",
        "the-server-received-one-holepunch-request",
        "the-server-introduced-both-peers",
        "the-keepalive-reached-the-server-udp-port",
        "the-punch-was-attempted-and-the-mapping-existed",
    ] {
        assert!(
            verdict.contains(expected),
            "natt-server-punch-symmetric: {expected} missing from the verdict:\n{verdict}",
        );
    }
    for peer in ["peer-a", "peer-b"] {
        assert_probed_symmetric(
            &run_dir,
            "natt-server-punch-symmetric",
            peer,
            "natt-server-punch-symmetric",
        );
    }
    for artifact in punch_artifacts("natt-server-punch-symmetric") {
        assert!(
            run_dir.join(&artifact).is_file(),
            "natt-server-punch-symmetric: the run is missing its {artifact}",
        );
    }
}

/// **`natt-server-punch-one-symmetric`**. Port prediction on the
/// one pair it can move: the requester behind a **symmetric** gateway, the
/// responder behind a **port-restricted** one, both with
/// `natt.port_prediction = birthday`.
///
/// One run is one draw, so the wrapper is the aggregation the flow cannot be:
/// it runs the flow `RMULE_BENCH_PREDICTION_RUNS` times (10 by default). Every
/// run must be `PASS` — each side read its own mapping, the symmetric gateway
/// mapped every Fan socket, the probe sets left, and **a Tunnel rose exactly
/// when the two port sets met** — and at least 4 in 10 must raise a Tunnel
/// (p ≈ 0.87 per run at two attempts, so 4 of 10 fails by chance < 10⁻⁴).
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn natt_server_punch_one_symmetric() {
    if !bench_enabled("natt-server-punch-one-symmetric") {
        return;
    }
    let runs: usize = std::env::var("RMULE_BENCH_PREDICTION_RUNS")
        .ok()
        .and_then(|runs| runs.parse().ok())
        .unwrap_or(10);
    let mut tunnels = 0;
    for run in 0..runs {
        let run_dir = run_natt_flow("natt-server-punch-one-symmetric");
        let verdict = read_string(&run_dir, "natt-server-punch-one-symmetric-verdict.toml");
        assert!(
            verdict.contains("verdict = \"PASS\""),
            "natt-server-punch-one-symmetric run {run}: every draw must agree with its own port sets:\n{verdict}",
        );
        for expected in [
            "each-lan-reached-the-wan-on-the-pinned-port",
            "each-gateway-probed-as-its-claimed-nat-type",
            "both-peers-earned-a-low-id-behind-their-own-gateway",
            "the-requester-routed-through-the-server-coordinator",
            "each-side-read-its-own-mapping-off-its-kad-observers",
            "the-symmetric-gateway-mapped-every-fan-socket",
            "the-port-restricted-side-sent-its-probe-sets",
            "a-tunnel-rose-exactly-when-the-port-sets-met",
        ] {
            assert!(
                verdict.contains(expected),
                "natt-server-punch-one-symmetric run {run}: {expected} missing from the verdict:\n{verdict}",
            );
        }
        for artifact in punch_artifacts("natt-server-punch-one-symmetric") {
            assert!(
                run_dir.join(&artifact).is_file(),
                "natt-server-punch-one-symmetric run {run}: the run is missing its {artifact}",
            );
        }
        let parsed: toml::Table = toml::from_str(&verdict).unwrap_or_else(|error| {
            panic!("natt-server-punch-one-symmetric run {run}: the verdict does not parse: {error}")
        });
        match parsed.get("tunnel_rose").and_then(toml::Value::as_bool) {
            Some(true) => tunnels += 1,
            Some(false) => {}
            None => panic!(
                "natt-server-punch-one-symmetric run {run}: the verdict carries no `tunnel_rose`:\n{verdict}"
            ),
        }
    }
    assert!(
        tunnels * 10 >= runs * 4,
        "natt-server-punch-one-symmetric: {tunnels} of {runs} runs raised a Tunnel; the row needs 4 in 10",
    );
}

/// **`natt-server-punch-symmetric --port-prediction`**. The both-symmetric
/// negative with the knob on: both sides read endpoint-dependent, so
/// neither may Probe, and the pair stays a negative with no random-port
/// punch from either pinned port. Every `natt-server-punch-symmetric`
/// claim still holds beside it.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn natt_server_punch_symmetric_with_prediction() {
    if !bench_enabled("natt-server-punch-symmetric --port-prediction") {
        return;
    }
    let run_dir = run_natt_flow_with("natt-server-punch-symmetric", &["--port-prediction"]);
    let verdict = read_string(&run_dir, "natt-server-punch-symmetric-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "natt-server-punch-symmetric --port-prediction: the knob must leave the negative a negative:\n{verdict}",
    );
    for expected in [
        "each-gateway-probed-as-its-claimed-nat-type",
        "no-tunnel-rose-behind-symmetric-gateways",
        "no-transport-frame-arrived-at-either-peer",
        "the-knob-left-the-both-hard-pair-a-negative-and-no-scan",
    ] {
        assert!(
            verdict.contains(expected),
            "natt-server-punch-symmetric --port-prediction: {expected} missing from the verdict:\n{verdict}",
        );
    }
}

/// **`natt-tunnel-transfer`.** Rung 1 of the ADR-0061 tree, end to end:
/// a file crosses a punched path between two Low-ID rmule nodes.
///
/// The claims that make it that, rather than another punch row, are asserted by
/// name: the Low-ID downloader admitted its Low-ID candidate at all, chose
/// NAT-T on its own 12 s clock, *claimed* the Tunnel the punch raised, and the
/// bytes that came out verify against the link's own ED2K hash.
///
/// **Red when first written, and deliberately so.** The first claim was
/// `absent` against a defect in `crates/`: the pool a Low-ID candidate is drawn
/// from was gated on this node being High-ID, so the LowID↔LowID pair rung 1
/// exists for could not reach the rung. The wrapper asserted the row it is
/// supposed to reach rather than the row it reached then, because a wrapper
/// rewritten to match a defect stops being a gate.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn natt_tunnel_transfer() {
    if !bench_enabled("natt-tunnel-transfer") {
        return;
    }
    let run_dir = run_natt_flow("natt-tunnel-transfer");
    let verdict = read_string(&run_dir, "natt-tunnel-transfer-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "natt-tunnel-transfer: every claim of the transfer must hold:\n{verdict}",
    );
    for expected in [
        "each-lan-reached-the-wan-on-the-pinned-port",
        "each-gateway-probed-as-its-claimed-nat-type",
        "both-peers-earned-a-low-id-behind-their-own-gateway",
        "the-requester-routed-through-the-server-coordinator",
        "a-tunnel-rose-between-the-two-firewalled-peers",
        "the-low-id-downloader-admitted-its-low-id-candidate",
        "the-download-fell-to-nat-t-on-its-own-clock",
        "the-download-adopted-the-tunnel-the-punch-raised",
        "the-file-completed-byte-equal-over-the-punched-path",
    ] {
        assert!(
            verdict.contains(expected),
            "natt-tunnel-transfer: {expected} missing from the verdict:\n{verdict}",
        );
    }
    for artifact in punch_artifacts("natt-tunnel-transfer") {
        assert!(
            run_dir.join(&artifact).is_file(),
            "natt-tunnel-transfer: the run is missing its {artifact}",
        );
    }
    assert!(
        run_dir
            .join("nat/natt-tunnel-transfer/peer-a/dl/downloaded.bin")
            .is_file(),
        "natt-tunnel-transfer: the fetched file itself is the row's claim and must be retained",
    );
}

/// The artifacts a buddy rendezvous row is not a row without: the buddy's own
/// attachment (the one place a counterparty statement is made in this
/// topology), each gatewayed body's two taps and its whole NAT Type Proof —
/// the **teardown** dump every gateway takes on exit and, whenever the
/// requester dialed, the **in-flight** one `take_inflight_proof` triggers off
/// that first dial — and the three driver rows.
///
/// The in-flight dump follows the requester's own `dials`, not the verdict
/// label: the flow's documented degrade for a requester that never dials is
/// to carry on without it, and that zero is on the row. A row that counts a
/// dial and lacks the dump is the driver losing its marker — every
/// `natt-buddy-transfer-cone` run before the driver's first-dial poller was
/// fixed — and fails here.
fn buddy_artifacts(flow: &str, requester_dialed: bool) -> Vec<String> {
    let mut artifacts = vec![
        format!("nat/{flow}/buddy/tap-buddy.pcap"),
        format!("nat/{flow}/buddy/buddy-rendezvous.toml"),
        format!("nat/{flow}/buddy/driver.log"),
    ];
    for body in ["requester", "target"] {
        for file in [
            "nft-ruleset.txt",
            "nft-seen-set.txt",
            "conntrack.txt",
            "nat-probe.toml",
            "nat-type.toml",
            "buddy-rendezvous.toml",
            "driver.log",
            "tap-wan.pcap",
            "tap-lan.pcap",
        ] {
            artifacts.push(format!("nat/{flow}/{body}/{file}"));
        }
        if requester_dialed {
            for file in [
                "inflight-nft-ruleset.txt",
                "inflight-nft-seen-set.txt",
                "inflight-conntrack.txt",
            ] {
                artifacts.push(format!("nat/{flow}/{body}/{file}"));
            }
        }
    }
    artifacts
}

/// The requester's own `dials` count off its driver row.
fn requester_dials(run_dir: &Path, flow: &str) -> u64 {
    let row = read_string(
        run_dir,
        &format!("nat/{flow}/requester/buddy-rendezvous.toml"),
    );
    row.lines()
        .find_map(|line| line.strip_prefix("dials = "))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or_else(|| panic!("the requester's row for {flow} carries no dials count"))
}

/// Every claim a positive buddy rendezvous row must hold, by name. The label
/// alone is reachable by dropping the Tunnel claim — and the self-proof, which
/// is what separates "a buddy relayed for us" from "a relation the bench
/// asserted into existence".
const BUDDY_POSITIVE_CLAIMS: [&str; 12] = [
    "each-lan-reached-the-wan-on-the-pinned-port",
    "each-gateway-probed-as-its-claimed-nat-type",
    "every-body-bound-its-serve-listener-without-a-server",
    "the-firewalled-target-holds-a-buddy-it-recruited-live",
    "the-recruit-landed-on-the-intended-buddy",
    "no-server-coordinator-was-asked",
    "the-requester-routed-through-the-buddy-coordinator",
    "the-rendezvous-reached-the-buddy-and-was-relayed",
    "the-buddy-relayed-the-rendezvous-onto-the-held-link",
    "the-target-acted-on-the-relayed-rendezvous",
    "the-buddy-answered-with-the-targets-observed-endpoint",
    "a-tunnel-rose-between-the-two-firewalled-peers",
];

fn assert_buddy_row(label: &str, flow: &str, claims: &[&str]) {
    let run_dir = run_natt_flow(flow);
    let verdict = read_string(&run_dir, &format!("{flow}-verdict.toml"));
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "{label}: every claim of the buddy rendezvous must hold:\n{verdict}",
    );
    for expected in claims {
        assert!(
            verdict.contains(expected),
            "{label}: {expected} missing from the verdict:\n{verdict}",
        );
    }
    let requester_dialed = requester_dials(&run_dir, flow) >= 1;
    for artifact in buddy_artifacts(flow, requester_dialed) {
        assert!(
            run_dir.join(&artifact).is_file(),
            "{label}: the run is missing its {artifact}",
        );
    }
}

/// **`natt-buddy-rendezvous-cone`.** ADR-0091 rung 1 through its
/// *second* Rendezvous coordinator, behind two `full-cone-pinned` gateways.
///
/// The row exists because the buddy path cannot be reached by asserting a
/// relation: the relay admits a **held** buddy only, and a held buddy is one a
/// live FINDBUDDY walk recruited. So the self-proof — `0x51` counted arriving
/// on the intended buddy's own wire, sourced at the target's own gateway, and
/// `0x5A` counted going back — is asserted beside the Tunnel, and
/// `no-server-coordinator-was-asked` is asserted too, because a `0x60`
/// anywhere would mean the run measured `natt-server-punch-cone`'s rung instead of this one.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn natt_buddy_rendezvous_cone() {
    if !bench_enabled("natt-buddy-rendezvous-cone") {
        return;
    }
    let mut claims = BUDDY_POSITIVE_CLAIMS.to_vec();
    // The one hello a buddy-holding node sends in this topology.
    claims.push("the-firewalled-targets-hello-named-its-buddy");
    assert_buddy_row(
        "natt-buddy-rendezvous-cone",
        "natt-buddy-rendezvous-cone",
        &claims,
    );
}

/// **`natt-buddy-rendezvous-restricted`.** The same topology behind two
/// **restricted** gateways (EIM + address-dependent filtering): the burst still
/// opens the far side's filter because each end has sent to the other's
/// address by the time the opener arrives.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn natt_buddy_rendezvous_restricted() {
    if !bench_enabled("natt-buddy-rendezvous-restricted") {
        return;
    }
    assert_buddy_row(
        "natt-buddy-rendezvous-restricted",
        "natt-buddy-rendezvous-restricted",
        &BUDDY_POSITIVE_CLAIMS,
    );
}

/// **`natt-buddy-rendezvous-symmetric`.** The honest negative on the
/// buddy path, qualified exactly as `natt-server-punch-symmetric` is: both gateways' NAT Type Proof
/// including the pinned-port leg, the RFC 5780 Reflector Probe beside their
/// claim, the `[UNREPLIED]` conntrack mappings proving the punch was fired and
/// translated, and the counterparty's own zero off the LAN taps.
///
/// Its positive control is `natt-buddy-rendezvous-cone`; a green
/// `natt-buddy-rendezvous-symmetric` beside a red
/// `natt-buddy-rendezvous-cone` would prove nothing about NAT type. The
/// rendezvous half is asserted *held* here too — the whole point of the
/// negative is that everything up to the transport worked and only the
/// mapping defeated it.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn natt_buddy_rendezvous_symmetric() {
    if !bench_enabled("natt-buddy-rendezvous-symmetric") {
        return;
    }
    assert_buddy_row(
        "natt-buddy-rendezvous-symmetric",
        "natt-buddy-rendezvous-symmetric",
        &[
            "each-lan-reached-the-wan-on-the-pinned-port",
            "each-gateway-probed-as-its-claimed-nat-type",
            "the-firewalled-target-holds-a-buddy-it-recruited-live",
            "the-recruit-landed-on-the-intended-buddy",
            "the-requester-routed-through-the-buddy-coordinator",
            "the-rendezvous-reached-the-buddy-and-was-relayed",
            "the-buddy-answered-with-the-targets-observed-endpoint",
            "each-side-burst-or-dialed-through-the-others-punch",
            "no-tunnel-rose-behind-symmetric-gateways",
            "the-outbound-punch-mapping-exists-in-each-gateways-conntrack",
            "no-transport-frame-arrived-at-either-body",
            "the-openers-left-the-lan-behind-symmetric-gateways",
        ],
    );
}

/// **`natt-buddy-transfer-cone`.** The buddy path driven by a real download:
/// the requester is handed only the ed2k link, finds the target's buddy row
/// over Kad, reaches the buddy coordinator from it, and fetches the file
/// byte-equal over the Tunnel the buddy coordinated — the
/// `natt-tunnel-transfer` shape on the buddy path. Every rendezvous claim of
/// `natt-buddy-rendezvous-cone` is asserted beside the four the download adds,
/// because a completed file with no buddy-relayed rendezvous behind it would
/// be some other road's.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn natt_buddy_transfer_cone() {
    if !bench_enabled("natt-buddy-transfer-cone") {
        return;
    }
    let mut claims = BUDDY_POSITIVE_CLAIMS.to_vec();
    claims.extend([
        "the-target-published-its-file-through-the-held-buddy",
        "the-download-found-the-buddy-coordinator-from-a-kad-row-alone",
        "the-download-adopted-the-tunnel-the-buddy-coordinated",
        "the-file-completed-byte-equal-over-the-buddy-path",
    ]);
    assert_buddy_row(
        "natt-buddy-transfer-cone",
        "natt-buddy-transfer-cone",
        &claims,
    );
}

/// **`natt-udp-selfcheck-cone`**. ADR-0058's UDP self-check,
/// end to end: a firewalled target behind a `full-cone-pinned` gateway finds
/// two fresh UDP Firewall Helpers through its own helper lookup, asks them
/// with `OP_FWCHECKUDPREQ`, reads its UDP verdict open off their `0x62`, and
/// the storer's own capture holds the type-6 row with bit `0x08` it then
/// publishes. Every claim is asserted by name: the label alone would read
/// `PASS` for a flow that stopped checking the published row.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn natt_udp_selfcheck_cone() {
    if !bench_enabled("natt-udp-selfcheck-cone") {
        return;
    }
    let run_dir = run_natt_flow("natt-udp-selfcheck-cone");
    let verdict = read_string(&run_dir, "natt-udp-selfcheck-cone-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "natt-udp-selfcheck-cone: every driveable claim must hold:\n{verdict}",
    );
    for expected in [
        "the-lan-reached-the-wan-on-the-pinned-port",
        "each-gateway-probed-as-its-claimed-nat-type",
        "a-fresh-helper-answered-0x62-to-the-gateway",
        "the-target-udp-verdict-read-open",
        "the-storer-captured-a-type-6-row-stating-0x08",
        "the-targets-post-verdict-hello-lights-misc-options2-bit-12",
    ] {
        assert!(
            verdict.contains(expected),
            "natt-udp-selfcheck-cone: {expected} missing from the verdict:\n{verdict}",
        );
    }
}

/// **`natt-udp-selfcheck-remapped`**. `natt-udp-selfcheck-cone`'s topology
/// behind a gateway that remaps the target's Kad port: the verdict reads open
/// only if the target learned its **Extern Kad Port** from its own `0x60`
/// pings before engaging a helper and named it in the `0xA7`, because a `0x62`
/// to the intern port never gets past the gateway.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn natt_udp_selfcheck_remapped() {
    if !bench_enabled("natt-udp-selfcheck-remapped") {
        return;
    }
    let run_dir = run_natt_flow("natt-udp-selfcheck-remapped");
    let verdict = read_string(&run_dir, "natt-udp-selfcheck-remapped-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "natt-udp-selfcheck-remapped: every driveable claim must hold:\n{verdict}",
    );
    for expected in [
        "each-gateway-probed-as-its-claimed-nat-type",
        "a-fresh-helper-answered-0x62-to-the-gateway",
        "the-target-udp-verdict-read-open",
        "the-storer-captured-a-type-6-row-stating-0x08",
        "the-target-pinged-for-its-extern-port-through-the-remap",
        "the-0x62-landed-on-the-learned-extern-port",
        "the-targets-post-verdict-hello-lights-misc-options2-bit-12",
    ] {
        assert!(
            verdict.contains(expected),
            "natt-udp-selfcheck-remapped: {expected} missing from the verdict:\n{verdict}",
        );
    }
}

/// **`natt-udp-selfcheck-amule`**. `natt-udp-selfcheck-cone`'s topology with
/// the firewalled body stock aMule 2.3.3 on the debug image
/// (`rmule/interop-amule-debug:local`, pre-built by hand): aMule's own
/// `OP_FWCHECKUDPREQ` to a fresh helper, its own UDP verdict read open off
/// the helper's `0x62`, and the publish that verdict earns at the storer.
///
/// Capture-gated: the type-6 claim is `held` on a captured row, or `blocked`
/// with aMule's own counts when stock 2.3.3's buddy gate keeps the publish
/// from leaving at all — so the label is `PASS` or `OBSERVED`, never `FAIL`.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn natt_udp_selfcheck_amule() {
    if !bench_enabled("natt-udp-selfcheck-amule") {
        return;
    }
    let run_dir = run_natt_flow("natt-udp-selfcheck-amule");
    let verdict = read_string(&run_dir, "natt-udp-selfcheck-amule-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\"") || verdict.contains("verdict = \"OBSERVED\""),
        "natt-udp-selfcheck-amule: every driveable claim must hold:\n{verdict}",
    );
    for expected in [
        "the-lan-reached-the-wan-on-the-pinned-port",
        "each-gateway-probed-as-its-claimed-nat-type",
        "amule-asked-a-fresh-helper-with-0xa7",
        "a-fresh-helper-answered-0x62-to-the-gateway",
        "the-amule-udp-verdict-read-open",
        "the-storer-captured-an-amule-type-6-row-stating-0x08",
    ] {
        assert!(
            verdict.contains(expected),
            "natt-udp-selfcheck-amule: {expected} missing from the verdict:\n{verdict}",
        );
    }
}

/// **`natt-udp-selfcheck-amule --low-id-buddy`** — `natt-udp-selfcheck-amule` on the **Low-ID Buddy
/// Recipe**: an `ed2ksrv` gives the rmule root a real Low ID, aMule's
/// `KADEMLIA2_PING`s are held at its gateway until its UDP verdict times out
/// firewalled and it holds the root as its buddy, then released so a
/// helper's `0x62` reads it open, then the Synthetic File is shared.
///
/// Unlike plain `natt-udp-selfcheck-amule`, this leg exists to earn the type-6 row, so it must
/// `PASS`: `OBSERVED` would mean a recipe step never landed, and a wrong-type
/// or missing `0x44` after every step landed is `FAIL`.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn natt_udp_selfcheck_amule_low_id_buddy() {
    if !bench_enabled("natt-udp-selfcheck-amule --low-id-buddy") {
        return;
    }
    let run_dir = run_natt_flow_with("natt-udp-selfcheck-amule", &["--low-id-buddy"]);
    let verdict = read_string(&run_dir, "natt-udp-selfcheck-amule-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "natt-udp-selfcheck-amule --low-id-buddy: the recipe must earn the type-6 row:\n{verdict}",
    );
    for expected in [
        "each-gateway-probed-as-its-claimed-nat-type",
        "the-root-logged-in-with-a-server-assigned-low-id",
        "the-held-amule-udp-verdict-timed-out-firewalled",
        "amule-recruited-the-low-id-root-as-its-buddy",
        "amules-hello-carried-the-pinned-user-hash",
        "the-amule-udp-verdict-read-open",
        "the-storer-captured-an-amule-type-6-row-stating-0x08",
    ] {
        assert!(
            verdict.contains(expected),
            "natt-udp-selfcheck-amule --low-id-buddy: {expected} missing from the verdict:\n{verdict}",
        );
    }
}

/// **`natt-udp-selfcheck-amule --kad-crypt`** — the same with Kad-UDP crypt armed
/// on aMule (`AMULE_KAD_CRYPT=1`) and on both helpers (`--peer-crypt requested`):
/// aMule's `0xA7` carries its verify key, the
/// helper's `0x62` rides the KadVerify family keyed on it, and aMule's verdict
/// reads open off a datagram it had to decrypt.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn natt_udp_selfcheck_amule_crypt() {
    if !bench_enabled("natt-udp-selfcheck-amule --kad-crypt") {
        return;
    }
    let run_dir = run_natt_flow_with("natt-udp-selfcheck-amule", &["--kad-crypt"]);
    let verdict = read_string(&run_dir, "natt-udp-selfcheck-amule-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\"") || verdict.contains("verdict = \"OBSERVED\""),
        "natt-udp-selfcheck-amule --kad-crypt: every driveable claim must hold:\n{verdict}",
    );
    for expected in [
        "each-gateway-probed-as-its-claimed-nat-type",
        "the-amule-udp-verdict-read-open",
        "amule-accepted-the-helpers-keyed-0x62",
        "the-storer-captured-an-amule-type-6-row-stating-0x08",
    ] {
        assert!(
            verdict.contains(expected),
            "natt-udp-selfcheck-amule --kad-crypt: {expected} missing from the verdict:\n{verdict}",
        );
    }
}

/// **`natt-buddy-recruit-amule`** — rmule's Firewalled Front against stock
/// aMule 2.3.3 (`rmule/interop-amule-debug:local`, pre-built by hand) as the
/// open buddy. aMule reads itself open off two rmule TCP testers in its
/// routing zone and two fresh UDP helpers; a Core rmule behind a
/// `port-restricted` gateway, holding an `ed2ksrv` Low ID, walks to it, adopts
/// its `0x5A`, dials and holds the link, pings it, and dials back the
/// requester of the `OP_CALLBACK` aMule relays over it.
///
/// Every step must hold: a step aMule's own gate kept from running is
/// `blocked` and reads `OBSERVED`, which this wrapper does not accept. About
/// 35 minutes — drive it once in the foreground and score the retained run
/// with `RMULE_BENCH_VERDICT_DIR`.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1; ~35 min, score a retained run with RMULE_BENCH_VERDICT_DIR"]
fn natt_buddy_recruit_amule() {
    if !bench_enabled("natt-buddy-recruit-amule") {
        return;
    }
    let run_dir = run_natt_flow("natt-buddy-recruit-amule");
    let verdict = read_string(&run_dir, "natt-buddy-recruit-amule-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "natt-buddy-recruit-amule: every step of the front's lifecycle must hold:\n{verdict}",
    );
    for expected in [
        "each-gateway-probed-as-its-claimed-nat-type",
        "the-target-holds-a-server-low-id",
        "the-amule-read-kad-tcp-open",
        "the-amule-udp-verdict-read-open",
        "the-target-walked-to-amule-with-0x51",
        "amule-answered-the-recruit-with-0x5a",
        "the-target-dialed-amule-and-amule-answered-its-hello",
        "the-target-held-the-link-through-its-window",
        "the-target-pinged-its-buddy-0x9f",
        "amule-ponged-0xa0-on-the-buddy-link",
        "the-walker-sent-0x52-to-amule",
        "amule-relayed-the-callback-as-0x99",
        "the-target-dialed-the-requester-back",
    ] {
        assert!(
            verdict.contains(expected),
            "natt-buddy-recruit-amule: {expected} missing from the verdict:\n{verdict}",
        );
    }
}

/// **`natt-buddy-recruit-amule --no-server`** — the same lifecycle with no
/// `ed2ksrv` on the WAN: the target is firewalled on Kad alone, so every
/// `OP_HELLO` aMule receives from it must name the Kad-firewalled id `1`
/// (aMule's `GetID`), the Low ID an open aMule keeps a buddy for — and aMule
/// must still pong it at the second keepalive, the first it answers.
///
/// About 35 minutes — drive it once in the foreground and score the retained
/// run with `RMULE_BENCH_VERDICT_DIR`.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1; ~35 min, score a retained run with RMULE_BENCH_VERDICT_DIR"]
fn natt_buddy_recruit_amule_no_server() {
    if !bench_enabled("natt-buddy-recruit-amule --no-server") {
        return;
    }
    let run_dir = run_natt_flow_with("natt-buddy-recruit-amule", &["--no-server"]);
    let verdict = read_string(&run_dir, "natt-buddy-recruit-amule-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "natt-buddy-recruit-amule --no-server: the serverless target must hold aMule:\n{verdict}",
    );
    for expected in [
        "the-target-presents-the-kad-firewalled-id-1",
        "the-target-dialed-amule-and-amule-answered-its-hello",
        "the-target-held-the-link-through-its-window",
        "amule-ponged-0xa0-on-the-buddy-link",
    ] {
        assert!(
            verdict.contains(expected),
            "natt-buddy-recruit-amule --no-server: {expected} missing from the verdict:\n{verdict}",
        );
    }
}
