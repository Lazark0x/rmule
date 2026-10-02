//! ADR-0092's **Bench Tier** wrappers for the **Port-Mapping Gateway**
//! flows (ADR-0086).
//!
//! Each wrapper asserts the label its row is supposed to reach *and* the
//! decisive claims by name, and then the artifacts without which a row is not a
//! row: the gateway's own table and log beside whatever rmule said about itself.

use std::path::{Path, PathBuf};

use super::{bench_enabled, bench_run_root, read_string, run_flow};

/// Run one port-mapping flow and hand back its run dir.
///
/// The repo-relative driver-image defaults are re-pointed for the same reason
/// `natgw-selfproof` re-points them: the wrapper runs the binary from the crate directory,
/// so `tools/interop-harness/images/…` would resolve one level too deep.
fn run_portmap_flow(flow: &str) -> PathBuf {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let dockerfile = repo_root.join("tools/interop-harness/images/rmule-tools/Dockerfile");
    let miniupnpd = repo_root.join("tools/interop-harness/images/miniupnpd");
    let natprobe = repo_root.join("tools/interop-harness/images/natprobe");
    let capture = repo_root.join("tools/interop-harness/images/capture");
    let (repo_root, dockerfile, miniupnpd, natprobe, capture) = (
        repo_root.to_str().unwrap().to_string(),
        dockerfile.to_str().unwrap().to_string(),
        miniupnpd.to_str().unwrap().to_string(),
        natprobe.to_str().unwrap().to_string(),
        capture.to_str().unwrap().to_string(),
    );
    let mut args = vec![
        flow,
        "--skip-build",
        "--timeout",
        "180",
        "--miniupnpd-build-context",
        &miniupnpd,
        "--natprobe-build-context",
        &natprobe,
        "--capture-build-context",
        &capture,
        "--rmule-tools-dockerfile",
        &dockerfile,
        "--rmule-tools-build-context",
        &repo_root,
    ];
    let run_root = bench_run_root();
    if let Some(root) = &run_root {
        args.extend_from_slice(&["--run-root", root]);
    }
    run_flow("portmap", &args)
}

/// Every artifact a port-mapping flow must retain: the gateway's own two dumps and
/// its lease table, the NAT Type Proof and the probe row it rests on, both
/// **Per-Attachment Tap** pcaps, and rmule's own row.
///
/// Asserted rather than implied: a verdict with no proof beside it is exactly
/// the fabricated row ADR-0045 forbids.
fn assert_portmap_artifacts(run_dir: &Path, flow: &str) {
    for artifact in [
        "nat-type.toml",
        "nat-probe.toml",
        "nft-ruleset.txt",
        "conntrack.txt",
        "gateway-table.txt",
        "gateway-table6.txt",
        "miniupnpd.conf",
        "gateway.log",
        "driver.log",
        "portmap-row.toml",
        "taps.toml",
        "tap-wan.pcap",
        "tap-lan.pcap",
    ] {
        let path = format!("nat/{flow}/{artifact}");
        assert!(
            run_dir.join(&path).is_file(),
            "{flow}: the run is missing its {artifact}",
        );
    }
}

/// **`portmap-highid`.** rmule's **Port Mapper** (ADR-0086) against a real
/// miniupnpd gateway: the mapping lands in the gateway's own lease table on the
/// **exact** port, the gateway renews it, Address Learning adopts the granted
/// endpoint, and `release_on_exit` empties the table again.
///
/// `PASS` is the expected label and is asserted as such. ADR-0092's fourth
/// assertion for this row — "Kad verdict flips open" — was `blocked` when the
/// wrapper was written and the flow graded `OBSERVED`; a later change wired the
/// modern ack path and stood two stock-aMule Kad helpers on the WAN, so the
/// claim is now earned from their own bytes. Asserting the claim *name* beside
/// the label is what keeps a `PASS` from being reachable by dropping a claim.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn portmap_highid() {
    if !bench_enabled("portmap-highid") {
        return;
    }
    let run_dir = run_portmap_flow("portmap-highid");
    let verdict = read_string(&run_dir, "portmap-highid-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "portmap-highid: every claim must hold, the Kad flip included:\n{verdict}",
    );
    for expected in [
        "each-gateway-probed-as-its-claimed-nat-type",
        "gateway-table-holds-the-exact-port",
        "every-row-mapped-on-its-own-port",
        "one-renewal-in-the-gateways-own-record",
        "release-on-exit-empties-the-gateway-table",
        "kad-verdict-flips-open",
        "agrees = true",
    ] {
        assert!(
            verdict.contains(expected),
            "portmap-highid: {expected} missing from the verdict:\n{verdict}",
        );
    }
    assert_portmap_artifacts(&run_dir, "portmap-highid");
}

/// **`portmap-mismatch`.** A second LAN host claims 4662/TCP and
/// 4672/UDP on the gateway first, so rmule's `AddPortMapping` conflicts and the
/// IGD2 `AddAnyPortMapping` fallback grants other ports. The TCP row must then
/// read `Degraded` and the port Address Learning would advertise must still be
/// the **bound** one; the UDP rows read `Mapped` at the shifted port and carry
/// it. No reachability recheck is earned, because a `Mismatched` install is not
/// an `Exact` one.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn portmap_mismatch() {
    if !bench_enabled("portmap-mismatch") {
        return;
    }
    let run_dir = run_portmap_flow("portmap-mismatch");
    let verdict = read_string(&run_dir, "portmap-mismatch-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "portmap-mismatch: the shifted-grant path must hold end to end:\n{verdict}",
    );
    for expected in [
        "each-gateway-probed-as-its-claimed-nat-type",
        "the-tcp-row-reads-degraded",
        "the-degraded-tcp-grant-is-never-advertised",
        "a-shifted-udp-grant-is-mapped-and-carried",
        "no-reachability-recheck-was-earned",
        "status = \"degraded\"",
    ] {
        assert!(
            verdict.contains(expected),
            "portmap-mismatch: {expected} missing from the verdict:\n{verdict}",
        );
    }
    assert_portmap_artifacts(&run_dir, "portmap-mismatch");
}

/// **`portmap-ipv6-pinhole`.** A PCP MAP on the **Fake-Public v6 Plan**
/// address, asserted from the gateway's own IPv6 pinhole table (`lease_file6`,
/// which is a different file in a different format from the IPv4 one).
///
/// The bench supplies a **global-scope** v6 next hop on the LAN's own `/64`;
/// `portmap-ipv6-pinhole-link-local` below is the same MAP through the
/// gateway's link-local address.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn portmap_ipv6_pinhole() {
    if !bench_enabled("portmap-ipv6-pinhole") {
        return;
    }
    let run_dir = run_portmap_flow("portmap-ipv6-pinhole");
    let verdict = read_string(&run_dir, "portmap-ipv6-pinhole-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "portmap-ipv6-pinhole: the pinhole must be granted and withdrawn:\n{verdict}",
    );
    for expected in [
        "each-gateway-probed-as-its-claimed-nat-type",
        "the-gateway-opened-a-pinhole-on-the-3fff-address",
        "rmule-graded-the-pinhole-usable",
        "the-pinhole-is-withdrawn-on-exit",
        "family = \"v6\"",
    ] {
        assert!(
            verdict.contains(expected),
            "portmap-ipv6-pinhole: {expected} missing from the verdict:\n{verdict}",
        );
    }
    assert_portmap_artifacts(&run_dir, "portmap-ipv6-pinhole");
}

/// **`portmap-ipv6-pinhole-link-local`**. `portmap-ipv6-pinhole` with the
/// gateway reached through its `fe80::` address, the shape every SLAAC default
/// route takes. The PCP request must still leave from the Known IPv6 its
/// header names — off the gateway's LAN tap — and the pinhole row must name it.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn portmap_ipv6_pinhole_link_local() {
    if !bench_enabled("portmap-ipv6-pinhole-link-local") {
        return;
    }
    let flow = "portmap-ipv6-pinhole-link-local";
    let run_dir = run_portmap_flow(flow);
    let verdict = read_string(&run_dir, &format!("{flow}-verdict.toml"));
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "portmap-ipv6-pinhole-link-local: the pinhole must be granted from the pinned source:\n{verdict}",
    );
    for expected in [
        "each-gateway-probed-as-its-claimed-nat-type",
        "every-pcp-request-went-to-the-link-local-next-hop",
        "every-pcp-request-left-from-its-header-client-address",
        "every-pcp-request-left-from-the-known-ipv6",
        "the-gateway-pinhole-row-names-the-known-ipv6",
        "rmule-graded-the-pinhole-usable",
    ] {
        assert!(
            verdict.contains(expected),
            "portmap-ipv6-pinhole-link-local: {expected} missing from the verdict:\n{verdict}",
        );
    }
    assert_portmap_artifacts(&run_dir, flow);
}
