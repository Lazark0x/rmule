//! Flow L, the consume leg (`peer-udp-reask`): a stock aMule held queued by a
//! serving rmule reasks over client UDP, and the retained tap is scored on
//! bytes — the `0x90` it sent, the `0x91` rmule answered with, and no TCP
//! fallback after the answer.
//!
//! Each run waits out aMule's ~21.4-minute `FILEREASKTIME`, so every wrapper
//! is meant to score a retained run: drive the subcommand once in the
//! foreground, then point `RMULE_BENCH_VERDICT_DIR` at its run dir (or at
//! `peer-udp-reask-score`'s output for an archived one).

use super::{bench_enabled, read_string, run_flow};
use crate::fixture::unused_local_port;

/// The claims every consume run makes.
const CLAIMS: [&str; 3] = [
    "the-reasker-pinged-rmules-client-udp-port",
    "rmule-answered-with-the-0x91-aMule-itself-writes",
    "the-reasker-opened-no-tcp-link-after-the-ack",
];

/// The claims only a run with peer obfuscation armed makes.
const CRYPT_CLAIMS: [&str; 2] = [
    "the-answer-left-obfuscated",
    "the-answer-opens-under-no-other-key",
];

fn assert_scored(label: &str, extra_args: &[&str], extra_claims: &[&str]) -> String {
    let port = unused_local_port();
    let port_arg = port.port().to_string();
    drop(port); // before the container's own host-port publish binds it
    let mut args = vec!["--skip-build", "--server-host-port", &port_arg];
    args.extend_from_slice(extra_args);
    let run_dir = run_flow("peer-udp-reask", &args);
    let verdict = read_string(&run_dir, "peer-udp-reask-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "{label}: every claim must hold:\n{verdict}",
    );
    for claim in CLAIMS.iter().chain(extra_claims) {
        assert!(
            verdict.contains(&format!("name = \"{claim}\"")),
            "{label}: {claim} missing from the verdict:\n{verdict}",
        );
    }
    verdict
}

/// **Flow L — plain consume.** aMule's `0x90` arrives in the clear and rmule's
/// `0x91` is byte-identical to the one aMule itself writes.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1; ~25 min, score a retained run with RMULE_BENCH_VERDICT_DIR"]
fn peer_udp_reask_consume_plain() {
    if !bench_enabled("L") {
        return;
    }
    assert_scored("flow L plain", &[], &[]);
}

/// **Flow L — crypt consume.** Both ends claim the crypt layer on the first
/// fake-public `/24`: aMule's `0x90` arrives obfuscated and rmule's `0x91`
/// leaves obfuscated, opening under the reasker's hash and rmule's address.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1; ~25 min, score a retained run with RMULE_BENCH_VERDICT_DIR"]
fn peer_udp_reask_consume_crypt() {
    if !bench_enabled("L-crypt") {
        return;
    }
    assert_scored(
        "flow L crypt",
        &[
            "--peer-crypt",
            "supported",
            "--amule-env",
            "AMULE_CRYPT_SUPPORTED=1",
            "--amule-env",
            "AMULE_CRYPT_REQUESTED=1",
        ],
        &CRYPT_CLAIMS,
    );
}

/// **Flow L — consume flip to `off`.** Both ends start on the crypt layer, so
/// the reasker learns rmule's claim before rmule's policy drops to `off` at
/// 300 s. Its `0x90` ~21 minutes later still arrives obfuscated; rmule must
/// open it under `off` and answer in the clear, as aMule trial-decrypts every
/// client datagram whatever its own setting (`EncryptedDatagramSocket.cpp:136`).
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1; ~25 min, score a retained run with RMULE_BENCH_VERDICT_DIR"]
fn peer_udp_reask_consume_flip_to_off() {
    if !bench_enabled("L-flip") {
        return;
    }
    let verdict = assert_scored(
        "flow L flip to off",
        &[
            "--peer-crypt",
            "supported",
            "--amule-env",
            "AMULE_CRYPT_SUPPORTED=1",
            "--amule-env",
            "AMULE_CRYPT_REQUESTED=1",
            "--peer-crypt-flip",
            "300:off",
        ],
        &[],
    );
    assert!(
        verdict.contains("obfuscated; opened to c590") && verdict.contains("[judged obfuscated]"),
        "flow L flip to off: the reasker's ping must arrive obfuscated:\n{verdict}",
    );
    assert!(
        verdict.contains("opened to c591") && verdict.contains("[judged plain]"),
        "flow L flip to off: rmule must answer in the clear under off:\n{verdict}",
    );
}
