//! `peer-oversized-range` (ADR-0031's block-request cap): a peer that holds a
//! slot asks rmule for one `0..4 GiB` `OP_REQUESTPARTS_I64` on a large shared
//! file, and a second peer asks for an ordinary block afterwards.
//!
//! **Both peers are `rmule-tools`, not a counterparty.** This is a robustness
//! claim, not interop: no stock client sends this ask, and what is measured is
//! rmule surviving it. It borrows the IPv6 bench for its server and network.

use std::fs::File;

use anyhow::{Context, Result};

use crate::flow::bench::Bench;
use crate::flow::nat::dialect::bench::{
    HOST_ED2KSRV, HOST_QUEUED, Ipv6DialectOptions, Stage, body_log, out, run_driver,
    start_detached_driver,
};
use crate::flow::nat::dialect::legs::RMULE_USER_HASH;
use crate::flow::nat::dialect::verdict::{Claim, Evidence};
use crate::flow::nat::dialect::{BODY_PEER_TCP_PORT, ED2KSRV_TCP_PORT};
use crate::flow::nat::synthetic::write_hashed;

/// The large file: sparse, past 4 GiB, so a `0..4 GiB` range lies inside it and
/// only the length rule can refuse it, and the 64-bit opcode is the one a
/// session frames.
const LARGE_BYTES: u64 = (4 << 30) + (1 << 20);
/// The one range the slot holder asks for.
const OVERSIZED_RANGE: &str = "0-4294967296";
/// rmule's container role and its bounded run.
const RMULE_ROLE: &str = "oversized";
const RMULE_SECS: u64 = 900;
/// The line rmule prints once its files are offered.
const ANNOUNCED: &str = "serve.files_announced";
/// How long the slot holder keeps its link after the ask.
const HOLDER_SECS: u64 = 25;
/// How long the second peer's ordinary download may take.
const CONTROL_SECS: u64 = 45;

fn link_of(hash_log: &str) -> Result<String> {
    hash_log
        .lines()
        .find_map(|line| line.strip_prefix("canonical_link: "))
        .map(str::to_owned)
        .context("the hash run printed no canonical link")
}

fn capture_args(link: &str, peer: &str, leg: &str, hash: &str, secs: u64) -> Vec<String> {
    [
        "ed2k",
        "peer",
        "transfer",
        "capture",
        "--peer",
        peer,
        "--file",
        link,
        "--output-dir",
        &out(leg),
        "--user-hash",
        hash,
        "--max-seconds",
        &secs.to_string(),
    ]
    .map(str::to_owned)
    .to_vec()
}

/// Drive the flow and return its claims.
///
/// # Errors
/// If rmule cannot start or a file cannot be staged. A peer run that ends
/// badly is a row.
pub(super) fn drive(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
) -> Result<(Vec<Claim>, String)> {
    let large_dir = stage.leg_dir.join("large");
    let small_dir = stage.leg_dir.join("small");
    for dir in [&large_dir, &small_dir] {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    File::create(large_dir.join("large.bin"))
        .and_then(|file| file.set_len(LARGE_BYTES))
        .context("stage the sparse large file")?;
    let small = write_hashed(&small_dir, 1 << 20)?;
    run_driver(
        bench,
        options,
        stage,
        "hash-large",
        &[
            "ed2k".to_owned(),
            "hash-file".to_owned(),
            out("large/large.bin"),
        ],
    )?;
    let large_link = link_of(
        &std::fs::read_to_string(stage.leg_dir.join("hash-large.log"))
            .context("read the large file's hash run")?,
    )?;

    let rmule_v4 = stage.v4(HOST_QUEUED).to_owned();
    let args = [
        "ed2k",
        "serve",
        "start",
        "--file",
        &out("large/large.bin"),
        "--file",
        &out("small/shared.bin"),
        "--server",
        &format!("{}:{ED2KSRV_TCP_PORT}", stage.v4(HOST_ED2KSRV)),
        "--listen",
        &format!("0.0.0.0:{BODY_PEER_TCP_PORT}"),
        "--own-ip",
        &rmule_v4,
        "--user-hash",
        RMULE_USER_HASH,
        "--max-seconds",
        &RMULE_SECS.to_string(),
    ]
    .map(str::to_owned);
    let (rmule, announced) = start_detached_driver(
        bench,
        options,
        stage,
        RMULE_ROLE,
        HOST_QUEUED,
        &args,
        ANNOUNCED,
    )?;
    if !announced {
        let log = body_log(bench, stage, &rmule, "rmule")?;
        anyhow::bail!(
            "rmule never offered its files: {}",
            log.lines().last().unwrap_or_default()
        );
    }

    let peer = format!("{rmule_v4}:{BODY_PEER_TCP_PORT}");
    let mut holder = capture_args(
        &large_link,
        &peer,
        "holder",
        "61616161616161616161616161616161",
        HOLDER_SECS,
    );
    holder.extend(["--range".to_owned(), OVERSIZED_RANGE.to_owned()]);
    let holder_ran = run_driver(bench, options, stage, "holder", &holder);
    let control_ran = run_driver(
        bench,
        options,
        stage,
        "control",
        &capture_args(
            &small.link,
            &peer,
            "control",
            "62626262626262626262626262626262",
            CONTROL_SECS,
        ),
    );
    let still_up = crate::flow::bench::run_checked(
        bench.docker.inspect_state(rmule.clone()),
        "ask whether rmule still runs",
    )
    .is_ok_and(|said| said.contains("running"));
    let log = body_log(bench, stage, &rmule, "rmule")?;
    let holder_log =
        std::fs::read_to_string(stage.leg_dir.join("holder.log")).context("read the holder")?;
    let control_log =
        std::fs::read_to_string(stage.leg_dir.join("control.log")).context("read the control")?;

    let refused = line_of(&log, "serve.block_ask_refused");
    let holder_peer = refused
        .split_whitespace()
        .find_map(|field| field.strip_prefix("peer="))
        .unwrap_or_default()
        .to_owned();
    let released = log.lines().find(|line| {
        line.contains("serve.upload_slot_released") && line.contains(&format!("peer={holder_peer}"))
    });
    let control_parts =
        control_log.matches("PartReceived").count() + control_log.matches("part_received").count();
    let claims = vec![
        Claim::about(
            "rmule-refused-the-range-with-no-read",
            !refused.is_empty(),
            Evidence::RmuleOnly,
            refused.to_owned(),
        ),
        Claim::about(
            "rmule-ended-that-peers-slot",
            released.is_some(),
            Evidence::RmuleOnly,
            released.unwrap_or_default().to_owned(),
        ),
        Claim::about(
            "rmule-stayed-up",
            still_up,
            Evidence::RmuleOnly,
            format!("rmule's container running after both peers: {still_up}"),
        ),
        Claim::about(
            "rmule-kept-serving-others",
            control_ran.is_ok() && control_parts > 0,
            Evidence::RmuleOnly,
            format!(
                "the second peer read {control_parts} part events; holder driver {holder_ran:?}; \
                 the holder's last line: {}",
                holder_log.lines().last().unwrap_or_default()
            ),
        ),
    ];
    Ok((
        claims,
        "A robustness claim with a harness peer, not interop: both peers are rmule-tools."
            .to_owned(),
    ))
}

fn line_of<'a>(log: &'a str, marker: &str) -> &'a str {
    log.lines()
        .find(|line| line.contains(marker))
        .unwrap_or_default()
}
