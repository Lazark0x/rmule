//! The one-link flow's **stalled** leg (ADR-0056 item 4): a stock aMule seed
//! that holds rmule's download slot stops sending while its link stays up.
//!
//! `tc netem loss 100%` on the seed's egress, a few seconds into the transfer,
//! leaves both sockets open: rmule hears no FIN and no RST, only silence. rmule
//! must send `OP_CANCELTRANSFER` (`0x56`) when its slot budget runs out, keep
//! the seed as a source standing queued, and fail no download. The times come
//! off the tap in rmule's namespace; the source's standing is rmule's own word
//! (`rmule-only`).

use crate::flow::evidence::read_toml;
use crate::verdict::Verdict;
use std::fs;
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

use super::severed::{after_close, stamped};
use super::verdict::{Addresses, RMULE_PCAP, ROOT_DIR, part_of};
use crate::flow::nat::claims::{Claim, Evidence, label};
use crate::flow::pcap::{records, tcp_capture};

/// The verdict file this leg writes.
pub(crate) const VERDICT: &str = "peer-one-link-stalled-verdict.toml";
/// rmule's slot budget, in seconds.
pub(crate) const SLOT_BUDGET_SECS: f64 = 180.0;
/// How far the give-back may land from the budget, in seconds: the budget runs
/// from the last block rmule's session assembled, not from the last frame.
const BUDGET_SLACK_SECS: f64 = 5.0;
/// Seconds rmule is watched after the seed goes silent: past the budget, with
/// time for several ticks behind it.
pub(crate) const WATCH_SECS: u64 = 215;

const OP_EDONKEYPROT: u8 = 0xE3;
const OP_CANCELTRANSFER: u8 = 0x56;

/// The give-back on the tap.
pub(crate) const GAVE_BACK: &str = "rmule-sent-0x56-at-its-slot-budget";
/// The link's state at the give-back.
pub(crate) const STAYED_UP: &str = "the-link-stayed-up-until-the-give-back";
/// rmule's record of the source after it.
pub(crate) const QUEUED: &str = "the-source-stayed-queued";

/// The rows beside the claims.
#[derive(Debug, Default, Serialize, PartialEq)]
struct Rows {
    /// Part frames the seed delivered, and the last one's capture time.
    parts: usize,
    last_part_at: f64,
    /// The first `0x56` rmule sent after that, and how long after it (`-1`
    /// without one), and how many it sent.
    cancel_at: f64,
    cancel_after_secs: f64,
    cancels: usize,
    /// FIN or RST segments from either side before the give-back.
    closes_before_cancel: usize,
    /// The stalled download.
    rider: u32,
    /// Its last tick after the give-back: sources known, asking, queued and
    /// transferring (`-1` without a tick).
    last_tick: [i64; 4],
    /// Whether rmule logged `download.failed` for it.
    failed: bool,
    /// Whether rmule logged the source queued after the give-back.
    source_queued_logged: bool,
}

/// The verdict file.
#[derive(Debug, Serialize)]
struct VerdictFile<'a> {
    #[serde(rename = "scenario")]
    flow: &'static str,
    verdict: Verdict,
    detail: String,
    rows: &'a Rows,
    claim: &'a [Claim],
}

/// Score the stalled run under `run_dir` and write `VERDICT`; the verdict.
///
/// # Errors
/// If the addresses, the tap or rmule's log cannot be read.
pub fn score_run_dir(run_dir: &Path) -> Result<Verdict> {
    let root = run_dir.join(ROOT_DIR);
    let at: Addresses = read_toml(&root.join("addresses.toml"))?;
    let capture = tcp_capture(&records(&root.join(RMULE_PCAP))?)?;
    let log_path = run_dir.join("rmule").join("stdout.log");
    let log =
        fs::read_to_string(&log_path).with_context(|| format!("read {}", log_path.display()))?;

    let sharer = IpAddr::V4(at.sharer);
    let rmule = IpAddr::V4(at.rmule);
    let parts: Vec<f64> = capture
        .streams
        .iter()
        .filter(|stream| stream.source.ip() == sharer)
        .flat_map(|stream| stream.ed2k_frames())
        .filter(|frame| part_of(frame).is_some())
        .map(|frame| frame.at)
        .collect();
    let last_part = parts.iter().copied().reduce(f64::max);
    let cancels: Vec<f64> = capture
        .streams
        .iter()
        .filter(|stream| stream.source.ip() == rmule && stream.destination.ip() == sharer)
        .flat_map(|stream| stream.ed2k_frames())
        .filter(|frame| (frame.protocol, frame.opcode) == (OP_EDONKEYPROT, OP_CANCELTRANSFER))
        .map(|frame| frame.at)
        .filter(|at| last_part.is_some_and(|last| *at > last))
        .collect();
    let cancel = cancels.iter().copied().reduce(f64::min);
    let (rider, failed, last_tick) = cancel.map_or((0, false, [-1; 4]), |at| after_close(&log, at));
    let rows = Rows {
        parts: parts.len(),
        last_part_at: last_part.unwrap_or(-1.0),
        cancel_at: cancel.unwrap_or(-1.0),
        cancel_after_secs: cancel
            .zip(last_part)
            .map_or(-1.0, |(cancel, last)| cancel - last),
        cancels: cancels.len(),
        closes_before_cancel: cancel.map_or(0, |cancel| {
            capture
                .closes
                .iter()
                .filter(|close| {
                    close.at < cancel
                        && [rmule, sharer].contains(&close.source.ip())
                        && [rmule, sharer].contains(&close.destination.ip())
                        && last_part.is_some_and(|last| close.at > last)
                })
                .count()
        }),
        rider,
        last_tick,
        failed,
        source_queued_logged: cancel.is_some_and(|cancel| {
            log.lines().filter_map(stamped).any(|(name, id, at)| {
                name == "download.source_remote_queued" && id == rider && at >= cancel - 1.0
            })
        }),
    };
    let claims = vec![
        Claim::about(
            GAVE_BACK,
            (rows.cancel_after_secs - SLOT_BUDGET_SECS).abs() <= BUDGET_SLACK_SECS,
            Evidence::Captured,
            format!(
                "{} part frames, the last at {:.3}; the first `0x56` after it at {:.3}, {:.1} s \
                 on; {} sent",
                rows.parts, rows.last_part_at, rows.cancel_at, rows.cancel_after_secs, rows.cancels
            ),
        ),
        Claim::about(
            STAYED_UP,
            cancel.is_some() && rows.closes_before_cancel == 0,
            Evidence::Captured,
            format!(
                "{} FIN or RST segments between the last part and the give-back",
                rows.closes_before_cancel
            ),
        ),
        Claim::about(
            QUEUED,
            !rows.failed && rows.source_queued_logged && rows.last_tick[2] >= 1,
            Evidence::RmuleOnly,
            format!(
                "download {}: failed {}, source queued logged {}, last tick \
                 known/asking/queued/transferring {:?}",
                rows.rider, rows.failed, rows.source_queued_logged, rows.last_tick
            ),
        ),
    ];
    let (verdict, detail) = label(&claims);
    let text = toml::to_string_pretty(&VerdictFile {
        flow: "peer-one-link-stalled",
        verdict,
        detail,
        rows: &rows,
        claim: &claims,
    })
    .context("serialize the stalled verdict")?;
    let path = run_dir.join(VERDICT);
    crate::verdict::write(&path, &text)?;
    Ok(verdict)
}
