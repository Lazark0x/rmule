//! The one-link flow's **severed** leg: the sharer goes away while a download
//! rides its link, and the download must keep the sharer as a source rather
//! than fail.
//!
//! aMule turns a `DS_DOWNLOADING` client into `DS_ONQUEUE` at a disconnect
//! and keeps it (`BaseClient.cpp:1283-1284`), asking again a reask period
//! after its last ask. The leg stops the sharer a few seconds into the first
//! transfer, so its link ends mid-part, and watches rmule for a while: the
//! download whose part was in flight must log no `download.failed` and must
//! count a queued source on its `download sources_tick` after the close.
//! The close is read off the tap (the sharer's FIN or RST after its part
//! frames, counterparty bytes); rmule's ticks are `rmule-only`.

use std::fs;
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

use super::verdict::{Addresses, RMULE_PCAP, ROOT_DIR, part_of};
use crate::flow::nat::claims::{Claim, Evidence, label};
use crate::flow::pcap::{records, tcp_capture};

/// The verdict file this leg writes.
pub(crate) const VERDICT: &str = "peer-one-link-severed-verdict.toml";
/// Seconds rmule is watched after the sharer is stopped: several ticks.
pub(crate) const WATCH_SECS: u64 = 45;

/// The close on the tap.
pub(crate) const SEVERED: &str = "the-sharer-closed-the-link-mid-transfer";
/// rmule's record of the riding download after it.
pub(crate) const STOOD: &str = "the-riding-download-kept-its-source-queued";

/// The rows beside the claims.
#[derive(Debug, Default, Serialize, PartialEq)]
struct Rows {
    /// Part frames the sharer sent before its close, and the close's capture
    /// time (`-1` without one).
    parts_before_close: usize,
    closed_at: f64,
    /// The download whose part was in flight at the close (`0` for none).
    rider: u32,
    /// That download's last tick after the close: sources known, asking,
    /// queued and transferring (`-1` without a tick).
    last_tick: [i64; 4],
    /// Whether rmule logged `download.failed` for it.
    failed: bool,
    /// The other downloads that logged `download.failed` after the close: a
    /// download waiting on the link has the same source and no transfer.
    others_failed: Vec<u32>,
}

/// The downloads other than `rider` that logged `download.failed` after
/// `closed`.
fn others_failed(log: &str, closed: f64, rider: u32) -> Vec<u32> {
    log.lines()
        .filter_map(stamped)
        .filter(|&(name, id, at)| name == "download.failed" && id != rider && at >= closed)
        .map(|(_, id, _)| id)
        .collect()
}

/// The verdict file.
#[derive(Debug, Serialize)]
struct Verdict<'a> {
    #[serde(rename = "scenario")]
    flow: &'static str,
    verdict: &'static str,
    detail: String,
    rows: &'a Rows,
    claim: &'a [Claim],
}

/// A stamped record of rmule's run log: its name, download id and time.
fn stamped(line: &str) -> Option<(&str, u32, f64)> {
    let mut words = line.split_whitespace();
    let mut name = words.next()?;
    let mut fields: Vec<&str> = words.collect();
    // `download sources_tick` carries its record name as a second word.
    if name == "download" && fields.first().is_some_and(|word| !word.contains('=')) {
        name = fields.remove(0);
    }
    let field = |key: &str| fields.iter().find_map(|field| field.strip_prefix(key));
    let at = field("at_unix_ms=")?.parse::<f64>().ok()? / 1000.0;
    Some((name, field("id=")?.parse().ok()?, at))
}

/// The download whose part was assigned last before `closed`, whether it
/// failed, and its last tick after `closed` as known, asking, queued and
/// transferring.
fn after_close(log: &str, closed: f64) -> (u32, bool, [i64; 4]) {
    let rider = log
        .lines()
        .filter_map(stamped)
        .rfind(|&(name, _, at)| name == "download.part_assigned" && at <= closed)
        .map_or(0, |(_, id, _)| id);
    let failed = log
        .lines()
        .filter_map(stamped)
        .any(|(name, id, _)| name == "download.failed" && id == rider);
    let tick = log
        .lines()
        .rfind(|line| {
            stamped(line)
                .is_some_and(|(name, id, at)| name == "sources_tick" && id == rider && at > closed)
        })
        .map_or([-1; 4], |line| {
            ["known=", "asking=", "queued=", "transferring="].map(|key| {
                line.split_whitespace()
                    .find_map(|field| field.strip_prefix(key))
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(-1)
            })
        });
    (rider, failed, tick)
}

/// Score the severed run under `run_dir` and write [`VERDICT`]; the verdict.
///
/// # Errors
/// If the addresses, the tap or rmule's log cannot be read.
pub fn score_run_dir(run_dir: &Path) -> Result<&'static str> {
    let root = run_dir.join(ROOT_DIR);
    let at: Addresses = toml::from_str(
        &fs::read_to_string(root.join("addresses.toml")).context("read addresses.toml")?,
    )
    .context("parse addresses.toml")?;
    let capture = tcp_capture(&records(&root.join(RMULE_PCAP))?)?;
    let log_path = run_dir.join("rmule").join("stdout.log");
    let log =
        fs::read_to_string(&log_path).with_context(|| format!("read {}", log_path.display()))?;

    let from_sharer = |ip: IpAddr| ip == IpAddr::V4(at.sharer);
    let parts: Vec<f64> = capture
        .streams
        .iter()
        .filter(|stream| from_sharer(stream.source.ip()))
        .flat_map(|stream| stream.ed2k_frames())
        .filter(|frame| part_of(frame).is_some())
        .map(|frame| frame.at)
        .collect();
    let first_part = parts.iter().copied().reduce(f64::min);
    let closed = first_part.and_then(|first| {
        capture
            .closes
            .iter()
            .find(|close| from_sharer(close.source.ip()) && close.at > first)
            .map(|close| close.at)
    });
    let (rider, failed, last_tick) = closed.map_or((0, false, [-1; 4]), |at| after_close(&log, at));
    let rows = Rows {
        parts_before_close: closed.map_or(0, |at| parts.iter().filter(|&&part| part <= at).count()),
        closed_at: closed.unwrap_or(-1.0),
        rider,
        last_tick,
        failed,
        others_failed: closed.map_or_else(Vec::new, |at| others_failed(&log, at, rider)),
    };
    let claims = vec![
        Claim::about(
            SEVERED,
            closed.is_some(),
            Evidence::Captured,
            format!(
                "the sharer's FIN or RST after its first part frame: {}; part frames before it: {}",
                closed.map_or("none".to_owned(), |at| format!("{at:.3}")),
                rows.parts_before_close
            ),
        ),
        Claim::about(
            STOOD,
            rider != 0 && !failed && last_tick[2] >= 1,
            Evidence::RmuleOnly,
            format!(
                "download {rider}: download.failed logged {failed}; its last sources_tick after \
                 the close reads known {}, asking {}, queued {}, transferring {}",
                last_tick[0], last_tick[1], last_tick[2], last_tick[3]
            ),
        ),
    ];
    let (verdict, detail) = label(&claims);
    let text = toml::to_string_pretty(&Verdict {
        flow: "peer-one-link-severed",
        verdict,
        detail,
        rows: &rows,
        claim: &claims,
    })
    .context("serialize the severed verdict")?;
    fs::write(run_dir.join(VERDICT), &text).context("write the severed verdict")?;
    println!("{text}");
    Ok(verdict)
}

#[cfg(test)]
mod tests {
    use super::{after_close, others_failed};

    #[test]
    fn the_rider_is_read_at_the_close_and_judged_by_its_ticks_after_it() {
        let log = "download.part_assigned id=1 peer=172.18.0.3:4662 part_index=0 at_unix_ms=1000\n\
                   download sources_tick id=1 at_unix_ms=1500 known=1 asking=0 queued=0 transferring=1\n\
                   download.part_released id=1 peer=172.18.0.3:4662 part_index=0 reason=peer_retired retired=peer_disconnected at_unix_ms=2100\n\
                   download sources_tick id=1 at_unix_ms=3000 known=1 asking=0 queued=1 transferring=0\n\
                   download sources_tick id=2 at_unix_ms=3000 known=1 asking=0 queued=1 transferring=0\n";
        assert_eq!(after_close(log, 2.0), (1, false, [1, 0, 1, 0]));
        let failed =
            format!("{log}download.failed id=1 failure=no_usable_sources at_unix_ms=3100\n");
        assert_eq!(after_close(&failed, 2.0), (1, true, [1, 0, 1, 0]));
        assert_eq!(after_close(log, 0.5).0, 0);
        let waiter =
            format!("{log}download.failed id=2 failure=no_usable_sources at_unix_ms=2105\n");
        assert_eq!(others_failed(&waiter, 2.0, 1), [2]);
        assert!(others_failed(&waiter, 2.2, 1).is_empty());
    }
}
