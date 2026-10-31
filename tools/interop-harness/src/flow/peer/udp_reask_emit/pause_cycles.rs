//! The Pause and Resume leg: rmule stands queued at a stock aMule sharer and
//! its operator pauses and resumes the download again and again inside
//! `MIN_REQUESTTIME` (590 s). A Resume is no ask of its own: a source that
//! holds nothing we need keeps its spacing across it (ADR-0107), so aMule's
//! `CheckForAggressive` (stock 2.3.3 `UploadClient.cpp:795-825`) never reaches
//! its ban.
//!
//! The sharer's own word decides: its logfile, on the debug image with
//! `AMULE_DEBUG_PEER_CATEGORIES=1`, carries `logClient`'s `Aggressive client
//! banned` line (`UploadClient.cpp:811`) when it bans. The asks replayed off
//! the tap sit beside it.

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Serialize;

use super::standing::{self, Ask, BAN_SCORE, Road, StandingRun};
use crate::flow::nat::claims::{Claim, Evidence, label};

/// The file whose existence holds rmule's downloads paused, under the run dir.
pub(crate) const GATE: &str = "pause-cycle-gate";
/// How long each Pause stands.
const PAUSED: Duration = Duration::from_secs(30);
/// How long the download runs between a Resume and the next Pause: past the
/// seconds a dial and hello take, so a Resume that would ask has asked.
const RUNNING: Duration = Duration::from_secs(70);
/// The sharer's `MIN_REQUESTTIME` (`Constants.h:67`), seconds.
const MIN_REQUEST_SECS: f64 = 590.0;
/// `logClient`'s ban line, `UploadClient.cpp:811`.
const BAN_LINE: &str = "Aggressive client banned";
/// A `logClient` or peer-protocol line any hello writes: without one the
/// logfile cannot speak for the rule.
const CATEGORY_ON: &str = "Remote Client:";
/// What the core prints at each gate.
const PAUSED_LINE: &str = "download paused_at_gate";
const RESUMED_LINE: &str = "download resumed_at_gate";

/// Pause and resume `cycles` times through the gate under `root`. Returns how
/// long that took.
pub(crate) fn drive(root: &Path, cycles: u32) -> Result<Duration> {
    let gate = root.join(GATE);
    let started = std::time::Instant::now();
    for cycle in 1..=cycles {
        fs::write(&gate, b"").with_context(|| format!("raise {}", gate.display()))?;
        println!("peer_udp_reask_emit pause_cycle={cycle} paused");
        std::thread::sleep(PAUSED);
        fs::remove_file(&gate).with_context(|| format!("drop {}", gate.display()))?;
        println!("peer_udp_reask_emit pause_cycle={cycle} resumed");
        std::thread::sleep(RUNNING);
    }
    Ok(started.elapsed())
}

/// When each line of `log` carrying `line` was stamped.
fn stamps(log: &str, line: &str) -> Vec<f64> {
    log.lines()
        .filter(|text| text.contains(line))
        .filter_map(|text| {
            let ms = text.rsplit_once("at_unix_ms=")?.1;
            ms.trim().parse::<f64>().ok().map(|ms| ms / 1000.0)
        })
        .collect()
}

/// What the run's word is on the rule.
struct Facts<'a> {
    cycles: u32,
    /// rmule's Run Log.
    rmule_log: &'a str,
    /// The sharer's logfile.
    sharer_log: &'a str,
    asks: &'a [Ask],
}

fn claims(facts: &Facts<'_>) -> Vec<Claim> {
    let paused = stamps(facts.rmule_log, PAUSED_LINE);
    let resumed = stamps(facts.rmule_log, RESUMED_LINE);
    let span = paused.first().zip(resumed.last()).map(|(a, b)| b - a);
    let scores = standing::aggressiveness(facts.asks);
    let peak = scores.iter().copied().max().unwrap_or(0);
    let bans = facts
        .sharer_log
        .lines()
        .filter(|line| line.contains(BAN_LINE))
        .count();
    let slot_asks = facts
        .asks
        .iter()
        .filter(|ask| ask.road == Road::SlotAsk)
        .count();
    let cycles = facts.cycles as usize;
    vec![
        Claim::about(
            "the-cycles-ran-inside-the-sharers-period",
            paused.len() == cycles
                && resumed.len() == cycles
                && span.is_some_and(|secs| secs < MIN_REQUEST_SECS),
            Evidence::Captured,
            format!(
                "{} pauses, {} resumes, first pause to last resume {span:?} s",
                paused.len(),
                resumed.len()
            ),
        ),
        Claim::about(
            "the-sharers-log-can-speak",
            facts.sharer_log.contains(CATEGORY_ON),
            Evidence::Captured,
            format!("`{CATEGORY_ON}` in the sharer's logfile, the debug categories on"),
        ),
        Claim::about(
            "no-aggressive-client-banned-line",
            bans == 0,
            Evidence::Captured,
            format!("`{BAN_LINE}` lines in the sharer's logfile: {bans}"),
        ),
        Claim::about(
            "aggressiveness-under-the-ban",
            peak < BAN_SCORE,
            Evidence::Captured,
            format!("{slot_asks} slot asks on the tap; aMule's score replayed: {scores:?}"),
        ),
    ]
}

/// The verdict file.
#[derive(Debug, Serialize)]
struct Verdict<'a> {
    #[serde(rename = "scenario")]
    flow: &'static str,
    verdict: &'static str,
    detail: String,
    claim: &'a [Claim],
}

/// Score the run and write its verdict under `root`.
///
/// # Errors
/// If the tap or a log cannot be read, or the verdict cannot be written.
pub(crate) fn write(
    root: &Path,
    run: &StandingRun<'_>,
    cycles: u32,
    sharer_log: &Path,
) -> Result<&'static str> {
    let asks = standing::asks(run)?;
    let log_path = root.join("rmule").join("stdout.log");
    let rmule_log =
        fs::read_to_string(&log_path).with_context(|| format!("read {}", log_path.display()))?;
    let sharer_log = fs::read_to_string(sharer_log).unwrap_or_default();
    let claims = claims(&Facts {
        cycles,
        rmule_log: &rmule_log,
        sharer_log: &sharer_log,
        asks: &asks,
    });
    let (verdict, detail) = label(&claims);
    let text = toml::to_string_pretty(&Verdict {
        flow: "peer-udp-reask-emit-pause-cycles",
        verdict,
        detail,
        claim: &claims,
    })
    .context("serialize the pause-cycle verdict")?;
    let path = root.join("peer-udp-reask-emit-pause-cycles-verdict.toml");
    fs::write(&path, &text).with_context(|| format!("write {}", path.display()))?;
    println!("peer_udp_reask_emit pause_cycles_verdict={verdict}");
    Ok(verdict)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = "download paused_at_gate ids=1 at_unix_ms=100000\n\
        download resumed_at_gate ids=1 at_unix_ms=130000\n\
        download paused_at_gate ids=1 at_unix_ms=200000\n\
        download resumed_at_gate ids=1 at_unix_ms=230000\n";

    fn held(claims: &[Claim], name: &str) -> bool {
        claims
            .iter()
            .any(|claim| claim.name == name && claim.outcome == "held")
    }

    /// The ban line in the sharer's own log fails the rule whatever the tap
    /// replays to, and a log with no client category says nothing.
    #[test]
    fn the_sharers_ban_line_decides() {
        let facts = |sharer_log| Facts {
            cycles: 2,
            rmule_log: LOG,
            sharer_log,
            asks: &[],
        };
        let banned = claims(&facts(
            "Remote Client: x\nAggressive client banned (score: 12): a\n",
        ));
        assert!(!held(&banned, "no-aggressive-client-banned-line"));
        assert!(held(&banned, "the-cycles-ran-inside-the-sharers-period"));
        assert!(!held(
            &claims(&facts("nothing")),
            "the-sharers-log-can-speak"
        ));
    }

    /// Cycles spread past the sharer's period prove nothing of it.
    #[test]
    fn cycles_past_the_period_do_not_count() {
        let log = "download paused_at_gate ids=1 at_unix_ms=0\n\
            download resumed_at_gate ids=1 at_unix_ms=600000\n";
        let facts = Facts {
            cycles: 1,
            rmule_log: log,
            sharer_log: "",
            asks: &[],
        };
        assert!(!held(
            &claims(&facts),
            "the-cycles-ran-inside-the-sharers-period"
        ));
    }
}
