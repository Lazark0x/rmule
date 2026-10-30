//! The Source Handover verdict, scored from a retained run dir.
//!
//! The tap names every frame rmule sent the sharer and when; the asks among
//! them are replayed through aMule's own scoring (`CheckForAggressive`, stock
//! 2.3.3 `UploadClient.cpp:795-825`). rmule's run log says the handover
//! happened, scored `rmule-only`; the sharer's part frames and the copy are
//! counterparty bytes (ADR-0045).

use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::flow::identity::parse_ed2k_file_hash;
use crate::flow::nat::claims::{Claim, Evidence, label};
use crate::flow::pcap::{TcpCapture, records, tcp_capture};
use crate::flow::peer::one_link::verdict::{part_of, requested};
use crate::flow::peer::udp_reask_emit::standing::{
    Ask, BAN_SCORE, FILE_REASK_SECS, StandingRun, aggressiveness, asks,
};

/// The flow's name and its verdict file's stem.
pub(crate) const FLOW: &str = "peer-source-handover";
/// Where the flow's own artifacts sit under the run dir.
pub(crate) const ROOT_DIR: &str = "peer-source-handover";
/// The tap in rmule's namespace.
pub(crate) const RMULE_PCAP: &str = "rmule.pcap";
/// The second download's copy, under rmule's dir.
pub(crate) const SECOND_COPY: &str = "output-2.bin";
/// The addresses the run stood its bodies at.
const ADDRESSES: &str = "addresses.toml";
/// The sharer's peer listener.
const SHARER_PORT: u16 = 4662;

/// The bodies' addresses, written by the flow and read back by the scorer.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Addresses {
    /// rmule's address.
    pub(crate) rmule: Ipv4Addr,
    /// The sharer's address.
    pub(crate) sharer: Ipv4Addr,
}

impl Addresses {
    /// Write them under the flow's dir `dir`.
    pub(crate) fn write(&self, dir: &Path) -> Result<()> {
        let path = dir.join(ADDRESSES);
        fs::write(&path, toml::to_string(self).context("serialize addresses")?)
            .with_context(|| format!("write {}", path.display()))
    }
}

/// What the claims read, in capture seconds.
#[derive(Debug, Default, Serialize, PartialEq)]
struct Rows {
    /// rmule's distinct connections to the sharer's listener.
    links: usize,
    /// rmule's last ask of the sharer before the second file's first word.
    last_ask_at: f64,
    /// rmule's first frame naming the second file.
    second_first_word_at: f64,
    /// The gap between them, the handover's wait.
    wait_secs: f64,
    /// aMule's replayed score after each ask.
    aggressiveness: Vec<u32>,
    /// The second copy's length, `-1` when never written.
    second_copy_bytes: i64,
    /// The sharer's part frames of each file.
    first_file_part_frames: usize,
    second_file_part_frames: usize,
}

#[derive(Debug, Serialize)]
struct Verdict<'a> {
    #[serde(rename = "scenario")]
    flow: &'static str,
    verdict: &'static str,
    detail: String,
    rows: &'a Rows,
    claim: &'a [Claim],
}

struct Observed {
    capture: TcpCapture,
    asks: Vec<Ask>,
    /// The first file's hash, then the second's.
    hashes: [[u8; 16]; 2],
    second_copy: Option<Vec<u8>>,
    second_staged: Vec<u8>,
    log: String,
}

/// Score `run_dir` and write `<FLOW>-verdict.toml` there.
///
/// # Errors
/// If the addresses, the tap, a staged file or rmule's log cannot be read.
pub fn score_run_dir(run_dir: &Path) -> Result<&'static str> {
    let root = run_dir.join(ROOT_DIR);
    let addresses_path = root.join(ADDRESSES);
    let at: Addresses = toml::from_str(
        &fs::read_to_string(&addresses_path)
            .with_context(|| format!("read {}", addresses_path.display()))?,
    )
    .with_context(|| format!("parse {}", addresses_path.display()))?;
    let observed = observe(run_dir, &at)?;
    let (claims, rows) = claims(&at, &observed);
    let (verdict, detail) = label(&claims);
    let text = toml::to_string_pretty(&Verdict {
        flow: FLOW,
        verdict,
        detail,
        rows: &rows,
        claim: &claims,
    })
    .context("serialize the verdict")?;
    let path = run_dir.join(format!("{FLOW}-verdict.toml"));
    fs::write(&path, &text).with_context(|| format!("write {}", path.display()))?;
    println!("{text}");
    Ok(verdict)
}

fn observe(run_dir: &Path, at: &Addresses) -> Result<Observed> {
    let root = run_dir.join(ROOT_DIR);
    let pcap = root.join(RMULE_PCAP);
    let hash_of = |dir: &str| -> Result<[u8; 16]> {
        let path = root.join(dir).join("stream.ed2k.txt");
        let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        parse_ed2k_file_hash(text.trim())
    };
    let staged_path = root.join("second/stream.mkv");
    let log_path = run_dir.join("rmule").join("stdout.log");
    Ok(Observed {
        capture: tcp_capture(&records(&pcap)?)?,
        asks: asks(&StandingRun {
            pcap: &pcap,
            rmule: at.rmule,
            sharer: at.sharer,
        })?,
        hashes: [hash_of("first")?, hash_of("second")?],
        // A copy never written is a download not finishing: an observation.
        second_copy: fs::read(run_dir.join("rmule").join(SECOND_COPY)).ok(),
        second_staged: fs::read(&staged_path)
            .with_context(|| format!("read {}", staged_path.display()))?,
        log: fs::read_to_string(&log_path)
            .with_context(|| format!("read {}", log_path.display()))?,
    })
}

fn is_v4(address: SocketAddr, ip: Ipv4Addr) -> bool {
    matches!(address, SocketAddr::V4(v4) if *v4.ip() == ip)
}

/// When the link dialed at `opened` ended, read off the capture's FINs and
/// RSTs on its port; `f64::INFINITY` when it never did.
fn link_end(capture: &TcpCapture, rmule_side: SocketAddr, opened: f64) -> f64 {
    capture
        .closes
        .iter()
        .filter(|close| close.at >= opened)
        .filter(|close| close.source == rmule_side || close.destination == rmule_side)
        .map(|close| close.at)
        .next()
        .unwrap_or(f64::INFINITY)
}

/// Whether no two of `links` (`(opened, ended)`) stood at once.
fn one_at_a_time(links: &[(f64, f64)]) -> bool {
    links
        .windows(2)
        .all(|pair| pair[0].1 <= pair[1].0)
}

fn claims(at: &Addresses, seen: &Observed) -> (Vec<Claim>, Rows) {
    let [first, second] = seen.hashes;
    let mut dials: Vec<_> = seen
        .capture
        .opens
        .iter()
        .filter(|open| {
            is_v4(open.source, at.rmule)
                && is_v4(open.destination, at.sharer)
                && open.destination.port() == SHARER_PORT
        })
        .collect();
    // A SYN retransmitted is one dial.
    dials.dedup_by_key(|open| open.source);
    let mut links: Vec<(f64, f64)> = dials
        .iter()
        .map(|open| (open.at, link_end(&seen.capture, open.source, open.at)))
        .collect();
    links.sort_by(|a, b| a.0.total_cmp(&b.0));

    let to_sharer: Vec<_> = seen
        .capture
        .streams
        .iter()
        .filter(|stream| is_v4(stream.source, at.rmule) && is_v4(stream.destination, at.sharer))
        .flat_map(|stream| stream.ed2k_frames())
        .collect();
    let from_sharer: Vec<_> = seen
        .capture
        .streams
        .iter()
        .filter(|stream| is_v4(stream.source, at.sharer) && is_v4(stream.destination, at.rmule))
        .flat_map(|stream| stream.ed2k_frames())
        .collect();
    let part_frames = |hash: [u8; 16]| {
        from_sharer
            .iter()
            .filter(|frame| part_of(frame) == Some(hash))
            .count()
    };
    let second_first_word = to_sharer
        .iter()
        .filter(|frame| requested(frame) == Some(second))
        .map(|frame| frame.at)
        .chain(
            seen.asks
                .iter()
                .filter(|ask| ask.file == second)
                .map(|ask| ask.at),
        )
        .min_by(f64::total_cmp);
    let last_ask = second_first_word.and_then(|word| {
        seen.asks
            .iter()
            .filter(|ask| ask.at < word)
            .map(|ask| ask.at)
            .max_by(f64::total_cmp)
    });
    let scores = aggressiveness(&seen.asks);
    let peak = scores.iter().copied().max().unwrap_or(0);
    let copy_equal = seen.second_copy.as_ref() == Some(&seen.second_staged);
    let handed_over = seen.log.contains("download.source_handed_over id=1");
    let waited = seen.log.contains("download.source_waits_on_standing id=2");
    let verified = seen.log.matches("download.part_verified id=1").count();
    let wait = second_first_word
        .zip(last_ask)
        .map(|(word, ask)| word - ask);
    let rows = Rows {
        links: links.len(),
        last_ask_at: last_ask.unwrap_or(-1.0),
        second_first_word_at: second_first_word.unwrap_or(-1.0),
        wait_secs: wait.unwrap_or(-1.0),
        aggressiveness: scores,
        second_copy_bytes: seen
            .second_copy
            .as_ref()
            .map_or(-1, |copy| i64::try_from(copy.len()).unwrap_or(i64::MAX)),
        first_file_part_frames: part_frames(first),
        second_file_part_frames: part_frames(second),
    };
    let claims = vec![
        Claim::about(
            "the-sharer-had-nothing-more-of-the-first-file",
            verified == 1 && rows.first_file_part_frames > 0,
            Evidence::Captured,
            format!(
                "{} part frames of the first file, {verified} part verified",
                rows.first_file_part_frames
            ),
        ),
        Claim::about(
            "the-standing-passed-to-the-second-download",
            handed_over && waited,
            Evidence::RmuleOnly,
            format!("handed over logged: {handed_over}; second waits logged: {waited}"),
        ),
        Claim::about(
            "the-second-files-first-word-came-on-the-peers-clock",
            wait.is_some_and(|wait| wait >= FILE_REASK_SECS),
            Evidence::Captured,
            format!(
                "first word {:.1} s after rmule's last ask of the sharer; aMule's period is {FILE_REASK_SECS} s",
                rows.wait_secs
            ),
        ),
        Claim::about(
            "one-socket-at-a-time",
            !links.is_empty() && one_at_a_time(&links),
            Evidence::Captured,
            format!("{} links to the sharer: {links:?}", links.len()),
        ),
        Claim::about(
            "no-aggressive-score",
            peak == 0,
            Evidence::RmuleOnly,
            format!("aMule's replayed score peaked at {peak} of {BAN_SCORE}"),
        ),
        Claim::about(
            "the-sharer-served-the-second-file-unbanned",
            copy_equal && rows.second_file_part_frames > 0,
            Evidence::Captured,
            format!(
                "{} part frames of the second file, copy {} bytes, byte-equal: {copy_equal}",
                rows.second_file_part_frames, rows.second_copy_bytes
            ),
        ),
    ];
    (claims, rows)
}

#[cfg(test)]
mod tests {
    use super::one_at_a_time;

    #[test]
    fn links_overlap_only_when_one_opens_before_the_last_ended() {
        assert!(one_at_a_time(&[(1.0, 2.0), (2.0, f64::INFINITY)]));
        assert!(!one_at_a_time(&[(1.0, 5.0), (2.0, 6.0)]));
    }
}
