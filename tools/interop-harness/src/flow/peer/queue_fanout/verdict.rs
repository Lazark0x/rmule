//! The queue fan-out verdict, scored from a retained run dir.
//!
//! The tap in rmule's namespace carries every link rmule dialed and every
//! sharer's dial-back to its listener: the dials are the connections the
//! asking budget spent, the part frames each sharer sent are counterparty
//! bytes. Which sharers ranked rmule and which dialed it back is read off the
//! tap, not taken from the shape: a holder that has not yet taken its slot, or
//! has lost it, turns a sharer meant to queue into one that grants at once, and
//! the claims follow what each sharer did. rmule's run log says which sharers
//! it hung up on, which grants it took unasked, and, tick by tick, how many
//! sources asked, waited and transferred at once (ADR-0116).

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::FanoutShape;
use super::run_log::{ActivityPeaks, RunLog};
use crate::flow::bench::AMULE_PEER_TCP_PORT;
use crate::flow::identity::parse_ed2k_file_hash;
use crate::flow::nat::claims::{Claim, Evidence, label};
use crate::flow::pcap::{Ed2kFrame, TcpCapture, records, tcp_capture};
use crate::flow::wire_filter::{OP_EDONKEYPROT, OP_EMULEPROT};
use crate::rmule::RMULE_SERVE_TCP_PORT;

/// The flow's name and its verdict file's stem.
pub(crate) const FLOW: &str = "peer-queue-fanout";
/// Where the flow's own artifacts sit under the run dir.
pub(crate) const ROOT_DIR: &str = "peer-queue-fanout";
/// The tap in rmule's namespace.
pub(crate) const RMULE_PCAP: &str = "rmule.pcap";
/// The topology the run stood up.
const TOPOLOGY: &str = "topology.toml";

/// `OP_SENDINGPART`.
const OP_SENDINGPART: u8 = 0x46;
/// The eMule-extension part frames: `OP_COMPRESSEDPART`,
/// `OP_SENDINGPART_I64`, `OP_COMPRESSEDPART_I64`.
const EMULE_PART_FRAMES: [u8; 3] = [0x40, 0xA2, 0xA1];
/// The eD2k frame header ahead of a payload: protocol, length, opcode.
const FRAME_HEADER_LEN: usize = 6;
/// The ranks: `OP_QUEUERANK` (eD2k) and `OP_QUEUERANKING` (eMule).
const OP_QUEUERANK: u8 = 0x5C;
const OP_QUEUERANKING: u8 = 0x60;

/// The claim on the sharers that grant at once.
pub(crate) const FREE_TRANSFERRED: &str = "every-free-sharer-sent-parts";
/// The claim on the sharers that queue rmule.
pub(crate) const QUEUED_HUNG_UP: &str = "rmule-hung-up-on-every-sharer-that-ranked-it";
/// The claim on the sharers that grant late.
pub(crate) const LATE_TAKEN: &str = "every-late-grant-became-a-transfer";
/// The claim on the copy.
pub(crate) const BYTE_EQUAL: &str = "the-download-completed-byte-equal";

/// What the flow stood up, written by the flow and read back by the scorer.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Topology {
    /// rmule's address.
    pub(crate) rmule: Ipv4Addr,
    /// Every sharer's address, in index order: the first `shape.queued`
    /// queue rmule, the first `shape.late` of those grant late.
    pub(crate) sharers: Vec<Ipv4Addr>,
    /// The flow's shape.
    pub(crate) shape: FanoutShape,
}

impl Topology {
    /// Write it under the flow's dir `dir`.
    pub(crate) fn write(&self, dir: &Path) -> Result<()> {
        let path = dir.join(TOPOLOGY);
        fs::write(
            &path,
            toml::to_string(self).context("serialize the topology")?,
        )
        .with_context(|| format!("write {}", path.display()))
    }
}

/// The rows a verdict reports beside its claims: the before/after numbers.
#[derive(Debug, Default, Serialize, PartialEq)]
pub(crate) struct Rows {
    /// The file's bytes over the seconds from rmule's first part assignment
    /// to its completion, KiB/s; `-1.0` when it did not complete.
    pub(crate) throughput_kib_per_sec: f64,
    /// Seconds from the first part assignment to completion; `-1.0` when it
    /// did not complete.
    pub(crate) seconds_to_complete: f64,
    /// rmule's SYNs to a sharer's listener: the roads its asking opened.
    pub(crate) rmule_dials: usize,
    /// Sharers' SYNs to rmule's listener: the grants by dial-back.
    pub(crate) dial_backs: usize,
    /// The most sources asking, queued and transferring at once.
    pub(crate) peaks: ActivityPeaks,
    /// Sharers that sent part frames of rmule's file.
    pub(crate) sharers_sending: usize,
    /// Sharers that sent rmule a rank, and how many of them the shape meant
    /// to queue.
    pub(crate) sharers_ranking: usize,
    pub(crate) ranking_as_shaped: usize,
    /// The copy's length, `-1` when never written.
    pub(crate) copy_bytes: i64,
}

/// The verdict file.
#[derive(Debug, Serialize)]
struct Verdict<'a> {
    #[serde(rename = "scenario")]
    flow: &'static str,
    verdict: &'static str,
    detail: String,
    shape: FanoutShape,
    rows: &'a Rows,
    claim: &'a [Claim],
}

/// What the run left.
struct Observed {
    capture: TcpCapture,
    hash: [u8; 16],
    size: u64,
    copy: (bool, i64),
    log: RunLog,
}

/// Score the run under `run_dir`, write its verdict file and return the
/// verdict.
///
/// # Errors
/// If the topology, the tap, the staged file or rmule's log cannot be read.
pub fn score_run_dir(run_dir: &Path) -> Result<&'static str> {
    let root = run_dir.join(ROOT_DIR);
    let topology_path = root.join(TOPOLOGY);
    let topology: Topology = toml::from_str(
        &fs::read_to_string(&topology_path)
            .with_context(|| format!("read {}", topology_path.display()))?,
    )
    .with_context(|| format!("parse {}", topology_path.display()))?;
    let observed = observe(run_dir)?;
    let (claims, rows) = claims(&topology, &observed);
    let (verdict, detail) = label(&claims);
    let text = toml::to_string_pretty(&Verdict {
        flow: FLOW,
        verdict,
        detail,
        shape: topology.shape,
        rows: &rows,
        claim: &claims,
    })
    .context("serialize the verdict")?;
    let path = run_dir.join(format!("{FLOW}-verdict.toml"));
    fs::write(&path, &text).with_context(|| format!("write {}", path.display()))?;
    println!("{text}");
    Ok(verdict)
}

fn observe(run_dir: &Path) -> Result<Observed> {
    let capture = tcp_capture(&records(&run_dir.join(ROOT_DIR).join(RMULE_PCAP))?)?;
    let synthetic = run_dir.join("synthetic");
    let link_path = synthetic.join("shared.ed2k.txt");
    let link =
        fs::read_to_string(&link_path).with_context(|| format!("read {}", link_path.display()))?;
    let hash = parse_ed2k_file_hash(link.trim())?;
    let staged_path = synthetic.join("shared.bin");
    let staged =
        fs::read(&staged_path).with_context(|| format!("read {}", staged_path.display()))?;
    let copy = fs::read(run_dir.join("rmule").join("output.bin")).map_or((false, -1), |copy| {
        (
            copy == staged,
            i64::try_from(copy.len()).unwrap_or(i64::MAX),
        )
    });
    Ok(Observed {
        capture,
        hash,
        size: u64::try_from(staged.len()).unwrap_or(u64::MAX),
        copy,
        log: RunLog::read(run_dir)?,
    })
}

/// The file a part frame carries: the 16 bytes its payload opens with.
pub(crate) fn part_of(frame: &Ed2kFrame) -> Option<[u8; 16]> {
    let part = (frame.protocol, frame.opcode) == (OP_EDONKEYPROT, OP_SENDINGPART)
        || (frame.protocol == OP_EMULEPROT && EMULE_PART_FRAMES.contains(&frame.opcode));
    let hash = frame.bytes.get(FRAME_HEADER_LEN..FRAME_HEADER_LEN + 16)?;
    part.then(|| hash.try_into().ok()).flatten()
}

/// Part frames of the file `hash` names that `sharer` sent rmule, on any link.
fn parts_from(capture: &TcpCapture, sharer: Ipv4Addr, hash: [u8; 16]) -> usize {
    capture
        .streams
        .iter()
        .filter(|stream| stream.source.ip() == IpAddr::V4(sharer))
        .flat_map(|stream| stream.ed2k_frames())
        .filter(|frame| part_of(frame) == Some(hash))
        .count()
}

/// Whether `sharer` sent rmule a rank, on any link.
fn ranked(capture: &TcpCapture, sharer: Ipv4Addr) -> bool {
    capture
        .streams
        .iter()
        .filter(|stream| stream.source.ip() == IpAddr::V4(sharer))
        .flat_map(|stream| stream.ed2k_frames())
        .any(|frame| {
            (frame.protocol, frame.opcode) == (OP_EDONKEYPROT, OP_QUEUERANK)
                || (frame.protocol, frame.opcode) == (OP_EMULEPROT, OP_QUEUERANKING)
        })
}

/// A claim over a set of sharers: held when `each` holds for every one, with
/// the ones it failed for in the note; blocked when the run drew no such
/// sharer.
fn over_all(
    name: &str,
    sharers: &[Ipv4Addr],
    evidence: Evidence,
    what: &str,
    each: impl Fn(Ipv4Addr) -> bool,
) -> Claim {
    if sharers.is_empty() {
        return Claim::blocked(name, format!("{what}: no such sharer in this run"));
    }
    let failed: Vec<Ipv4Addr> = sharers.iter().copied().filter(|&ip| !each(ip)).collect();
    Claim::about(
        name,
        failed.is_empty(),
        evidence,
        format!("{what}: {} sharers, failed for {failed:?}", sharers.len()),
    )
}

fn claims(at: &Topology, seen: &Observed) -> (Vec<Claim>, Rows) {
    let shape = at.shape;
    let listener = |ip: Ipv4Addr| SocketAddr::from((ip, AMULE_PEER_TCP_PORT));
    let rmule = IpAddr::V4(at.rmule);
    let dialed_back = |ip: Ipv4Addr| {
        seen.capture.opens.iter().any(|open| {
            open.source.ip() == IpAddr::V4(ip)
                && open.destination.ip() == rmule
                && open.destination.port() == RMULE_SERVE_TCP_PORT
        })
    };
    let (queued, free): (Vec<Ipv4Addr>, Vec<Ipv4Addr>) = at
        .sharers
        .iter()
        .partition(|&&ip| ranked(&seen.capture, ip));
    let late: Vec<Ipv4Addr> = queued
        .iter()
        .copied()
        .filter(|&ip| dialed_back(ip))
        .collect();
    let shaped_queued = &at.sharers[..shape.queued.min(at.sharers.len())];
    let sending = |ip: Ipv4Addr| parts_from(&seen.capture, ip, seen.hash) > 0;

    let mut claims = vec![
        over_all(
            FREE_TRANSFERRED,
            &free,
            Evidence::Captured,
            "part frames of rmule's file from each sharer that never ranked it",
            sending,
        ),
        over_all(
            QUEUED_HUNG_UP,
            &queued,
            Evidence::RmuleOnly,
            "rmule's log: download.peer_retired reason=queued for each sharer that ranked it",
            |ip| {
                seen.log.names(
                    "download.peer_retired",
                    listener(ip),
                    Some(("reason", "queued")),
                )
            },
        ),
        over_all(
            LATE_TAKEN,
            &late,
            Evidence::Captured,
            "download.slot_offered in rmule's log and part frames from each sharer that ranked \
             rmule and dialed it back",
            |ip| seen.log.names("download.slot_offered", listener(ip), None) && sending(ip),
        ),
    ];
    let (equal, len) = seen.copy;
    claims.push(Claim::about(
        BYTE_EQUAL,
        equal,
        Evidence::Captured,
        format!("output.bin {len} bytes, equal {equal}"),
    ));

    let rmule_dials = seen
        .capture
        .opens
        .iter()
        .filter(|open| open.source.ip() == rmule && open.destination.port() == AMULE_PEER_TCP_PORT)
        .count();
    // The server's port test dials the same listener; only a sharer's SYN is
    // a grant by dial-back.
    let dial_backs = seen
        .capture
        .opens
        .iter()
        .filter(|open| {
            open.destination.ip() == rmule
                && open.destination.port() == RMULE_SERVE_TCP_PORT
                && at
                    .sharers
                    .iter()
                    .any(|&ip| open.source.ip() == IpAddr::V4(ip))
        })
        .count();
    let started = seen.log.first_at("download.part_assigned");
    let completed = seen.log.first_at("download.completed");
    let seconds = match (started, completed) {
        (Some(start), Some(end)) if end > start => end - start,
        _ => -1.0,
    };
    let throughput = if seconds > 0.0 {
        seen.size as f64 / 1024.0 / seconds
    } else {
        -1.0
    };
    let rows = Rows {
        throughput_kib_per_sec: throughput,
        seconds_to_complete: seconds,
        rmule_dials,
        dial_backs,
        peaks: seen.log.activity_peaks(),
        sharers_sending: at.sharers.iter().filter(|&&ip| sending(ip)).count(),
        sharers_ranking: queued.len(),
        ranking_as_shaped: queued
            .iter()
            .filter(|ip| shaped_queued.contains(ip))
            .count(),
        copy_bytes: len,
    };
    (claims, rows)
}
