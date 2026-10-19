//! The queue fan-out verdict, scored from a retained run dir.
//!
//! The tap in rmule's namespace carries every link rmule dialed and every
//! sharer's dial-back to its listener: the dials are the connections the
//! asking budget spent, the part frames each sharer sent are counterparty
//! bytes. Which sharers ranked rmule and which dialed it back is read off the
//! tap, not taken from the shape: a holder that has not yet taken its slot, or
//! has lost it, turns a sharer meant to queue into one that grants at once, and
//! the claims follow what each sharer did. Every sharer is stock aMule 2, so
//! rmule holds each link it was ranked on until the sharer closes it or
//! grants there (ADR-0116, invariant 3). rmule's run log says which grants it
//! took unasked, and, tick by tick, how many sources asked, waited and
//! transferred at once.

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
use crate::flow::pcap::{Ed2kFrame, TcpCapture, TcpClose, records, tcp_capture};
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
/// `OP_ACCEPTUPLOADREQ`: a grant.
const OP_ACCEPTUPLOADREQ: u8 = 0x55;
/// The block requests: `OP_REQUESTPARTS` (eD2k) and `OP_REQUESTPARTS_I64`
/// (eMule).
const OP_REQUESTPARTS: u8 = 0x47;
const OP_REQUESTPARTS_I64: u8 = 0xA3;

/// The claim on the sharers that grant at once.
pub(crate) const FREE_TRANSFERRED: &str = "every-free-sharer-sent-parts";
/// The claim on the links the sharers ranked rmule on: every sharer here is
/// stock aMule 2, which reads no close until its 40 s idle timeout and writes
/// a promotion on the link it still counts as open (`UploadQueue.cpp:211-217`),
/// so rmule holds the link until the sharer closes it or grants on it
/// (ADR-0116, invariant 3).
pub(crate) const QUEUED_HELD: &str =
    "rmule-held-each-ranked-link-until-the-sharer-closed-or-granted-on-it";
/// The claim on the grants written on a ranked link.
pub(crate) const RANKED_GRANT_TAKEN: &str = "every-grant-on-a-ranked-link-became-a-transfer";
/// The claim on grants written after rmule closed their link.
pub(crate) const NONE_CROSSED: &str = "no-grant-crossed-a-hang-up";
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
    /// The most links between rmule and the sharers open at once, and their
    /// open seconds summed (a link still open at the capture's end counts to
    /// its last segment): what holding a queued link costs.
    pub(crate) links_open_peak: usize,
    pub(crate) link_seconds: f64,
    /// The most sources asking, queued and transferring at once.
    pub(crate) peaks: ActivityPeaks,
    /// Sharers that sent part frames of rmule's file.
    pub(crate) sharers_sending: usize,
    /// Sharers that sent rmule a rank, and how many of them the shape meant
    /// to queue.
    pub(crate) sharers_ranking: usize,
    pub(crate) ranking_as_shaped: usize,
    /// Grants a sharer wrote on a link after rmule had closed it: a promotion
    /// that crossed the hang-up, which rmule cannot read.
    pub(crate) grants_after_hang_up: usize,
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

/// The links between `rmule` and `sharers` as `(opened, closed)` times: a SYN
/// opens one, the first FIN or RST of either side closes it, and one never
/// closed ends at `end`.
fn link_spans(
    capture: &TcpCapture,
    rmule: IpAddr,
    sharers: &[Ipv4Addr],
    end: f64,
) -> Vec<(f64, f64)> {
    let ours = |a: SocketAddr, b: SocketAddr| {
        (a.ip() == rmule && sharers.iter().any(|&ip| b.ip() == IpAddr::V4(ip)))
            || (b.ip() == rmule && sharers.iter().any(|&ip| a.ip() == IpAddr::V4(ip)))
    };
    let mut spans: Vec<((SocketAddr, SocketAddr), f64, Option<f64>)> = Vec::new();
    for open in capture
        .opens
        .iter()
        .filter(|open| ours(open.source, open.destination))
    {
        let key = (open.source, open.destination);
        if !spans.iter().any(|(seen, _, _)| *seen == key) {
            spans.push((key, open.at, None));
        }
    }
    for close in &capture.closes {
        if let Some(span) = spans.iter_mut().find(|((a, b), opened, closed)| {
            closed.is_none()
                && close.at >= *opened
                && ((close.source, close.destination) == (*a, *b)
                    || (close.source, close.destination) == (*b, *a))
        }) {
            span.2 = Some(close.at);
        }
    }
    spans
        .into_iter()
        .map(|(_, opened, closed)| (opened, closed.unwrap_or(end).max(opened)))
        .collect()
}

/// The most spans open at one instant.
fn peak_open(spans: &[(f64, f64)]) -> usize {
    let mut edges: Vec<(f64, i32)> = spans
        .iter()
        .flat_map(|&(opened, closed)| [(opened, 1), (closed, -1)])
        .collect();
    // A close sorts before an open at the same instant.
    edges.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)));
    let (mut open, mut peak) = (0_i32, 0_i32);
    for (_, step) in edges {
        open += step;
        peak = peak.max(open);
    }
    usize::try_from(peak).unwrap_or(0)
}

/// One link a sharer ranked rmule on: the sharer's side, rmule's side, and
/// the first rank's capture time.
#[derive(Clone, Copy, Debug, PartialEq)]
struct RankedLink {
    sharer: SocketAddr,
    rmule: SocketAddr,
    ranked_at: f64,
}

/// Every link one of `sharers` ranked rmule on, at its first rank there.
fn ranked_links(capture: &TcpCapture, rmule: IpAddr, sharers: &[Ipv4Addr]) -> Vec<RankedLink> {
    capture
        .streams
        .iter()
        .filter(|stream| {
            stream.destination.ip() == rmule
                && sharers
                    .iter()
                    .any(|&ip| stream.source.ip() == IpAddr::V4(ip))
        })
        .filter_map(|stream| {
            let ranked_at = stream
                .ed2k_frames()
                .iter()
                .find(|frame| is_rank(frame))
                .map(|frame| frame.at)?;
            Some(RankedLink {
                sharer: stream.source,
                rmule: stream.destination,
                ranked_at,
            })
        })
        .collect()
}

/// Whether rmule held `link` past its rank: the first of rmule's close, the
/// sharer's close and a grant on it is not rmule's close. `None` when none
/// crossed the tap.
fn held_after_rank(capture: &TcpCapture, frames: &[Ed2kFrame], link: &RankedLink) -> Option<bool> {
    let closed = capture
        .closes
        .iter()
        .filter(|close| {
            close.at >= link.ranked_at
                && ((close.source, close.destination) == (link.sharer, link.rmule)
                    || (close.source, close.destination) == (link.rmule, link.sharer))
        })
        .map(|close| (close.at, close.source == link.sharer))
        .min_by(|a, b| a.0.total_cmp(&b.0));
    let granted = first_grant_on(frames, link).map(|at| (at, true));
    match (closed, granted) {
        (Some(close), Some(grant)) => Some(if grant.0 <= close.0 { grant.1 } else { close.1 }),
        (one, other) => one.or(other).map(|(_, held)| held),
    }
}

/// The first grant the sharer wrote on `link` after its rank there.
fn first_grant_on(frames: &[Ed2kFrame], link: &RankedLink) -> Option<f64> {
    frames
        .iter()
        .filter(|frame| {
            is_grant(frame)
                && frame.source == link.sharer
                && frame.destination == link.rmule
                && frame.at >= link.ranked_at
        })
        .map(|frame| frame.at)
        .reduce(f64::min)
}

/// Part frames of the file `hash` names the sharer sent on `link` after `at`.
fn parts_on_after(frames: &[Ed2kFrame], link: &RankedLink, hash: [u8; 16], at: f64) -> usize {
    frames
        .iter()
        .filter(|frame| {
            frame.source == link.sharer
                && frame.destination == link.rmule
                && frame.at > at
                && part_of(frame) == Some(hash)
        })
        .count()
}

/// Whether `frame` is a rank.
fn is_rank(frame: &Ed2kFrame) -> bool {
    (frame.protocol, frame.opcode) == (OP_EDONKEYPROT, OP_QUEUERANK)
        || (frame.protocol, frame.opcode) == (OP_EMULEPROT, OP_QUEUERANKING)
}

/// Whether `sharer` sent rmule a rank, on any link.
fn ranked(capture: &TcpCapture, sharer: Ipv4Addr) -> bool {
    capture
        .streams
        .iter()
        .filter(|stream| stream.source.ip() == IpAddr::V4(sharer))
        .flat_map(|stream| stream.ed2k_frames())
        .any(|frame| is_rank(&frame))
}

/// Whether `frame` is a grant.
fn is_grant(frame: &Ed2kFrame) -> bool {
    (frame.protocol, frame.opcode) == (OP_EDONKEYPROT, OP_ACCEPTUPLOADREQ)
}

/// Whether `sharer`'s first grant on a dial-back to rmule's listener came
/// while rmule still had blocks to ask: no later than rmule's last block
/// request on any link. A grant after that finds the whole file asked and
/// cannot become a transfer; one without any grant on the tap stays in the
/// claim.
fn granted_before_last_ask(frames: &[Ed2kFrame], sharer: Ipv4Addr, rmule: IpAddr) -> bool {
    let last_ask = frames
        .iter()
        .filter(|frame| {
            frame.source.ip() == rmule
                && ((frame.protocol, frame.opcode) == (OP_EDONKEYPROT, OP_REQUESTPARTS)
                    || (frame.protocol, frame.opcode) == (OP_EMULEPROT, OP_REQUESTPARTS_I64))
        })
        .map(|frame| frame.at)
        .fold(f64::NEG_INFINITY, f64::max);
    frames
        .iter()
        .filter(|frame| {
            is_grant(frame)
                && frame.source.ip() == IpAddr::V4(sharer)
                && frame.destination.ip() == rmule
                && frame.destination.port() == RMULE_SERVE_TCP_PORT
        })
        .map(|frame| frame.at)
        .reduce(f64::min)
        .is_none_or(|granted| granted <= last_ask)
}

/// The grants written on a link after rmule's FIN or RST on it.
fn grants_after_hang_up(frames: &[Ed2kFrame], closes: &[TcpClose], rmule: IpAddr) -> usize {
    frames
        .iter()
        .filter(|frame| is_grant(frame) && frame.destination.ip() == rmule)
        .filter(|frame| {
            closes.iter().any(|close| {
                close.at < frame.at
                    && close.source == frame.destination
                    && close.destination == frame.source
            })
        })
        .count()
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
    let frames: Vec<Ed2kFrame> = seen
        .capture
        .streams
        .iter()
        .flat_map(|stream| stream.ed2k_frames())
        .collect();
    let (late, past_last_ask): (Vec<Ipv4Addr>, Vec<Ipv4Addr>) = queued
        .iter()
        .copied()
        .filter(|&ip| dialed_back(ip))
        .partition(|&ip| granted_before_last_ask(&frames, ip, rmule));
    let ranked = ranked_links(&seen.capture, rmule, &at.sharers);
    let held_note: Vec<String> = ranked
        .iter()
        .map(|link| {
            let who = match held_after_rank(&seen.capture, &frames, link) {
                Some(true) => "held",
                Some(false) => "rmule closed it first",
                None => "nothing crossed",
            };
            format!("{} -> {}: {who}", link.sharer, link.rmule)
        })
        .collect();
    let ranked_grants: Vec<(RankedLink, usize)> = ranked
        .iter()
        .filter_map(|link| {
            let granted = first_grant_on(&frames, link)?;
            Some((*link, parts_on_after(&frames, link, seen.hash, granted)))
        })
        .collect();
    let crossed = grants_after_hang_up(&frames, &seen.capture.closes, rmule);
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
            QUEUED_HELD,
            &queued,
            Evidence::RmuleOnly,
            &format!(
                "on each link a sharer ranked rmule on, the first of rmule's close, the \
                 sharer's close and a grant ({})",
                held_note.join(", ")
            ),
            |ip| {
                ranked
                    .iter()
                    .filter(|link| link.sharer.ip() == IpAddr::V4(ip))
                    .all(|link| held_after_rank(&seen.capture, &frames, link) == Some(true))
            },
        ),
        if ranked_grants.is_empty() {
            Claim::blocked(
                RANKED_GRANT_TAKEN,
                "no sharer wrote a grant on a link it had ranked rmule on",
            )
        } else {
            Claim::about(
                RANKED_GRANT_TAKEN,
                ranked_grants.iter().all(|(_, parts)| *parts > 0),
                Evidence::Captured,
                format!(
                    "part frames of rmule's file after each grant on a ranked link: {}",
                    ranked_grants
                        .iter()
                        .map(|(link, parts)| format!("{}: {parts}", link.sharer))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )
        },
        Claim::absence(
            NONE_CROSSED,
            i64::try_from(crossed).unwrap_or(i64::MAX),
            format!("grants a sharer wrote on a link after rmule's FIN or RST on it: {crossed}"),
        ),
        over_all(
            LATE_TAKEN,
            &late,
            Evidence::Captured,
            &format!(
                "download.slot_offered in rmule's log and part frames from each sharer that \
                 ranked rmule and dialed it back before rmule's last block request (granted \
                 after it: {past_last_ask:?})"
            ),
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
    let end = frames.iter().map(|frame| frame.at).fold(0.0, f64::max);
    let spans = link_spans(&seen.capture, rmule, &at.sharers, end);
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
        links_open_peak: peak_open(&spans),
        link_seconds: spans.iter().map(|(opened, closed)| closed - opened).sum(),
        peaks: seen.log.activity_peaks(),
        sharers_sending: at.sharers.iter().filter(|&&ip| sending(ip)).count(),
        sharers_ranking: queued.len(),
        ranking_as_shaped: queued
            .iter()
            .filter(|ip| shaped_queued.contains(ip))
            .count(),
        grants_after_hang_up: crossed,
        copy_bytes: len,
    };
    (claims, rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RMULE: Ipv4Addr = Ipv4Addr::new(172, 18, 0, 17);
    const SHARER: Ipv4Addr = Ipv4Addr::new(172, 18, 0, 6);

    fn frame(at: f64, source: SocketAddr, destination: SocketAddr, opcode: u8) -> Ed2kFrame {
        Ed2kFrame {
            at,
            source,
            destination,
            protocol: OP_EDONKEYPROT,
            opcode,
            bytes: vec![OP_EDONKEYPROT, 1, 0, 0, 0, opcode],
        }
    }

    #[test]
    fn a_dial_back_grant_after_the_last_block_request_is_not_held_to_a_transfer() {
        let dialed = SocketAddr::from((SHARER, 40250));
        let listener = SocketAddr::from((RMULE, RMULE_SERVE_TCP_PORT));
        let ask = frame(
            10.0,
            SocketAddr::from((RMULE, 48022)),
            SocketAddr::from((Ipv4Addr::new(172, 18, 0, 7), AMULE_PEER_TCP_PORT)),
            OP_REQUESTPARTS,
        );
        let grant = |at| frame(at, dialed, listener, OP_ACCEPTUPLOADREQ);
        let rmule = IpAddr::V4(RMULE);
        assert!(!granted_before_last_ask(
            &[ask.clone(), grant(10.8)],
            SHARER,
            rmule
        ));
        assert!(granted_before_last_ask(
            &[grant(9.0), ask.clone()],
            SHARER,
            rmule
        ));
        assert!(granted_before_last_ask(&[ask], SHARER, rmule));
    }

    #[test]
    fn a_grant_written_after_rmule_closed_its_link_crossed_the_hang_up() {
        let ours = SocketAddr::from((RMULE, 41682));
        let theirs = SocketAddr::from((SHARER, AMULE_PEER_TCP_PORT));
        let grant = |at| frame(at, theirs, ours, OP_ACCEPTUPLOADREQ);
        let closed_by = |source, destination| TcpClose {
            at: 1.0,
            source,
            destination,
        };
        let rmule = IpAddr::V4(RMULE);
        let hang_up = [closed_by(ours, theirs)];
        assert_eq!(grants_after_hang_up(&[grant(1.38)], &hang_up, rmule), 1);
        assert_eq!(grants_after_hang_up(&[grant(0.9)], &hang_up, rmule), 0);
        let sharer_closed = [closed_by(theirs, ours)];
        assert_eq!(
            grants_after_hang_up(&[grant(1.38)], &sharer_closed, rmule),
            0
        );
    }

    /// At aMule 2 a ranked link is held: rmule's own close before the
    /// sharer's close or grant is the hang-up the old rule made.
    #[test]
    fn a_ranked_link_is_held_until_the_sharer_closes_it_or_grants_on_it() {
        let link = RankedLink {
            sharer: SocketAddr::from((SHARER, AMULE_PEER_TCP_PORT)),
            rmule: SocketAddr::from((RMULE, 41682)),
            ranked_at: 1.0,
        };
        let closed_by = |at, source, destination| TcpClose {
            at,
            source,
            destination,
        };
        let capture = |closes| TcpCapture {
            streams: Vec::new(),
            closes,
            opens: Vec::new(),
        };
        let grant = frame(30.0, link.sharer, link.rmule, OP_ACCEPTUPLOADREQ);
        let hung_up = capture(vec![
            closed_by(1.0007, link.rmule, link.sharer),
            closed_by(42.0, link.sharer, link.rmule),
        ]);
        assert_eq!(held_after_rank(&hung_up, &[], &link), Some(false));
        let idle_closed = capture(vec![
            closed_by(42.0, link.sharer, link.rmule),
            closed_by(42.001, link.rmule, link.sharer),
        ]);
        assert_eq!(held_after_rank(&idle_closed, &[], &link), Some(true));
        let granted = capture(vec![closed_by(90.0, link.rmule, link.sharer)]);
        assert_eq!(
            held_after_rank(&granted, std::slice::from_ref(&grant), &link),
            Some(true)
        );
        assert_eq!(held_after_rank(&capture(Vec::new()), &[], &link), None);
        let part = Ed2kFrame {
            protocol: OP_EDONKEYPROT,
            opcode: OP_SENDINGPART,
            bytes: [
                vec![OP_EDONKEYPROT, 0, 0, 0, 0, OP_SENDINGPART],
                vec![7; 16],
            ]
            .concat(),
            ..frame(30.5, link.sharer, link.rmule, OP_SENDINGPART)
        };
        assert_eq!(parts_on_after(&[grant, part], &link, [7; 16], 30.0), 1);
    }

    #[test]
    fn the_peak_counts_links_open_together_and_a_close_frees_its_place_first() {
        assert_eq!(peak_open(&[]), 0);
        assert_eq!(peak_open(&[(0.0, 10.0), (1.0, 2.0), (3.0, 4.0)]), 2);
        assert_eq!(peak_open(&[(0.0, 5.0), (5.0, 9.0)]), 1);
    }
}
