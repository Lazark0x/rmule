//! The dial-back grant verdict, scored from a retained run dir.
//!
//! The tap in rmule's namespace carries the sharer's dial to rmule's
//! listener and every frame on that link: the sharer's `OP_ACCEPTUPLOADREQ`
//! and its part frames are counterparty bytes, rmule's slot ask on the link
//! is rmule's own (ADR-0045). The copy against the staged file says whether
//! the grant became the download; rmule's run log says it was queued and
//! hung up before the grant came.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::flow::identity::parse_ed2k_file_hash;
use crate::flow::nat::claims::{Claim, Evidence, label};
use crate::flow::pcap::{Ed2kFrame, TcpCapture, TcpStream, records, tcp_capture};
use crate::flow::wire_filter::{OP_EDONKEYPROT, OP_EMULEPROT};
use crate::rmule::RMULE_SERVE_TCP_PORT;

/// The flow's name and its verdict file's stem.
pub(crate) const FLOW: &str = "peer-dial-back-grant";
/// Where the flow's own artifacts sit under the run dir.
pub(crate) const ROOT_DIR: &str = "peer-dial-back-grant";
/// The tap in rmule's namespace.
pub(crate) const RMULE_PCAP: &str = "rmule.pcap";
/// The addresses the run stood its bodies at.
const ADDRESSES: &str = "addresses.toml";

/// `OP_STARTUPLOADREQ`.
const OP_STARTUPLOADREQ: u8 = 0x54;
/// `OP_ACCEPTUPLOADREQ`.
const OP_ACCEPTUPLOADREQ: u8 = 0x55;
/// `OP_SENDINGPART`.
const OP_SENDINGPART: u8 = 0x46;
/// The eMule-extension part frames: `OP_COMPRESSEDPART`,
/// `OP_SENDINGPART_I64`, `OP_COMPRESSEDPART_I64`.
const EMULE_PART_FRAMES: [u8; 3] = [0x40, 0xA2, 0xA1];
/// The eD2k frame header ahead of a payload: protocol, length, opcode.
const FRAME_HEADER_LEN: usize = 6;

/// The claim on rmule's standing before the grant.
pub(crate) const QUEUED: &str = "rmule-was-queued-and-hung-up";
/// The claim on the sharer's dial to rmule.
pub(crate) const DIALED_BACK: &str = "the-sharer-dialed-rmule-back";
/// The claim on the sharer's grant over that link.
pub(crate) const GRANTED: &str = "the-sharer-granted-on-the-dial-back-link";
/// The claim on rmule taking the grant into the download.
pub(crate) const TAKEN: &str = "rmule-asked-for-its-file-on-the-dial-back-link";
/// The claim on bytes riding that link.
pub(crate) const BYTES: &str = "the-sharer-sent-parts-on-the-dial-back-link";
/// The claim on the copy.
pub(crate) const BYTE_EQUAL: &str = "the-download-completed-byte-equal";

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

/// The counts a verdict reports beside its claims.
#[derive(Debug, Default, Serialize, PartialEq)]
pub(crate) struct Rows {
    /// The sharer's SYNs to rmule's listener.
    pub(crate) dial_backs: usize,
    /// `OP_ACCEPTUPLOADREQ` frames the sharer sent on those links.
    pub(crate) grants_on_dial_back: usize,
    /// `OP_STARTUPLOADREQ` frames rmule sent on those links.
    pub(crate) asks_on_dial_back: usize,
    /// Part frames of rmule's file the sharer sent on those links.
    pub(crate) part_frames_on_dial_back: usize,
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
    rows: &'a Rows,
    claim: &'a [Claim],
}

/// What the run left: the tap, the copy against what was staged, the file's
/// hash and rmule's stdout.
struct Observed {
    capture: TcpCapture,
    hash: [u8; 16],
    copy: (bool, i64),
    rmule_log: String,
}

/// Score the run under `run_dir`, write its verdict file and return the
/// verdict.
///
/// # Errors
/// If the addresses, the tap, the staged file or rmule's log cannot be read.
pub fn score_run_dir(run_dir: &Path) -> Result<&'static str> {
    let root = run_dir.join(ROOT_DIR);
    let addresses_path = root.join(ADDRESSES);
    let addresses: Addresses = toml::from_str(
        &fs::read_to_string(&addresses_path)
            .with_context(|| format!("read {}", addresses_path.display()))?,
    )
    .with_context(|| format!("parse {}", addresses_path.display()))?;
    let observed = observe(run_dir)?;
    let (claims, rows) = claims(&addresses, &observed);
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
    // A copy never written is a grant not taken — an observation, not a
    // broken run.
    let copy = fs::read(run_dir.join("rmule").join("output.bin")).map_or((false, -1), |copy| {
        (
            copy == staged,
            i64::try_from(copy.len()).unwrap_or(i64::MAX),
        )
    });
    let log_path = run_dir.join("rmule").join("stdout.log");
    let rmule_log =
        fs::read_to_string(&log_path).with_context(|| format!("read {}", log_path.display()))?;
    Ok(Observed {
        capture,
        hash,
        copy,
        rmule_log,
    })
}

/// Whether `address` is `ip` on IPv4.
fn is_v4(address: SocketAddr, ip: Ipv4Addr) -> bool {
    address.ip() == IpAddr::V4(ip)
}

/// The file a part frame carries: the 16 bytes its payload opens with.
fn part_of(frame: &Ed2kFrame) -> Option<[u8; 16]> {
    let part = (frame.protocol, frame.opcode) == (OP_EDONKEYPROT, OP_SENDINGPART)
        || (frame.protocol == OP_EMULEPROT && EMULE_PART_FRAMES.contains(&frame.opcode));
    let hash = frame.bytes.get(FRAME_HEADER_LEN..FRAME_HEADER_LEN + 16)?;
    part.then(|| hash.try_into().ok()).flatten()
}

/// Whether rmule's run log names a record `name` for `peer`.
fn logged(log: &str, name: &str, peer: SocketAddr) -> bool {
    let peer = format!("peer={peer}");
    log.lines().any(|line| {
        line.split_whitespace().next() == Some(name)
            && line.split_whitespace().any(|field| field == peer)
    })
}

/// How many frames of `streams` match `pick`.
fn count(streams: &[&TcpStream], pick: impl Fn(&Ed2kFrame) -> bool) -> usize {
    streams
        .iter()
        .flat_map(|stream| stream.ed2k_frames())
        .filter(|frame| pick(frame))
        .count()
}

fn claims(at: &Addresses, seen: &Observed) -> (Vec<Claim>, Rows) {
    let sharer_listener = SocketAddr::from((at.sharer, crate::flow::bench::AMULE_PEER_TCP_PORT));
    let queued = logged(&seen.rmule_log, "download.peer_queued", sharer_listener);
    let hung_up = logged(
        &seen.rmule_log,
        "download.source_remote_queued",
        sharer_listener,
    );
    // The sharer's dials to rmule's listener: the ends it dialed from name
    // the dial-back links.
    let dial_backs: Vec<SocketAddr> = seen
        .capture
        .opens
        .iter()
        .filter(|open| {
            is_v4(open.source, at.sharer)
                && is_v4(open.destination, at.rmule)
                && open.destination.port() == RMULE_SERVE_TCP_PORT
        })
        .map(|open| open.source)
        .collect();
    let from_sharer: Vec<&TcpStream> = seen
        .capture
        .streams
        .iter()
        .filter(|stream| dial_backs.contains(&stream.source))
        .collect();
    let from_rmule: Vec<&TcpStream> = seen
        .capture
        .streams
        .iter()
        .filter(|stream| dial_backs.contains(&stream.destination))
        .collect();
    let unreadable = from_sharer
        .iter()
        .chain(&from_rmule)
        .any(|stream| !stream.opens_plain());
    let grants = count(&from_sharer, |frame| {
        (frame.protocol, frame.opcode) == (OP_EDONKEYPROT, OP_ACCEPTUPLOADREQ)
    });
    let asks = count(&from_rmule, |frame| {
        (frame.protocol, frame.opcode) == (OP_EDONKEYPROT, OP_STARTUPLOADREQ)
    });
    let parts = count(&from_sharer, |frame| part_of(frame) == Some(seen.hash));

    let mut claims = vec![
        Claim::about(
            QUEUED,
            queued && hung_up,
            Evidence::RmuleOnly,
            format!(
                "rmule's log: download.peer_queued for {sharer_listener} {queued}, \
                 download.source_remote_queued {hung_up}"
            ),
        ),
        Claim::about(
            DIALED_BACK,
            !dial_backs.is_empty(),
            Evidence::Captured,
            format!("the sharer's SYNs to rmule's listener, from: {dial_backs:?}"),
        ),
    ];
    if unreadable {
        let why = "a dial-back link did not open as plain eD2k, so its frames cannot be read";
        for claim in [GRANTED, TAKEN, BYTES] {
            claims.push(Claim::blocked(claim, why));
        }
    } else {
        claims.push(Claim::about(
            GRANTED,
            grants > 0,
            Evidence::Captured,
            format!("OP_ACCEPTUPLOADREQ frames from the sharer on a dial-back link: {grants}"),
        ));
        claims.push(Claim::about(
            TAKEN,
            asks > 0,
            Evidence::RmuleOnly,
            format!("OP_STARTUPLOADREQ frames from rmule on a dial-back link: {asks}"),
        ));
        claims.push(Claim::about(
            BYTES,
            parts > 0,
            Evidence::Captured,
            format!("part frames of rmule's file from the sharer on a dial-back link: {parts}"),
        ));
    }
    let (equal, len) = seen.copy;
    claims.push(Claim::about(
        BYTE_EQUAL,
        equal,
        Evidence::Captured,
        format!("output.bin {len} bytes, equal {equal}"),
    ));
    let rows = Rows {
        dial_backs: dial_backs.len(),
        grants_on_dial_back: grants,
        asks_on_dial_back: asks,
        part_frames_on_dial_back: parts,
        copy_bytes: len,
    };
    (claims, rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_is_read_for_its_peer_only() {
        let sharer: SocketAddr = "172.18.0.6:4662".parse().unwrap();
        let log = "download.peer_queued id=1 peer=172.18.0.6:4662 rank=1\n\
                   download.source_remote_queued id=1 peer=172.18.0.7:4662\n";
        assert!(logged(log, "download.peer_queued", sharer));
        assert!(!logged(log, "download.source_remote_queued", sharer));
    }
}
