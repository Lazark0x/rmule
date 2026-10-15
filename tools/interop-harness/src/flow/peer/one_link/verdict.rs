//! The one-link verdict, scored from a retained run dir.
//!
//! The tap in rmule's namespace carries rmule's dials to the sharer and every
//! frame on each link: the sharer's part frames name the file they carry, so
//! the stream they ride says whether one link carried both files. The two
//! copies against the staged files say whether both downloads finished, and
//! rmule's run log whether the second waited on the link before it rode it.
//! rmule's own dials and log are scored `rmule-only`; the sharer's part frames
//! and the copies are counterparty bytes (ADR-0045).

use std::collections::BTreeSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::flow::identity::parse_ed2k_file_hash;
use crate::flow::nat::claims::{Claim, Evidence, label};
use crate::flow::pcap::{Ed2kFrame, TcpCapture, TcpStream, records, tcp_capture};
use crate::flow::wire_filter::{OP_EDONKEYPROT, OP_EMULEPROT};

pub(crate) use super::super::udp_reask_emit::{SECOND_FILE, SECOND_LINK};

/// The flow's name and its verdict file's stem.
pub(crate) const FLOW: &str = "peer-one-link";
/// Where the flow's own artifacts sit under the run dir.
pub(crate) const ROOT_DIR: &str = "peer-one-link";
/// The tap in rmule's namespace.
pub(crate) const RMULE_PCAP: &str = "rmule.pcap";
/// The addresses the run stood its bodies at.
const ADDRESSES: &str = "addresses.toml";
/// The sharer's peer listener.
const SHARER_PORT: u16 = 4662;

/// `OP_SENDINGPART`.
const OP_SENDINGPART: u8 = 0x46;
/// The eMule-extension part frames: `OP_COMPRESSEDPART`,
/// `OP_SENDINGPART_I64`, `OP_COMPRESSEDPART_I64`.
const EMULE_PART_FRAMES: [u8; 3] = [0x40, 0xA2, 0xA1];
/// The eD2k frame header ahead of a payload: protocol, length, opcode.
const FRAME_HEADER_LEN: usize = 6;

/// The claim on rmule's dials to the sharer.
pub(crate) const ONE_DIAL: &str = "rmule-dialed-the-sharer-once";
/// The claim on the sharer serving both files over that one link.
pub(crate) const ONE_LINK: &str = "the-sharer-served-both-files-over-one-link";
/// The claim on both copies.
pub(crate) const BYTE_EQUAL: &str = "both-downloads-completed-byte-equal";
/// The claim on the second download's turn.
pub(crate) const WAITED: &str = "the-second-download-waited-on-the-link-then-rode-it";

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
    /// rmule's SYNs to the sharer's listener.
    pub(crate) dials_rmule_tap: usize,
    /// Links from the sharer that carried part frames of the first file.
    pub(crate) links_with_first_file: usize,
    /// Links from the sharer that carried part frames of the second file.
    pub(crate) links_with_second_file: usize,
    /// The copies' lengths, `-1` when never written.
    pub(crate) first_copy_bytes: i64,
    pub(crate) second_copy_bytes: i64,
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

/// What the run left: the tap, the two copies against what was staged, the
/// two files' hashes and rmule's stdout.
struct Observed {
    capture: TcpCapture,
    hashes: [[u8; 16]; 2],
    copies: [(bool, i64); 2],
    rmule_log: String,
}

/// Score the run under `run_dir`, write its verdict file and return the
/// verdict.
///
/// # Errors
/// If the addresses, the tap, a staged file or rmule's log cannot be read.
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
    let hash_of = |link: PathBuf| -> Result<[u8; 16]> {
        let text = fs::read_to_string(&link).with_context(|| format!("read {}", link.display()))?;
        parse_ed2k_file_hash(text.trim())
    };
    let hashes = [
        hash_of(synthetic.join("shared.ed2k.txt"))?,
        hash_of(synthetic.join(SECOND_LINK))?,
    ];
    let copy = |staged: &str, written: &str| -> Result<(bool, i64)> {
        let staged_path = synthetic.join(staged);
        let staged =
            fs::read(&staged_path).with_context(|| format!("read {}", staged_path.display()))?;
        // A copy never written is a download not finishing — an observation,
        // not a broken run.
        Ok(
            fs::read(run_dir.join("rmule").join(written)).map_or((false, -1), |copy| {
                (
                    copy == staged,
                    i64::try_from(copy.len()).unwrap_or(i64::MAX),
                )
            }),
        )
    };
    let copies = [
        copy("shared.bin", "output.bin")?,
        copy(SECOND_FILE, "output-2.bin")?,
    ];
    let log_path = run_dir.join("rmule").join("stdout.log");
    let rmule_log =
        fs::read_to_string(&log_path).with_context(|| format!("read {}", log_path.display()))?;
    Ok(Observed {
        capture,
        hashes,
        copies,
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

/// The `download.link_shared` turns rmule's log names, in order.
fn turns(log: &str) -> Vec<String> {
    log.lines()
        .filter(|line| line.starts_with("download.link_shared "))
        .filter_map(|line| {
            line.split_whitespace()
                .find_map(|field| field.strip_prefix("turn="))
                .map(str::to_owned)
        })
        .collect()
}

fn claims(at: &Addresses, seen: &Observed) -> (Vec<Claim>, Rows) {
    let dials: Vec<_> = seen
        .capture
        .opens
        .iter()
        .filter(|open| {
            is_v4(open.source, at.rmule)
                && is_v4(open.destination, at.sharer)
                && open.destination.port() == SHARER_PORT
        })
        .collect();
    let from_sharer: Vec<&TcpStream> = seen
        .capture
        .streams
        .iter()
        .filter(|stream| {
            is_v4(stream.source, at.sharer)
                && stream.source.port() == SHARER_PORT
                && is_v4(stream.destination, at.rmule)
        })
        .collect();
    let carrying = |hash: [u8; 16]| -> BTreeSet<SocketAddr> {
        from_sharer
            .iter()
            .filter(|stream| {
                stream
                    .ed2k_frames()
                    .iter()
                    .any(|frame| part_of(frame) == Some(hash))
            })
            .map(|stream| stream.destination)
            .collect()
    };
    let (first, second) = (carrying(seen.hashes[0]), carrying(seen.hashes[1]));
    let unreadable = from_sharer.iter().any(|stream| !stream.opens_plain());

    let mut claims = vec![Claim::about(
        ONE_DIAL,
        dials.len() == 1,
        Evidence::RmuleOnly,
        format!(
            "rmule's SYNs to the sharer's listener: {}",
            dials
                .iter()
                .map(|open| format!("{} at {:.3}", open.source, open.at))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    )];
    if unreadable {
        claims.push(Claim::blocked(
            ONE_LINK,
            "a link from the sharer did not open as plain eD2k, so its frames cannot be read",
        ));
    } else {
        let shared = first.len() == 1 && first == second;
        claims.push(Claim::about(
            ONE_LINK,
            shared,
            Evidence::Captured,
            format!("links carrying the first file's parts: {first:?}; the second's: {second:?}"),
        ));
    }
    let [(first_equal, first_len), (second_equal, second_len)] = seen.copies;
    claims.push(Claim::about(
        BYTE_EQUAL,
        first_equal && second_equal,
        Evidence::Captured,
        format!(
            "output.bin {first_len} bytes, equal {first_equal}; output-2.bin {second_len} \
             bytes, equal {second_equal}"
        ),
    ));
    let turns = turns(&seen.rmule_log);
    let waited = turns
        .iter()
        .position(|turn| turn == "waiting")
        .is_some_and(|wait| turns[wait..].iter().any(|turn| turn == "riding"));
    claims.push(Claim::about(
        WAITED,
        waited,
        Evidence::RmuleOnly,
        format!("download.link_shared turns in rmule's log: {turns:?}"),
    ));
    let rows = Rows {
        dials_rmule_tap: dials.len(),
        links_with_first_file: first.len(),
        links_with_second_file: second.len(),
        first_copy_bytes: first_len,
        second_copy_bytes: second_len,
    };
    (claims, rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_turns_are_read_in_order_from_the_link_shared_records() {
        let log = "download.started id=1\n\
                   download.link_shared id=2 turn=waiting peer=172.18.0.6:4662\n\
                   download.completed id=1\n\
                   download.link_shared id=2 turn=riding peer=172.18.0.6:4662\n";
        assert_eq!(turns(log), ["waiting", "riding"]);
    }

    #[test]
    fn a_part_frame_names_its_file_and_no_other_frame_does() {
        let hash = [0xAB; 16];
        let frame = |protocol: u8, opcode: u8| Ed2kFrame {
            at: 0.0,
            source: "172.18.0.6:4662".parse().unwrap(),
            destination: "172.18.0.5:40000".parse().unwrap(),
            protocol,
            opcode,
            bytes: [&[protocol, 0, 0, 0, 0, opcode][..], &hash, &[0; 8]].concat(),
        };
        assert_eq!(part_of(&frame(OP_EDONKEYPROT, OP_SENDINGPART)), Some(hash));
        assert_eq!(part_of(&frame(OP_EMULEPROT, 0xA2)), Some(hash));
        assert_eq!(part_of(&frame(OP_EDONKEYPROT, 0x58)), None);
    }
}
