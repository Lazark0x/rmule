//! The one-link verdict, scored from a retained run dir.
//!
//! The tap in rmule's namespace carries rmule's dials to the sharer and every
//! frame on each link: the sharer's part frames name the file they carry, so
//! the stream they ride says whether one link carried both files. The two
//! copies against the staged files say whether both downloads finished, and
//! rmule's run log whether the second waited on the link before it rode it.
//! The **file switch** is read off the link too: how the first download let
//! its slot go (`OP_CANCELTRANSFER` or silently), how the sharer answered the
//! second's `OP_STARTUPLOADREQ`, and what it sent after (ADR-0107's table,
//! `UploadQueue.cpp:486-493`). rmule's own dials and log are scored
//! `rmule-only`; the sharer's frames and the copies are counterparty bytes
//! (ADR-0045).

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
/// The eD2k slot frames: `OP_STARTUPLOADREQ`, `OP_ACCEPTUPLOADREQ`,
/// `OP_CANCELTRANSFER`, `OP_QUEUERANK`.
const OP_STARTUPLOADREQ: u8 = 0x54;
const OP_ACCEPTUPLOADREQ: u8 = 0x55;
const OP_CANCELTRANSFER: u8 = 0x56;
const OP_QUEUERANK: u8 = 0x5C;
/// `OP_QUEUERANKING`, the eMule-extension rank.
const OP_QUEUERANKING: u8 = 0x60;
/// The file requests whose payload opens with the file they ask for:
/// `OP_REQUESTFILENAME`, `OP_SETREQFILEID` (eD2k) and `OP_MULTIPACKET`,
/// `OP_MULTIPACKET_EXT` (eMule).
const EDONKEY_FILE_REQUESTS: [u8; 2] = [0x58, 0x4F];
const EMULE_FILE_REQUESTS: [u8; 2] = [0x92, 0xA4];

/// The claim on rmule's dials to the sharer.
pub(crate) const ONE_DIAL: &str = "rmule-dialed-the-sharer-once";
/// The claim on the sharer serving both files over that one link.
pub(crate) const ONE_LINK: &str = "the-sharer-served-both-files-over-one-link";
/// The claim on both copies.
pub(crate) const BYTE_EQUAL: &str = "both-downloads-completed-byte-equal";
/// The claim on the second download's turn.
pub(crate) const WAITED: &str = "the-second-download-waited-on-the-link-then-rode-it";
/// The claim on the sharer's answer to the file switch.
pub(crate) const SWITCH_GRANTED: &str = "the-sharer-granted-the-file-switch-at-once";

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
    /// How the first download let its slot go before the switch: `cancel`,
    /// `silent`, or `none` when no switch crossed the link.
    pub(crate) switch_release: &'static str,
    /// The sharer's answer to the second download's ask: `accept`, `rank` or
    /// `none`.
    pub(crate) switch_answer: &'static str,
    /// Milliseconds from that ask to the answer, `-1` without one.
    pub(crate) switch_answer_ms: f64,
    /// The next file's part frames the sharer sent after the switch.
    pub(crate) parts_after_switch: usize,
}

/// The file switch one link carried.
#[derive(Debug, PartialEq)]
pub(crate) struct Switch {
    /// `cancel` when rmule sent `OP_CANCELTRANSFER` between the riding file's
    /// last part frame and the next file's request, else `silent`.
    pub(crate) release: &'static str,
    /// `accept`, `rank` or `none`, and how long after the ask it came.
    pub(crate) answer: &'static str,
    pub(crate) answer_ms: Option<f64>,
    /// The next file's part frames after the switch.
    pub(crate) parts_after: usize,
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

/// The file a file request names: the 16 bytes its payload opens with.
fn requested(frame: &Ed2kFrame) -> Option<[u8; 16]> {
    let request = (frame.protocol == OP_EDONKEYPROT
        && EDONKEY_FILE_REQUESTS.contains(&frame.opcode))
        || (frame.protocol == OP_EMULEPROT && EMULE_FILE_REQUESTS.contains(&frame.opcode));
    let hash = frame.bytes.get(FRAME_HEADER_LEN..FRAME_HEADER_LEN + 16)?;
    request.then(|| hash.try_into().ok()).flatten()
}

/// The switch on one link from the file `[from, to]` rode first to the other,
/// read from the frames rmule `sent` and the frames it `heard`; `None` when
/// rmule named `to` only before `from`'s last part, or never.
pub(crate) fn link_switch(
    sent: &[Ed2kFrame],
    heard: &[Ed2kFrame],
    [from, to]: [[u8; 16]; 2],
) -> Option<Switch> {
    let is = |frame: &Ed2kFrame, protocol: u8, opcode: u8| {
        (frame.protocol, frame.opcode) == (protocol, opcode)
    };
    let last_from_part = heard
        .iter()
        .filter(|frame| part_of(frame) == Some(from))
        .map(|frame| frame.at)
        .reduce(f64::max)?;
    let request = sent
        .iter()
        .find(|frame| frame.at >= last_from_part && requested(frame) == Some(to))?;
    let cancelled = sent.iter().any(|frame| {
        (last_from_part..=request.at).contains(&frame.at)
            && is(frame, OP_EDONKEYPROT, OP_CANCELTRANSFER)
    });
    let ask = sent
        .iter()
        .find(|frame| frame.at >= request.at && is(frame, OP_EDONKEYPROT, OP_STARTUPLOADREQ));
    let answer = ask.and_then(|ask| {
        heard.iter().find_map(|frame| {
            let kind = if is(frame, OP_EDONKEYPROT, OP_ACCEPTUPLOADREQ) {
                "accept"
            } else if is(frame, OP_EDONKEYPROT, OP_QUEUERANK)
                || is(frame, OP_EMULEPROT, OP_QUEUERANKING)
            {
                "rank"
            } else {
                return None;
            };
            (frame.at >= ask.at).then_some((kind, (frame.at - ask.at) * 1000.0))
        })
    });
    Some(Switch {
        release: if cancelled { "cancel" } else { "silent" },
        answer: answer.map_or("none", |(kind, _)| kind),
        answer_ms: answer.map(|(_, ms)| ms),
        parts_after: heard
            .iter()
            .filter(|frame| frame.at >= request.at && part_of(frame) == Some(to))
            .count(),
    })
}

/// The file switch on the first link to the sharer that carried one, whichever
/// download rode first.
fn file_switch(at: &Addresses, capture: &TcpCapture, hashes: [[u8; 16]; 2]) -> Option<Switch> {
    capture
        .streams
        .iter()
        .filter(|stream| {
            is_v4(stream.source, at.rmule)
                && is_v4(stream.destination, at.sharer)
                && stream.destination.port() == SHARER_PORT
        })
        .find_map(|to_sharer| {
            let back = capture.streams.iter().find(|stream| {
                stream.source == to_sharer.destination && stream.destination == to_sharer.source
            })?;
            let (sent, heard) = (to_sharer.ed2k_frames(), back.ed2k_frames());
            link_switch(&sent, &heard, hashes)
                .or_else(|| link_switch(&sent, &heard, [hashes[1], hashes[0]]))
        })
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
    let switch = file_switch(at, &seen.capture, seen.hashes);
    claims.push(match &switch {
        _ if unreadable => Claim::blocked(
            SWITCH_GRANTED,
            "a link from the sharer did not open as plain eD2k, so its frames cannot be read",
        ),
        None => Claim::about(
            SWITCH_GRANTED,
            false,
            Evidence::Captured,
            "no link named the other file after the riding file's last part frame",
        ),
        Some(switch) => Claim::about(
            SWITCH_GRANTED,
            switch.answer == "accept",
            Evidence::Captured,
            format!(
                "release {}; the next download's OP_STARTUPLOADREQ answered {} after {} ms; \
                 its file's part frames after the switch: {}",
                switch.release,
                switch.answer,
                switch
                    .answer_ms
                    .map_or_else(|| "-".to_owned(), |ms| format!("{ms:.1}")),
                switch.parts_after
            ),
        ),
    });
    let rows = Rows {
        dials_rmule_tap: dials.len(),
        links_with_first_file: first.len(),
        links_with_second_file: second.len(),
        first_copy_bytes: first_len,
        second_copy_bytes: second_len,
        switch_release: switch.as_ref().map_or("none", |switch| switch.release),
        switch_answer: switch.as_ref().map_or("none", |switch| switch.answer),
        switch_answer_ms: switch
            .as_ref()
            .and_then(|switch| switch.answer_ms)
            .unwrap_or(-1.0),
        parts_after_switch: switch.as_ref().map_or(0, |switch| switch.parts_after),
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

    /// A frame at `at` opening with `hash` (zeros past it).
    fn framed(at: f64, protocol: u8, opcode: u8, hash: [u8; 16]) -> Ed2kFrame {
        Ed2kFrame {
            at,
            source: "172.18.0.5:40000".parse().unwrap(),
            destination: "172.18.0.6:4662".parse().unwrap(),
            protocol,
            opcode,
            bytes: [&[protocol, 0, 0, 0, 0, opcode][..], &hash, &[0; 8]].concat(),
        }
    }

    #[test]
    fn the_switch_reads_the_release_and_the_answer_to_the_next_ask() {
        let (a, b) = ([0xA1; 16], [0xB2; 16]);
        let heard = [
            framed(1.0, OP_EDONKEYPROT, OP_SENDINGPART, a),
            framed(2.0, OP_EDONKEYPROT, OP_SENDINGPART, a),
            framed(3.03, OP_EDONKEYPROT, OP_ACCEPTUPLOADREQ, [0; 16]),
        ];
        let silent = [
            framed(0.5, OP_EMULEPROT, 0xA4, b),
            framed(3.0, OP_EMULEPROT, 0xA4, b),
            framed(3.01, OP_EDONKEYPROT, OP_STARTUPLOADREQ, b),
        ];
        let switch = link_switch(&silent, &heard, [a, b]).unwrap();
        assert_eq!(
            (switch.release, switch.answer, switch.parts_after),
            ("silent", "accept", 0)
        );
        assert!((switch.answer_ms.unwrap() - 20.0).abs() < 1e-6);

        let cancelled = [
            framed(2.5, OP_EDONKEYPROT, OP_CANCELTRANSFER, [0; 16]),
            framed(3.0, OP_EDONKEYPROT, 0x58, b),
            framed(3.01, OP_EDONKEYPROT, OP_STARTUPLOADREQ, b),
        ];
        assert_eq!(
            link_switch(&cancelled, &heard, [a, b]).unwrap().release,
            "cancel"
        );
        assert_eq!(link_switch(&silent[..1], &heard, [a, b]), None);
        assert_eq!(link_switch(&silent, &heard, [b, a]), None);
    }
}
