//! What the tap on rmule's namespace shows between rmule and the seeds: each
//! seed's part status for the stream file, every part request rmule sent it,
//! and every dial rmule made to it.
//!
//! The status is read here, from the counterparty's bytes, by a reader of the
//! harness's own: rmule's reader is what the flow tests. aMule answers a
//! file ask with `OP_FILESTATUS` (`0xE3 0x50`) alone or as an entry of
//! `OP_MULTIPACKETANSWER` (`0xC5 0x93`, `ClientTCPSocket.cpp:1104-1141`,
//! stock 2.3.3) beside `OP_REQFILENAMEANSWER` and `OP_AICHFILEHASHANS`. rmule
//! asks for parts with `OP_REQUESTPARTS` (`0xE3 0x47`, three 32-bit start and
//! end offsets) or `OP_REQUESTPARTS_I64` (`0xC5 0xA3`, 64-bit); an end is
//! exclusive.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::Result;
use rmule_primitives::{ED2K_PART_SIZE, ed2k_status_part_count, part_count};

use crate::flow::pcap::{Ed2kFrame, records, tcp_capture};

const OP_EDONKEYPROT: u8 = 0xE3;
const OP_EMULEPROT: u8 = 0xC5;
const OP_REQUESTPARTS: u8 = 0x47;
const OP_FILESTATUS: u8 = 0x50;
const OP_REQFILENAMEANSWER: u8 = 0x59;
const OP_MULTIPACKETANSWER: u8 = 0x93;
const OP_AICHFILEHASHANS: u8 = 0x9D;
const OP_REQUESTPARTS_I64: u8 = 0xA3;
/// The AICH master hash an `OP_AICHFILEHASHANS` entry carries.
const AICH_HASH_LEN: usize = 20;
const HASH_LEN: usize = 16;
/// The seeds' peer TCP port.
const SEED_TCP_PORT: u16 = 4662;

/// One status as it sits in a frame: its count and its bitmap bytes.
type StatusEntry<'a> = (u16, &'a [u8]);

/// Which of aMule's two status forms a count is, for this file's size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StatusForm {
    /// Count `0`: a complete source, every part held.
    Complete,
    /// Count `size / PARTSIZE + 1`; `phantom` when the size is an exact
    /// multiple of the part size, so the count names one part past the last.
    Counted {
        /// The count is one more than the file's real parts.
        phantom: bool,
    },
    /// Any other count, which aMule refuses (`DownloadClient.cpp:417-425`).
    Refused,
}

/// One seed's status for the stream file, as it crossed the tap.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Status {
    /// Capture time.
    pub(crate) at: f64,
    /// The seed that sent it.
    pub(crate) seed: Ipv4Addr,
    /// The count it states.
    pub(crate) count: u16,
    /// Its form for this file.
    pub(crate) form: StatusForm,
    /// The real parts it advertises (none for a refused form).
    pub(crate) held: BTreeSet<u32>,
}

/// One part request rmule sent a seed.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Request {
    /// Capture time.
    pub(crate) at: f64,
    /// The seed asked.
    pub(crate) seed: Ipv4Addr,
    /// Every part a non-empty range of it falls in.
    pub(crate) parts: BTreeSet<u32>,
}

/// A SYN rmule sent a seed's peer port.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Dial {
    /// Capture time.
    pub(crate) at: f64,
    /// The seed dialed.
    pub(crate) seed: Ipv4Addr,
}

/// Everything the scorer reads off the tap.
#[derive(Debug, Default)]
pub(crate) struct Wire {
    /// Every status a seed sent rmule for the file, in capture order.
    pub(crate) statuses: Vec<Status>,
    /// Every part request rmule sent a seed for the file, in capture order.
    pub(crate) requests: Vec<Request>,
    /// Every dial rmule made to a seed, in capture order.
    pub(crate) dials: Vec<Dial>,
    /// Links between rmule and a seed that did not open with an eD2k frame —
    /// obfuscated, so unreadable here.
    pub(crate) unread_links: usize,
    /// The last record's capture time: how far the tap reaches.
    pub(crate) last_at: f64,
}

/// Read `pcap` for the file `file_hash` of `size` bytes, between `rmule`
/// and the `seeds`.
///
/// # Errors
/// If the capture cannot be read.
pub(crate) fn read(
    pcap: &Path,
    rmule: Ipv4Addr,
    seeds: &[Ipv4Addr],
    file_hash: &[u8; 16],
    size: u64,
) -> Result<Wire> {
    let records = records(pcap)?;
    let capture = tcp_capture(&records)?;
    let mut wire = Wire {
        last_at: records.last().map_or(0.0, |record| record.at),
        ..Wire::default()
    };
    let seed_of = |address: SocketAddr| match address.ip() {
        IpAddr::V4(ip) if address.port() == SEED_TCP_PORT && seeds.contains(&ip) => Some(ip),
        _ => None,
    };
    let is_rmule = |address: SocketAddr| address.ip() == IpAddr::V4(rmule);
    for open in &capture.opens {
        if is_rmule(open.source)
            && let Some(seed) = seed_of(open.destination)
        {
            wire.dials.push(Dial { at: open.at, seed });
        }
    }
    for stream in &capture.streams {
        let from_seed = seed_of(stream.source).filter(|_| is_rmule(stream.destination));
        let to_seed = seed_of(stream.destination).filter(|_| is_rmule(stream.source));
        if (from_seed.is_some() || to_seed.is_some()) && !stream.opens_plain() {
            wire.unread_links += 1;
            continue;
        }
        for frame in stream.ed2k_frames() {
            if let Some(seed) = from_seed {
                for (count, bitmap) in status_entries(&frame, file_hash) {
                    let (form, held) = decode_status(count, bitmap, size);
                    wire.statuses.push(Status {
                        at: frame.at,
                        seed,
                        count,
                        form,
                        held,
                    });
                }
            } else if let Some(seed) = to_seed
                && let Some(parts) = requested_parts(&frame, file_hash)
            {
                wire.requests.push(Request {
                    at: frame.at,
                    seed,
                    parts,
                });
            }
        }
    }
    let by_time = |a: &f64, b: &f64| a.total_cmp(b);
    wire.statuses.sort_by(|a, b| by_time(&a.at, &b.at));
    wire.requests.sort_by(|a, b| by_time(&a.at, &b.at));
    wire.dials.sort_by(|a, b| by_time(&a.at, &b.at));
    Ok(wire)
}

/// Every `(count, bitmap)` status `frame` carries for `file_hash`: the frame
/// itself when it is an `OP_FILESTATUS`, or its status entry when it is an
/// `OP_MULTIPACKETANSWER`.
pub(crate) fn status_entries<'a>(
    frame: &'a Ed2kFrame,
    file_hash: &[u8; 16],
) -> Vec<StatusEntry<'a>> {
    let payload = frame.payload();
    if payload.get(..HASH_LEN) != Some(file_hash.as_slice()) {
        return Vec::new();
    }
    let body = &payload[HASH_LEN..];
    match (frame.protocol, frame.opcode) {
        (OP_EDONKEYPROT, OP_FILESTATUS) => status_at(body)
            .map(|(entry, _)| entry)
            .into_iter()
            .collect(),
        (OP_EMULEPROT, OP_MULTIPACKETANSWER) => multipacket_statuses(body),
        _ => Vec::new(),
    }
}

/// The status entries of a multipacket answer's body, walking every entry
/// aMule writes there and stopping at the first it does not.
fn multipacket_statuses(mut body: &[u8]) -> Vec<StatusEntry<'_>> {
    let mut statuses = Vec::new();
    while let Some((&opcode, rest)) = body.split_first() {
        body = match opcode {
            OP_REQFILENAMEANSWER => {
                let Some(len) = rest
                    .get(..2)
                    .map(|len| usize::from(u16::from_le_bytes([len[0], len[1]])))
                else {
                    break;
                };
                match rest.get(2 + len..) {
                    Some(rest) => rest,
                    None => break,
                }
            }
            OP_AICHFILEHASHANS => match rest.get(AICH_HASH_LEN..) {
                Some(rest) => rest,
                None => break,
            },
            OP_FILESTATUS => match status_at(rest) {
                Some((entry, rest)) => {
                    statuses.push(entry);
                    rest
                }
                None => break,
            },
            _ => break,
        };
    }
    statuses
}

/// A `<count u16><bitmap>` at the front of `bytes`, and what follows it.
fn status_at(bytes: &[u8]) -> Option<(StatusEntry<'_>, &[u8])> {
    let count = u16::from_le_bytes([*bytes.first()?, *bytes.get(1)?]);
    let len = usize::from(count).div_ceil(8);
    let bitmap = bytes.get(2..2 + len)?;
    Some(((count, bitmap), &bytes[2 + len..]))
}

/// The form of a `count` status for a `size`-byte file, and the real parts
/// its bitmap advertises — the first `part_count(size)` bits, least
/// significant first in each byte (`PartFile.cpp:1338-1355`).
pub(crate) fn decode_status(count: u16, bitmap: &[u8], size: u64) -> (StatusForm, BTreeSet<u32>) {
    let parts = part_count(size);
    if count == 0 {
        return (StatusForm::Complete, (0..parts).collect());
    }
    if u32::from(count) != ed2k_status_part_count(size) {
        return (StatusForm::Refused, BTreeSet::new());
    }
    let held = (0..parts)
        .filter(|part| {
            bitmap
                .get(*part as usize / 8)
                .is_some_and(|byte| byte >> (part % 8) & 1 == 1)
        })
        .collect();
    (
        StatusForm::Counted {
            phantom: u32::from(count) > parts,
        },
        held,
    )
}

/// The parts an `OP_REQUESTPARTS` or `OP_REQUESTPARTS_I64` frame for
/// `file_hash` names, or `None` for any other frame.
pub(crate) fn requested_parts(frame: &Ed2kFrame, file_hash: &[u8; 16]) -> Option<BTreeSet<u32>> {
    let width = match (frame.protocol, frame.opcode) {
        (OP_EDONKEYPROT, OP_REQUESTPARTS) => 4,
        (OP_EMULEPROT, OP_REQUESTPARTS_I64) => 8,
        _ => return None,
    };
    let payload = frame.payload();
    if payload.get(..HASH_LEN) != Some(file_hash.as_slice()) {
        return None;
    }
    let offsets = payload.get(HASH_LEN..HASH_LEN + 6 * width)?;
    let read = |index: usize| {
        let bytes = &offsets[index * width..(index + 1) * width];
        let mut wide = [0_u8; 8];
        wide[..width].copy_from_slice(bytes);
        u64::from_le_bytes(wide)
    };
    Some(
        (0..3)
            .map(|range| (read(range), read(range + 3)))
            .filter(|(start, end)| end > start)
            .flat_map(|(start, end)| {
                let first = start / ED2K_PART_SIZE;
                let last = (end - 1) / ED2K_PART_SIZE;
                (first..=last).filter_map(|part| u32::try_from(part).ok())
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests;
