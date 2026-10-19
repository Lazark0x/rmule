//! A seed that serves bad bytes for one part (ADR-0117 §1, ADR-0029): a
//! stock aMule shares the stream file, hashes it, and only then has one
//! part's bytes overwritten in its own copy, the modification date put back.
//! aMule keeps the hash set it computed (it rehashes a shared file only when
//! its date or size changed, `SharedFileList.cpp`) and reads every block it
//! serves from disk, so its answers for that part carry bytes the part hash
//! refuses. The link carries no AICH root and three seeds cannot vote one in
//! (ADR-0038 asks ten), so the failed part takes the rootless path.
//!
//! The claims: the corrupt seed's part frames of that part carry bytes the
//! file does not hold (counterparty bytes, off the tap); rmule's first
//! `download.part_corrupt` names no writer; no honest seed is retired
//! `part_verification_failed`; the corrupt seed is, and rmule distrusts it;
//! the copy is byte-equal to the file.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::{Context, Result, bail};
use rmule_primitives::ED2K_PART_SIZE;
use serde::{Deserialize, Serialize};

use super::verdict::{RMULE_PCAP, TopologyFile};
use super::{ROOT_DIR, SEED_INCOMING_MOUNT, seed::STREAM_FILE_NAME};
use crate::flow::bench::{AMULE_PEER_TCP_PORT, Bench, run_checked};
use crate::flow::nat::claims::{Claim, Evidence, label};
use crate::flow::pcap::{Ed2kFrame, tcp_streams};
use crate::flow::wire_filter::{OP_EDONKEYPROT, OP_EMULEPROT};

/// The verdict file this leg writes beside the flow's own.
pub(crate) const VERDICT: &str = "peer-streaming-window-corrupt-verdict.toml";
/// `dd`'s block: the part size is 2,375 of them.
const DD_BLOCK: u64 = 4_096;
/// `OP_SENDINGPART` (eD2k) and `OP_SENDINGPART_I64` (eMule): plain part
/// bytes.
const OP_SENDINGPART: u8 = 0x46;
const OP_SENDINGPART_I64: u8 = 0xA2;
/// The file hash ahead of a part frame's offsets.
const HASH_LEN: usize = 16;
/// rmule's own download id: one download per run.
const DOWNLOAD_ID: &str = "id=1";
/// The trace line rmule writes when it distrusts a peer.
const DISTRUSTED: &str = "a peer that served bad data is distrusted for this download";

/// Which seed serves bad bytes, and for which part: `--corrupt-seed c:1`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorruptSeed {
    /// The seed's role letter, in start order from `a`.
    pub role: String,
    /// The part whose bytes it serves wrong.
    pub part: u32,
}

/// `clap` value parser for `--corrupt-seed`.
///
/// # Errors
/// On a spelling other than `<role letter>:<part>`.
pub fn corrupt_seed_arg(text: &str) -> std::result::Result<CorruptSeed, String> {
    let (role, part) = text
        .split_once(':')
        .ok_or_else(|| format!("{text:?}: expected <seed letter>:<part>, as c:1"))?;
    if role.len() != 1 || !role.chars().all(|letter| letter.is_ascii_lowercase()) {
        return Err(format!("{role:?}: a seed is named by one letter, a to z"));
    }
    Ok(CorruptSeed {
        role: role.to_owned(),
        part: part
            .parse()
            .map_err(|error| format!("part {part:?}: {error}"))?,
    })
}

/// What the overwrite left on the seed, kept beside the run.
#[derive(Debug, Serialize)]
struct Overwrite<'a> {
    seed: &'a CorruptSeed,
    container: &'a str,
    offset: u64,
    bytes: u64,
    /// The modification date before the overwrite and after it was put back.
    mtime: String,
}

/// Overwrite `corrupt`'s part of the stream file in `container`'s own copy
/// with random bytes and put its modification date back; the seed has hashed
/// and shared it already.
///
/// # Errors
/// If the part lies past the file, or the overwrite or the date fails.
pub(crate) fn overwrite_part(
    bench: &Bench,
    container: &str,
    corrupt: &CorruptSeed,
    file_size: u64,
    root: &Path,
) -> Result<()> {
    let offset = u64::from(corrupt.part) * ED2K_PART_SIZE;
    if offset >= file_size {
        bail!("part {} lies past a {file_size}-byte file", corrupt.part);
    }
    let blocks = (file_size - offset).min(ED2K_PART_SIZE) / DD_BLOCK;
    let file = format!("{SEED_INCOMING_MOUNT}/{STREAM_FILE_NAME}");
    let script = format!(
        "set -e; m=$(stat -c %Y {file}); \
         dd if=/dev/urandom of={file} bs={DD_BLOCK} seek={} count={blocks} conv=notrunc 2>/dev/null; \
         touch -d @$m {file}; echo $m $(stat -c %Y {file})",
        offset / DD_BLOCK
    );
    let mtime = run_checked(
        bench.docker.exec(
            container.to_owned(),
            ["sh".into(), "-c".into(), script.into()],
        ),
        "overwrite the corrupt seed's part",
    )?;
    let record = Overwrite {
        seed: corrupt,
        container,
        offset,
        bytes: blocks * DD_BLOCK,
        mtime: mtime.trim().to_owned(),
    };
    println!(
        "peer_streaming_window corrupt seed={} part={} offset={offset} bytes={} mtime_before_after={}",
        corrupt.role, corrupt.part, record.bytes, record.mtime
    );
    let path = root.join("corrupt.toml");
    fs::write(
        &path,
        toml::to_string_pretty(&record).context("serialize the overwrite")?,
    )
    .with_context(|| format!("write {}", path.display()))
}

/// A plain part frame's file offset and bytes, for the file `hash`.
fn plain_part(frame: &Ed2kFrame, hash: &[u8; 16]) -> Option<(u64, Vec<u8>)> {
    let width = match (frame.protocol, frame.opcode) {
        (OP_EDONKEYPROT, OP_SENDINGPART) => 4,
        (OP_EMULEPROT, OP_SENDINGPART_I64) => 8,
        _ => return None,
    };
    let payload = frame.payload();
    if payload.get(..HASH_LEN) != Some(hash.as_slice()) {
        return None;
    }
    let mut start = [0_u8; 8];
    start[..width].copy_from_slice(payload.get(HASH_LEN..HASH_LEN + width)?);
    let data = payload.get(HASH_LEN + 2 * width..)?.to_vec();
    Some((u64::from_le_bytes(start), data))
}

/// Of `frames` the seed sent, those inside `part`: how many, and how many
/// carry bytes `file` does not hold at their offset.
fn bad_frames(frames: &[Ed2kFrame], hash: &[u8; 16], file: &[u8], part: u32) -> (usize, usize) {
    let range = u64::from(part) * ED2K_PART_SIZE..(u64::from(part) + 1) * ED2K_PART_SIZE;
    let inside: Vec<(u64, Vec<u8>)> = frames
        .iter()
        .filter_map(|frame| plain_part(frame, hash))
        .filter(|(start, _)| range.contains(start))
        .collect();
    let bad = inside
        .iter()
        .filter(|(start, data)| {
            usize::try_from(*start)
                .ok()
                .and_then(|start| file.get(start..start + data.len()))
                != Some(data.as_slice())
        })
        .count();
    (inside.len(), bad)
}

/// rmule's run-log records of download 1 named `name` (`download.` dropped).
fn records<'a>(log: &'a str, name: &str) -> Vec<&'a str> {
    let head = format!("download.{name}");
    log.lines()
        .filter(|line| {
            let mut words = line.split_whitespace();
            words.next() == Some(head.as_str()) && line.split_whitespace().any(|w| w == DOWNLOAD_ID)
        })
        .collect()
}

/// The `key=` field of a record.
fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split_whitespace()
        .find_map(|word| word.strip_prefix(key)?.strip_prefix('='))
}

/// The peers rmule retired `part_verification_failed`, in order.
fn retired_for_failed_parts(log: &str) -> Vec<Ipv4Addr> {
    records(log, "peer_retired")
        .into_iter()
        .filter(|line| field(line, "reason") == Some("part_verification_failed"))
        .filter_map(|line| field(line, "peer")?.parse::<SocketAddr>().ok())
        .filter_map(|peer| match peer.ip() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })
        .collect()
}

/// The peers rmule's trace says it distrusted.
fn distrusted(trace: &str) -> Vec<Ipv4Addr> {
    trace
        .lines()
        .filter(|line| line.contains(DISTRUSTED))
        .filter_map(|line| field(line, "peer")?.parse::<SocketAddr>().ok())
        .filter_map(|peer| match peer.ip() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })
        .collect()
}

/// The rows beside the claims.
#[derive(Debug, Serialize)]
struct Rows {
    corrupt_seed: String,
    corrupt_part: u32,
    /// The corrupt seed's plain part frames inside its part, and how many
    /// carried bytes the file does not hold.
    frames_in_part: usize,
    bad_frames: usize,
    /// Every `download.part_corrupt` record, as logged.
    part_corrupt: Vec<String>,
    /// The seeds rmule retired `part_verification_failed`, and those it
    /// distrusted, by role.
    retired_for_failed_parts: Vec<String>,
    distrusted: Vec<String>,
}

#[derive(Serialize)]
struct Verdict<'a> {
    #[serde(rename = "scenario")]
    flow: &'static str,
    verdict: &'static str,
    detail: String,
    rows: &'a Rows,
    claim: &'a [Claim],
}

/// Score the corrupt seed's run under `run_dir` and write [`VERDICT`].
///
/// # Errors
/// If the tap, rmule's logs or the staged file cannot be read.
pub(crate) fn write(
    run_dir: &Path,
    topology: &TopologyFile,
    corrupt: &CorruptSeed,
    hash: &[u8; 16],
    copy_claim: Claim,
) -> Result<&'static str> {
    let root = run_dir.join(ROOT_DIR);
    let seed = topology
        .seeds
        .iter()
        .find(|seed| seed.role == corrupt.role)
        .with_context(|| format!("no seed {} in the topology", corrupt.role))?;
    let file_path = run_dir.join("synthetic").join(STREAM_FILE_NAME);
    let file = fs::read(&file_path).with_context(|| format!("read {}", file_path.display()))?;
    let from_seed: Vec<Ed2kFrame> = tcp_streams(&root.join(RMULE_PCAP))?
        .iter()
        .filter(|stream| {
            stream.source == SocketAddr::from((seed.ip, AMULE_PEER_TCP_PORT))
                && stream.destination.ip() == IpAddr::V4(topology.rmule_ip)
        })
        .flat_map(|stream| stream.ed2k_frames())
        .collect();
    let (frames_in_part, bad) = bad_frames(&from_seed, hash, &file, corrupt.part);
    let log = fs::read_to_string(run_dir.join("rmule/stdout.log")).context("read rmule's log")?;
    let trace = fs::read_to_string(run_dir.join("rmule/stderr.log")).unwrap_or_default();
    let corrupt_records = records(&log, "part_corrupt");
    let retired = retired_for_failed_parts(&log);
    let distrusted = distrusted(&trace);
    let role_of = |ip: &Ipv4Addr| {
        topology
            .seeds
            .iter()
            .find(|seed| seed.ip == *ip)
            .map_or_else(|| ip.to_string(), |seed| seed.role.clone())
    };
    let honest_retired = retired.iter().filter(|ip| **ip != seed.ip).count();
    let first = corrupt_records.first();
    let claims = vec![
        Claim::about(
            "the-corrupt-seed-sent-bytes-the-file-does-not-hold",
            bad > 0,
            Evidence::Captured,
            format!(
                "seed {}'s plain part frames inside part {}: {frames_in_part}, of which {bad} \
                 differ from the file at their offset",
                corrupt.role, corrupt.part
            ),
        ),
        match first {
            Some(line) => Claim::about(
                "the-first-failure-named-no-writer",
                field(line, "named") == Some("0"),
                Evidence::RmuleOnly,
                format!("rmule's first download.part_corrupt: {line}"),
            ),
            None => Claim::about(
                "the-first-failure-named-no-writer",
                false,
                Evidence::RmuleOnly,
                "rmule logged no download.part_corrupt",
            ),
        },
        if first.is_some() {
            Claim::absence(
                "no-honest-seed-was-retired-for-a-failed-part",
                i64::try_from(honest_retired).unwrap_or(i64::MAX),
                format!(
                    "seeds rmule retired part_verification_failed: {:?}",
                    retired.iter().map(role_of).collect::<Vec<_>>()
                ),
            )
        } else {
            Claim::blocked(
                "no-honest-seed-was-retired-for-a-failed-part",
                "no part failed, so no retirement could follow one",
            )
        },
        Claim::about(
            "the-corrupt-seed-was-retired-and-distrusted",
            retired.contains(&seed.ip) && distrusted.contains(&seed.ip),
            Evidence::RmuleOnly,
            format!(
                "retired part_verification_failed: {:?}; distrusted: {:?}",
                retired.iter().map(role_of).collect::<Vec<_>>(),
                distrusted.iter().map(role_of).collect::<Vec<_>>()
            ),
        ),
        copy_claim,
    ];
    let rows = Rows {
        corrupt_seed: corrupt.role.clone(),
        corrupt_part: corrupt.part,
        frames_in_part,
        bad_frames: bad,
        part_corrupt: corrupt_records
            .iter()
            .map(|line| (*line).to_owned())
            .collect(),
        retired_for_failed_parts: retired.iter().map(role_of).collect(),
        distrusted: distrusted.iter().map(role_of).collect(),
    };
    let (verdict, detail) = label(&claims);
    let text = toml::to_string_pretty(&Verdict {
        flow: "peer-streaming-window-corrupt",
        verdict,
        detail,
        rows: &rows,
        claim: &claims,
    })
    .context("serialize the corrupt verdict")?;
    let path = run_dir.join(VERDICT);
    fs::write(&path, &text).with_context(|| format!("write {}", path.display()))?;
    println!("{text}");
    Ok(verdict)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::*;

    fn part_frame(start: u32, data: &[u8], hash: [u8; 16]) -> Ed2kFrame {
        let body = [
            hash.as_slice(),
            &start.to_le_bytes(),
            &(start + u32::try_from(data.len()).unwrap()).to_le_bytes(),
            data,
        ]
        .concat();
        let length = u32::try_from(body.len() + 1).unwrap().to_le_bytes();
        Ed2kFrame {
            at: 1.0,
            source: SocketAddr::from((Ipv4Addr::new(172, 18, 0, 5), 4662)),
            destination: SocketAddr::from((Ipv4Addr::new(172, 18, 0, 9), 50_000)),
            protocol: OP_EDONKEYPROT,
            opcode: OP_SENDINGPART,
            bytes: [&[OP_EDONKEYPROT][..], &length, &[OP_SENDINGPART], &body].concat(),
        }
    }

    #[test]
    fn a_part_frame_is_bad_where_its_bytes_differ_from_the_file_at_its_offset() {
        let file: Vec<u8> = (0..32_u8).collect();
        let hash = [7; 16];
        let frames = [
            part_frame(0, &file[0..8], hash),
            part_frame(8, &[0xFF; 8], hash),
            part_frame(16, &file[16..24], [9; 16]),
        ];
        assert_eq!(bad_frames(&frames, &hash, &file, 0), (2, 1));
        assert_eq!(bad_frames(&frames, &hash, &file, 1), (0, 0));
    }

    #[test]
    fn retirements_and_distrust_are_read_by_peer() {
        let log = "download.part_corrupt id=1 part_index=1 writers=3 named=0\n\
                   download.peer_retired id=1 peer=172.18.0.5:4662 reason=part_verification_failed\n\
                   download.peer_retired id=1 peer=172.18.0.3:4662 reason=no_free_part\n";
        assert_eq!(records(log, "part_corrupt").len(), 1);
        assert_eq!(
            retired_for_failed_parts(log),
            [Ipv4Addr::new(172, 18, 0, 5)]
        );
        let trace = "2026-10-19T07:25:00Z  INFO download{download_id=1}: rmule_core::download::state::worker_event: a peer that served bad data is distrusted for this download peer=172.18.0.5:4662\n";
        assert_eq!(distrusted(trace), [Ipv4Addr::new(172, 18, 0, 5)]);
    }
}
