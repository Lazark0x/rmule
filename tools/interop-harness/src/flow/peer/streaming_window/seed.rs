//! The seeds of the streaming-window flow and the fixture a partial one loads.
//!
//! Stock aMule loads every `*.part.met` in its Temp dir at start
//! (`DownloadQueue.cpp:119-138`, stock 2.3.3) and shares every ready part
//! file, paused or not (`SharedFileList.cpp:327-336`). So a harness-written
//! `001.part` + `001.part.met` stages a seed that holds exactly the parts it
//! is given: `FT_STATUS = 1` loads it paused (`PartFile.cpp:453-454`), so it
//! fetches nothing itself and its bitmap holds still.
//!
//! The `.part.met` is laid out as aMule's loader reads it (`PartFile.cpp:353-392`):
//! version `0xE0`, the `.part`'s modification date, the file hash, the part
//! hash set (`KnownFile.cpp:503-540`; short of `GetED2KPartHashCount()` the
//! file waits for a hash set and never shares, `PartFile.cpp:691-694`), then
//! the tags — name, size, status and one `FT_GAPSTART`/`FT_GAPEND` pair per
//! run of missing parts, the end exclusive (`PartFile.cpp:540-560`). The tags
//! ride rmule's own codec (ADR-0053). The `.part` holds the real bytes of every
//! held part and zeros elsewhere, and is stamped with the date the `.part.met`
//! names; a copy that loses the stamp is rehashed, and the rehash finds the
//! same parts from the bytes (`PartFile.cpp:709-722`, `:1122-1219`).

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use rmule_primitives::{
    ED2K_PART_SIZE, Ed2kFileLink, Ed2kLink, Ed2kText, FileHash, FileHashSummary, PartHash, Tag,
    TagName, TagValue, part_count,
};

use crate::artifacts::write_incompressible_file;

/// The file every seed holds: a video name, so the download is Streaming
/// Priority (ADR-0112 §5).
pub(crate) const STREAM_FILE_NAME: &str = "stream.mkv";
/// The part file a partial seed loads, and its metadata.
pub(crate) const PART_FILE: &str = "001.part";
const PART_MET_FILE: &str = "001.part.met";
/// `PARTFILE_VERSION` (`DataFileVersion.h:34`): a file under 4 GiB.
const PART_MET_VERSION: u8 = 0xE0;
const FT_FILENAME: u8 = 0x01;
const FT_FILESIZE: u8 = 0x02;
const FT_STATUS: u8 = 0x14;
/// A gap tag's name is this byte and then its key in decimal
/// (`FileTags.h:37-38`).
const FT_GAPSTART: char = '\u{09}';
const FT_GAPEND: char = '\u{0A}';
/// `FT_STATUS` value aMule reads as paused.
const STATUS_PAUSED: u32 = 1;
/// The modification date stamped on every staged `.part` and named in its
/// `.part.met`, so aMule's date check (`PartFile.cpp:709-722`) passes and the
/// gaps are taken as written.
const PART_DATE_UNIX_SECS: u32 = 1_767_225_600;

/// What one seed holds of the stream file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SeedHolding {
    /// The whole file, shared from Incoming: aMule writes count `0` for it
    /// (`ClientTCPSocket.cpp:525-528`).
    Complete,
    /// These parts, from a paused part file in the Temp dir.
    Partial(BTreeSet<u32>),
}

impl SeedHolding {
    /// `complete`, or a part list such as `0-5,11`.
    ///
    /// # Errors
    /// On an empty list, a malformed number or a descending range.
    pub fn parse(text: &str) -> Result<Self> {
        if text.eq_ignore_ascii_case("complete") {
            return Ok(Self::Complete);
        }
        let mut parts = BTreeSet::new();
        for item in text.split(',').map(str::trim) {
            let (low, high) = item.split_once('-').unwrap_or((item, item));
            let low: u32 = low.parse().with_context(|| format!("part {low:?}"))?;
            let high: u32 = high.parse().with_context(|| format!("part {high:?}"))?;
            if high < low {
                bail!("part range {item:?} descends");
            }
            parts.extend(low..=high);
        }
        Ok(Self::Partial(parts))
    }

    /// The parts this seed holds of a `parts`-part file.
    pub(crate) fn parts(&self, parts: u32) -> BTreeSet<u32> {
        match self {
            Self::Complete => (0..parts).collect(),
            Self::Partial(held) => held.iter().copied().filter(|part| *part < parts).collect(),
        }
    }

    /// The spelling [`Self::parse`] reads back.
    pub fn spec(&self) -> String {
        match self {
            Self::Complete => "complete".to_owned(),
            Self::Partial(held) => held
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(","),
        }
    }
}

/// `clap` value parser for `--seed`.
///
/// # Errors
/// As [`SeedHolding::parse`].
pub fn seed_holding_arg(text: &str) -> std::result::Result<SeedHolding, String> {
    SeedHolding::parse(text).map_err(|error| format!("{error:#}"))
}

/// The two-seed default for a `parts`-part file: seed `a` the head up to the
/// middle part, seed `b` from the middle part on, both holding the Preview
/// Band's ends. Each holds parts only it holds, so each worker's first part is
/// very rare (ADR-0112 §4), and the shared parts are the band and the middle.
pub fn default_seeds(parts: u32) -> Vec<SeedHolding> {
    let last = parts.saturating_sub(1);
    let middle = parts / 2;
    let head: BTreeSet<u32> = (0..=middle).chain([last]).collect();
    let tail: BTreeSet<u32> = [0].into_iter().chain(middle..=last).collect();
    vec![SeedHolding::Partial(head), SeedHolding::Partial(tail)]
}

/// The staged stream file: its bytes, hashes and canonical link.
pub(crate) struct StreamFile {
    /// The complete file.
    pub(crate) path: PathBuf,
    /// What hashing it yields.
    pub(crate) summary: FileHashSummary,
    /// Its ed2k link, part hash set included.
    pub(crate) link: String,
}

/// Write `size` bytes no compressor shrinks to `dir/stream.mkv`, hash them
/// and write the link beside it as `stream.ed2k.txt`.
///
/// # Errors
/// If the file cannot be written or read back.
pub(crate) fn write_stream_file(dir: &Path, size: u64, seed: u64) -> Result<StreamFile> {
    fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let path = dir.join(STREAM_FILE_NAME);
    write_incompressible_file(&path, size, seed)?;
    let file = File::open(&path).with_context(|| format!("open {}", path.display()))?;
    let summary =
        FileHashSummary::digest_reader(file).with_context(|| format!("hash {}", path.display()))?;
    let link = Ed2kLink::File(Ed2kFileLink {
        name: Ed2kText::from_utf8(STREAM_FILE_NAME),
        size: summary.file_size(),
        file_hash: summary.file_hash(),
        part_hash_set: summary.part_hash_set().cloned(),
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    })
    .to_string();
    let link_path = dir.join("stream.ed2k.txt");
    fs::write(&link_path, &link).with_context(|| format!("write {}", link_path.display()))?;
    Ok(StreamFile {
        path,
        summary,
        link,
    })
}

/// Stage a partial seed's Temp dir: `001.part` holding `held`'s bytes and
/// zeros elsewhere, stamped with the date `001.part.met` names.
///
/// # Errors
/// If a file cannot be written, or the stream file is 4 GiB or larger.
pub(crate) fn stage_partial_seed(
    temp_dir: &Path,
    stream: &StreamFile,
    held: &BTreeSet<u32>,
) -> Result<()> {
    fs::create_dir_all(temp_dir).with_context(|| format!("create {}", temp_dir.display()))?;
    let size = stream.summary.file_size();
    let part_path = temp_dir.join(PART_FILE);
    {
        let mut source =
            File::open(&stream.path).with_context(|| format!("open {}", stream.path.display()))?;
        let mut part =
            File::create(&part_path).with_context(|| format!("create {}", part_path.display()))?;
        part.set_len(size)
            .with_context(|| format!("size {}", part_path.display()))?;
        let mut buffer = Vec::new();
        for index in held.iter().copied().filter(|part| *part < part_count(size)) {
            let start = u64::from(index) * ED2K_PART_SIZE;
            let len = (size - start).min(ED2K_PART_SIZE);
            buffer.resize(usize::try_from(len).context("part length")?, 0);
            source.seek(SeekFrom::Start(start))?;
            source
                .read_exact(&mut buffer)
                .with_context(|| format!("read part {index} of {}", stream.path.display()))?;
            part.seek(SeekFrom::Start(start))?;
            part.write_all(&buffer)
                .with_context(|| format!("write part {index} of {}", part_path.display()))?;
        }
        part.sync_all()?;
    }
    File::options()
        .write(true)
        .open(&part_path)
        .and_then(|part| {
            part.set_modified(
                SystemTime::UNIX_EPOCH + Duration::from_secs(u64::from(PART_DATE_UNIX_SECS)),
            )
        })
        .with_context(|| format!("stamp {}", part_path.display()))?;
    let hashes = stream
        .summary
        .part_hash_set()
        .map(|set| set.hashes().to_vec())
        .unwrap_or_default();
    let met = part_met(&PartMet {
        file_hash: stream.summary.file_hash(),
        part_hashes: &hashes,
        size,
        name: STREAM_FILE_NAME,
        date: PART_DATE_UNIX_SECS,
        held,
    })?;
    let met_path = temp_dir.join(PART_MET_FILE);
    fs::write(&met_path, met).with_context(|| format!("write {}", met_path.display()))
}

/// Give a complete seed its Incoming dir: the stream file, linked when the
/// filesystem allows and copied when not.
///
/// # Errors
/// If neither works.
pub(crate) fn stage_complete_seed(incoming_dir: &Path, stream: &StreamFile) -> Result<()> {
    fs::create_dir_all(incoming_dir)
        .with_context(|| format!("create {}", incoming_dir.display()))?;
    let target = incoming_dir.join(STREAM_FILE_NAME);
    if fs::hard_link(&stream.path, &target).is_err() {
        fs::copy(&stream.path, &target).with_context(|| format!("copy to {}", target.display()))?;
    }
    Ok(())
}

/// What one `.part.met` states.
struct PartMet<'a> {
    file_hash: FileHash,
    part_hashes: &'a [PartHash],
    size: u64,
    name: &'a str,
    date: u32,
    held: &'a BTreeSet<u32>,
}

/// The `.part.met` bytes for `met`.
fn part_met(met: &PartMet<'_>) -> Result<Vec<u8>> {
    let Ok(size) = u32::try_from(met.size) else {
        bail!(
            "a part file of {} bytes needs the large-file layout",
            met.size
        );
    };
    let mut tags = vec![
        Tag::new(
            TagName::compact_id(FT_FILENAME),
            TagValue::String(Ed2kText::from_utf8(met.name)),
        ),
        Tag::new(TagName::compact_id(FT_FILESIZE), TagValue::U32(size)),
        Tag::new(TagName::compact_id(FT_STATUS), TagValue::U32(STATUS_PAUSED)),
    ];
    for (key, (start, end)) in gaps(met.size, met.held).into_iter().enumerate() {
        for (mark, at) in [(FT_GAPSTART, start), (FT_GAPEND, end)] {
            tags.push(Tag::new(
                TagName::text(format!("{mark}{key}"))?,
                TagValue::U32(u32::try_from(at).context("gap offset")?),
            ));
        }
    }
    let mut bytes = vec![PART_MET_VERSION];
    bytes.extend_from_slice(&met.date.to_le_bytes());
    bytes.extend_from_slice(met.file_hash.as_bytes());
    bytes.extend_from_slice(
        &u16::try_from(met.part_hashes.len())
            .context("part hash count")?
            .to_le_bytes(),
    );
    for hash in met.part_hashes {
        bytes.extend_from_slice(hash.as_bytes());
    }
    bytes.extend_from_slice(
        &u32::try_from(tags.len())
            .context("tag count")?
            .to_le_bytes(),
    );
    for tag in &tags {
        bytes.extend_from_slice(&tag.encode());
    }
    Ok(bytes)
}

/// The byte ranges `[start, end)` of a `size`-byte file that `held` leaves
/// missing, one per run of missing parts.
fn gaps(size: u64, held: &BTreeSet<u32>) -> Vec<(u64, u64)> {
    let mut gaps: Vec<(u64, u64)> = Vec::new();
    for part in (0..part_count(size)).filter(|part| !held.contains(part)) {
        let start = u64::from(part) * ED2K_PART_SIZE;
        let end = (start + ED2K_PART_SIZE).min(size);
        match gaps.last_mut() {
            Some(last) if last.1 == start => last.1 = end,
            _ => gaps.push((start, end)),
        }
    }
    gaps
}

#[cfg(test)]
mod tests;
