//! The **Sparse Part File** (ADR-0111): a write that extends the `.part`
//! punches the **Extension Gap** it opened, so a filesystem that zero-fills
//! the range it skipped gives the space back, and each run's **Hole Probe**
//! measures whether the disk under the `.part` holds holes at all. The calls
//! themselves are `rmule-os`'s; what to punch and what a reading means are
//! decided here.

use std::fs::File;
use std::io;
use std::ops::Range;
use std::path::{Path, PathBuf};

/// The punch's alignment: an Extension Gap is aligned inward to it, so the
/// verified bytes on both sides are untouched and APFS never sees an
/// unaligned range. The eD2k part size is 2,375 of these, so a whole-part
/// write's gap is aligned already.
const PUNCH_ALIGN: u64 = 4096;

/// The gap the Hole Probe opens between its two 4 KiB writes: past XFS
/// preallocation and cluster rounding with margin, and past APFS's 16 MiB
/// fill threshold.
const PROBE_GAP: u64 = 32 * 1024 * 1024;

/// One write of the probe, at each end of its gap.
const PROBE_RUN: usize = 4096;

/// The range one write at `offset` may make a filesystem zero-fill in a file
/// whose length was `end`, aligned inward to 4 KiB: `None` when the write
/// extends nothing (contiguous, or inside the file) or the aligned range is
/// empty.
pub(crate) fn extension_gap(end: u64, offset: u64) -> Option<Range<u64>> {
    if offset <= end {
        return None;
    }
    let start = end.checked_next_multiple_of(PUNCH_ALIGN)?;
    let stop = offset - offset % PUNCH_ALIGN;
    (start < stop).then_some(start..stop)
}

/// Write `bytes` at `offset` into `file`, then punch the Extension Gap when
/// `end` — the file's length just before the write — is given. `None` punches
/// nothing: the length is unknown, or the file did not take the sparse flag,
/// where a punch would write zeros. A punch that fails costs space, never
/// correctness: it is logged at `debug` and the write stands.
///
/// # Errors
/// What the write reported.
pub(crate) fn write_at(file: &File, offset: u64, bytes: &[u8], end: Option<u64>) -> io::Result<()> {
    write_all_at(file, bytes, offset)?;
    if let Some(gap) = end.and_then(|end| extension_gap(end, offset)) {
        let len = gap.end - gap.start;
        if let Err(error) = rmule_os::sparse::punch_hole(file, gap.start, len) {
            tracing::debug!(%error, offset = gap.start, len, "an Extension Gap was not punched");
        }
    }
    Ok(())
}

/// Ready `file` for writes that punch their Extension Gap: set its sparse
/// flag, and answer whether it took. A volume that refuses the flag is no
/// error — it is logged at `debug` — but its writes then punch nothing,
/// since a punch there would write zeros.
pub(crate) fn open_for_writes(file: &File) -> bool {
    match rmule_os::sparse::set_sparse(file) {
        Ok(()) => true,
        Err(error) => {
            tracing::debug!(%error, "the volume refused the sparse flag");
            false
        }
    }
}

/// [`write_at`] with the file's length read on the handle just before the
/// write, as a run reads it, punching only when `punches`
/// ([`open_for_writes`]).
///
/// # Errors
/// What the length read or the write reported.
pub(crate) fn write_punching(
    file: &File,
    offset: u64,
    bytes: &[u8],
    punches: bool,
) -> io::Result<()> {
    let end = file.metadata()?.len();
    write_at(file, offset, bytes, punches.then_some(end))
}

#[cfg(unix)]
fn write_all_at(file: &File, bytes: &[u8], offset: u64) -> io::Result<()> {
    std::os::unix::fs::FileExt::write_all_at(file, bytes, offset)
}

#[cfg(windows)]
fn write_all_at(file: &File, mut bytes: &[u8], mut offset: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !bytes.is_empty() {
        match file.seek_write(bytes, offset) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(written) => {
                bytes = &bytes[written..];
                offset = offset.saturating_add(written as u64);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Whether the disk under a run's `.part` holds holes, as its Hole Probe
/// measured (ADR-0111, "Each run measures whether its disk holds holes"). A
/// level on the download's diagnostics row; it changes nothing the run does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HoleVerdict {
    /// The punched probe took under half its length: a part file here
    /// occupies only the bytes written, plus slack.
    HoldsHoles,
    /// The punched probe took half its length or more: a part file here
    /// occupies every byte up to its end.
    HoleLess,
    /// A step of the probe failed, with the operating system's error kind.
    Unknown(io::ErrorKind),
}

impl HoleVerdict {
    /// The verdict on a probe of `logical` bytes the filesystem reserved
    /// `allocated` for: holes are held when under half was reserved.
    #[must_use]
    pub const fn from_sizes(allocated: u64, logical: u64) -> Self {
        if allocated < logical / 2 {
            Self::HoldsHoles
        } else {
            Self::HoleLess
        }
    }
}

/// The Hole Probe's file beside `part_path`: `.<part file name>.holeprobe`.
/// Fixed per download, so the next probe truncates a file a crash left
/// behind. `None` for a path with no file name.
pub(crate) fn probe_path(part_path: &Path) -> Option<PathBuf> {
    super::dot_sibling(part_path, ".holeprobe")
}

/// Run the Hole Probe beside `part_path`, on the blocking pool: the probe
/// file created or truncated, the sparse flag set, 4 KiB at 0 and 4 KiB past
/// a 32 MiB gap through the same write as a part, `fsync`, Allocated Bytes,
/// then the file removed. A volume that refuses the sparse flag is probed
/// unpunched, as the run writes there.
pub(crate) async fn probe_holes(part_path: &Path) -> HoleVerdict {
    let Some(probe) = probe_path(part_path) else {
        return HoleVerdict::Unknown(io::ErrorKind::InvalidInput);
    };
    match super::on_pool(move || probe_at(&probe)).await {
        Ok(verdict) => verdict,
        Err(error) => HoleVerdict::Unknown(error.kind()),
    }
}

fn probe_at(probe: &Path) -> io::Result<HoleVerdict> {
    let measured = measure(probe);
    let removed = std::fs::remove_file(probe);
    let verdict = measured?;
    removed?;
    Ok(verdict)
}

fn measure(probe: &Path) -> io::Result<HoleVerdict> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(probe)?;
    let punches = open_for_writes(&file);
    // Not zeros: a filesystem that compresses would store a zero run as a
    // hole, and the probe measures the gap, not its ends.
    let run = [0xA5u8; PROBE_RUN];
    let tail = PROBE_RUN as u64 + PROBE_GAP;
    for offset in [0, tail] {
        write_punching(&file, offset, &run, punches)?;
    }
    file.sync_all()?;
    let allocated = rmule_os::sparse::allocated_bytes(&file)?;
    Ok(HoleVerdict::from_sizes(allocated, tail + PROBE_RUN as u64))
}

#[cfg(test)]
mod tests;
