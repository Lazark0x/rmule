//! The **Held Part File** (ADR-0094, "The run holds its part
//! file"): a run opens its `.part` file once and writes every verified
//! part through that one handle, never re-opening by path. A removed file's
//! handle stays valid and writes into it succeed — into a file nobody can
//! reach — so an I/O error is never the signal. Before each part is written,
//! the run compares the [`FileKey`] of the file at the path with the held
//! handle's, and the handle's length with the end of the parts recorded. The
//! link count alone (`st_nlink == 0`) would miss a move away inside the file
//! system; the key comparison does not.
//!
//! The `Replaced` check relies on one invariant: while the run holds its
//! handle, the file at the path has the handle's key exactly when it is the
//! held file. Both keys are read at the check, never kept: exFAT gives an empty
//! file a made-up number and its first write a real one, through the handle
//! and the path alike, so a key read at hold names no file by the first part.
//! A path that names nothing proves a loss only when the handle reads no link
//! left: a parent directory renamed or a volume lazily unmounted leaves a whole
//! file with its handle healthy, which is a **Volume Stop** (ADR-0094), no
//! `Gone`. Where a file system keeps a link count on a removed file the stop
//! errs towards keeping the records, and the next hold says `Gone`.
//! On Unix the key is the device and inode, `stat` against `fstat`: one of
//! each per 9.28 MB part, and an open file's inode is never reused.
//!
//! On Windows the key is the volume serial number and the file index that
//! `GetFileInformationByHandle` reports, the pair Microsoft names as what
//! tells two handles to one file apart. The path's is read through an open
//! that asks for no access and shares read, write and delete, so it never
//! stands in another program's way. NTFS keeps a file's index until the file is deleted, and a
//! file held open is not freed, so no other file can take its index while
//! the run holds it: the invariant holds there.
//! Where the key is weaker the check errs towards silence: ReFS's 64-bit
//! index is not guaranteed unique and a cloned volume can repeat a serial
//! number, which can only miss a `Replaced`. Only FAT can err the other way:
//! a third-party defragmenter can move a FAT file's index, which would read
//! as `Replaced`. Size and creation time were rejected as the key: file
//! system tunnelling gives a file created under a just-removed name the old
//! file's creation time, which is exactly how a replacement is made. A
//! removed part file is `Gone` where Windows takes the name away at once
//! (POSIX delete semantics, NTFS on current Windows); where the name lingers
//! until the last handle closes, the path cannot be opened, which is no proof
//! of a change, and the next part is written into a file that is about to
//! vanish.
//!
//! The handle is the **Sparse Part File**'s (ADR-0111): it carries the sparse
//! flag on Windows, and each batch of writes is one blocking-pool call — the
//! check, the positional writes, the punch of each **Extension Gap**, and the
//! **Allocated Bytes** reading. Every write of a run goes through its **Persist
//! Lane**, one operation at a time, so no other is in flight on the handle
//! while a raw-handle call runs on it.

use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ed2k::Ed2kBlue;
use ed2k::digest::Digest;
use rmule_primitives::{EMBLOCKSIZE, PartHash, aich_block_hash};

use crate::assembly::CellHash;
use crate::content::{free_space, on_pool, sparse};
use crate::file_key::{FileKey, links_of_open};
use crate::planning::PartPlan;

/// What a run found at its part file's path that is no longer the file it
/// holds, or no longer all of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PartFileChange {
    /// The path names no file: the part file was removed or moved away.
    Gone,
    /// The path names another file than the one the run holds.
    Replaced,
    /// The file the run holds is shorter than the parts recorded in it.
    Truncated {
        /// Its length now.
        len: u64,
    },
}

impl std::fmt::Display for PartFileChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gone => f.write_str("the part file was removed"),
            Self::Replaced => f.write_str("the part file was replaced by another file"),
            Self::Truncated { len } => write!(f, "the part file was cut short to {len} bytes"),
        }
    }
}

/// Why a write through the held handle did not land.
#[derive(Debug)]
pub(crate) enum HeldWriteError {
    /// The file at the path is not (all of) the file the run holds. Nothing
    /// was written.
    Changed(PartFileChange),
    /// The path names nothing, while the handle reads a file with a link
    /// left. Nothing was written, and nothing proves a byte lost.
    PathAbsent,
    /// The volume is under the free-space floor. Nothing was written, or a
    /// write the volume refused left it there.
    OutOfSpace {
        /// The free bytes read beside the part file.
        free_bytes: u64,
    },
    /// The OS refused the open, the read of its metadata, or the write.
    Io(std::io::Error),
}

/// What a look at the held file found amiss.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HeldCheckFailed {
    /// The file at the path is not (all of) the file the run holds.
    Changed(PartFileChange),
    /// [`HeldWriteError::PathAbsent`].
    PathAbsent,
}

impl From<HeldCheckFailed> for HeldWriteError {
    fn from(failed: HeldCheckFailed) -> Self {
        match failed {
            HeldCheckFailed::Changed(change) => Self::Changed(change),
            HeldCheckFailed::PathAbsent => Self::PathAbsent,
        }
    }
}

/// The one open handle a run holds on its `.part` file.
#[derive(Debug)]
pub(crate) struct HeldPartFile {
    /// Shared with the blocking-pool call each write and check is.
    file: Arc<File>,
    path: PathBuf,
    /// Where the highest part recorded or byte written ends: a file shorter
    /// than this has lost them.
    recorded_end: u64,
    /// Whether a write punches its Extension Gap: off for the run when the
    /// volume refused the sparse flag, where a punch writes zeros.
    punches: bool,
    /// The directory of the store that records this file's parts.
    store_dir: Option<PathBuf>,
}

impl HeldPartFile {
    /// Open `path` for the run. With nothing recorded the file is created
    /// (with its parent directory) if absent; with parts recorded it must
    /// already be there, and a missing one is [`PartFileChange::Gone`] —
    /// never recreated behind the operator's back. `recorded_end` is where
    /// the highest recorded part ends. The sparse flag is set once here; a
    /// volume that refuses it is no error, but the run then punches nothing.
    /// Answers the run-start Allocated Bytes reading too, `None` when it
    /// failed.
    pub(crate) async fn hold(
        path: &Path,
        recorded_end: u64,
    ) -> Result<(Self, Option<u64>), HeldWriteError> {
        let path = path.to_path_buf();
        on_pool(move || Self::hold_blocking(path, recorded_end)).await
    }

    fn hold_blocking(
        path: PathBuf,
        recorded_end: u64,
    ) -> Result<(Self, Option<u64>), HeldWriteError> {
        let parts_recorded = recorded_end > 0;
        if !parts_recorded && let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(HeldWriteError::Io)?;
        }
        let opened = OpenOptions::new()
            .read(true)
            .write(true)
            .create(!parts_recorded)
            .truncate(false)
            .open(&path);
        let file = match opened {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Err(HeldWriteError::Changed(PartFileChange::Gone));
            }
            Err(error) => return Err(HeldWriteError::Io(error)),
        };
        let punches = sparse::open_for_writes(&file);
        check_file(&file, &path, recorded_end)?;
        let allocated = rmule_os::sparse::allocated_bytes(&file).ok();
        let held = Self {
            file: Arc::new(file),
            path,
            recorded_end,
            punches,
            store_dir: None,
        };
        Ok((held, allocated))
    }

    /// Is the file at the path still the file held, and all of it? Reads the
    /// keys of the path and the handle, and the handle's length.
    pub(crate) async fn check(&self) -> Result<(), HeldCheckFailed> {
        let file = Arc::clone(&self.file);
        let path = self.path.clone();
        let recorded_end = self.recorded_end;
        on_pool(move || check_file(&file, &path, recorded_end))
            .await
            .map(|_| ())
    }

    /// Write `blocks`, each an offset and its bytes, through the held handle
    /// in order of offset, after checking the file is still the one held and
    /// the volume over its free-space floor, and punch the Extension Gap each
    /// write opened, the file's length carried from one to the next. A write
    /// the volume refuses with the floor crossed is
    /// [`HeldWriteError::OutOfSpace`], whatever error it gave: a nearly full
    /// exFAT volume answers `EINVAL` as well as `ENOSPC`. Never truncates, and
    /// handed to the operating system before returning, so a crash of the
    /// process cannot lose a byte a checkpoint claims. Answers the Allocated
    /// Bytes reading after the writes, `None` when it failed.
    pub(crate) async fn write_blocks(
        &mut self,
        mut blocks: Vec<(u64, Vec<u8>)>,
    ) -> Result<Option<u64>, HeldWriteError> {
        blocks.sort_unstable_by_key(|&(offset, _)| offset);
        let file = Arc::clone(&self.file);
        let path = self.path.clone();
        let (recorded_end, punches) = (self.recorded_end, self.punches);
        let store_dir = self.store_dir.clone();
        let written_end = blocks
            .iter()
            .map(|(offset, bytes)| offset.saturating_add(bytes.len() as u64))
            .fold(recorded_end, u64::max);
        let allocated = on_pool(move || {
            let mut end = check_file(&file, &path, recorded_end)?;
            let len: u64 = blocks.iter().map(|(_, bytes)| bytes.len() as u64).sum();
            if let Some(free_bytes) = free_space::under_the_floor(&path, store_dir.as_deref(), len)
            {
                return Err(HeldWriteError::OutOfSpace { free_bytes });
            }
            for (offset, bytes) in &blocks {
                sparse::write_at(&file, *offset, bytes, end.filter(|_| punches)).map_err(
                    |error| match free_space::under_the_floor(&path, store_dir.as_deref(), len) {
                        Some(free_bytes) => HeldWriteError::OutOfSpace { free_bytes },
                        None => HeldWriteError::Io(error),
                    },
                )?;
                let written = offset.saturating_add(bytes.len() as u64);
                end = end.map(|end| end.max(written));
            }
            Ok(rmule_os::sparse::allocated_bytes(&file).ok())
        })
        .await?;
        self.recorded_end = written_end;
        Ok(allocated)
    }

    /// Read `plan`'s bytes back through the held handle, one cell at a time:
    /// the part hash they make and, when `read_cells` asks, each cell's AICH
    /// block hash. The file is short of nothing a run claims (ADR-0117 §4), so
    /// an end of file is an error like any other.
    pub(crate) async fn read_part(
        &self,
        plan: PartPlan,
        read_cells: bool,
    ) -> io::Result<(PartHash, Option<Vec<CellHash>>)> {
        let file = Arc::clone(&self.file);
        on_pool(move || {
            let mut digest = Ed2kBlue::new();
            let mut cells = read_cells.then(|| Vec::with_capacity(plan.cells()));
            let mut buffer = vec![0; EMBLOCKSIZE as usize];
            for cell in 0..plan.cells() {
                let start = plan.cell_start(cell);
                let len = (plan.end() - start).min(EMBLOCKSIZE) as usize;
                sparse::read_all_at(&file, start, &mut buffer[..len])?;
                digest.update(&buffer[..len]);
                if let Some(cells) = cells.as_mut() {
                    cells.push(aich_block_hash(&buffer[..len]));
                }
            }
            Ok((PartHash::from_bytes(digest.finalize().into()), cells))
        })
        .await
    }

    /// `plan`'s bytes, whole: what a recovery answer is judged against.
    pub(crate) async fn read_bytes(&self, plan: PartPlan) -> io::Result<Vec<u8>> {
        let file = Arc::clone(&self.file);
        on_pool(move || {
            let mut bytes = vec![0; plan.len as usize];
            sparse::read_all_at(&file, plan.offset, &mut bytes)?;
            Ok(bytes)
        })
        .await
    }

    /// Sync the file's data to the disk: what a checkpoint's claim rests on
    /// (ADR-0117 §4).
    pub(crate) async fn sync(&self) -> io::Result<()> {
        let file = Arc::clone(&self.file);
        on_pool(move || file.sync_data()).await
    }

    /// The file's length as the handle reads it: what a checkpoint is cut to.
    pub(crate) async fn len(&self) -> io::Result<u64> {
        let file = Arc::clone(&self.file);
        on_pool(move || Ok(file.metadata()?.len())).await
    }

    /// The held file's key and its metadata, read through the handle.
    pub(crate) async fn held_metadata(&self) -> io::Result<(FileKey, std::fs::Metadata)> {
        let file = Arc::clone(&self.file);
        on_pool(move || Ok((FileKey::of_open(&file)?, file.metadata()?))).await
    }

    /// Cut the file to `size`, the download's, when it is longer: no byte past
    /// the file's end lands, whatever a leftover held (ADR-0115). A healthy
    /// run never writes past it.
    pub(crate) async fn cut_to(&self, size: u64) -> io::Result<()> {
        let file = Arc::clone(&self.file);
        on_pool(move || {
            if file.metadata()?.len() > size {
                file.set_len(size)?;
            }
            Ok(())
        })
        .await
    }

    /// A handle the volume refuses every write through, standing for a
    /// volume that does: the file at `path`, open for reading alone.
    #[cfg(test)]
    pub(crate) fn refusing_writes(path: &Path) -> Self {
        Self {
            file: Arc::new(File::open(path).expect("open the part file")),
            path: path.to_path_buf(),
            recorded_end: 0,
            punches: false,
            store_dir: None,
        }
    }

    /// The directory of the store this file's parts are recorded in, whose
    /// volume each write is held to the floor on as well (ADR-0083).
    #[must_use]
    pub(crate) fn recorded_in(mut self, store_dir: Option<PathBuf>) -> Self {
        self.store_dir = store_dir;
        self
    }

    /// The parts a truncation cut were dropped: the recorded parts now end at
    /// `recorded_end`, which the file still reaches.
    pub(crate) fn parts_dropped(&mut self, recorded_end: u64) {
        self.recorded_end = recorded_end;
    }
}

/// Is the file at `path` the one `file` holds, and at least `recorded_end`
/// long? Answers the handle's length, `None` when it could not
/// be read: an unreadable key or length is not proof of a change, and the
/// write that follows says what is wrong.
fn check_file(file: &File, path: &Path, recorded_end: u64) -> Result<Option<u64>, HeldCheckFailed> {
    let Ok(held) = FileKey::of_open(file) else {
        return Ok(None);
    };
    match FileKey::at(path) {
        Ok(at_path) if at_path != held => {
            return Err(HeldCheckFailed::Changed(PartFileChange::Replaced));
        }
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Err(match links_of_open(file) {
                Ok(0) => HeldCheckFailed::Changed(PartFileChange::Gone),
                _ => HeldCheckFailed::PathAbsent,
            });
        }
        Err(_) => return Ok(None),
    }
    let Ok(meta) = file.metadata() else {
        return Ok(None);
    };
    let len = meta.len();
    if len < recorded_end {
        return Err(HeldCheckFailed::Changed(PartFileChange::Truncated { len }));
    }
    Ok(Some(len))
}

#[cfg(test)]
mod tests;
