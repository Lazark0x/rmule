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
//! handle, the file at the path has the held key exactly when it is the held
//! file. On Unix the key is the device and inode, `stat` against `fstat`: one
//! of each per 9.28 MB part, and an open file's inode is never reused.
//!
//! On Windows the key is the volume serial number and the file index that
//! `GetFileInformationByHandle` reports, the pair Microsoft names as what
//! tells two handles to one file apart. The handle's key is read once, at
//! hold; the path's at each check, through an open that asks for no access
//! and shares read, write and delete, so it never stands in another
//! program's way. NTFS keeps a file's index until the file is deleted, and a
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
//! flag on Windows, and each write is one blocking-pool call — the check, the
//! positional write, the punch of its **Extension Gap**, and the **Allocated
//! Bytes** reading — so no other operation is in flight on the handle while a
//! raw-handle call runs on it.

use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::content::sparse;
use crate::file_key::FileKey;

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
    /// The OS refused the open, the read of its metadata, or the write.
    Io(std::io::Error),
}

/// The one open handle a run holds on its `.part` file.
#[derive(Debug)]
pub(crate) struct HeldPartFile {
    /// Shared with the blocking-pool call each write and check is.
    file: Arc<File>,
    path: PathBuf,
    /// Which file the handle holds.
    key: FileKey,
    /// Where the highest part recorded in the file ends: a file shorter than
    /// this has lost parts.
    recorded_end: u64,
    /// Whether a write punches its Extension Gap: off for the run when the
    /// volume refused the sparse flag, where a punch writes zeros.
    punches: bool,
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
        blocking(move || Self::hold_blocking(path, recorded_end)).await
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
        let key = FileKey::of_open(&file).map_err(HeldWriteError::Io)?;
        let punches = match rmule_os::sparse::set_sparse(&file) {
            Ok(()) => true,
            Err(error) => {
                tracing::debug!(%error, "the part file's volume refused the sparse flag");
                false
            }
        };
        check_file(&file, &path, key, recorded_end).map_err(HeldWriteError::Changed)?;
        let allocated = rmule_os::sparse::allocated_bytes(&file).ok();
        let held = Self {
            file: Arc::new(file),
            path,
            key,
            recorded_end,
            punches,
        };
        Ok((held, allocated))
    }

    /// Is the file at the path still the file held, and all of it? Reads the
    /// path's key and the handle's length.
    pub(crate) async fn check(&self) -> Result<(), PartFileChange> {
        let file = Arc::clone(&self.file);
        let path = self.path.clone();
        let (key, recorded_end) = (self.key, self.recorded_end);
        match tokio::task::spawn_blocking(move || check_file(&file, &path, key, recorded_end)).await
        {
            Ok(checked) => checked.map(|_| ()),
            // A check that could not run is no proof of a change.
            Err(_) => Ok(()),
        }
    }

    /// Write one verified part at `offset` through the held handle, after
    /// checking the file is still the one held, and punch the Extension Gap
    /// the write opened. Never truncates, and handed to the operating system
    /// before returning, so a crash of the process cannot lose a part the
    /// store says it has. Answers the Allocated Bytes reading after the
    /// write, `None` when it failed.
    pub(crate) async fn write_part(
        &mut self,
        offset: u64,
        bytes: &[u8],
    ) -> Result<Option<u64>, HeldWriteError> {
        let file = Arc::clone(&self.file);
        let path = self.path.clone();
        let (key, recorded_end, punches) = (self.key, self.recorded_end, self.punches);
        let part = bytes.to_vec();
        let allocated = blocking(move || {
            let end =
                check_file(&file, &path, key, recorded_end).map_err(HeldWriteError::Changed)?;
            sparse::write_at(&file, offset, &part, end.filter(|_| punches))
                .map_err(HeldWriteError::Io)?;
            Ok(rmule_os::sparse::allocated_bytes(&file).ok())
        })
        .await?;
        self.recorded_end = self
            .recorded_end
            .max(offset.saturating_add(bytes.len() as u64));
        Ok(allocated)
    }

    /// The parts a truncation cut were dropped: the recorded parts now end at
    /// `recorded_end`, which the file still reaches.
    pub(crate) fn parts_dropped(&mut self, recorded_end: u64) {
        self.recorded_end = recorded_end;
    }
}

/// Is the file at `path` the one `file` holds (`key`), and at least
/// `recorded_end` long? Answers the handle's length, `None` when it could not
/// be read: an unreadable key or length is not proof of a change, and the
/// write that follows says what is wrong.
fn check_file(
    file: &File,
    path: &Path,
    key: FileKey,
    recorded_end: u64,
) -> Result<Option<u64>, PartFileChange> {
    match FileKey::at(path) {
        Ok(at_path) if at_path != key => return Err(PartFileChange::Replaced),
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => return Err(PartFileChange::Gone),
        Err(_) => return Ok(None),
    }
    let Ok(meta) = file.metadata() else {
        return Ok(None);
    };
    let len = meta.len();
    if len < recorded_end {
        return Err(PartFileChange::Truncated { len });
    }
    Ok(Some(len))
}

/// Run `work` on the blocking pool; a call that could not run is an I/O
/// error.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, HeldWriteError> + Send + 'static,
) -> Result<T, HeldWriteError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| HeldWriteError::Io(io::Error::other(error)))?
}

#[cfg(test)]
mod tests;
