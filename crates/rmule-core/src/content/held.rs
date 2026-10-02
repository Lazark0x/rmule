//! The **Held Part File** (ADR-0093, "The part file under a running
//! download"): a run opens its `.part` file once and writes every verified
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

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncSeekExt, AsyncWriteExt, SeekFrom};

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
    file: File,
    path: PathBuf,
    /// Which file the handle holds.
    key: FileKey,
    /// Where the highest part recorded in the file ends: a file shorter than
    /// this has lost parts.
    recorded_end: u64,
}

impl HeldPartFile {
    /// Open `path` for the run. With nothing recorded the file is created
    /// (with its parent directory) if absent; with parts recorded it must
    /// already be there, and a missing one is [`PartFileChange::Gone`] —
    /// never recreated behind the operator's back. `recorded_end` is where
    /// the highest recorded part ends.
    pub(crate) async fn hold(path: &Path, recorded_end: u64) -> Result<Self, HeldWriteError> {
        let parts_recorded = recorded_end > 0;
        if !parts_recorded && let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(HeldWriteError::Io)?;
        }
        let opened = OpenOptions::new()
            .read(true)
            .write(true)
            .create(!parts_recorded)
            .truncate(false)
            .open(path)
            .await;
        let file = match opened {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Err(HeldWriteError::Changed(PartFileChange::Gone));
            }
            Err(error) => return Err(HeldWriteError::Io(error)),
        };
        let key = FileKey::of_open(&file).await.map_err(HeldWriteError::Io)?;
        let held = Self {
            key,
            file,
            path: path.to_path_buf(),
            recorded_end,
        };
        held.check().await.map_err(HeldWriteError::Changed)?;
        Ok(held)
    }

    /// Is the file at the path still the file held, and all of it? Reads the
    /// path's key and the handle's length.
    pub(crate) async fn check(&self) -> Result<(), PartFileChange> {
        let at_path = match FileKey::at_async(&self.path).await {
            Ok(key) => key,
            Err(error) if error.kind() == ErrorKind::NotFound => return Err(PartFileChange::Gone),
            // An unreadable key is not proof of a change; the write that
            // follows says what is wrong.
            Err(_) => return Ok(()),
        };
        if at_path != self.key {
            return Err(PartFileChange::Replaced);
        }
        let len = match self.file.metadata().await {
            Ok(meta) => meta.len(),
            Err(_) => return Ok(()),
        };
        if len < self.recorded_end {
            return Err(PartFileChange::Truncated { len });
        }
        Ok(())
    }

    /// Write one verified part at `offset` through the held handle, after
    /// checking the file is still the one held. Never truncates, and flushed
    /// before returning, so a crash cannot lose a part the store says it has.
    pub(crate) async fn write_part(
        &mut self,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), HeldWriteError> {
        self.check().await.map_err(HeldWriteError::Changed)?;
        let written = async {
            self.file.seek(SeekFrom::Start(offset)).await?;
            self.file.write_all(bytes).await?;
            self.file.flush().await
        };
        written.await.map_err(HeldWriteError::Io)?;
        self.recorded_end = self
            .recorded_end
            .max(offset.saturating_add(bytes.len() as u64));
        Ok(())
    }

    /// The parts a truncation cut were dropped: the recorded parts now end at
    /// `recorded_end`, which the file still reaches.
    pub(crate) fn parts_dropped(&mut self, recorded_end: u64) {
        self.recorded_end = recorded_end;
    }
}

#[cfg(test)]
mod tests;
