//! The on-disk side of a download's content: writing a verified part into the
//! file at its planned offset, and re-reading what a restart found so a resumed
//! download trusts only the parts that still hash. The store is the one place
//! part bytes meet the filesystem — every caller reaches it with a part that the
//! hash set has already vouched for.

use std::path::Path;

use tokio::fs::{self, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};

use rmule_primitives::FileHash;

use crate::hashing::{file_hash_streamed, part_hash_of};
use crate::{
    CoreError, DownloadPaths, FinalizeError, PartFault, StorageIntegrityFault, VerifiedPartRecord,
};

/// The download content filesystem operations, gathered as one namespace. It
/// holds no state — every call names the paths it works on — so it is a set of
/// associated functions rather than a handle.
pub struct ContentFileStore;

mod held;

pub use held::PartFileChange;
pub(crate) use held::{HeldPartFile, HeldWriteError};

impl ContentFileStore {
    /// Write `bytes` into the `.part` file at absolute `offset`, creating the
    /// file and its parent directory if needed — for a part file written
    /// outside a run (a test's or a tool's seed). A run never writes by path:
    /// it writes through its held handle (ADR-0094, "The run holds its part
    /// file"). Never truncates, and flushed before returning.
    pub async fn write_verified_part(
        paths: &DownloadPaths,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), CoreError> {
        if let Some(parent) = paths.part_path().parent() {
            fs::create_dir_all(parent).await.map_err(io_error)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(paths.part_path())
            .await
            .map_err(io_error)?;
        file.seek(SeekFrom::Start(offset)).await.map_err(io_error)?;
        file.write_all(bytes).await.map_err(io_error)?;
        file.flush().await.map_err(io_error)
    }

    /// Read exactly `len` bytes from `path` starting at `offset`. A short file
    /// is an error, not a short read — the caller asked for a range it believed
    /// was there.
    pub async fn read_range(path: &Path, offset: u64, len: u64) -> Result<Vec<u8>, CoreError> {
        let len = usize::try_from(len)
            .map_err(|_| CoreError::Repository("read range length exceeds usize".into()))?;
        read_exact_at(path, offset, len).await.map_err(io_error)
    }

    /// Rename the completed `.part` file onto its destination. Refuses with
    /// [`FinalizeError::FinalPathTaken`] when the destination already exists
    /// rather than overwriting a file the user may want.
    pub async fn finalize(paths: &DownloadPaths) -> Result<(), FinalizeError> {
        if paths.final_path().exists() {
            return Err(FinalizeError::FinalPathTaken);
        }
        fs::rename(paths.part_path(), paths.final_path())
            .await
            .map_err(|error| FinalizeError::NotMoved {
                os_code: error.raw_os_error(),
            })
    }

    /// The eD2k file hash of the `.part` file's first `file_size` bytes,
    /// streamed one part at a time on the blocking pool. A file that cannot be
    /// read, or holds fewer bytes, is [`FinalizeError::Unreadable`].
    pub(crate) async fn hash_for_finalize(
        paths: &DownloadPaths,
        file_size: u64,
    ) -> Result<FileHash, FinalizeError> {
        let path = paths.part_path().to_path_buf();
        let hashed = tokio::task::spawn_blocking(move || {
            let file = std::fs::File::open(path)?;
            file_hash_streamed(file, file_size)
        })
        .await
        .map_err(|_| FinalizeError::Unreadable { os_code: None })?;
        hashed.map_err(|error| FinalizeError::Unreadable {
            os_code: error.raw_os_error(),
        })
    }

    /// Remove the `.part` file. Idempotent: an already-absent file is success,
    /// so a cancel after a finalize is not an error.
    pub async fn delete_part(paths: &DownloadPaths) -> Result<(), CoreError> {
        match fs::remove_file(paths.part_path()).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io_error(error)),
        }
    }
}

/// Restored-progress facts from resume-time revalidation
/// ([`DownloadRepository::revalidate`](crate::DownloadRepository::revalidate)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestoredProgress {
    verified_parts: usize,
    verified_bytes: u64,
}

impl RestoredProgress {
    pub(crate) const fn new(verified_parts: usize, verified_bytes: u64) -> Self {
        Self {
            verified_parts,
            verified_bytes,
        }
    }

    /// How many durable part records still hashed correctly against the bytes
    /// on disk. Parts that failed are not counted and will be re-fetched.
    #[must_use]
    pub const fn verified_parts(self) -> usize {
        self.verified_parts
    }

    /// The bytes those parts account for — their real lengths summed, so the
    /// file's short tail part counts as its true length.
    #[must_use]
    pub const fn verified_bytes(self) -> u64 {
        self.verified_bytes
    }
}

/// What resume-time revalidation found (ADR-0094, "Damaged parts"): a part
/// file that still backs its records, less any part that stopped hashing, or
/// one that backs none of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Revalidation {
    /// At least one recorded part still holds, or none was recorded. Each part
    /// in `damaged` failed its check; the store has dropped its record, so the
    /// run fetches it again.
    Restored {
        /// The parts that held.
        progress: RestoredProgress,
        /// The parts that did not, lowest first.
        damaged: Vec<PartFault>,
    },
    /// Nothing recorded can be trusted: the download fails with this fault.
    Condemned(StorageIntegrityFault),
}

/// The content-file re-hash walk behind
/// [`DownloadRepository::revalidate`](crate::DownloadRepository::revalidate):
/// re-read each durable verified-part record's range from the `.part` file and
/// check its hash still holds. A part that does not is named in `damaged`
/// rather than condemning the rest; the file is condemned only when it is
/// missing or unreadable with parts recorded, or when no recorded part holds.
pub(crate) async fn revalidate_verified_parts(
    paths: &DownloadPaths,
    parts: &[VerifiedPartRecord],
) -> Revalidation {
    if parts.is_empty() {
        return Revalidation::Restored {
            progress: RestoredProgress::new(0, 0),
            damaged: Vec::new(),
        };
    }
    let unreadable = |error: std::io::Error| {
        Revalidation::Condemned(StorageIntegrityFault::PartFileUnreadable {
            os_code: error.raw_os_error(),
        })
    };
    let mut file = match fs::File::open(paths.part_path()).await {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Revalidation::Condemned(StorageIntegrityFault::PartFileMissing);
        }
        Err(error) => return unreadable(error),
    };
    let found_len = match file.metadata().await {
        Ok(metadata) => metadata.len(),
        Err(error) => return unreadable(error),
    };
    let mut held = 0usize;
    let mut verified_bytes = 0u64;
    let mut damaged = Vec::new();
    for part in parts {
        let expected_end = part.offset.saturating_add(part.len);
        if expected_end > found_len {
            damaged.push(PartFault::Short {
                part_index: part.part_index,
                expected_end,
                found_len,
            });
            continue;
        }
        let Ok(len) = usize::try_from(part.len) else {
            damaged.push(PartFault::Short {
                part_index: part.part_index,
                expected_end,
                found_len,
            });
            continue;
        };
        let mut bytes = vec![0; len];
        let read = async {
            file.seek(SeekFrom::Start(part.offset)).await?;
            file.read_exact(&mut bytes).await
        };
        if let Err(error) = read.await {
            return unreadable(error);
        }
        let found = part_hash_of(&bytes);
        if found == part.part_hash {
            held += 1;
            verified_bytes = verified_bytes.saturating_add(part.len);
        } else {
            damaged.push(PartFault::HashMismatch {
                part_index: part.part_index,
                expected: part.part_hash,
                found,
            });
        }
    }
    if held == 0 {
        let recorded = u32::try_from(parts.len()).unwrap_or(u32::MAX);
        let first = damaged.swap_remove(0);
        return Revalidation::Condemned(StorageIntegrityFault::NoPartHolds { recorded, first });
    }
    Revalidation::Restored {
        progress: RestoredProgress::new(held, verified_bytes),
        damaged,
    }
}

async fn read_exact_at(path: &Path, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
    let mut file = OpenOptions::new().read(true).open(path).await?;
    file.seek(SeekFrom::Start(offset)).await?;
    let mut bytes = vec![0; len];
    file.read_exact(&mut bytes).await?;
    Ok(bytes)
}

fn io_error(error: std::io::Error) -> CoreError {
    CoreError::Repository(error.to_string())
}
