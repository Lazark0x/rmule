//! The on-disk side of a download's content: writing a verified part into the
//! file at its planned offset, and re-reading what a restart found so a resumed
//! download trusts only the parts that still hash. The store is the one place
//! part bytes meet the filesystem — every caller reaches it with a part that the
//! hash set has already vouched for.

use std::io::{Read, Seek};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::fs::{self, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, SeekFrom};

use rmule_primitives::FileHash;

use crate::file_key::FileKey;
use crate::hashing::{file_hash_streamed, part_hash_of};
use crate::served_downloads::PartFileIdentity;
use crate::{
    CoreError, DownloadPaths, FinalizeError, PartFault, StorageIntegrityFault, VerifiedPartRecord,
};

/// The download content filesystem operations, gathered as one namespace. It
/// holds no state — every call names the paths it works on — so it is a set of
/// associated functions rather than a handle.
pub struct ContentFileStore;

mod checked;
mod held;
mod sparse;

pub(crate) use checked::CheckedReadError;
pub use held::PartFileChange;
pub(crate) use held::{HeldPartFile, HeldWriteError};
pub use sparse::HoleVerdict;
pub(crate) use sparse::probe_holes;

/// `.<file name><suffix>` beside `path`, dot-prefixed so the scan and its
/// watch pass over it (ADR-0101): the Hole Probe's file and the Completion
/// Copy. `None` for a path with no file name.
pub(crate) fn dot_sibling(path: &Path, suffix: &str) -> Option<PathBuf> {
    let name = path.file_name()?;
    let mut sibling = std::ffi::OsString::from(".");
    sibling.push(name);
    sibling.push(suffix);
    Some(path.with_file_name(sibling))
}

/// Run `work` on the blocking pool and answer what it returned: the one way
/// core's file work leaves the async threads. A panic in `work` resumes on
/// the caller, as if it had run there; what the work itself can fail with is
/// its own result's to say.
pub(crate) async fn on_pool<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    match tokio::task::spawn_blocking(work).await {
        Ok(done) => done,
        Err(error) => match error.try_into_panic() {
            Ok(panic) => std::panic::resume_unwind(panic),
            // The pool cancels only work it never started, as the runtime
            // shuts down, when nothing awaits it any more.
            Err(error) => unreachable!("the blocking pool cancelled work it took: {error}"),
        },
    }
}

impl ContentFileStore {
    /// Write `bytes` into the `.part` file at absolute `offset`, creating the
    /// file and its parent directory if needed — for a part file written
    /// outside a run (a test's or a tool's seed). A run never writes by path:
    /// it writes through its held handle (ADR-0094, "The run holds its part
    /// file"). Never truncates, and handed to the operating system before
    /// returning. It is the run's write all the same (ADR-0111): the sparse
    /// flag set, the Extension Gap punched, so a seeded part file is as sparse
    /// as one a run wrote.
    pub async fn write_verified_part(
        paths: &DownloadPaths,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), CoreError> {
        let path = paths.part_path().to_path_buf();
        let bytes = bytes.to_vec();
        on_pool(move || {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(&path)?;
            let punches = sparse::open_for_writes(&file);
            sparse::write_punching(&file, offset, &bytes, punches)
        })
        .await
        .map_err(io_error)
    }

    /// Read exactly `len` bytes from `path` starting at `offset`. A short file
    /// is an error, not a short read — the caller asked for a range it believed
    /// was there.
    pub async fn read_range(path: &Path, offset: u64, len: u64) -> Result<Vec<u8>, CoreError> {
        let len = usize::try_from(len)
            .map_err(|_| CoreError::Repository("read range length exceeds usize".into()))?;
        read_exact_at(path, offset, len).await.map_err(io_error)
    }

    /// The eD2k file hash of the first `file_size` bytes of the file at
    /// `path`, streamed one part at a time on the blocking pool: the
    /// completion move's check of a part file, and its look at a destination
    /// attach found beside one (ADR-0115). A file that cannot be read, or
    /// holds fewer bytes, is [`FinalizeError::Unreadable`].
    pub(crate) async fn hash_file(path: &Path, file_size: u64) -> Result<FileHash, FinalizeError> {
        let path = path.to_path_buf();
        on_pool(move || {
            let file = std::fs::File::open(path)?;
            file_hash_streamed(file, file_size)
        })
        .await
        .map_err(|error| FinalizeError::Unreadable {
            os_code: error.raw_os_error(),
        })
    }

    /// Remove the `.part` file and the Hole Probe's file beside it.
    /// Idempotent: an already-absent file is success, so a cancel after a
    /// finalize is not an error.
    pub async fn delete_part(paths: &DownloadPaths) -> Result<(), CoreError> {
        remove_if_present(paths.part_path()).await?;
        match sparse::probe_path(paths.part_path()) {
            Some(probe) => remove_if_present(&probe).await,
            None => Ok(()),
        }
    }
}

/// Restored-progress facts from resume-time revalidation
/// ([`DownloadRepository::revalidate`](crate::DownloadRepository::revalidate)),
/// and the file they were read through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestoredProgress {
    verified_parts: usize,
    verified_bytes: u64,
    read_through: Option<PartFileIdentity>,
}

impl RestoredProgress {
    pub(crate) const fn new(verified_parts: usize, verified_bytes: u64) -> Self {
        Self {
            verified_parts,
            verified_bytes,
            read_through: None,
        }
    }

    /// The **Part File Identity** of the handle the parts were read
    /// through — its key, length and time, with no run writing the file —
    /// which the Offer Check hands the download's Served Download (ADR-0113).
    /// `None` when no part was read, or the handle's identity could not be.
    pub(crate) const fn read_through(self) -> Option<PartFileIdentity> {
        self.read_through
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
    let (paths, parts) = (paths.clone(), parts.to_vec());
    on_pool(move || walk_verified_parts(&paths, &parts, &AtomicBool::new(false)))
        .await
        .map_or(
            Revalidation::Condemned(StorageIntegrityFault::PartFileUnreadable { os_code: None }),
            |walked| walked.revalidation,
        )
}

/// What a walk of a download's recorded parts found, and the bytes it read
/// from the part file to find it.
#[derive(Debug)]
pub(crate) struct PartsWalked {
    /// What the parts read again came to.
    pub(crate) revalidation: Revalidation,
    /// The bytes read: every recorded part that lies inside the part file, up
    /// to a read that failed.
    pub(crate) bytes_read: u64,
}

/// [`revalidate_verified_parts`]' walk, on the calling thread, looking at
/// `stop` before each part: `None` once it is raised. The walk the Offer
/// Check runs on the blocking pool under the scans' hashing turn (ADR-0113),
/// and Resume's own.
pub(crate) fn walk_verified_parts(
    paths: &DownloadPaths,
    parts: &[VerifiedPartRecord],
    stop: &AtomicBool,
) -> Option<PartsWalked> {
    let mut bytes_read = 0;
    let revalidation = walk(paths, parts, stop, &mut bytes_read)?;
    Some(PartsWalked {
        revalidation,
        bytes_read,
    })
}

/// [`walk_verified_parts`], adding each part it reads to `bytes_read`.
fn walk(
    paths: &DownloadPaths,
    parts: &[VerifiedPartRecord],
    stop: &AtomicBool,
    bytes_read: &mut u64,
) -> Option<Revalidation> {
    if parts.is_empty() {
        return Some(Revalidation::Restored {
            progress: RestoredProgress::new(0, 0),
            damaged: Vec::new(),
        });
    }
    let unreadable = |error: std::io::Error| {
        Some(Revalidation::Condemned(
            StorageIntegrityFault::PartFileUnreadable {
                os_code: error.raw_os_error(),
            },
        ))
    };
    let mut file = match std::fs::File::open(paths.part_path()) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Some(Revalidation::Condemned(
                StorageIntegrityFault::PartFileMissing,
            ));
        }
        Err(error) => return unreadable(error),
    };
    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(error) => return unreadable(error),
    };
    let found_len = metadata.len();
    let read_through = FileKey::of_open(&file)
        .ok()
        .and_then(|key| PartFileIdentity::at_rest(key, &metadata));
    let mut held = 0usize;
    let mut verified_bytes = 0u64;
    let mut damaged = Vec::new();
    for part in parts {
        if stop.load(Ordering::Relaxed) {
            return None;
        }
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
        let read = file
            .seek(SeekFrom::Start(part.offset))
            .and_then(|_| file.read_exact(&mut bytes));
        if let Err(error) = read {
            return unreadable(error);
        }
        *bytes_read = bytes_read.saturating_add(part.len);
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
        return Some(Revalidation::Condemned(
            StorageIntegrityFault::NoPartHolds { recorded, first },
        ));
    }
    Some(Revalidation::Restored {
        progress: RestoredProgress {
            read_through,
            ..RestoredProgress::new(held, verified_bytes)
        },
        damaged,
    })
}

async fn read_exact_at(path: &Path, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
    let mut file = OpenOptions::new().read(true).open(path).await?;
    file.seek(SeekFrom::Start(offset)).await?;
    let mut bytes = vec![0; len];
    file.read_exact(&mut bytes).await?;
    Ok(bytes)
}

async fn remove_if_present(path: &Path) -> Result<(), CoreError> {
    match fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(error)),
    }
}

fn io_error(error: std::io::Error) -> CoreError {
    CoreError::Repository(error.to_string())
}
