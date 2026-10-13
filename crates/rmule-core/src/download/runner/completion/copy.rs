//! The **Completion Copy** (ADR-0115): the finished file copied across
//! volumes to `.<destination name>.completing` beside its destination, hashed
//! as it is read, so the bytes that land are the bytes that were checked.
//! The dot prefix keeps the scan and its watch off the copy (ADR-0101). The
//! copy answers a stop between parts and never leaves a partial copy behind.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use ed2k::digest::Digest;
use rmule_primitives::{ED2K_PART_SIZE, FileHash};

/// Where the copy for `destination` is written: beside it, dot-prefixed.
pub(crate) fn copy_path(destination: &Path) -> PathBuf {
    let name = destination
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    destination.with_file_name(format!(".{name}.completing"))
}

/// How a copy ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Copied {
    /// Every byte is copied and synced; the file hash of what was read.
    Whole(FileHash),
    /// The stop was raised: the partial copy is deleted.
    Stopped,
}

/// Copy the first `size` bytes of `from` to `to`, a path nothing stands at,
/// one part at a time, hashing what it reads and telling `copied` the bytes
/// written after each part, then sync the copy to disk. `stop` is looked at
/// before each part. On a stop or an error the partial copy is deleted.
/// Blocking.
pub(crate) fn copy_hashed(
    from: &Path,
    to: &Path,
    size: u64,
    stop: &AtomicBool,
    copied: &mut dyn FnMut(u64),
) -> io::Result<Copied> {
    let result = copy_into(from, to, size, stop, copied);
    if !matches!(result, Ok(Copied::Whole(_))) {
        let _ = std::fs::remove_file(to);
    }
    result
}

fn copy_into(
    from: &Path,
    to: &Path,
    size: u64,
    stop: &AtomicBool,
    copied: &mut dyn FnMut(u64),
) -> io::Result<Copied> {
    let mut source = File::open(from)?;
    let mut copy = OpenOptions::new().write(true).create_new(true).open(to)?;
    let chunk = usize::try_from(ED2K_PART_SIZE.min(size)).unwrap_or(usize::MAX);
    let mut buffer = vec![0; chunk];
    let mut hasher = ed2k::Ed2kRed::default();
    let mut written = 0u64;
    while written < size {
        if stop.load(Ordering::Relaxed) {
            return Ok(Copied::Stopped);
        }
        let take = usize::try_from((size - written).min(ED2K_PART_SIZE)).unwrap_or(chunk);
        let bytes = &mut buffer[..take];
        source.read_exact(bytes)?;
        hasher.update(&*bytes);
        copy.write_all(bytes)?;
        written += take as u64;
        copied(written);
    }
    copy.sync_all()?;
    Ok(Copied::Whole(FileHash::from_bytes(
        hasher.finalize().into(),
    )))
}

/// Sync `directory` so a rename into it survives a crash, where the
/// platform lets a directory be opened; elsewhere a no-op.
pub(crate) fn sync_directory(directory: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(directory)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use rmule_primitives::ED2K_PART_SIZE;

    use super::{Copied, copy_hashed, copy_path};
    use crate::hashing::file_hash_streamed;

    #[test]
    fn a_whole_copy_hashes_what_it_read_and_a_stop_leaves_no_copy() {
        let dir = tempfile::tempdir().unwrap();
        let from = dir.path().join("film.mkv.part");
        let bytes: Vec<u8> = (0..ED2K_PART_SIZE + 4096)
            .map(|i| (i % 251) as u8)
            .collect();
        std::fs::write(&from, &bytes).unwrap();
        let size = bytes.len() as u64;
        let to = copy_path(&dir.path().join("film.mkv"));
        assert_eq!(to, dir.path().join(".film.mkv.completing"));

        let mut told = Vec::new();
        let copied = copy_hashed(&from, &to, size, &AtomicBool::new(false), &mut |n| {
            told.push(n);
        })
        .unwrap();
        let expected = file_hash_streamed(std::fs::File::open(&from).unwrap(), size).unwrap();
        assert_eq!(copied, Copied::Whole(expected));
        assert_eq!(std::fs::read(&to).unwrap(), bytes);
        assert_eq!(told, [ED2K_PART_SIZE, size]);
        std::fs::remove_file(&to).unwrap();

        // A stop raised once the first part is written ends the copy there.
        let stop = AtomicBool::new(false);
        let copied = copy_hashed(&from, &to, size, &stop, &mut |_| {
            stop.store(true, Ordering::Relaxed);
        })
        .unwrap();
        assert_eq!(copied, Copied::Stopped);
        assert!(!to.exists(), "the partial copy is deleted");
        assert_eq!(
            std::fs::read(&from).unwrap(),
            bytes,
            "the part is untouched"
        );
    }
}
