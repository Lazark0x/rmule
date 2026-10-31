//! The free-space floor a part's write is held to (ADR-0094, "A volume's
//! refusal is a Volume Stop"): aMule's `CheckFreeDiskSpace`
//! (`PartFile.cpp:2485-2510`), which stops writing under one part free, and
//! under the bytes of the write and `MinFreeDiskSpace`'s default of 1 MiB
//! (`Preferences.cpp:1086`). The two meet at the full part a run writes.
//! Sparse files keep a write inside the file from being known to fit, so the
//! floor holds for every write, as there.

use std::path::Path;

use rmule_primitives::ED2K_PART_SIZE;

/// What must stay free beside the bytes of a write.
const MIN_FREE_BYTES: u64 = 1024 * 1024;

/// How often a download stopped for free space reads it again
/// (`DISKSPACERECHECKTIME`, `DownloadQueue.cpp:1229`).
pub(crate) const SPACE_RECHECK: std::time::Duration = std::time::Duration::from_secs(60);

/// Whether `free` bytes are under the floor for a write of `len` bytes.
const fn is_under_the_floor(free: u64, len: u64) -> bool {
    free < ED2K_PART_SIZE || free < len.saturating_add(MIN_FREE_BYTES)
}

/// The free bytes beside `part_path`, when they are under the floor for a
/// write of `len` bytes. `None` over it, and when they cannot be read: no
/// reading is no proof, and the write says what is wrong.
pub(crate) fn under_the_floor(part_path: &Path, len: u64) -> Option<u64> {
    let free = rmule_os::volume::free_bytes(part_path.parent()?).ok()?;
    is_under_the_floor(free, len).then_some(free)
}

/// Whether `free` bytes hold the `needed` bytes a file still has to write and
/// leave the floor for a full part: `free - GetNeededSpace() > min`
/// (`DownloadQueue.cpp:1267-1269`), `min` being what the write floor holds to.
/// Stock's subtraction wraps past the free space and resumes; here it does not.
const fn fits_the_rest(free: u64, needed: u64) -> bool {
    match free.checked_sub(needed) {
        Some(rest) => !is_under_the_floor(rest, ED2K_PART_SIZE),
        None => false,
    }
}

/// Whether a download stopped for free space may run again: all it has left of
/// its `file_size` fits over the floor. The file's allocated bytes are what it
/// holds, as a sparse file's length says nothing. No reading of the volume is
/// no proof, and the write says what is wrong; no reading of the file counts
/// nothing held.
pub(crate) fn fits_what_is_left(part_path: &Path, file_size: u64) -> bool {
    let Some(free) = part_path
        .parent()
        .and_then(|dir| rmule_os::volume::free_bytes(dir).ok())
    else {
        return true;
    };
    let held = std::fs::File::open(part_path)
        .and_then(|file| rmule_os::sparse::allocated_bytes(&file))
        .unwrap_or(0);
    fits_the_rest(free, file_size.saturating_sub(held))
}

#[cfg(test)]
mod tests {
    use super::{ED2K_PART_SIZE, MIN_FREE_BYTES, fits_the_rest, is_under_the_floor};

    /// A resume needs the whole remainder over the floor: on the free space
    /// of one part a file with two to go would stop at once and flap.
    #[test]
    fn a_stopped_file_resumes_with_its_whole_remainder_over_the_floor() {
        let floor = ED2K_PART_SIZE + MIN_FREE_BYTES;
        let needed = 2 * ED2K_PART_SIZE;
        assert!(!fits_the_rest(floor, needed));
        assert!(!fits_the_rest(floor + needed - 1, needed));
        assert!(fits_the_rest(floor + needed, needed));
        assert!(fits_the_rest(floor, 0));
    }

    #[test]
    fn the_floor_is_one_part_then_the_write_and_the_minimum() {
        assert!(is_under_the_floor(ED2K_PART_SIZE - 1, 1));
        assert!(!is_under_the_floor(ED2K_PART_SIZE, 1));
        assert!(is_under_the_floor(
            ED2K_PART_SIZE + MIN_FREE_BYTES - 1,
            ED2K_PART_SIZE
        ));
        assert!(!is_under_the_floor(
            ED2K_PART_SIZE + MIN_FREE_BYTES,
            ED2K_PART_SIZE
        ));
    }
}
