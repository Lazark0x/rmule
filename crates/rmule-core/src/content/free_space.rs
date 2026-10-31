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

/// Whether a download stopped for free space may run again: a whole part
/// fits over the floor.
pub(crate) fn fits_a_part(part_path: &Path) -> bool {
    under_the_floor(part_path, ED2K_PART_SIZE).is_none()
}

#[cfg(test)]
mod tests {
    use super::{ED2K_PART_SIZE, MIN_FREE_BYTES, is_under_the_floor};

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
