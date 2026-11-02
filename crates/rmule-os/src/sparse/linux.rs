//! The Linux **Punch**: `fallocate(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)`
//! through `rustix`, so no `unsafe` is needed. ext4, XFS, Btrfs and tmpfs free
//! the range; a filesystem without the call answers `EOPNOTSUPP`. A range that
//! is not block-aligned is not refused: its partial blocks are zeroed in place.

use std::fs::File;
use std::io;

use rustix::fs::{FallocateFlags, fallocate};

/// Punch `len` bytes of `file` from `offset`, keeping its length.
pub(super) fn punch_hole(file: &File, offset: u64, len: u64) -> io::Result<()> {
    fallocate(
        file,
        FallocateFlags::PUNCH_HOLE | FallocateFlags::KEEP_SIZE,
        offset,
        len,
    )
    .map_err(io::Error::from)
}
