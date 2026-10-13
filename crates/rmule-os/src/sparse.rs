//! The three filesystem primitives behind a **Sparse Part File**, each over a
//! borrowed `&File` the caller keeps open:
//!
//! - [`set_sparse`]: the **Sparse flag**. NTFS allocates every byte up to the
//!   end of a file without it, and a punch there writes zeros instead of
//!   freeing; ext4 and APFS need no flag, so off Windows it does nothing.
//! - [`punch_hole`]: the **Punch**, freeing a byte range without changing the
//!   file's length. The caller aligns the range; a filesystem that cannot
//!   punch answers with an error, never a panic.
//! - [`allocated_bytes`]: what the filesystem reserved for the file. It falls
//!   when a range is punched and may exceed the file's length.
//!
//! No policy lives here: which range to punch, the Hole Probe and its verdict
//! are `rmule-core`'s.

use std::fs::File;
use std::io;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(test)]
mod tests;
#[cfg(windows)]
mod windows;

/// Mark `file` sparse, so a later [`punch_hole`] frees its range. Windows
/// alone needs the flag; elsewhere every file can hold holes as it is.
///
/// # Errors
/// What `DeviceIoControl(FSCTL_SET_SPARSE)` reported — FAT and exFAT refuse
/// it. None off Windows.
pub fn set_sparse(file: &File) -> io::Result<()> {
    #[cfg(windows)]
    {
        windows::set_sparse(file)
    }
    #[cfg(not(windows))]
    {
        let _ = file;
        Ok(())
    }
}

/// Free `len` bytes of `file` from `offset`, keeping the file's length: the
/// range reads back as zeros and, where the filesystem holds holes, no longer
/// takes disk space. The caller aligns the range to the filesystem's block;
/// an unaligned range is the filesystem's to refuse or to zero partly.
///
/// # Errors
/// What the filesystem reported: `EOPNOTSUPP` or `EINVAL` where it cannot
/// punch that range. [`io::ErrorKind::Unsupported`] on a platform other than
/// Linux, macOS and Windows.
pub fn punch_hole(file: &File, offset: u64, len: u64) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::punch_hole(file, offset, len)
    }
    #[cfg(target_os = "macos")]
    {
        macos::punch_hole(file, offset, len)
    }
    #[cfg(windows)]
    {
        windows::punch_hole(file, offset, len)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = (file, offset, len);
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// The bytes the filesystem reserved for `file`, holes excluded and
/// preallocation included, so it can exceed the file's length. Read on the
/// open handle, so it answers for the file the caller writes even after a
/// rename.
///
/// # Errors
/// What reading the file's metadata reported.
pub fn allocated_bytes(file: &File) -> io::Result<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        // `st_blocks` counts 512-byte units on every Unix, whatever the
        // filesystem's own block size.
        Ok(file.metadata()?.blocks().saturating_mul(512))
    }
    #[cfg(windows)]
    {
        windows::allocated_bytes(file)
    }
}
