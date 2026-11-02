//! The **exclusive rename** behind the completion move (ADR-0115, step 3): a
//! rename that the call itself refuses when a file stands at the target, so a
//! file another program created there is never replaced. Std's `rename`
//! replaces on every platform, and a check before it leaves a window.
//!
//! - Linux: `renameat2(RENAME_NOREPLACE)` and macOS: `renameatx_np(RENAME_EXCL)`,
//!   both through `rustix`'s `renameat_with`, with no `unsafe`.
//! - Windows: `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING` or
//!   `MOVEFILE_COPY_ALLOWED`.
//!
//! What to do when a filesystem refuses the flag is the caller's.

use std::io;
use std::path::Path;

#[cfg(test)]
mod tests;
#[cfg(windows)]
mod windows;

/// Rename `from` onto `to` unless something stands at `to`. Across volumes it
/// copies nothing: the caller makes its own copy.
///
/// # Errors
/// [`io::ErrorKind::AlreadyExists`] when something stands at `to`, both files
/// left as they were. [`io::ErrorKind::Unsupported`] when the filesystem
/// refuses the exclusive flag (`EINVAL` or `ENOSYS` on Linux; `ENOTSUP` on a
/// macOS SMB or exFAT volume), and on a platform other than Linux, macOS and
/// Windows. Otherwise what the system reported, `EXDEV` /
/// `ERROR_NOT_SAME_DEVICE` across volumes and a sharing violation on Windows
/// among them.
pub fn rename_exclusive(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use rustix::fs::{CWD, RenameFlags, renameat_with};
        use rustix::io::Errno;

        renameat_with(CWD, from, CWD, to, RenameFlags::NOREPLACE).map_err(|errno| {
            let refuses_flag = [Errno::INVAL, Errno::NOSYS, Errno::NOTSUP, Errno::OPNOTSUPP];
            if refuses_flag.contains(&errno) {
                io::Error::from(io::ErrorKind::Unsupported)
            } else {
                io::Error::from(errno)
            }
        })
    }
    #[cfg(windows)]
    {
        windows::rename_exclusive(from, to)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = (from, to);
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}
