//! What a volume says of itself: the free bytes a write can still take
//! (ADR-0094, "A volume's refusal is a Volume Stop") and whether it is FAT,
//! which holds no file of 4 GiB (ADR-0115).
//!
//! - Linux and macOS: `statvfs` and `statfs` through `rustix`, with no
//!   `unsafe`. Free bytes are those an unprivileged process may take.
//! - Windows: `GetDiskFreeSpaceExW` and `GetVolumeInformationByHandleW`.
//!
//! What a reading means is core's.

use std::io;
use std::path::Path;

#[cfg(test)]
mod tests;
#[cfg(windows)]
mod windows;

/// The bytes a write by this process can still take on the volume that holds
/// `dir`.
///
/// # Errors
/// What the system reported: `NotFound` when `dir` is not there. `Unsupported`
/// on a platform other than Linux, macOS and Windows.
pub fn free_bytes(dir: &Path) -> io::Result<u64> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let found = rustix::fs::statvfs(dir).map_err(io::Error::from)?;
        Ok(found.f_bavail.saturating_mul(found.f_frsize))
    }
    #[cfg(windows)]
    {
        windows::free_bytes(dir)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = dir;
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// Whether the volume that holds `dir` is FAT, whose files end below 4 GiB.
/// exFAT is not.
///
/// # Errors
/// What the system reported: `NotFound` when `dir` is not there. `Unsupported`
/// on a platform other than Linux, macOS and Windows.
pub fn is_fat(dir: &Path) -> io::Result<bool> {
    #[cfg(target_os = "linux")]
    {
        // `MSDOS_SUPER_MAGIC` (`linux/magic.h`): vfat and msdos alike.
        const MSDOS_SUPER_MAGIC: u64 = 0x4d44;
        let found = rustix::fs::statfs(dir).map_err(io::Error::from)?;
        Ok(u64::try_from(found.f_type).is_ok_and(|kind| kind == MSDOS_SUPER_MAGIC))
    }
    #[cfg(target_os = "macos")]
    {
        let found = rustix::fs::statfs(dir).map_err(io::Error::from)?;
        Ok(found
            .f_fstypename
            .iter()
            .map(|&c| c as u8)
            .take_while(|&c| c != 0)
            .eq(*b"msdos"))
    }
    #[cfg(windows)]
    {
        windows::is_fat(dir)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = dir;
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}
