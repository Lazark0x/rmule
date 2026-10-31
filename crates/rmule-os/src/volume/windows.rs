//! The Windows volume readings: `GetDiskFreeSpaceExW` for the free bytes the
//! calling user may take, and `GetVolumeInformationByHandleW` for the file
//! system's name. No safe wrapper offers either.

use std::fs::OpenOptions;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, GetDiskFreeSpaceExW, GetVolumeInformationByHandleW,
};

/// The bytes the calling user may still write on the volume that holds `dir`.
#[allow(unsafe_code)]
pub(super) fn free_bytes(dir: &Path) -> io::Result<u64> {
    let mut wide: Vec<u16> = std::path::absolute(dir)?
        .as_os_str()
        .encode_wide()
        .collect();
    if wide.contains(&0) {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    wide.push(0);
    let mut free = 0_u64;
    // SAFETY: `wide` is NUL-terminated UTF-16 with no interior NUL and `free`
    // a live out-parameter, both owned by this frame until the call returns;
    // the other two out-parameters may be null, and the call keeps no pointer.
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &raw mut free,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(free)
}

/// Whether the file system of the volume that holds `dir` is named `FAT` or
/// `FAT32`. `exFAT` is neither.
#[allow(unsafe_code)]
pub(super) fn is_fat(dir: &Path) -> io::Result<bool> {
    let opened = OpenOptions::new()
        .access_mode(0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(dir)?;
    let handle: HANDLE = opened.as_raw_handle();
    // `MAX_PATH + 1`, the size Microsoft names for this buffer.
    let mut name = [0_u16; 261];
    // SAFETY: `handle` is open for this whole frame, `name` is a live buffer
    // of the length passed, the other out-parameters may be null, and the call
    // keeps no pointer.
    let ok = unsafe {
        GetVolumeInformationByHandleW(
            handle,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            name.as_mut_ptr(),
            name.len() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let end = name
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(name.len());
    let name = String::from_utf16_lossy(&name[..end]);
    Ok(name == "FAT" || name == "FAT32")
}
