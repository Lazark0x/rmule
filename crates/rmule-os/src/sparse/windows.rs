//! The Windows primitives, three calls no safe wrapper offers: the **Sparse
//! flag** (`DeviceIoControl(FSCTL_SET_SPARSE)`), the **Punch**
//! (`DeviceIoControl(FSCTL_SET_ZERO_DATA)`) and the allocated size
//! (`GetFileInformationByHandleEx(FileStandardInfo)`). NTFS frees a punched
//! range only on a file carrying the flag; without it the same call writes
//! zeros. FAT and exFAT refuse the flag.

use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle;

use windows_sys::Win32::Storage::FileSystem::{
    FILE_STANDARD_INFO, FileStandardInfo, GetFileInformationByHandleEx,
};
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::Ioctl::{
    FILE_ZERO_DATA_INFORMATION, FSCTL_SET_SPARSE, FSCTL_SET_ZERO_DATA,
};

/// Mark `file` sparse. No input buffer: the call then sets the flag.
#[allow(unsafe_code)]
pub(super) fn set_sparse(file: &File) -> io::Result<()> {
    let mut returned: u32 = 0;
    // SAFETY: `file` is borrowed, so its handle stays open for the whole call.
    // There is no input or output buffer and no overlapped structure (std
    // opens its files synchronous), so the call completes before it returns
    // and keeps no pointer; `returned` outlives it.
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            FSCTL_SET_SPARSE,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            0,
            &raw mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Punch `len` bytes of `file` from `offset`, keeping its length.
#[allow(unsafe_code)]
pub(super) fn punch_hole(file: &File, offset: u64, len: u64) -> io::Result<()> {
    let out_of_range = || io::Error::from(io::ErrorKind::InvalidInput);
    let zero = FILE_ZERO_DATA_INFORMATION {
        FileOffset: i64::try_from(offset).map_err(|_| out_of_range())?,
        BeyondFinalZero: offset
            .checked_add(len)
            .and_then(|end| i64::try_from(end).ok())
            .ok_or_else(out_of_range)?,
    };
    let mut returned: u32 = 0;
    // SAFETY: `file` is borrowed, so its handle stays open for the whole call.
    // The input is one `FILE_ZERO_DATA_INFORMATION` on this stack frame, its
    // exact size passed; there is no output buffer and no overlapped
    // structure, so the call completes before it returns and keeps no
    // pointer.
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            FSCTL_SET_ZERO_DATA,
            std::ptr::from_ref(&zero).cast(),
            size_of::<FILE_ZERO_DATA_INFORMATION>() as u32,
            std::ptr::null_mut(),
            0,
            &raw mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The bytes NTFS reserved for `file`: `FILE_STANDARD_INFO::AllocationSize`.
#[allow(unsafe_code)]
pub(super) fn allocated_bytes(file: &File) -> io::Result<u64> {
    let mut info = FILE_STANDARD_INFO::default();
    // SAFETY: `file` is borrowed, so its handle stays open for the whole call.
    // The output is one `FILE_STANDARD_INFO` on this stack frame, its exact
    // size passed, which is what `FileStandardInfo` writes; the call keeps no
    // pointer once it returns.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileStandardInfo,
            std::ptr::from_mut(&mut info).cast(),
            size_of::<FILE_STANDARD_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    u64::try_from(info.AllocationSize).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
}
