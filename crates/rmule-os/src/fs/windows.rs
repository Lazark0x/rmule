//! The Windows **exclusive rename**: `MoveFileExW` with neither
//! `MOVEFILE_REPLACE_EXISTING`, so a standing target answers
//! `ERROR_ALREADY_EXISTS`, nor `MOVEFILE_COPY_ALLOWED`, so another volume
//! answers `ERROR_NOT_SAME_DEVICE` instead of a copy. No safe wrapper offers
//! it: std's `rename` always passes the replace flag.

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Storage::FileSystem::MoveFileExW;

/// Rename `from` onto `to` unless something stands at `to`.
#[allow(unsafe_code)]
pub(super) fn rename_exclusive(from: &Path, to: &Path) -> io::Result<()> {
    let (from, to) = (verbatim(from)?, verbatim(to)?);
    // SAFETY: both buffers are NUL-terminated UTF-16 with no interior NUL,
    // owned by this frame until the call returns; the call keeps no pointer
    // and, with no flags, neither copies nor defers the move.
    let ok = unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 0) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `path` made absolute and verbatim (`\\?\`, or `\\?\UNC\` for a share),
/// NUL-terminated: the form std hands the system, so a path past
/// `MAX_PATH` renames as std's own calls would reach it.
fn verbatim(path: &Path) -> io::Result<Vec<u16>> {
    let absolute = std::path::absolute(path)?;
    let wide: Vec<u16> = absolute.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let utf16 = |text: &str| text.encode_utf16().collect::<Vec<u16>>();
    let (verbatim_prefix, unc_prefix) = (utf16(r"\\?\"), utf16(r"\\"));
    let mut out = if wide.starts_with(&verbatim_prefix) {
        wide
    } else if let Some(share) = wide.strip_prefix(unc_prefix.as_slice()) {
        [utf16(r"\\?\UNC\").as_slice(), share].concat()
    } else {
        [verbatim_prefix.as_slice(), wide.as_slice()].concat()
    };
    out.push(0);
    Ok(out)
}
