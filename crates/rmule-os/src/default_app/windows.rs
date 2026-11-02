//! The Windows **Default app lookup**: `AssocQueryStringW` with
//! `ASSOCSTR_EXECUTABLE` for `.<extension>` and the `open` verb. The Unknown
//! type is ignored (`ASSOCF_INIT_IGNOREUNKNOWN`), so an extension with no app
//! answers `ERROR_NO_ASSOCIATION` rather than the Open With dialog's
//! program, and the answer is never truncated (`ASSOCF_NOTRUNCATE`).

use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use windows_sys::Win32::Foundation::{ERROR_NO_ASSOCIATION, S_OK};
use windows_sys::Win32::UI::Shell::{
    ASSOCF_INIT_IGNOREUNKNOWN, ASSOCF_NOTRUNCATE, ASSOCSTR_EXECUTABLE, AssocQueryStringW,
};
use windows_sys::core::HRESULT;

/// Room for the longest path Windows names, in UTF-16 units with the
/// terminating NUL.
const LONGEST_PATH: usize = 32_768;

/// The executable the shell opens files with `extension` with, if any.
#[allow(unsafe_code)]
pub(super) fn for_extension(extension: &str) -> io::Result<Option<PathBuf>> {
    let association: Vec<u16> = "."
        .encode_utf16()
        .chain(extension.encode_utf16())
        .chain([0])
        .collect();
    let verb: Vec<u16> = "open".encode_utf16().chain([0]).collect();
    let mut path = vec![0_u16; LONGEST_PATH];
    let mut length =
        u32::try_from(path.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `association` and `verb` are NUL-terminated UTF-16 strings that
    // live on this frame for the call. `path` is `length` units long, past
    // which the call never writes (`ASSOCF_NOTRUNCATE` fails instead), and
    // `length` is a live `u32` it writes back. It keeps no pointer to any.
    let result = unsafe {
        AssocQueryStringW(
            ASSOCF_NOTRUNCATE | ASSOCF_INIT_IGNOREUNKNOWN,
            ASSOCSTR_EXECUTABLE,
            association.as_ptr(),
            verb.as_ptr(),
            path.as_mut_ptr(),
            &raw mut length,
        )
    };
    if result == S_OK {
        let end = path
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(path.len());
        return Ok(Some(PathBuf::from(OsString::from_wide(&path[..end]))));
    }
    match win32_error(result) {
        Some(ERROR_NO_ASSOCIATION) => Ok(None),
        Some(code) => Err(i32::try_from(code).map_or_else(
            |_| io::Error::from(io::ErrorKind::Other),
            io::Error::from_raw_os_error,
        )),
        None => Err(io::Error::from(io::ErrorKind::Other)),
    }
}

/// The Win32 error code a failed `HRESULT` carries (`HRESULT_FROM_WIN32`
/// read back), or `None` for one of another facility.
fn win32_error(result: HRESULT) -> Option<u32> {
    let bits = result.cast_unsigned();
    (bits & 0xFFFF_0000 == 0x8007_0000).then_some(bits & 0xFFFF)
}
