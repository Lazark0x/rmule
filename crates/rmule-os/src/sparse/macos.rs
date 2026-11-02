//! The macOS **Punch**: `fcntl(F_PUNCHHOLE)` with an `fpunchhole_t`, which no
//! safe wrapper offers (neither std nor `rustix` has it). APFS frees the
//! range, which must be aligned to the filesystem's block; a filesystem
//! without the call answers with an error.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

/// Punch `len` bytes of `file` from `offset`, keeping its length.
#[allow(unsafe_code)]
pub(super) fn punch_hole(file: &File, offset: u64, len: u64) -> io::Result<()> {
    let out_of_range = |_| io::Error::from(io::ErrorKind::InvalidInput);
    let hole = libc::fpunchhole_t {
        fp_flags: 0,
        reserved: 0,
        fp_offset: libc::off_t::try_from(offset).map_err(out_of_range)?,
        fp_length: libc::off_t::try_from(len).map_err(out_of_range)?,
    };
    // SAFETY: `file` is borrowed, so its descriptor stays open for the whole
    // call. `F_PUNCHHOLE` reads one `fpunchhole_t`, which lives on this stack
    // frame until the call returns; the kernel keeps no pointer to it.
    let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_PUNCHHOLE, &raw const hole) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
