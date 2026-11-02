//! The macOS **Send side**: `getsockopt(SOL_SOCKET, SO_NWRITE)`, the bytes in
//! the socket's send buffer, which keeps a byte until it is acked. `rustix`
//! has no such option.

use std::ffi::{c_int, c_void};
use std::os::fd::{AsRawFd, BorrowedFd};

/// The bytes the kernel holds for the stream on `socket`.
#[allow(unsafe_code)]
pub(super) fn held(socket: BorrowedFd<'_>) -> Option<u64> {
    let mut held: c_int = 0;
    let mut len = size_of::<c_int>() as libc::socklen_t;
    // SAFETY: `socket` is borrowed, so it stays open throughout. `SO_NWRITE`
    // writes at most `len` bytes into `held`, and both live on this stack
    // frame until the call returns; the kernel keeps no pointer to them.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_NWRITE,
            (&raw mut held).cast::<c_void>(),
            &raw mut len,
        )
    };
    if result == -1 {
        return None;
    }
    u64::try_from(held).ok()
}
