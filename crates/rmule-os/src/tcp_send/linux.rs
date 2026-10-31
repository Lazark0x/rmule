//! The Linux **Send side**: `ioctl(SIOCOUTQ)`, the bytes of the send queue,
//! unsent and unacked (`tcp(7)`). `rustix` carries the call but not this
//! request, and its typed `ioctl` is `unsafe` by contract.

use std::os::fd::BorrowedFd;

use rustix::ioctl::{Getter, Opcode, ioctl};

/// `SIOCOUTQ` (`<linux/sockios.h>`), which is `TIOCOUTQ`: this value on every
/// target rmule ships for.
const SIOCOUTQ: Opcode = 0x5411;

/// The bytes the kernel holds for the stream on `socket`.
#[allow(unsafe_code)]
pub(super) fn held(socket: BorrowedFd<'_>) -> Option<u64> {
    // SAFETY: `SIOCOUTQ` writes one `int` (`tcp(7)`), the output `Getter`
    // holds for the length of the call; `socket` is borrowed, so it stays
    // open throughout, and the kernel keeps no pointer.
    let held = unsafe { ioctl(socket, Getter::<SIOCOUTQ, std::ffi::c_int>::new()) }.ok()?;
    u64::try_from(held).ok()
}
