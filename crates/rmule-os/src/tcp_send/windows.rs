//! The Windows **Send side**: `WSAIoctl(SIO_TCP_INFO)` with a `TCP_INFO_v0`.
//! Nothing there counts a byte buffered and not yet sent, so the kernel's hold
//! cannot be read; `BytesOut` and `BytesInFlight` give the bytes acknowledged.

use std::mem::MaybeUninit;
use std::os::windows::io::{AsRawSocket, BorrowedSocket};

use windows_sys::Win32::Networking::WinSock::{
    SIO_TCP_INFO, SOCKET, SOCKET_ERROR, TCP_INFO_v0, WSAIoctl,
};

/// The bytes the peer has acknowledged on `socket`. The documentation does not
/// say whether `BytesOut` counts a retransmission, so `BytesRetrans` comes off:
/// a dead peer's re-sent bytes must not read as bytes taken, and a live peer's
/// losing a window of them to this only delays the next rise.
#[allow(unsafe_code)]
pub(super) fn acked(socket: BorrowedSocket<'_>) -> Option<u64> {
    let version: u32 = 0;
    let mut info = MaybeUninit::<TCP_INFO_v0>::zeroed();
    let mut returned: u32 = 0;
    // SAFETY: `socket` is borrowed, so its handle stays open for the whole
    // call. The input is the 4-byte version and the output one `TCP_INFO_v0`,
    // both on this stack frame; with no overlapped structure or completion
    // routine the call completes before it returns and keeps no pointer. The
    // structure is plain data, for which the zeros it began as are valid, so
    // it is initialised whatever the call wrote.
    let info = unsafe {
        let result = WSAIoctl(
            socket.as_raw_socket() as SOCKET,
            SIO_TCP_INFO,
            std::ptr::from_ref(&version).cast(),
            size_of::<u32>() as u32,
            info.as_mut_ptr().cast(),
            size_of::<TCP_INFO_v0>() as u32,
            &raw mut returned,
            std::ptr::null_mut(),
            None,
        );
        if result == SOCKET_ERROR {
            return None;
        }
        info.assume_init()
    };
    Some(
        info.BytesOut
            .saturating_sub(u64::from(info.BytesRetrans))
            .saturating_sub(u64::from(info.BytesInFlight)),
    )
}
