//! The **ICMP-reset switch**: Windows reports an ICMP port- or
//! net-unreachable that answers a sent datagram as an error on the socket's
//! next receive (`WSAECONNRESET`, `WSAENETRESET`), on an unconnected socket
//! too and whichever peer the datagram went to. A Kad cold start against
//! stale contacts draws a run of them, enough to end a receive pump. Linux and
//! macOS never report an ICMP error on an unconnected UDP socket, so switching
//! both reports off makes Windows receive as they do.
//!
//! The switch is one `WSAIoctl` no safe wrapper offers: std, socket2, mio and
//! quinn-udp all lack it, so it is one of the functions `scripts/guards.sh`
//! pins to a single `unsafe` block.

use std::io;

/// Switch off the ICMP-unreachable reports on `socket`. Off Windows an
/// unconnected UDP socket never reports them, so there is nothing to switch.
///
/// # Errors
/// None off Windows.
#[cfg(not(windows))]
pub fn disable_udp_connection_reset(_socket: &impl std::os::fd::AsFd) -> io::Result<()> {
    Ok(())
}

/// Switch off the ICMP-unreachable reports on `socket`: `SIO_UDP_CONNRESET`
/// (port unreachable) and `SIO_UDP_NETRESET` (TTL expired), both set to
/// `FALSE`.
///
/// # Errors
/// Whatever `WSAIoctl` reported.
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn disable_udp_connection_reset(
    socket: &impl std::os::windows::io::AsSocket,
) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;

    use windows_sys::Win32::Networking::WinSock::{
        SIO_UDP_CONNRESET, SIO_UDP_NETRESET, SOCKET, SOCKET_ERROR, WSAIoctl,
    };

    let socket = socket.as_socket();
    let off: i32 = 0;
    let mut returned: u32 = 0;
    for control in [SIO_UDP_CONNRESET, SIO_UDP_NETRESET] {
        // SAFETY: `socket` is a `BorrowedSocket`, so its handle stays open for
        // the whole call. The input is a 4-byte `BOOL` that outlives the call;
        // there is no output buffer, overlapped structure or completion
        // routine, so the call completes before it returns and keeps no
        // pointer.
        let result = unsafe {
            WSAIoctl(
                socket.as_raw_socket() as SOCKET,
                control,
                std::ptr::from_ref(&off).cast(),
                size_of::<i32>() as u32,
                std::ptr::null_mut(),
                0,
                &raw mut returned,
                std::ptr::null_mut(),
                None,
            )
        };
        if result == SOCKET_ERROR {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
