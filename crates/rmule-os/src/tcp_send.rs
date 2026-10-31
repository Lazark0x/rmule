//! The **Send side** of a TCP stream: what the kernel can say about bytes
//! already written to it, which tells a peer that reads slowly from one that
//! stopped. Linux and macOS count the bytes the kernel still holds, unsent and
//! unacked; Windows counts none it has not sent, so it answers the bytes
//! acknowledged instead. [`SendProgress`] keeps the two apart, and only its
//! comparison crosses this crate. What a reading means for a connection is
//! `rmule-net`'s (ADR-0031).

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests;
#[cfg(windows)]
mod windows;

/// One reading of a TCP stream's send side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendProgress {
    /// Bytes the kernel still holds for the stream, unsent and unacked: Linux
    /// and macOS. Falls as the peer acknowledges, rises with a write.
    Held(u64),
    /// Bytes the peer has acknowledged since the stream opened: Windows.
    /// Rises as the peer acknowledges.
    Acked(u64),
}

impl SendProgress {
    /// Whether the peer took bytes between `earlier` and this reading of the
    /// same stream, nothing having been written between them.
    #[must_use]
    pub const fn is_past(self, earlier: Self) -> bool {
        match (earlier, self) {
            (Self::Held(earlier), Self::Held(now)) => now < earlier,
            (Self::Acked(earlier), Self::Acked(now)) => now > earlier,
            _ => false,
        }
    }
}

/// Read `stream`'s send side. `None` when the system refuses, or has no such
/// call: the caller then knows nothing, and must not read that as movement.
#[cfg(unix)]
#[must_use]
pub fn send_progress(stream: &impl std::os::fd::AsFd) -> Option<SendProgress> {
    #[cfg(target_os = "linux")]
    {
        linux::held(stream.as_fd()).map(SendProgress::Held)
    }
    #[cfg(target_os = "macos")]
    {
        macos::held(stream.as_fd()).map(SendProgress::Held)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = stream;
        None
    }
}

/// Read `stream`'s send side. `None` when the system refuses: `SIO_TCP_INFO`
/// needs Windows 10 1703 or Server 2016.
#[cfg(windows)]
#[must_use]
pub fn send_progress(stream: &impl std::os::windows::io::AsSocket) -> Option<SendProgress> {
    windows::acked(stream.as_socket()).map(SendProgress::Acked)
}
