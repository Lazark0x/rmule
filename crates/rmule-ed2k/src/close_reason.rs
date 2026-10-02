//! Why an eD2k server session ended — always its final fact, carried by both
//! the disconnect event and the session's close drain.
//!
//! Non-exhaustive on purpose: a new transport may add a reason without
//! breaking anyone's matchers.

use crate::SessionError;

/// Why an [`Ed2kSession`](crate::Ed2kSession) ended.
///
/// Always the final fact of a session: carried by
/// [`Ed2kEvent::Disconnected`](crate::Ed2kEvent::Disconnected) and by the
/// session's `Output::Close` drain. Non-exhaustive so new transports
/// (transfer, Kad) can add variants without breaking matchers.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// Local caller invoked `Disconnect` (or dropped the connection handle).
    Local,
    /// Peer closed the TCP socket without an `OP_REJECT` payload.
    ServerClosed,
    /// Session refused to continue because of an illegal sequence or a
    /// malformed frame.
    ProtocolViolation(SessionError),
    /// Driver-side I/O failure. `ErrorKind` is the smallest portable
    /// summary; the full `io::Error` is logged by the driver.
    Io(std::io::ErrorKind),
    /// Driver-side TCP connect did not complete inside
    /// `ConnectOptions::connect_timeout`.
    ConnectTimeout,
    /// Driver-side login response did not arrive inside
    /// `ConnectOptions::login_timeout`.
    LoginTimeout,
    /// Server explicitly refused the login via `OP_REJECT`. Distinct
    /// from [`Self::ServerClosed`] (a TCP FIN with no explanation) so
    /// consumers can decide between "give up" vs "retry later" without
    /// guessing.
    LoginRejected,
}

impl CloseReason {
    /// Stable discriminant label (`&'static str`) for diagnostics and capture.
    /// Honest about payload-carrying variants: `ProtocolViolation(_)` returns
    /// `"ProtocolViolation"`, never the unit-variant `"ServerClosed"` stand-in
    /// an earlier driver used. The single source of truth for these labels,
    /// consumed by the `-net` capture layer and diagnostic tooling.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            CloseReason::Local => "Local",
            CloseReason::ServerClosed => "ServerClosed",
            CloseReason::ProtocolViolation(_) => "ProtocolViolation",
            CloseReason::Io(_) => "Io",
            CloseReason::ConnectTimeout => "ConnectTimeout",
            CloseReason::LoginTimeout => "LoginTimeout",
            CloseReason::LoginRejected => "LoginRejected",
        }
    }
}
