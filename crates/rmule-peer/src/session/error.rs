//! Why a peer session refuses a command or ends a connection: the guard
//! rejections ([`PeerError`]), the Secure User Identification failures that
//! cost credit but not the connection, and the terminal
//! [`PeerCloseReason`] vocabulary.

use std::fmt;

use thiserror::Error;

/// Why a Secure User Identification exchange failed (ADR-0041). Both are
/// non-terminal: the peer simply keeps unsecured credit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecureIdentFailure {
    /// The peer's `OP_PUBLICKEY` was not a valid RSA public key.
    BadPublicKey,
    /// The peer's signature did not verify over the challenge we sent.
    BadSignature,
}

/// Typed peer-protocol errors surfaced through `NoticeEvent::CommandRejected`
/// or out-of-band reporting. Decode errors live in the per-packet
/// error enums (`PeerHelloDecodeError`, `FileRequestDecodeError`, ...).
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PeerError {
    /// Second `RequestParts` issued while a slot context is already
    /// active for some file. Application must wait for `SlotReleased`
    /// before issuing the next `RequestParts`.
    #[error("peer slot context already active; wait for SlotReleased before requesting more parts")]
    SlotBusy,
    /// `RequestParts.file_size` disagrees with the value learned from
    /// a prior probe of the same `file_hash`.
    #[error("peer file size {requested} does not match probed file size {known}")]
    FileSizeMismatch {
        /// The size this command named.
        requested: u64,
        /// The size the probe established.
        known: u64,
    },
    /// Peer broke wire-level protocol in a way the session cannot
    /// recover from for the active flow.
    #[error("peer protocol violation: {reason}")]
    PeerProtocolViolation {
        /// What the peer did, in one fixed phrase — a label to count and
        /// match on, not a message to compose.
        reason: &'static str,
    },
    /// Core issued an emit command before the hello exchange completed.
    /// The command is dropped (no bytes ride the wire); the session lives.
    /// A **local** ordering bug, not the peer's — kept out of
    /// [`Self::PeerProtocolViolation`] so no offender accounting ever
    /// counts our own timing against the peer (cf. [`Self::SlotBusy`] /
    /// [`Self::ServeSlotNotGranted`], the other core-attributed rejects).
    #[error("core command issued before the peer identified")]
    CommandBeforeIdentified,
    /// Core asked the session to send a block for a file it holds no
    /// granted serve slot for. Defends the wire: the session never frames
    /// `OP_SENDINGPART` on an ungranted slot.
    #[error("no serve slot granted for the requested file")]
    ServeSlotNotGranted,
    /// Core answered a source ask for a file the peer never asked sources
    /// about on this connection, so no wire form was negotiated for it. The
    /// answer is dropped; nothing rides the wire.
    #[error("sources answered for a file the peer never asked about")]
    SourcesNotAsked,
}

impl PeerError {
    /// Whether the refused command was a serving one: a block or a source
    /// answer the serve half issued. The link outlives such a refusal, so a
    /// download sharing it has nothing to react to; a refused download
    /// command ([`Self::SlotBusy`], [`Self::FileSizeMismatch`]) is the
    /// downloader's own.
    #[must_use]
    pub const fn is_serving_refusal(&self) -> bool {
        matches!(self, Self::ServeSlotNotGranted | Self::SourcesNotAsked)
    }
}

/// Peer-protocol close taxonomy. Variant names diverge from
/// `rmule_ed2k::CloseReason` because peer semantics (`PeerClosed`,
/// `HelloTimeout`) do not match server semantics (`ServerClosed`,
/// `LoginTimeout`); ADR-0081 + the "peer disconnection taxonomy"
/// resolution in `CONTEXT.md` keep these types distinct.
///
/// `ConnectTimeout` is reserved for parity with the rest of the close
/// taxonomy: the runtime's connect timeout surfaces as
/// `DriverError::ConnectTimeout` before any `PeerSession` exists, so no
/// session path constructs this variant. It stays in the vocabulary so a
/// runtime that does own a session when its dial fails projects onto the
/// same shape consumers already match on.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PeerCloseReason {
    /// We closed it: a `Disconnect` command, or a local teardown.
    Local,
    /// The peer closed it, cleanly or by vanishing.
    PeerClosed,
    /// The peer did something the session cannot continue past.
    ProtocolViolation,
    /// Driver-side I/O failure. `ErrorKind` is the smallest portable
    /// summary; the full `io::Error` is logged by the driver. Mirrors
    /// `rmule_ed2k::CloseReason::Io`.
    Io(std::io::ErrorKind),
    /// The dial never completed. Unreachable today (see the type docs).
    ConnectTimeout,
    /// No hello arrived inside the startup deadline — whichever side owed
    /// one, since the timeout inverts with the role.
    HelloTimeout,
}

impl fmt::Display for PeerCloseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local => f.write_str("closed locally"),
            Self::PeerClosed => f.write_str("closed by the peer"),
            Self::ProtocolViolation => f.write_str("the peer broke the protocol"),
            Self::Io(kind) => write!(f, "I/O error: {kind}"),
            Self::ConnectTimeout => f.write_str("the connection timed out"),
            Self::HelloTimeout => f.write_str("no hello arrived in time"),
        }
    }
}

impl PeerCloseReason {
    /// Stable discriminant label (`&'static str`) for diagnostics and capture.
    /// The single source of truth for these labels, consumed by the peer `-net`
    /// capture layer and diagnostic tooling. Mirrors `rmule_ed2k::CloseReason::label`.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            PeerCloseReason::Local => "Local",
            PeerCloseReason::PeerClosed => "PeerClosed",
            PeerCloseReason::ProtocolViolation => "ProtocolViolation",
            PeerCloseReason::Io(_) => "Io",
            PeerCloseReason::ConnectTimeout => "ConnectTimeout",
            PeerCloseReason::HelloTimeout => "HelloTimeout",
        }
    }
}
