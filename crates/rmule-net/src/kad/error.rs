//! The error surface of the Kad UDP runtime: socket bind, capture-tap setup,
//! and the two ways the driver task can stop being there.

use thiserror::Error;

/// Failures surfaced by the Kad UDP runtime.
#[derive(Debug, Error)]
pub enum KadNetError {
    /// The UDP socket could not be bound or inspected.
    #[error("failed to bind the Kad UDP socket: {0}")]
    Bind(#[source] std::io::Error),

    /// The capture directory could not be prepared.
    #[error("failed to set up the Kad capture tap: {0}")]
    Capture(#[source] std::io::Error),

    /// The driver task is no longer running (it shut down or panicked), so
    /// commands cannot be delivered.
    #[error("the Kad driver task is no longer running")]
    DriverGone,

    /// The driver task panicked or was cancelled instead of returning.
    #[error("the Kad driver task ended abnormally")]
    Join,

    /// The transport's consecutive-error budget
    /// ([`rmule_net::family::ReceiveErrorBudget`](crate::family::ReceiveErrorBudget))
    /// was exhausted: `consecutive` receive errors in a row, most recently of
    /// `kind`, with no successful receive between them — a dead socket, not a
    /// lossy network. The driver still ran its clean-shutdown
    /// path (routing-table persist, capture finalize) before returning this.
    #[error(
        "the Kad UDP receive failed {consecutive} times in a row (last: {kind}); the driver ended"
    )]
    TransportFailing {
        /// The most recent receive error's kind.
        kind: std::io::ErrorKind,
        /// How many consecutive errors preceded this one (inclusive).
        consecutive: u32,
    },
}
