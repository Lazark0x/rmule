//! The error surface of the peer runtime: the transport-specific failures
//! (dial, bind, accept, handshake, plaintext refusal) beside the shared
//! runtime failures, all above `rmule_peer`'s protocol errors.

use thiserror::Error;

use crate::driver::DriverError;

/// Runtime failures of a peer connection or listener. Non-exhaustive so a
/// later transport can extend it without breaking matchers.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum PeerNetError {
    /// The dial failed at the socket layer (refused, unreachable, reset). A
    /// dial that neither completes nor fails times out as
    /// [`DriverError::ConnectTimeout`] instead.
    #[error("connect to peer failed: {source}")]
    Connect {
        /// What `connect` returned.
        #[source]
        source: std::io::Error,
    },

    /// The listen port could not be bound, or the bound socket turned out not
    /// to be IPv4 — eD2k advertises a `SocketAddrV4` or nothing.
    #[error("bind listen socket failed: {source}")]
    Bind {
        /// What `bind` (or `local_addr`) returned.
        #[source]
        source: std::io::Error,
    },

    /// Accepting an inbound peer failed. Fatal to the accept loop, unlike a
    /// connection that fails after it is accepted.
    #[error("accept inbound peer failed: {source}")]
    Accept {
        /// What `accept` returned.
        #[source]
        source: std::io::Error,
    },

    /// The link ended before the peer identified itself, so there is no peer
    /// to report — carries the session's own reason for giving up.
    #[error("peer disconnected before identifying: {0}")]
    HandshakeIncomplete(rmule_peer::PeerCloseReason),

    /// An inbound peer opened in plaintext while the policy required
    /// obfuscation (ADR-0042); the byte-0 discrimination refused it before any
    /// session existed. `peer` is the refused dialer, so the caller can tell a
    /// reachability test that came late from a stranger.
    #[error("obfuscation required but peer connected in plaintext")]
    PlaintextRefused {
        /// The address the refused dial came from.
        peer: rmule_primitives::PeerEndpoint,
    },

    /// The dial was refused before any socket: a side that requires
    /// obfuscation met one that cannot provide it (ADR-0049's outbound rule,
    /// [`PeerCrypt::outbound`](rmule_primitives::PeerCrypt::outbound)).
    #[error("peer and local crypt stances are incompatible; dial refused")]
    CryptIncompatible,

    /// A failure of the shared driver harness (connect timeout, driver
    /// liveness, teardown, socket I/O).
    #[error(transparent)]
    Driver(#[from] DriverError),
}

impl From<std::io::Error> for PeerNetError {
    fn from(error: std::io::Error) -> Self {
        Self::Driver(DriverError::Io(error))
    }
}
