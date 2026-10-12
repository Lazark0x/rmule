//! The error surface of the eD2k runtime: the shared runtime failures
//! (connect, I/O, driver liveness, teardown) that sit above `rmule_ed2k`'s
//! protocol errors.

use thiserror::Error;

use crate::driver::DriverError;

/// Errors surfaced by the eD2k runtime APIs.
///
/// Layered above `rmule_ed2k::SessionError`: protocol-level faults stay in
/// the session crate; this enum carries runtime failures — the shared
/// [`DriverError`]s, and the one failure the eD2k transport adds: an
/// obfuscated dial whose crypt handshake did not complete. Non-exhaustive so
/// a later transport can add its own.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum Ed2kNetError {
    /// A failure of the shared driver harness (connect timeout, driver
    /// liveness, teardown, socket I/O).
    #[error(transparent)]
    Driver(#[from] DriverError),
    /// The TCP link to the server's obfuscation port came up, but the server
    /// form of the crypt handshake (ADR-0042) did not complete: the server
    /// closed it, answered what does not decrypt to the sync magic, or said
    /// nothing within the connect timeout (`TimedOut`).
    #[error("server obfuscation handshake failed: {0}")]
    CryptHandshake(#[source] std::io::Error),
}

impl From<std::io::Error> for Ed2kNetError {
    fn from(error: std::io::Error) -> Self {
        Self::Driver(DriverError::Io(error))
    }
}
