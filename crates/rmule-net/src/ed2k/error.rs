//! The error surface of the eD2k runtime: the shared runtime failures
//! (connect, I/O, driver liveness, teardown) that sit above `rmule_ed2k`'s
//! protocol errors.

use thiserror::Error;

use crate::driver::DriverError;

/// Errors surfaced by the eD2k runtime APIs.
///
/// Layered above `rmule_ed2k::SessionError`: protocol-level faults stay in
/// the session crate; this enum carries runtime failures. Every one of them
/// is a [`DriverError`] today — the eD2k transport adds no failure of its
/// own — and the enum is non-exhaustive so a later transport can.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum Ed2kNetError {
    /// A failure of the shared driver harness (connect timeout, driver
    /// liveness, teardown, socket I/O).
    #[error(transparent)]
    Driver(#[from] DriverError),
}

impl From<std::io::Error> for Ed2kNetError {
    fn from(error: std::io::Error) -> Self {
        Self::Driver(DriverError::Io(error))
    }
}
