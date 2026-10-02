//! Explicit-time instant for the sans-I/O Kad node.
//!
//! `rmule-kad` never reads a clock (ADR-0043): every state transition takes
//! the current instant as a parameter, so a driver maps its real clock (or a
//! simulation its virtual one) onto this monotonic millisecond scale. The
//! epoch is whatever instant the driver calls zero.

use std::ops::Add;
use std::time::Duration;

/// A monotonic instant in driver-defined milliseconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KadInstant(u64);

impl KadInstant {
    /// The driver-defined zero instant.
    pub const EPOCH: Self = Self(0);

    /// An instant `millis` after the driver's zero.
    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    /// Milliseconds since the driver's zero.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }
}

impl Add<Duration> for KadInstant {
    type Output = Self;

    /// Saturates at the far end of the scale rather than wrapping: a deadline
    /// past `u64::MAX` milliseconds is "never" for any realistic driver.
    fn add(self, duration: Duration) -> Self {
        Self(
            self.0
                .saturating_add(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)),
        )
    }
}
