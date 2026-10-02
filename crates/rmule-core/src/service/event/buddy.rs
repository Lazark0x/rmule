//! Why a dial to the own recruited **Buddy** did not hold a link (ADR-0075,
//! Run Log). The buddy's state is a level; a failed dial leaves it where it
//! was, so the failure is reported as a step of its own.

use super::login::DialFailure;

/// Why a buddy dial did not hold a link, carried by
/// [`CoreEvent::BuddyDialFailed`](super::CoreEvent::BuddyDialFailed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuddyDialFailure {
    /// The TCP dial did not come up.
    Dial {
        /// Why.
        cause: DialFailure,
    },
    /// The link came up and the buddy closed it before its hello finished.
    HelloIncomplete,
    /// Our crypt stance and the one the buddy's `0x5A` stated cannot meet, so
    /// no dial left.
    CryptIncompatible,
    /// A node answered whose user hash is not the one the `0x5A` named.
    Stranger,
}
