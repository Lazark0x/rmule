//! The **relay service**: a rendezvous rmule is asked to forward because it
//! is somebody's serving buddy.
//!
//! eMuleAI relays for anyone who names a served buddy, with no cap and no
//! per-source limit located anywhere in its tree.
//! ADR-0091 refuses that laxity (the counterparty-defect pattern, ADR-0055):
//!
//! - rmule relays **only within its buddy relation** — the claimed buddy ID
//!   must be the registered one and the held link must be up, which is the
//!   [`BuddySlot`](crate::buddy_link)'s verification and runs *before* this
//!   admission, so the target always resolves to a client we know;
//! - at most [`RELAY_PENDING_MAX`] relays are outstanding at once;
//! - one requester bucket gets one relay per [`RELAY_SOURCE_INTERVAL`].
//!
//! Verification runs first on purpose. Admission stamps a limiter and takes a
//! pending slot, and a datagram that names the wrong buddy must be able to do
//! neither — otherwise a spoofed flood with junk buddy IDs would fill the
//! pending table and deny the real requester.
//!
//! This limiter is **not** the acting path's
//! ([`acting`](super::acting)): they are separate tables so that traffic a
//! stranger can generate never spends a budget rmule needs for itself
//! (amule#1177 correction 5).

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use rmule_primitives::AccountingKey;

use crate::interval_limiter::IntervalLimiter;

/// Relays outstanding at once — eMuleAI's `ESERVERBUDDY_MAX_PENDING_RELAYS`,
/// the one relay cap its tree publishes (for its eServer-buddy path; its Kad
/// buddy path has none).
pub(crate) const RELAY_PENDING_MAX: usize = 10;

/// How long a forwarded relay counts as outstanding — eMuleAI's
/// `ESERVERBUDDY_RELAY_TIMEOUT`. The dialect has no completion frame, so a
/// relay leaves the table by ageing out and no other way.
pub(crate) const RELAY_PENDING_TTL: Duration = Duration::from_secs(15);

/// Minimum time between two relays for one requester bucket — eMuleAI's
/// `ESERVERBUDDY_RELAY_REASK_TIME`.
pub(crate) const RELAY_SOURCE_INTERVAL: Duration = Duration::from_secs(8);

/// Hard cap on tracked requester buckets (see [`IntervalLimiter`]).
pub(crate) const RELAY_TRACKED_MAX: usize = 4096;

/// Why an otherwise-valid relay was not forwarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelayRefusal {
    /// This requester bucket was served inside [`RELAY_SOURCE_INTERVAL`].
    SourceRateLimited,
    /// [`RELAY_PENDING_MAX`] relays are already outstanding.
    PendingFull,
}

/// The relay service's admission state.
#[derive(Debug)]
pub(crate) struct RelayAdmission {
    sources: IntervalLimiter,
    /// When each outstanding relay was forwarded, oldest first, and for
    /// which requester bucket.
    pending: VecDeque<(Instant, AccountingKey)>,
}

impl Default for RelayAdmission {
    fn default() -> Self {
        Self {
            sources: IntervalLimiter::new(RELAY_SOURCE_INTERVAL, RELAY_TRACKED_MAX),
            pending: VecDeque::new(),
        }
    }
}

impl RelayAdmission {
    /// Admit one **already verified** relay from `requester`. On `Ok` the
    /// relay holds a pending slot until it ages out.
    ///
    /// The pending cap is consulted before the source limiter so that a
    /// refusal for a full table does not also cost the requester its window:
    /// it did nothing wrong, and it should get its relay the moment a slot
    /// frees rather than eight seconds after.
    ///
    /// One requester bucket holds **one** slot: its re-ask, admitted on its
    /// own window, supersedes the slot it already holds rather than taking a
    /// second. So the table is filled only by as many buckets as it has
    /// slots, never by one stranger re-asking.
    pub(crate) fn admit(&mut self, requester: Ipv4Addr, now: Instant) -> Result<(), RelayRefusal> {
        while self
            .pending
            .front()
            .is_some_and(|(sent, _)| now.saturating_duration_since(*sent) >= RELAY_PENDING_TTL)
        {
            self.pending.pop_front();
        }
        let bucket = AccountingKey::of(requester.into());
        let holds_a_slot = self.pending.iter().any(|(_, held)| *held == bucket);
        if !holds_a_slot && self.pending.len() >= RELAY_PENDING_MAX {
            return Err(RelayRefusal::PendingFull);
        }
        if !self.sources.admit(bucket, now) {
            return Err(RelayRefusal::SourceRateLimited);
        }
        self.pending.retain(|(_, held)| *held != bucket);
        self.pending.push_back((now, bucket));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn requester(n: u8) -> Ipv4Addr {
        Ipv4Addr::new(45, 55, 200, n)
    }

    #[test]
    fn one_requester_gets_one_relay_per_window() {
        let mut admission = RelayAdmission::default();
        let t0 = Instant::now();
        assert_eq!(admission.admit(requester(7), t0), Ok(()));
        assert_eq!(
            admission.admit(requester(7), t0 + RELAY_SOURCE_INTERVAL / 2),
            Err(RelayRefusal::SourceRateLimited)
        );
        assert_eq!(
            admission.admit(requester(8), t0),
            Ok(()),
            "another source is unaffected"
        );
        assert_eq!(
            admission.admit(requester(7), t0 + RELAY_SOURCE_INTERVAL),
            Ok(())
        );
    }

    /// Ten outstanding and the eleventh waits — for a slot, not for its own
    /// window: refused while the table was full, it is served the instant
    /// the oldest relay ages out.
    #[test]
    fn the_pending_table_caps_at_ten_and_a_full_table_costs_the_refused_nothing() {
        let mut admission = RelayAdmission::default();
        let t0 = Instant::now();
        for n in 0..RELAY_PENDING_MAX as u8 {
            assert_eq!(admission.admit(requester(n), t0), Ok(()));
        }
        assert_eq!(
            admission.admit(requester(200), t0),
            Err(RelayRefusal::PendingFull)
        );
        let just_before = t0 + RELAY_PENDING_TTL - Duration::from_millis(1);
        assert_eq!(
            admission.admit(requester(200), just_before),
            Err(RelayRefusal::PendingFull)
        );
        assert_eq!(
            admission.admit(requester(200), t0 + RELAY_PENDING_TTL),
            Ok(())
        );
    }

    /// One requester bucket holds one pending slot at a time: with the table
    /// full, a bucket that holds a slot is still served on its window — its
    /// re-ask supersedes its own slot — and the table stays full to everyone
    /// else. So filling it takes as many addresses as slots, not one address
    /// re-asking every window.
    #[test]
    fn one_requester_holds_one_pending_slot() {
        let mut admission = RelayAdmission::default();
        let t0 = Instant::now();
        for n in 0..RELAY_PENDING_MAX as u8 {
            assert_eq!(admission.admit(requester(n), t0), Ok(()));
        }
        let later = t0 + RELAY_SOURCE_INTERVAL;
        assert_eq!(
            admission.admit(requester(200), later),
            Err(RelayRefusal::PendingFull)
        );
        assert_eq!(
            admission.admit(requester(7), later),
            Ok(()),
            "served on its window, in the slot it already held"
        );
        assert_eq!(
            admission.admit(requester(200), later),
            Err(RelayRefusal::PendingFull),
            "the re-ask took no second slot"
        );
    }
}
