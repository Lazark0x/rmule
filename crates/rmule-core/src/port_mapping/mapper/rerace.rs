//! The **re-race** (ADR-0086, "the mapper keeps looking for Exact"): a winner
//! that left any row of the Desired Mapping Set short of its own port — a
//! shifted TCP port, a refused row, an IPv6 pinhole its protocol cannot
//! express — is not the end of the search. The other enabled protocols are
//! raced again on a schedule while the incumbent stays installed and keeps
//! renewing, and only a strictly better standing replaces it.
//!
//! The incumbent is not re-trialled: its standing is already known, and a
//! second trial of the protocol that holds the leases would ask the gateway
//! for mappings the mapper already owns.

use std::time::{Duration, Instant};

use rmule_net::portmap::MappingProtocol;

use super::super::renewal::BACKOFF_CEILING;
use super::{Phase, PortMapper, Standing, Trial};

/// How long a not-wholly-Exact install stands before the other protocols are
/// raced again: the backoff ladder's ceiling, the slowest the mapper ever
/// retries a race that fell short.
pub(crate) const RERACE_INTERVAL: Duration = BACKOFF_CEILING;

impl PortMapper {
    /// Schedule the next re-race of a freshly installed winner, or none when
    /// it is Exact on every row or no other enabled protocol could be asked.
    /// A winner of a short round is re-raced at once: the round asked the
    /// learned method alone, so the others have not been heard from at all.
    pub(super) fn schedule_rerace(
        &mut self,
        winner: MappingProtocol,
        whole_set_exact: bool,
        now: Instant,
    ) {
        self.reracing = None;
        let others = self
            .candidates()
            .into_iter()
            .any(|protocol| protocol != winner);
        self.rerace_at = (!whole_set_exact && others).then(|| {
            if self.short_round {
                now
            } else {
                now + RERACE_INTERVAL
            }
        });
    }

    /// Race every other candidate while the incumbent stays installed.
    pub(super) fn rerace(&mut self, now: Instant) {
        self.rerace_at = None;
        self.reracing = self.leases.values().map(|lease| lease.protocol).next();
        if self.reracing.is_none() {
            // Nothing is held to compare against: this is an ordinary race.
            self.installed = None;
        }
        self.open_probe_round(now);
    }

    /// A race's winner: installed, unless a re-race found nothing strictly
    /// better than the incumbent — then the winner's grants go back and the
    /// incumbent stands.
    pub(super) fn settle_winner(&mut self, winner: Trial, standing: Standing, now: Instant) {
        let beaten = self.reracing.is_none() || self.installed.is_none_or(|held| standing > held);
        if beaten {
            self.install(winner, standing, now);
        } else {
            self.release_trials(std::iter::once(winner));
            self.resume_mapped(now);
        }
    }

    /// End a re-race with the incumbent still installed, and schedule the next.
    pub(super) fn resume_mapped(&mut self, now: Instant) {
        self.reracing = None;
        self.phase = Phase::Mapped;
        self.rerace_at = Some(now + RERACE_INTERVAL);
    }

    /// Forget the installed winner and any re-race of it: the leases are
    /// being dropped or re-raced from scratch.
    pub(super) fn forget_install(&mut self) {
        self.installed = None;
        self.rerace_at = None;
        self.reracing = None;
    }
}
