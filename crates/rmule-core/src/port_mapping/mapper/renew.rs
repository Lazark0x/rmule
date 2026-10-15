//! Renewal and backoff: the lease ladder, what a renewal answer settles, and the retreat when nothing is available.

use super::super::renewal::PERMANENT_POLL;
use super::{
    DesiredMapping, Duration, GrantAnswer, Instant, MAX_RENEW_FAILURES, MIN_RENEW_GAP,
    MappingCommand, MappingError, MappingProtocol, MappingStatus, Phase, PortMapper, backoff_delay,
    clamp_hold_off, clamp_lease, renewal_delay,
};

impl PortMapper {
    /// Emit a renewal for every lease that is due.
    pub(super) fn fire_due_renewals(&mut self, now: Instant) {
        let due: Vec<_> = self
            .leases
            .iter()
            .filter(|(mapping, lease)| {
                lease.renew_at <= now && !self.readd_outstanding.contains(*mapping)
            })
            .map(|(mapping, lease)| (*mapping, lease.protocol, lease.external.port()))
            .collect();
        for (mapping, protocol, external_port) in due {
            self.commands.push_back(MappingCommand::Map {
                protocol,
                mapping,
                suggested_external_port: external_port,
                lease: self.config.lease,
            });
            self.advance_ladder(mapping, now);
        }
    }

    /// Move one lease onto the next rung of its renewal ladder, so an
    /// unanswered renewal retries later instead of re-firing on the next tick.
    fn advance_ladder(&mut self, mapping: DesiredMapping, now: Instant) {
        let draw = self.jitter.draw();
        let Some(lease) = self.leases.get_mut(&mapping) else {
            return;
        };
        lease.attempt = lease.attempt.saturating_add(1);
        let next = match lease.lease {
            // A permanent mapping has no expiry to take a fraction of, so its
            // verification poll paces from the attempt rather than the grant.
            None => now + PERMANENT_POLL,
            Some(_) => {
                lease.granted_at + renewal_delay(lease.protocol, lease.lease, lease.attempt, draw)
            }
        };
        // Forward progress even when the lease is already past its last rung.
        lease.renew_at = next.max(now + MIN_RENEW_GAP);
    }

    /// Take one renewal (or epoch re-add) answer.
    pub(super) fn settle_renewal(
        &mut self,
        mapping: DesiredMapping,
        outcome: Result<GrantAnswer, MappingError>,
        now: Instant,
    ) {
        let was_readd = self.readd_outstanding.remove(&mapping);
        match outcome {
            Ok(grant) => {
                let lease = clamp_lease(grant.lease);
                let status = self.adopt(mapping, &grant, lease);
                let draw = self.jitter.draw();
                let delay = renewal_delay(
                    self.leases
                        .get(&mapping)
                        .map_or(MappingProtocol::Pcp, |held| held.protocol),
                    lease,
                    0,
                    draw,
                );
                let mut moved = None;
                if let Some(held) = self.leases.get_mut(&mapping) {
                    // UPnP keys a mapping by its external port: an answer on
                    // another one is a second mapping, and the old one is
                    // still forwarding with nothing here to renew it.
                    if held.protocol.keys_by_external_port()
                        && held.external.port() != grant.external.port()
                    {
                        moved = Some((held.protocol, held.external.port()));
                    }
                    held.external = grant.external;
                    held.lease = lease;
                    held.granted_at = now;
                    held.renew_at = now + delay;
                    held.attempt = 0;
                    held.failures = 0;
                    held.status = status;
                }
                if let Some((protocol, external_port)) = moved {
                    self.commands.push_back(MappingCommand::Release {
                        protocol,
                        mapping,
                        external_port,
                    });
                }
                // A renewal the store no longer takes (a TCP port that moved,
                // an address gone private) must not leave the last grant it
                // took standing for a lease.
                if status != MappingStatus::Mapped {
                    self.withdraw_grant(mapping);
                }
                self.readd_succeeded |= was_readd;
            }
            Err(_) => {
                let exhausted = self.leases.get_mut(&mapping).is_some_and(|held| {
                    held.failures = held.failures.saturating_add(1);
                    held.failures >= MAX_RENEW_FAILURES
                });
                if exhausted {
                    // Three consecutive failures on one mapping is not a lost
                    // datagram — the gateway changed its mind, or changed.
                    self.reprobe(now);
                    return;
                }
            }
        }
        if was_readd
            && self.readd_succeeded
            && self.readd_queue.is_empty()
            && self.readd_outstanding.is_empty()
        {
            // The set has been re-added after a reboot, so the Kad verdict is
            // stale now rather than in an hour.
            self.readd_succeeded = false;
            self.commands.push_back(MappingCommand::RecheckReachability);
        }
    }

    /// Nothing available: climb the backoff ladder, respecting any hold-off a
    /// refusal asked for.
    ///
    /// The learned method is forgotten here, and that is load-bearing. A method
    /// that probes fine but grants nothing would otherwise be tried alone
    /// forever: every retry would open the same short round, fail the same way,
    /// and never reach the other two protocols. Remembering a method is an
    /// optimisation over a race that once worked, so a race that produced
    /// nothing is exactly when it stops being one.
    pub(super) fn enter_backoff(&mut self, now: Instant, hold_off: Option<Duration>) {
        if self.reracing.is_some() {
            // A re-race that found nothing better is not a failure: the
            // incumbent is still installed and renewing.
            self.resume_mapped(now);
            return;
        }
        self.learned = None;
        self.failures = self.failures.saturating_add(1);
        let delay = backoff_delay(self.failures).max(clamp_hold_off(hold_off));
        self.phase = Phase::BackingOff {
            retry_at: now + delay,
        };
    }

    /// Remember a probe refusal against every desired row, so a diagnostics
    /// table says why nothing is mapped rather than only that nothing is.
    pub(super) fn note_error(&mut self, error: &MappingError) {
        for mapping in self.desired.mappings() {
            self.errors.insert(*mapping, error.clone());
        }
    }
}
