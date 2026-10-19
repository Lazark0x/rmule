//! The trials: each surviving protocol is mapped in turn with the real desired set, graded, and the winner installed with the losers released.

use super::{
    AddressObservation, DesiredMapping, Duration, GrantAnswer, Instant, MAX_LEASE, MappingCommand,
    MappingError, MappingGrade, MappingLease, MappingProtocol, MappingStatus, ObservationOutcome,
    Phase, PortMapper, SocketRole, Standing, TRIAL_DEADLINE, Trial, TrialStep, VecDeque, better,
    clamp_lease, renewal_delay,
};

impl PortMapper {
    /// Start trialling `candidates`, in preference order.
    pub(super) fn begin_trials(&mut self, mut candidates: Vec<MappingProtocol>, now: Instant) {
        candidates.sort_unstable();
        let mut queue: VecDeque<_> = candidates.into_iter().collect();
        let Some(first) = queue.pop_front() else {
            self.enter_backoff(now, None);
            return;
        };
        self.phase = Phase::Trialling {
            queue,
            current: Trial::new(first, &self.desired),
            deadline: now + TRIAL_DEADLINE,
            completed: Vec::new(),
        };
        self.emit_trial_maps(first);
    }

    /// Ask one protocol for every row of the desired set it can express.
    fn emit_trial_maps(&mut self, protocol: MappingProtocol) {
        for mapping in self.desired.expressible(protocol) {
            self.commands.push_back(MappingCommand::Map {
                protocol,
                mapping,
                suggested_external_port: mapping.internal_port,
                lease: self.config.lease,
            });
        }
    }

    pub(super) fn on_map(
        &mut self,
        protocol: MappingProtocol,
        mapping: DesiredMapping,
        outcome: Result<GrantAnswer, MappingError>,
        now: Instant,
    ) {
        if let Err(error) = &outcome {
            self.errors.insert(mapping, error.clone());
        }
        if let Ok(grant) = &outcome
            && grant.epoch_reset
            && matches!(self.phase, Phase::Mapped)
        {
            self.queue_readds(now);
        }
        // A renewal names a lease this protocol holds, and renewals fire
        // only while mapped — or for the incumbent while a re-race asks the
        // others.
        let renewing = self
            .leases
            .get(&mapping)
            .is_some_and(|held| held.protocol == protocol)
            && (matches!(self.phase, Phase::Mapped) || self.reracing == Some(protocol));
        match &mut self.phase {
            Phase::Trialling { current, .. } if current.protocol == protocol => {
                current.record(mapping, outcome);
                self.settle_trial(now);
            }
            _ if renewing => self.settle_renewal(mapping, outcome, now),
            // A trial that already closed, or a race that was interrupted:
            // nothing here holds what it granted.
            _ => self.release_stray(protocol, mapping, &outcome),
        }
    }

    /// Close the trial in flight at its deadline: its unanswered rows count
    /// as timed out, and the race moves on exactly as if they had answered.
    pub(super) fn expire_trial(&mut self, now: Instant) {
        let Phase::Trialling { current, .. } = &mut self.phase else {
            return;
        };
        let protocol = current.protocol;
        for mapping in current.expire() {
            self.errors.insert(mapping, MappingError::Timeout(protocol));
        }
        self.settle_trial(now);
    }

    /// Conclude the in-flight trial when every mapping has answered. The phase
    /// borrow decides; acting on the decision happens without it.
    fn settle_trial(&mut self, now: Instant) {
        let decision = {
            let desired = &self.desired;
            let Phase::Trialling {
                queue,
                current,
                deadline,
                completed,
            } = &mut self.phase
            else {
                return;
            };
            if !current.is_complete() {
                return;
            }
            let standing = current.standing(desired);
            let placeholder = Trial::new(current.protocol, desired);
            let finished = std::mem::replace(current, placeholder);
            // `Exact` on the lead family cannot be beaten where the High-ID
            // is decided, so the race stops here and the losers' mappings go
            // back. Candidates run in preference order, so PCP — the one
            // protocol that could also pinhole IPv6 — has already had its turn.
            if standing.lead == MappingGrade::Exact {
                TrialStep::Won(finished, standing, std::mem::take(completed))
            } else {
                completed.push((finished, standing));
                match queue.pop_front() {
                    Some(next) => {
                        *current = Trial::new(next, desired);
                        *deadline = now + TRIAL_DEADLINE;
                        TrialStep::Next(next)
                    }
                    None => TrialStep::Exhausted,
                }
            }
        };
        match decision {
            TrialStep::Won(winner, standing, losers) => {
                self.release_trials(losers.into_iter().map(|(trial, _)| trial));
                self.settle_winner(winner, standing, now);
            }
            TrialStep::Next(next) => self.emit_trial_maps(next),
            TrialStep::Exhausted => self.conclude_race(now),
        }
    }

    /// Every candidate has been trialled: install the best and release the
    /// rest.
    fn conclude_race(&mut self, now: Instant) {
        let Phase::Trialling { completed, .. } = &mut self.phase else {
            return;
        };
        let mut trials = std::mem::take(completed);
        let Some(winner) = trials
            .iter()
            .enumerate()
            .filter(|(_, (_, standing))| standing.granted_anything())
            .max_by(|(_, (left, left_standing)), (_, (right, right_standing))| {
                if better(
                    (*left_standing, left.protocol),
                    (*right_standing, right.protocol),
                ) {
                    std::cmp::Ordering::Greater
                } else {
                    std::cmp::Ordering::Less
                }
            })
            .map(|(index, _)| index)
        else {
            let hold_off = trials.iter().find_map(|(trial, _)| trial.hold_off);
            self.release_trials(trials.into_iter().map(|(trial, _)| trial));
            self.enter_backoff(now, hold_off);
            return;
        };
        let (best, standing) = trials.remove(winner);
        self.release_trials(trials.into_iter().map(|(trial, _)| trial));
        self.settle_winner(best, standing, now);
    }

    /// Hand back every mapping these trials were granted, so no duplicate
    /// forwarding stays on the router.
    pub(super) fn release_trials(&mut self, trials: impl Iterator<Item = Trial>) {
        for trial in trials {
            for (mapping, grant) in trial.grants {
                self.commands.push_back(MappingCommand::Release {
                    protocol: trial.protocol,
                    mapping,
                    external_port: grant.external.port(),
                });
            }
        }
    }

    /// Adopt a winning trial: turn each grant into a lease, feed the usable
    /// ones to **Address Learning**, and fire the reachability recheck a fresh
    /// `Exact` round earns.
    ///
    /// A lease a set change kept (ADR-0093) that this trial does not re-grant
    /// under the same protocol — the race moved to another protocol, or its
    /// row was refused — is still forwarding on the gateway, so it is handed
    /// back before the table is replaced; a loser trial of that
    /// protocol that already released the row is not released twice.
    pub(super) fn install(&mut self, trial: Trial, standing: Standing, now: Instant) {
        // Only a winner with nothing left to improve is remembered: a learned
        // method is probed alone next time, and a non-Exact one probed alone
        // would never let the others try.
        let whole_set_exact = trial.is_whole_set_exact(&self.desired);
        self.learned = whole_set_exact.then_some(trial.protocol);
        self.failures = 0;
        let fresh_exact = standing.lead == MappingGrade::Exact
            && self
                .installed
                .is_none_or(|held| held.lead != MappingGrade::Exact);
        self.installed = Some(standing);
        self.schedule_rerace(trial.protocol, whole_set_exact, now);
        // A held lease is superseded unless this trial re-grants the very
        // same gateway mapping: same protocol, and under UPnP — which keys a
        // mapping by its external port — the same external port.
        let superseded: Vec<_> = self
            .leases
            .iter()
            .filter(|(mapping, lease)| {
                trial.grants.get(mapping).is_none_or(|grant| {
                    lease.protocol != trial.protocol
                        || (lease.protocol.keys_by_external_port()
                            && grant.external.port() != lease.external.port())
                })
            })
            .map(|(mapping, lease)| (*mapping, lease.protocol))
            .collect();
        for (mapping, protocol) in superseded {
            let queued = self.commands.iter().any(|command| {
                matches!(command, MappingCommand::Release { protocol: p, mapping: m, .. }
                    if *p == protocol && *m == mapping)
            });
            self.end_lease(mapping, !queued);
        }
        let mut any_usable = false;
        for (mapping, grant) in trial.grants {
            let lease = clamp_lease(grant.lease);
            let status = self.adopt(mapping, &grant, lease);
            any_usable |= status == MappingStatus::Mapped;
            let draw = self.jitter.draw();
            let delay = renewal_delay(trial.protocol, lease, 0, draw);
            self.leases.insert(
                mapping,
                MappingLease {
                    protocol: trial.protocol,
                    external: grant.external,
                    lease,
                    granted_at: now,
                    renew_at: now + delay,
                    attempt: 0,
                    failures: 0,
                    status,
                },
            );
        }
        self.phase = Phase::Mapped;
        // The thing neither reference does: a grant that actually works means
        // the Kad verdict is stale *now*, not in an hour. Guarded to a genuinely
        // usable round, freshly Exact on the lead family — a `Degraded`
        // install has nothing to recheck, the IPv6 rows an IPv4-only backend
        // cannot express are no reason to withhold it, and a re-race that
        // only improved IPv6 changed nothing the Kad verdict reads.
        if fresh_exact && any_usable {
            self.commands.push_back(MappingCommand::RecheckReachability);
        }
    }

    /// Feed one grant to **Address Learning** and read back what it is worth.
    ///
    /// Two rules decide, and only one of them lives here:
    ///
    /// - **A mismatched TCP grant is never advertised.** The eD2k hello carries
    ///   one port and has no external-port tag, so advertising the internal
    ///   port would be a lie and advertising the external one is impossible.
    ///   A mismatched **UDP** grant is the opposite: it is the same fact Kad's
    ///   extern-port rule learns, so it goes in and the self-check verifies it.
    /// - **An unroutable external address is the store's call.** Private means
    ///   the gateway is behind a second NAT and `100.64/10` means the ISP holds
    ///   the public address; the store refuses both and raises the NAT hint, so
    ///   reading its outcome is the whole check — duplicating the rule here
    ///   would be a second copy that could disagree.
    pub(super) fn adopt(
        &self,
        mapping: DesiredMapping,
        grant: &GrantAnswer,
        lease: Option<Duration>,
    ) -> MappingStatus {
        let exact = grant.external.port() == mapping.internal_port;
        if mapping.role == SocketRole::Tcp && !exact {
            return MappingStatus::Degraded;
        }
        // A permanent mapping has no lifetime to be the freshness, so it takes
        // the clamp ceiling; the 30-minute verification poll re-observes it far
        // inside that window, so the rung never goes stale while the mapping
        // holds.
        let freshness = lease.unwrap_or(MAX_LEASE);
        match self.addresses.observe(AddressObservation::mapping_grant(
            mapping.role,
            grant.external,
            freshness,
        )) {
            ObservationOutcome::Recorded => MappingStatus::Mapped,
            ObservationOutcome::NotPubliclyUsable
            | ObservationOutcome::Ipv4PeerVoteRefused
            | ObservationOutcome::UnheldPeerVoteRefused
            | ObservationOutcome::PortZeroRefused => MappingStatus::Degraded,
        }
    }
}
