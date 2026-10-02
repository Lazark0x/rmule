//! The probe round: which protocols to ask, who has answered, and when the round closes on whoever did.

use super::super::ProbeAnswer;
use super::{
    AddressFamily, Instant, MappingCommand, MappingError, MappingProtocol, PROBE_GRACE, Phase,
    PortMapper, SLOW_PROBE_GRACE,
};

impl PortMapper {
    /// Open a probe round: the learned method alone if there is one, otherwise
    /// every enabled protocol that could map something we want.
    pub(super) fn open_probe_round(&mut self, now: Instant) {
        let mut candidates = self.candidates();
        candidates.retain(|protocol| Some(*protocol) != self.reracing);
        let learned_only = self
            .learned
            .filter(|method| self.reracing.is_none() && candidates.contains(method))
            .map(|method| vec![method]);
        self.short_round = learned_only.is_some();
        let outstanding = learned_only.clone().unwrap_or(candidates);
        if outstanding.is_empty() {
            self.enter_backoff(now, None);
            return;
        }
        for protocol in &outstanding {
            self.commands.push_back(MappingCommand::Probe {
                protocol: *protocol,
            });
        }
        self.phase = Phase::Probing {
            started: now,
            deadline: now + PROBE_GRACE,
            extended: false,
            learned_only: learned_only.is_some(),
            outstanding,
            available: Vec::new(),
        };
    }

    /// The enabled protocols that could map at least one family we want. A
    /// protocol that is IPv4-only against an IPv4-less desired set would only
    /// ever grade `None`.
    pub(super) fn candidates(&self) -> Vec<MappingProtocol> {
        self.config
            .enabled_protocols()
            .into_iter()
            .filter(|protocol| {
                [AddressFamily::V4, AddressFamily::V6]
                    .into_iter()
                    .any(|family| self.desired.wants(family) && protocol.supports(family))
            })
            .collect()
    }

    pub(super) fn on_probe(
        &mut self,
        protocol: MappingProtocol,
        outcome: &Result<ProbeAnswer, MappingError>,
        now: Instant,
    ) {
        if let Ok(answer) = outcome
            && answer.epoch_reset
        {
            self.queue_readds(now);
        }
        let usable = self.probe_is_usable(outcome);
        if !matches!(self.phase, Phase::Probing { .. }) {
            // A probe that answered after its round closed is still adopted —
            // but only if that round ended with nothing at all. Otherwise the
            // race already has a winner, and a late arrival would install a
            // second, duplicate set on the router.
            if usable && self.leases.is_empty() && matches!(self.phase, Phase::BackingOff { .. }) {
                self.begin_trials(vec![protocol], now);
            }
            return;
        }
        if let Phase::Probing {
            outstanding,
            available,
            ..
        } = &mut self.phase
        {
            outstanding.retain(|pending| *pending != protocol);
            if usable {
                available.push(protocol);
            }
        }
        if let Err(error) = outcome {
            self.note_error(error);
        }
        self.settle_probe_round(now);
    }

    /// Whether a probe answer is one the race can use: the protocol is there
    /// and can map at least one family the desired set wants.
    fn probe_is_usable(&self, outcome: &Result<ProbeAnswer, MappingError>) -> bool {
        outcome.as_ref().is_ok_and(|answer| {
            answer
                .families
                .iter()
                .any(|family| self.desired.wants(*family))
        })
    }

    /// Close the round if it is due, extending the grace once.
    pub(super) fn settle_probe_round(&mut self, now: Instant) {
        let Phase::Probing {
            started,
            deadline,
            extended,
            learned_only,
            outstanding,
            available,
        } = &mut self.phase
        else {
            return;
        };
        let everyone_answered = outstanding.is_empty();
        if !everyone_answered && now < *deadline {
            return;
        }
        // Still working, nothing available yet, and the grace has not been
        // extended: give the slow path its 15 seconds rather than concluding
        // "no protocol" against a router that would have answered.
        if !everyone_answered && available.is_empty() && !*extended {
            *extended = true;
            *deadline = *started + SLOW_PROBE_GRACE;
            return;
        }
        let winners = std::mem::take(available);
        let learned_only = *learned_only;
        if winners.is_empty() {
            if learned_only {
                // The short round is an optimisation, not a verdict: the
                // learned method being gone means run the full race now, not
                // wait out a backoff.
                self.learned = None;
                self.open_probe_round(now);
            } else {
                self.enter_backoff(now, None);
            }
            return;
        }
        self.begin_trials(winners, now);
    }
}
