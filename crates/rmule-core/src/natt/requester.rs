//! The **requester side**: rendezvous rmule began, waiting on a serving
//! buddy's `OP_NATT_ENDPOINT_HINT`, and what becomes of each.
//!
//! One [`RendezvousSchedule`] per target, keyed by the target's user hash —
//! the one name for it that survives its address changing under a NAT. The
//! schedule owns the budget; this owns what the budget cannot know: which
//! buddy a hint must come from, when the rendezvous left (the relay round trip
//! is measured from it), and where the burst goes.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use rmule_peer::BUDDY_ID_LEN;
use rmule_peer::natt::{
    EndpointHint, PunchJitter, RENDEZVOUS_BACKOFF, RendezvousFailure, RendezvousSchedule,
    RendezvousStep, RendezvousTrigger, burst_delay, is_public_punch_address,
};
use rmule_primitives::{Ipv4Endpoint, UserHash};

/// How long a rendezvous waits for its hint before the attempt counts as
/// failed — eMuleAI's `ESERVERBUDDY_RELAY_TIMEOUT`, the one relay timeout its
/// tree publishes.
pub(crate) const HINT_TIMEOUT: Duration = Duration::from_secs(15);

/// One target's attempt state.
#[derive(Debug)]
struct Attempt {
    buddy_id: [u8; BUDDY_ID_LEN],
    buddy_udp: Ipv4Endpoint,
    /// When the in-flight rendezvous left; `None` between attempts.
    sent_at: Option<Instant>,
    /// When the last rendezvous failed — what an idle entry's failure count is
    /// remembered from, for [`RENDEZVOUS_BACKOFF`].
    failed_at: Option<Instant>,
    schedule: RendezvousSchedule,
}

/// What a hint led to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HintVerdict {
    /// Fire a burst at `target` after `delay` — half the relay round trip
    /// this very exchange measured.
    Punch {
        target: Ipv4Endpoint,
        delay: Duration,
    },
    /// Dropped, silently.
    Refuse(HintRefusal),
}

/// Why a hint was dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HintRefusal {
    /// No rendezvous toward this target is in flight — unsolicited, or late.
    NotExpected,
    /// Not from the buddy the rendezvous was sent to: buddy ID, source
    /// address and source port must all match (eMuleAI's acceptance rule).
    UntrustedSource,
    /// The endpoint it names is not publicly routable.
    NotPublic,
    /// The endpoint it names is one of our own interfaces.
    SelfPunch,
}

/// Every rendezvous rmule has begun.
#[derive(Debug, Default)]
pub(crate) struct RendezvousRequester {
    attempts: HashMap<UserHash, Attempt>,
}

impl RendezvousRequester {
    /// The route tree chose NAT traversal for `target`: arm its schedule. A
    /// fresh target is armed immediate — the jitter exists to de-synchronise
    /// *retries*, and delaying a first attempt buys nothing. Returns what the
    /// schedule says now, which for a retired target is its retirement.
    pub(crate) fn begin(
        &mut self,
        target: UserHash,
        buddy_id: [u8; BUDDY_ID_LEN],
        buddy_udp: Ipv4Endpoint,
        now: Instant,
        jitter: PunchJitter,
    ) -> RendezvousStep {
        let attempt = self.attempts.entry(target).or_insert_with(|| Attempt {
            buddy_id,
            buddy_udp,
            sent_at: None,
            failed_at: None,
            schedule: RendezvousSchedule::default(),
        });
        // A target can change buddies between attempts; a hint is only ever
        // believed from the one the *current* rendezvous went to.
        if attempt.sent_at.is_none() {
            attempt.buddy_id = buddy_id;
            attempt.buddy_udp = buddy_udp;
        }
        attempt
            .schedule
            .arm(RendezvousTrigger::RouteChosen, now, jitter, true);
        attempt.schedule.poll(now)
    }

    /// The rendezvous the schedule asked for went out.
    pub(crate) fn on_sent(&mut self, target: &UserHash, now: Instant) {
        if let Some(attempt) = self.attempts.get_mut(target) {
            attempt.sent_at = Some(now);
            attempt.schedule.on_sent();
        }
    }

    /// An `OP_NATT_ENDPOINT_HINT` arrived from `from`.
    pub(crate) fn on_hint(
        &mut self,
        hint: &EndpointHint,
        from: Ipv4Endpoint,
        is_own_interface: impl FnOnce(IpAddr) -> bool,
        now: Instant,
    ) -> HintVerdict {
        let Some(attempt) = self.attempts.get_mut(&hint.target) else {
            return HintVerdict::Refuse(HintRefusal::NotExpected);
        };
        let Some(sent_at) = attempt.sent_at else {
            return HintVerdict::Refuse(HintRefusal::NotExpected);
        };
        if !hint.is_from(&attempt.buddy_id, attempt.buddy_udp, from) {
            return HintVerdict::Refuse(HintRefusal::UntrustedSource);
        }
        let target = hint.target_endpoint;
        // Port 0 is no destination: the burst's first send would fail and
        // the dial would follow it nowhere, as the server road and the
        // acting path already refuse.
        if target.port == 0 || !is_public_punch_address(target.ip) {
            return HintVerdict::Refuse(HintRefusal::NotPublic);
        }
        if is_own_interface(IpAddr::V4(target.ip)) {
            return HintVerdict::Refuse(HintRefusal::SelfPunch);
        }
        // The relay answered: this rendezvous is no longer waiting on a hint,
        // so its silence clock stops here. The attempt stays in flight — its
        // outcome is now the dial's, a Tunnel or a `Transport` failure at the
        // dial budget — and a second hint for it is unsolicited.
        attempt.sent_at = None;
        HintVerdict::Punch {
            target,
            delay: burst_delay(Some(now.saturating_duration_since(sent_at))),
        }
    }

    /// What every live attempt's schedule says at `now` — the caller's clock,
    /// and the only way a *scheduled* retry ever becomes a send.
    ///
    /// Deliberately not [`begin`](Self::begin) on a timer: arming grants the
    /// trigger's retries again, which is the route tree choosing NAT traversal
    /// a second time. A clock choosing it every second would hand a target an
    /// unbounded budget by doing nothing at all.
    pub(crate) fn poll(&mut self, now: Instant) -> Vec<(UserHash, RendezvousStep)> {
        self.attempts
            .iter_mut()
            .map(|(target, attempt)| (*target, attempt.schedule.poll(now)))
            .collect()
    }

    /// Targets whose in-flight rendezvous has waited [`HINT_TIMEOUT`] with no
    /// outcome. The caller reports each as a
    /// [`Silence`](RendezvousFailure::Silence) failure.
    pub(crate) fn overdue(&self, now: Instant) -> Vec<UserHash> {
        self.attempts
            .iter()
            .filter(|(_, attempt)| {
                attempt
                    .sent_at
                    .is_some_and(|sent| now.saturating_duration_since(sent) >= HINT_TIMEOUT)
            })
            .map(|(target, _)| *target)
            .collect()
    }

    /// The in-flight attempt toward `target` failed. Returns the schedule's
    /// next step — `Retired` carries the reason diagnostics report.
    pub(crate) fn on_failure(
        &mut self,
        target: &UserHash,
        failure: RendezvousFailure,
        now: Instant,
        jitter: PunchJitter,
    ) -> Option<RendezvousStep> {
        let attempt = self.attempts.get_mut(target)?;
        attempt.sent_at = None;
        attempt.failed_at = Some(now);
        Some(attempt.schedule.on_failure(failure, now, jitter))
    }

    /// Forget what no longer bounds anything: a retirement whose
    /// backoff has lapsed — a fresh trigger would reset it anyway — and an
    /// idle entry, its grant spent, [`RENDEZVOUS_BACKOFF`] after its last
    /// failure. The failure count carries the five-attempt cap across runs
    /// the route tree starts back to back; it is not a record kept forever.
    pub(crate) fn prune(&mut self, now: Instant) {
        self.attempts
            .retain(|_, attempt| match attempt.schedule.poll(now) {
                RendezvousStep::Retired(_, until) => now < until,
                RendezvousStep::Idle => attempt
                    .failed_at
                    .is_some_and(|at| now.saturating_duration_since(at) < RENDEZVOUS_BACKOFF),
                RendezvousStep::Wait(_) | RendezvousStep::InFlight | RendezvousStep::Send => true,
            });
    }

    /// Nobody wants `target` any more — its claimant let go: forget the
    /// attempt, budget and all, as eMuleAI's abort resets its session. A
    /// retired target keeps its entry, because the retirement *is* the
    /// backoff a fresh trigger must wait out.
    pub(crate) fn abandon(&mut self, target: &UserHash, now: Instant) {
        if let Some(attempt) = self.attempts.get_mut(target)
            && !matches!(attempt.schedule.poll(now), RendezvousStep::Retired(..))
        {
            self.attempts.remove(target);
        }
    }

    /// A Tunnel to `target` rose: the attempt is over and forgotten.
    pub(crate) fn on_tunnel_up(&mut self, target: &UserHash) {
        self.attempts.remove(target);
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rmule_peer::natt::{NattConnectOptions, RENDEZVOUS_BACKOFF, RetireReason};

    use super::*;

    fn at(d: u8, port: u16) -> Ipv4Endpoint {
        Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, d), port)
    }

    fn target() -> UserHash {
        UserHash::from_bytes([0x44; 16])
    }

    fn jitter() -> PunchJitter {
        PunchJitter::clamped(Duration::from_millis(100))
    }

    fn hint_naming(endpoint: Ipv4Endpoint) -> EndpointHint {
        EndpointHint {
            target: target(),
            buddy_id: [0xBB; 16],
            file_hash: None,
            target_endpoint: endpoint,
            options: NattConnectOptions::from_byte(0),
        }
    }

    fn in_flight(now: Instant) -> RendezvousRequester {
        let mut requester = RendezvousRequester::default();
        assert_eq!(
            requester.begin(target(), [0xBB; 16], at(2, 4672), now, jitter()),
            RendezvousStep::Send,
            "a first attempt is not jittered"
        );
        requester.on_sent(&target(), now);
        requester
    }

    /// The exchange itself is the measurement: the hint arrives one relay
    /// round trip after the rendezvous left, and the burst is held for half
    /// of it.
    #[test]
    fn a_trusted_hint_schedules_the_burst_at_half_the_round_trip_it_measured() {
        let t0 = Instant::now();
        let mut requester = in_flight(t0);
        assert_eq!(
            requester.on_hint(
                &hint_naming(at(9, 31999)),
                at(2, 4672),
                |_| false,
                t0 + Duration::from_millis(240)
            ),
            HintVerdict::Punch {
                target: at(9, 31999),
                delay: Duration::from_millis(120),
            }
        );
    }

    /// A believed hint ends the wait for a hint: fifteen seconds on, while the
    /// dial it armed is still working, the rendezvous is not reported silent —
    /// which would spend one of the five and emit a second rendezvous beside
    /// the running dial. The attempt stays in flight, owed by the dial.
    #[test]
    fn a_believed_hint_stops_the_rendezvous_silence_clock() {
        let t0 = Instant::now();
        let mut requester = in_flight(t0);
        let heard = t0 + Duration::from_millis(240);
        assert!(matches!(
            requester.on_hint(&hint_naming(at(9, 31999)), at(2, 4672), |_| false, heard),
            HintVerdict::Punch { .. }
        ));
        assert!(requester.overdue(t0 + HINT_TIMEOUT).is_empty());
        assert_eq!(
            requester.poll(t0 + HINT_TIMEOUT),
            vec![(target(), RendezvousStep::InFlight)]
        );
    }

    /// The ledger's entries keep a deadline: an idle target's failure count
    /// is forgotten a backoff after its last failure, and a retirement once
    /// its backoff has lapsed.
    #[test]
    fn idle_and_retired_ledger_entries_are_pruned_at_their_backoff() {
        let t0 = Instant::now();
        let mut requester = in_flight(t0);
        // RouteChosen grants two retries: the second silence spends the grant.
        let mut now = t0 + HINT_TIMEOUT;
        requester.on_failure(&target(), RendezvousFailure::Silence, now, jitter());
        requester.on_sent(&target(), now);
        now += HINT_TIMEOUT;
        requester.on_failure(&target(), RendezvousFailure::Silence, now, jitter());
        assert_eq!(requester.poll(now), vec![(target(), RendezvousStep::Idle)]);
        requester.prune(now + RENDEZVOUS_BACKOFF - Duration::from_millis(1));
        assert_eq!(
            requester.poll(now).len(),
            1,
            "remembered inside the backoff"
        );
        requester.prune(now + RENDEZVOUS_BACKOFF);
        assert!(requester.poll(now).is_empty(), "forgotten at it");

        let mut retired = in_flight(t0);
        let step = loop {
            let step = retired.on_failure(&target(), RendezvousFailure::Silence, t0, jitter());
            if let Some(RendezvousStep::Retired(_, until)) = step {
                break until;
            }
            retired.begin(target(), [0xBB; 16], at(2, 4672), t0, jitter());
            retired.on_sent(&target(), t0);
        };
        retired.prune(step - Duration::from_millis(1));
        assert_eq!(retired.poll(t0).len(), 1, "the backoff still stands");
        retired.prune(step);
        assert!(retired.poll(t0).is_empty());
    }

    /// Success ends the attempt outright: a hint that arrives after the
    /// Tunnel rose — a duplicate, or a replay — aims no second burst, and the
    /// next rendezvous toward the same target starts on a whole budget.
    #[test]
    fn a_risen_tunnel_forgets_the_attempt() {
        let t0 = Instant::now();
        let mut requester = in_flight(t0);
        requester.on_tunnel_up(&target());
        assert_eq!(
            requester.on_hint(&hint_naming(at(9, 31999)), at(2, 4672), |_| false, t0),
            HintVerdict::Refuse(HintRefusal::NotExpected)
        );
        assert_eq!(
            requester.begin(target(), [0xBB; 16], at(2, 4672), t0, jitter()),
            RendezvousStep::Send
        );
    }

    /// The acceptance matrix. Each refusal removes one fact; none of them
    /// consumes the attempt, so the real hint still lands afterwards.
    #[test]
    fn a_hint_is_acted_on_only_when_expected_trusted_public_and_not_ourselves() {
        let t0 = Instant::now();
        let mut requester = in_flight(t0);
        let good = hint_naming(at(9, 31999));
        let refused = |verdict| HintVerdict::Refuse(verdict);

        let stranger = EndpointHint {
            target: UserHash::from_bytes([0x99; 16]),
            ..good
        };
        assert_eq!(
            requester.on_hint(&stranger, at(2, 4672), |_| false, t0),
            refused(HintRefusal::NotExpected)
        );
        assert_eq!(
            requester.on_hint(&good, at(2, 4673), |_| false, t0),
            refused(HintRefusal::UntrustedSource)
        );
        let private = hint_naming(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 5), 31999));
        assert_eq!(
            requester.on_hint(&private, at(2, 4672), |_| false, t0),
            refused(HintRefusal::NotPublic)
        );
        // Port 0 is no destination either.
        assert_eq!(
            requester.on_hint(&hint_naming(at(9, 0)), at(2, 4672), |_| false, t0),
            refused(HintRefusal::NotPublic)
        );
        assert_eq!(
            requester.on_hint(&good, at(2, 4672), |_| true, t0),
            refused(HintRefusal::SelfPunch)
        );
        assert!(matches!(
            requester.on_hint(&good, at(2, 4672), |_| false, t0),
            HintVerdict::Punch { .. }
        ));
    }

    /// Silence is the dialect's only failure signal. Fifteen seconds without a
    /// hint makes the attempt overdue; reporting it spends the budget, a late
    /// hint for it is no longer expected, and the fifth retires the target
    /// with the reason diagnostics carry.
    #[test]
    fn hint_silence_spends_the_budget_and_retires_the_target_with_a_reason() {
        let mut now = Instant::now();
        let mut requester = in_flight(now);
        assert!(
            requester
                .overdue(now + HINT_TIMEOUT - Duration::from_millis(1))
                .is_empty()
        );
        now += HINT_TIMEOUT;
        assert_eq!(requester.overdue(now), vec![target()]);

        let mut step = requester.on_failure(&target(), RendezvousFailure::Silence, now, jitter());
        assert_eq!(
            requester.on_hint(&hint_naming(at(9, 31999)), at(2, 4672), |_| false, now),
            HintVerdict::Refuse(HintRefusal::NotExpected),
            "a hint for an attempt already written off"
        );
        // Re-trigger run after run, as the route tree would, until the cap.
        let mut failures = 1;
        while !matches!(step, Some(RendezvousStep::Retired(..))) {
            now += Duration::from_millis(200);
            if requester.begin(target(), [0xBB; 16], at(2, 4672), now, jitter())
                == RendezvousStep::Send
            {
                requester.on_sent(&target(), now);
                step = requester.on_failure(&target(), RendezvousFailure::Silence, now, jitter());
                failures += 1;
            }
        }
        assert_eq!(failures, 5);
        assert_eq!(
            step,
            Some(RendezvousStep::Retired(
                RetireReason::AttemptsExhausted,
                now + RENDEZVOUS_BACKOFF
            ))
        );
    }
}
