//! The per-source **Rendezvous Schedule** (ADR-0091): when the next
//! rendezvous toward one unreachable source may go out, and when the source
//! stops being tried.
//!
//! Sans-I/O and explicit-time: every transition takes `now`, and the jitter is
//! handed in by the caller, because a state machine that owns a clock or a
//! random source cannot be driven through its matrix deterministically.
//!
//! There is **no NAT-type gate** in here. RFC 8489 dropped NAT classification
//! because labels lie and outcomes do not; every eligible pair is attempted
//! within this budget, and the budget is what bounds the cost of a pair that
//! can never succeed.
//!
//! # The budget (eMuleAI `Opcodes.h:175-177`, `BaseClient.cpp:3505-3527`)
//!
//! - a **trigger** grants retries — 2 for most, 4 for a candidate promotion,
//!   6 for a rendezvous answer — and schedules the next attempt a jittered
//!   50–150 ms out (or at once, when forced);
//! - a **transport failure** backs the source off for 60 s;
//! - 5 failed attempts, or 120 s without a Tunnel, and the source is
//!   **temporarily unreachable**, with the reason kept for diagnostics.
//!
//! The dialect has no failure frame (amule#1177 correction 9), so every
//! failure this machine hears about is one the caller inferred from silence.

use std::time::{Duration, Instant};

/// Failed rendezvous attempts before a source is retired
/// (`NAT_TRAVERSAL_RENDEZVOUS_MAX_ATTEMPTS`).
pub const RENDEZVOUS_MAX_ATTEMPTS: u8 = 5;

/// Total wait for a Tunnel before a source is retired
/// (`NAT_TRAVERSAL_RENDEZVOUS_TIMEOUT`).
pub const RENDEZVOUS_TIMEOUT: Duration = Duration::from_secs(120);

/// The delay after a transport failure, and how long *temporarily
/// unreachable* lasts (`NAT_TRAVERSAL_RENDEZVOUS_BACKOFF`).
pub const RENDEZVOUS_BACKOFF: Duration = Duration::from_secs(60);

/// How long a HighID↔LowID pair's ordinary callback is given before the
/// NAT-T rung is tried instead (`RENDEZVOUSFALLBACKDELAY`).
pub const CALLBACK_SILENCE_FALLBACK: Duration = Duration::from_secs(12);

/// How often a punched path is refreshed so the NAT keeps its mapping.
pub const PUNCHED_PATH_KEEPALIVE: Duration = Duration::from_secs(60);

/// The jitter window a scheduled attempt is delayed into
/// (`NatTraversalJitterMinMs` / `MaxMs` defaults).
const JITTER_MIN: Duration = Duration::from_millis(50);
const JITTER_MAX: Duration = Duration::from_millis(150);

/// A retry delay known to lie inside the dialect's 50–150 ms window.
///
/// The caller owns the randomness; this type owns the window, so an
/// out-of-range draw cannot widen it and a test can pin an exact value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PunchJitter(Duration);

impl PunchJitter {
    /// Clamp `drawn` into the window.
    #[must_use]
    pub fn clamped(drawn: Duration) -> Self {
        Self(drawn.clamp(JITTER_MIN, JITTER_MAX))
    }

    /// Map a uniform draw over `u32` onto the window — the form a caller with
    /// a raw random word wants.
    #[must_use]
    pub fn from_random(word: u32) -> Self {
        let span = (JITTER_MAX - JITTER_MIN).as_millis() as u64 + 1;
        Self(JITTER_MIN + Duration::from_millis(u64::from(word) % span))
    }
}

/// What set a source up for a rendezvous — it decides the retry grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RendezvousTrigger {
    /// The ordinary case: the route tree chose the NAT-T rung. 2 retries.
    RouteChosen,
    /// A candidate was promoted to a download source. 4 retries.
    CandidatePromotion,
    /// We are answering someone else's rendezvous — they are punching *now*,
    /// so this is the attempt most worth repeating. 6 retries.
    RendezvousAnswer,
}

impl RendezvousTrigger {
    const fn retries(self) -> u8 {
        match self {
            Self::RouteChosen => 2,
            Self::CandidatePromotion => 4,
            Self::RendezvousAnswer => 6,
        }
    }
}

/// How an attempt failed, as far as silence lets the caller tell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RendezvousFailure {
    /// The relay never answered, or the punch drew no reply: try again on the
    /// ordinary jittered schedule.
    Silence,
    /// A transport was started over the punched path and failed. The path is
    /// suspect, so the source backs off a full [`RENDEZVOUS_BACKOFF`].
    Transport,
}

/// Why a source became temporarily unreachable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetireReason {
    /// [`RENDEZVOUS_MAX_ATTEMPTS`] attempts failed.
    AttemptsExhausted,
    /// [`RENDEZVOUS_TIMEOUT`] passed with no Tunnel.
    TimedOut,
}

/// What the schedule says to do at `now`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RendezvousStep {
    /// Nothing is scheduled; the source waits for a trigger.
    Idle,
    /// An attempt is due at the carried instant — not yet.
    Wait(Instant),
    /// An attempt went out and its outcome has not been reported.
    InFlight,
    /// Send a rendezvous now, then call
    /// [`on_sent`](RendezvousSchedule::on_sent).
    Send,
    /// Temporarily unreachable until the carried instant.
    Retired(RetireReason, Instant),
}

/// One source's rendezvous budget.
#[derive(Clone, Copy, Debug, Default)]
pub struct RendezvousSchedule {
    /// When this run of attempts began — the anchor of the 120 s timeout.
    /// `None` between runs.
    started: Option<Instant>,
    /// Failed attempts in this run.
    failed: u8,
    /// Retries the triggers so far have granted and failures not yet spent.
    retries_left: u8,
    /// When the next attempt is due, if one is scheduled.
    next_attempt: Option<Instant>,
    /// An attempt is in flight: sent, outcome not yet reported.
    in_flight: bool,
    /// Set on retirement: the reason, and when the source may be tried again.
    retired: Option<(RetireReason, Instant)>,
}

impl RendezvousSchedule {
    /// Grant `trigger`'s retries and schedule an attempt `jitter` out — or at
    /// once when `force_immediate` (eMuleAI's `bForceImmediate`, used when the
    /// other side is known to be punching already).
    ///
    /// Grants do not stack: a second trigger raises the budget to the larger
    /// grant rather than adding to it, so a peer that can cause triggers
    /// cannot buy itself unbounded attempts. A retired source ignores triggers
    /// until its retirement lapses, then starts a fresh run.
    pub fn arm(
        &mut self,
        trigger: RendezvousTrigger,
        now: Instant,
        jitter: PunchJitter,
        force_immediate: bool,
    ) {
        if let Some((_, until)) = self.retired {
            if now < until {
                return;
            }
            *self = Self::default();
        }
        self.started.get_or_insert(now);
        self.retries_left = self.retries_left.max(trigger.retries());
        let due = if force_immediate { now } else { now + jitter.0 };
        // An earlier due time is never pushed later by a new trigger.
        self.next_attempt = Some(self.next_attempt.map_or(due, |at| at.min(due)));
    }

    /// What to do at `now`. Pure apart from recording a timeout it discovers.
    pub fn poll(&mut self, now: Instant) -> RendezvousStep {
        if let Some((reason, until)) = self.retired {
            return RendezvousStep::Retired(reason, until);
        }
        if let Some(started) = self.started
            && now.duration_since(started) >= RENDEZVOUS_TIMEOUT
        {
            return self.retire(RetireReason::TimedOut, now);
        }
        if self.in_flight {
            return RendezvousStep::InFlight;
        }
        match self.next_attempt {
            Some(due) if due > now => RendezvousStep::Wait(due),
            Some(_) => RendezvousStep::Send,
            None => RendezvousStep::Idle,
        }
    }

    /// The attempt [`poll`](Self::poll) asked for went out.
    pub fn on_sent(&mut self) {
        self.in_flight = true;
    }

    /// The in-flight attempt failed. Spends one retry; schedules the next
    /// attempt (jittered, or a full backoff out after a transport failure) if
    /// any retries remain; retires the source at the attempt cap.
    pub fn on_failure(
        &mut self,
        failure: RendezvousFailure,
        now: Instant,
        jitter: PunchJitter,
    ) -> RendezvousStep {
        self.in_flight = false;
        self.failed = self.failed.saturating_add(1);
        if self.failed >= RENDEZVOUS_MAX_ATTEMPTS {
            return self.retire(RetireReason::AttemptsExhausted, now);
        }
        self.retries_left = self.retries_left.saturating_sub(1);
        self.next_attempt = (self.retries_left > 0).then(|| match failure {
            RendezvousFailure::Silence => now + jitter.0,
            RendezvousFailure::Transport => now + RENDEZVOUS_BACKOFF,
        });
        if self.next_attempt.is_none() {
            // The grant is spent and the run is over, so its clock stops: a
            // trigger an hour from now must not meet a timeout that expired
            // while nothing was being tried. The failure count survives —
            // that is what keeps trigger-by-trigger retries under the cap.
            self.started = None;
        }
        self.poll(now)
    }

    /// A Tunnel rose. The run is over and the budget is whole again — a
    /// source that worked once is not penalised for how long it took.
    pub fn on_tunnel_up(&mut self) {
        *self = Self::default();
    }

    fn retire(&mut self, reason: RetireReason, now: Instant) -> RendezvousStep {
        let until = now + RENDEZVOUS_BACKOFF;
        *self = Self {
            retired: Some((reason, until)),
            ..Self::default()
        };
        RendezvousStep::Retired(reason, until)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const J: Duration = Duration::from_millis(100);

    fn jitter() -> PunchJitter {
        PunchJitter::clamped(J)
    }

    /// Drive one failed attempt end to end at `now`.
    fn fail(
        schedule: &mut RendezvousSchedule,
        now: Instant,
        how: RendezvousFailure,
    ) -> RendezvousStep {
        assert_eq!(schedule.poll(now), RendezvousStep::Send);
        schedule.on_sent();
        schedule.on_failure(how, now, jitter())
    }

    #[test]
    fn a_jitter_never_leaves_the_dialects_window() {
        assert_eq!(PunchJitter::clamped(Duration::ZERO).0, JITTER_MIN);
        assert_eq!(PunchJitter::clamped(Duration::from_secs(9)).0, JITTER_MAX);
        for word in [0, 1, 100, 101, u32::MAX] {
            let drawn = PunchJitter::from_random(word).0;
            assert!(
                (JITTER_MIN..=JITTER_MAX).contains(&drawn),
                "{word} → {drawn:?}"
            );
        }
        assert_eq!(PunchJitter::from_random(100).0, JITTER_MAX);
    }

    /// A trigger schedules the first attempt a jitter out; forcing collapses
    /// the jitter to now; and nothing is sent twice while one is in flight.
    #[test]
    fn a_trigger_schedules_a_jittered_attempt_and_force_collapses_it() {
        let t0 = Instant::now();
        let mut schedule = RendezvousSchedule::default();
        assert_eq!(schedule.poll(t0), RendezvousStep::Idle);

        schedule.arm(RendezvousTrigger::RouteChosen, t0, jitter(), false);
        assert_eq!(schedule.poll(t0), RendezvousStep::Wait(t0 + J));
        assert_eq!(schedule.poll(t0 + J), RendezvousStep::Send);
        schedule.on_sent();
        assert_eq!(schedule.poll(t0 + J * 5), RendezvousStep::InFlight);

        let mut forced = RendezvousSchedule::default();
        forced.arm(RendezvousTrigger::RendezvousAnswer, t0, jitter(), true);
        assert_eq!(forced.poll(t0), RendezvousStep::Send);
    }

    /// The retry grant is the trigger's — 2, 4 or 6 — and once it is spent the
    /// source goes idle rather than retired: it failed cheaply and may be
    /// triggered again.
    #[test]
    fn the_retry_grant_follows_the_trigger_and_spending_it_idles_the_source() {
        for (trigger, grant) in [
            (RendezvousTrigger::RouteChosen, 2),
            (RendezvousTrigger::CandidatePromotion, 4),
        ] {
            let mut now = Instant::now();
            let mut schedule = RendezvousSchedule::default();
            schedule.arm(trigger, now, jitter(), true);
            for attempt in 1..=grant {
                let step = fail(&mut schedule, now, RendezvousFailure::Silence);
                if attempt < grant {
                    assert_eq!(
                        step,
                        RendezvousStep::Wait(now + J),
                        "{trigger:?} #{attempt}"
                    );
                    now += J;
                } else {
                    assert_eq!(step, RendezvousStep::Idle, "{trigger:?} #{attempt}");
                }
            }
        }
    }

    /// An idle source's clock is stopped — a trigger long after meets no stale
    /// timeout — but its failures are remembered, so a source re-triggered
    /// run after run still reaches the cap.
    #[test]
    fn an_idle_source_keeps_its_failures_but_not_its_clock() {
        let t0 = Instant::now();
        let mut schedule = RendezvousSchedule::default();
        schedule.arm(RendezvousTrigger::RouteChosen, t0, jitter(), true);
        fail(&mut schedule, t0, RendezvousFailure::Silence);
        assert_eq!(
            fail(&mut schedule, t0 + J, RendezvousFailure::Silence),
            RendezvousStep::Idle
        );

        let later = t0 + RENDEZVOUS_TIMEOUT * 30;
        schedule.arm(RendezvousTrigger::RouteChosen, later, jitter(), true);
        fail(&mut schedule, later, RendezvousFailure::Silence);
        fail(&mut schedule, later + J, RendezvousFailure::Silence);

        let last = later + RENDEZVOUS_TIMEOUT;
        schedule.arm(RendezvousTrigger::RouteChosen, last, jitter(), true);
        assert_eq!(
            fail(&mut schedule, last, RendezvousFailure::Silence),
            RendezvousStep::Retired(RetireReason::AttemptsExhausted, last + RENDEZVOUS_BACKOFF)
        );
    }

    /// The attempt cap binds even under the largest grant: a rendezvous answer
    /// grants 6 retries and the fifth failure retires the source anyway.
    #[test]
    fn five_failures_retire_the_source_whatever_was_granted() {
        let mut now = Instant::now();
        let mut schedule = RendezvousSchedule::default();
        schedule.arm(RendezvousTrigger::RendezvousAnswer, now, jitter(), true);
        for _ in 1..RENDEZVOUS_MAX_ATTEMPTS {
            fail(&mut schedule, now, RendezvousFailure::Silence);
            now += J;
        }
        assert_eq!(
            fail(&mut schedule, now, RendezvousFailure::Silence),
            RendezvousStep::Retired(RetireReason::AttemptsExhausted, now + RENDEZVOUS_BACKOFF)
        );
    }

    /// Grants do not stack. Re-triggering a source mid-run raises its budget
    /// to the larger grant and no further, so whoever can cause triggers
    /// cannot buy attempts — and cannot delay one already due.
    #[test]
    fn a_second_trigger_raises_the_grant_but_never_stacks_or_delays() {
        let t0 = Instant::now();
        let mut schedule = RendezvousSchedule::default();
        schedule.arm(RendezvousTrigger::RouteChosen, t0, jitter(), true);
        schedule.arm(RendezvousTrigger::RouteChosen, t0, jitter(), false);
        assert_eq!(
            schedule.poll(t0),
            RendezvousStep::Send,
            "not pushed out by the jitter"
        );

        assert_eq!(
            fail(&mut schedule, t0, RendezvousFailure::Silence),
            RendezvousStep::Wait(t0 + J)
        );
        assert_eq!(
            fail(&mut schedule, t0 + J, RendezvousFailure::Silence),
            RendezvousStep::Idle,
            "2 + 2 is still 2"
        );
    }

    /// A transport failure means the punched path itself is suspect: the next
    /// attempt is a full backoff out, not a jitter.
    #[test]
    fn a_transport_failure_backs_off_a_full_minute() {
        let t0 = Instant::now();
        let mut schedule = RendezvousSchedule::default();
        schedule.arm(RendezvousTrigger::CandidatePromotion, t0, jitter(), true);
        assert_eq!(
            fail(&mut schedule, t0, RendezvousFailure::Transport),
            RendezvousStep::Wait(t0 + RENDEZVOUS_BACKOFF)
        );
    }

    /// 120 s with no Tunnel retires the source even with retries in hand and
    /// an attempt in flight — the timeout is on the run, not on an attempt.
    #[test]
    fn a_run_that_outlives_the_timeout_is_retired() {
        let t0 = Instant::now();
        let mut schedule = RendezvousSchedule::default();
        schedule.arm(RendezvousTrigger::RendezvousAnswer, t0, jitter(), true);
        assert_eq!(schedule.poll(t0), RendezvousStep::Send);
        schedule.on_sent();
        let late = t0 + RENDEZVOUS_TIMEOUT;
        assert_eq!(
            schedule.poll(late),
            RendezvousStep::Retired(RetireReason::TimedOut, late + RENDEZVOUS_BACKOFF)
        );
    }

    /// *Temporarily* unreachable: triggers are ignored while retired, and the
    /// first one after the lapse starts a run with a whole budget.
    #[test]
    fn retirement_ignores_triggers_until_it_lapses_then_starts_fresh() {
        let mut now = Instant::now();
        let mut schedule = RendezvousSchedule::default();
        schedule.arm(RendezvousTrigger::RendezvousAnswer, now, jitter(), true);
        for _ in 0..RENDEZVOUS_MAX_ATTEMPTS {
            fail(&mut schedule, now, RendezvousFailure::Silence);
            now += J;
        }
        let until = now - J + RENDEZVOUS_BACKOFF;

        schedule.arm(RendezvousTrigger::RouteChosen, now, jitter(), true);
        assert_eq!(
            schedule.poll(now),
            RendezvousStep::Retired(RetireReason::AttemptsExhausted, until)
        );

        schedule.arm(RendezvousTrigger::RouteChosen, until, jitter(), true);
        assert_eq!(schedule.poll(until), RendezvousStep::Send);
        schedule.on_sent();
        assert_eq!(
            schedule.on_failure(RendezvousFailure::Silence, until, jitter()),
            RendezvousStep::Wait(until + J),
            "the failure count began again"
        );
    }

    /// Success wipes the run: a later trigger meets a whole budget and a
    /// fresh 120 s, not the remains of the run that worked.
    #[test]
    fn a_tunnel_resets_the_budget() {
        let t0 = Instant::now();
        let mut schedule = RendezvousSchedule::default();
        schedule.arm(RendezvousTrigger::RouteChosen, t0, jitter(), true);
        fail(&mut schedule, t0, RendezvousFailure::Silence);
        schedule.on_tunnel_up();
        assert_eq!(
            schedule.poll(t0 + RENDEZVOUS_TIMEOUT * 2),
            RendezvousStep::Idle
        );
    }
}
