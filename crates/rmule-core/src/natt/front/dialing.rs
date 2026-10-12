//! The **dial schedule**: how long one dial over a punched path is given, and
//! what the attempt does with the time that is left.
//!
//! # Why one dial is short and the attempt re-dials
//!
//! `librqbit-utp` 0.7.0 sends a dial's `ST_SYN` **exactly once** and never
//! retransmits it (`socket.rs`, `ControlRequest::ConnectRequest`: the header is
//! built, sent, and the `Connecting` record it leaves behind carries no resend
//! timer — its `start` is read only to seed the RTT estimate). Its `connect()`
//! has no timeout of its own either: it awaits a oneshot that only a dead
//! dispatcher ever completes, and `SocketOpts` exposes no connect deadline to
//! configure. What *does* retransmit is the far side's SYN-ACK — six sends,
//! 200 ms apart, capped by `max_segment_retransmissions` (default 5).
//!
//! So a dial resolves inside about a second when its opener arrived, and never
//! when the opener was lost. Waiting the whole attempt on one `connect()` —
//! which is what a single 120 s timeout did — spends 119 of those seconds on a
//! SYN that will not be sent again. Each dial is bounded at
//! [`DIAL_ATTEMPT_TIMEOUT`] instead, and the attempt **re-dials**: a fresh
//! `connect()` is a fresh opener, which is the only thing that recovers a lost
//! one.
//!
//! The attempt's own budget is unchanged — [`DIAL_BUDGET`] is ADR-0091's 120 s,
//! eMuleAI's number, measured from the attempt's Begin rather than its first
//! dial — and when it runs out the attempt ends with the ordinary
//! `RendezvousFailure::Transport`, as it always did.
//!
//! # What may not happen
//!
//! - **Never two dials at once toward one target.** `librqbit-utp` allows four
//!   concurrent connects per address and then silently refuses the fifth
//!   (`MAX_CONNECTING_PER_ADDR`), and two dials on one pinhole are what the
//!   dialect's who-dials asymmetry exists to prevent in the first place.
//! - **Never a dial a datagram asked for out of turn.** A `0xA1` re-dials
//!   immediately — it is the trigger, and it may have corrected the port — but
//!   only into a free slot, and only while the budget lasts.
//! - **Never a burst the destination limiter refused.** A cadence re-dial asks
//!   for a fresh punch first, because the NAT mapping may have aged out; if the
//!   limiter says no, it dials without one rather than skipping the dial.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use rmule_primitives::{Ipv4Endpoint, UserHash};

/// How long one `connect()` is given before the dial is abandoned and re-made.
///
/// Three seconds: the opener is sent once, so the only outcomes are a SYN-ACK
/// inside a round trip, or nothing. Three covers a punched path's round trip
/// plus the far side's whole ~1 s SYN-ACK retransmit window with slack, and
/// costs a lost opener three seconds rather than the attempt.
pub(super) const DIAL_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3);

/// Minimum time between two dials toward one target, measured from the start of
/// the previous one.
///
/// Five seconds against a three-second dial leaves two seconds of quiet between
/// openers — about twenty-three dials inside the budget, one datagram each. Fast
/// enough that a path that opens late is used, slow enough that a target that is
/// simply unreachable is not flooded.
pub(super) const REDIAL_INTERVAL: Duration = Duration::from_secs(5);

/// How long the whole attempt toward one target may keep dialing. ADR-0091's
/// budget, unchanged: the dialect has no reset frame, so a traversal that has
/// not worked in two minutes has failed.
pub(super) const DIAL_BUDGET: Duration = rmule_peer::natt::RENDEZVOUS_TIMEOUT;

/// What the schedule wants done for one target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DialOrder {
    /// Start a dial toward `at`.
    Dial {
        peer: UserHash,
        at: Ipv4Endpoint,
        /// Fire a fresh punch burst first, if the destination limiter allows
        /// one. Set on a cadence re-dial, where silence may mean the mapping
        /// aged out; never on a re-dial a `0xA1` asked for, because that
        /// datagram just proved the mapping alive.
        burst: bool,
    },
    /// The budget is spent with no tunnel: the attempt is a transport failure.
    Exhausted {
        peer: UserHash,
        /// How many dials it spent, for diagnostics.
        dials: u32,
    },
}

/// One target's in-flight traversal.
#[derive(Clone, Copy, Debug)]
struct Dial {
    /// Where the next dial goes. A `0xA1` corrects it.
    at: Ipv4Endpoint,
    /// When the attempt's budget started running: its Begin.
    began: Instant,
    /// Whether a `connect()` is running right now. One at a time, always.
    in_flight: bool,
    /// The earliest a further dial may start.
    next: Instant,
    dials: u32,
}

/// Which targets are being dialed, and when each may be dialed again.
#[derive(Debug, Default)]
pub(super) struct DialSchedule {
    dials: HashMap<UserHash, Dial>,
}

impl DialSchedule {
    /// A trigger asks for a dial toward `at`: an introduction, a released
    /// burst, or a `0xA1` (which may name a corrected port).
    ///
    /// Returns what to do, or nothing when a dial is already in flight toward
    /// that target — the correction is recorded either way, so the *next* dial
    /// goes to the endpoint the punch came from.
    ///
    /// `began` is when the attempt began, not this dial: the budget bounds the
    /// attempt, so a dial a server introduction armed fifteen
    /// seconds in keeps only what is left of it, and one armed past it spends
    /// nothing.
    pub(super) fn arm(
        &mut self,
        peer: UserHash,
        at: Ipv4Endpoint,
        began: Instant,
        now: Instant,
    ) -> Option<DialOrder> {
        let Some(dial) = self.dials.get_mut(&peer) else {
            if now.saturating_duration_since(began) >= DIAL_BUDGET {
                return Some(DialOrder::Exhausted { peer, dials: 0 });
            }
            self.dials.insert(
                peer,
                Dial {
                    at,
                    began,
                    in_flight: true,
                    next: now + REDIAL_INTERVAL,
                    dials: 1,
                },
            );
            return Some(DialOrder::Dial {
                peer,
                at,
                burst: false,
            });
        };
        dial.at = at;
        if dial.in_flight {
            return None;
        }
        if now.saturating_duration_since(dial.began) >= DIAL_BUDGET {
            return Some(self.exhausted(peer));
        }
        dial.in_flight = true;
        dial.next = now + REDIAL_INTERVAL;
        dial.dials += 1;
        Some(DialOrder::Dial {
            peer,
            at,
            burst: false,
        })
    }

    /// One dial ended without a tunnel. The attempt continues on the cadence
    /// unless its budget is spent.
    pub(super) fn settled(&mut self, peer: UserHash, now: Instant) -> Option<DialOrder> {
        let dial = self.dials.get_mut(&peer)?;
        dial.in_flight = false;
        (now.saturating_duration_since(dial.began) >= DIAL_BUDGET).then(|| self.exhausted(peer))
    }

    /// The clock: dials whose cadence has come round, and attempts whose budget
    /// ran out while nothing was in flight.
    pub(super) fn due(&mut self, now: Instant) -> Vec<DialOrder> {
        let ready: Vec<UserHash> = self
            .dials
            .iter()
            .filter(|(_, dial)| !dial.in_flight && dial.next <= now)
            .map(|(peer, _)| *peer)
            .collect();
        let mut orders = Vec::with_capacity(ready.len());
        for peer in ready {
            let dial = self
                .dials
                .get_mut(&peer)
                .expect("the target was just read from this map");
            if now.saturating_duration_since(dial.began) >= DIAL_BUDGET {
                orders.push(self.exhausted(peer));
                continue;
            }
            dial.in_flight = true;
            dial.next = now + REDIAL_INTERVAL;
            dial.dials += 1;
            orders.push(DialOrder::Dial {
                peer,
                at: dial.at,
                burst: true,
            });
        }
        orders
    }

    /// A tunnel rose toward `peer`: the attempt is over. Returns how many dials
    /// it spent.
    pub(super) fn risen(&mut self, peer: UserHash) -> Option<u32> {
        self.dials.remove(&peer).map(|dial| dial.dials)
    }

    /// `peer`'s attempt ended some other way — retired, idle, abandoned or
    /// identified: forget its schedule, so no cadence re-dials a peer nothing
    /// is traversing toward any more and no spent budget reports a second
    /// retirement.
    pub(super) fn forget(&mut self, peer: &UserHash) {
        self.dials.remove(peer);
    }

    /// The dial just ordered toward `peer` was never started — its path
    /// already holds a Tunnel. Free the slot it would have held, so the
    /// cadence and the budget still reach this target: an order that never
    /// runs would otherwise stay in flight forever.
    pub(super) fn skipped(&mut self, peer: UserHash) {
        if let Some(dial) = self.dials.get_mut(&peer) {
            dial.in_flight = false;
        }
    }

    /// Whether `peer` has a dial schedule at all — what a `0xA1` may re-arm.
    pub(super) fn holds(&self, peer: UserHash) -> bool {
        self.dials.contains_key(&peer)
    }

    /// Whether a dial toward `peer` is running right now.
    #[cfg(test)]
    pub(super) fn in_flight(&self, peer: UserHash) -> bool {
        self.dials.get(&peer).is_some_and(|dial| dial.in_flight)
    }

    /// Where the next dial toward `peer` would go.
    #[cfg(test)]
    pub(super) fn target(&self, peer: UserHash) -> Option<Ipv4Endpoint> {
        self.dials.get(&peer).map(|dial| dial.at)
    }

    /// How many targets are being dialed.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.dials.len()
    }

    /// End the attempt and say what it cost.
    fn exhausted(&mut self, peer: UserHash) -> DialOrder {
        let dials = self.dials.remove(&peer).map_or(0, |dial| dial.dials);
        DialOrder::Exhausted { peer, dials }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn at(last: u8, port: u16) -> Ipv4Endpoint {
        Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, last), port)
    }

    fn hash(fill: u8) -> UserHash {
        UserHash::from_bytes([fill; UserHash::BYTE_LEN])
    }

    /// The mismatch this schedule ends: a dial that cannot complete costs three
    /// seconds, not the attempt, and the attempt spends its budget on fresh
    /// openers instead of on one that was already lost.
    #[test]
    fn a_lost_opener_costs_one_dial_and_the_attempt_keeps_dialing() {
        let t0 = Instant::now();
        let mut schedule = DialSchedule::default();
        assert_eq!(
            schedule.arm(hash(1), at(9, 4001), t0, t0),
            Some(DialOrder::Dial {
                peer: hash(1),
                at: at(9, 4001),
                burst: false
            })
        );

        let settled = t0 + DIAL_ATTEMPT_TIMEOUT;
        assert_eq!(schedule.settled(hash(1), settled), None);
        assert!(
            schedule.due(settled).is_empty(),
            "the cadence is not up yet"
        );
        assert_eq!(
            schedule.due(t0 + REDIAL_INTERVAL),
            vec![DialOrder::Dial {
                peer: hash(1),
                at: at(9, 4001),
                burst: true
            }],
            "a cadence re-dial asks for a fresh burst: the mapping may have aged"
        );
    }

    /// The budget is ADR-0091's, unchanged: the attempt ends at it, naming what
    /// it spent, and the schedule forgets the target.
    #[test]
    fn the_attempt_ends_at_the_budget_and_says_what_it_cost() {
        let t0 = Instant::now();
        let mut schedule = DialSchedule::default();
        schedule.arm(hash(1), at(9, 4001), t0, t0);

        // Every dial fails; the clock runs on the cadence until the budget is.
        let mut dials = 1;
        let spent = loop {
            let settle = t0 + REDIAL_INTERVAL * (dials - 1) + DIAL_ATTEMPT_TIMEOUT;
            if let Some(DialOrder::Exhausted { dials: spent, .. }) =
                schedule.settled(hash(1), settle)
            {
                break spent;
            }
            let due = schedule.due(t0 + REDIAL_INTERVAL * dials);
            match due.as_slice() {
                [DialOrder::Exhausted { dials: spent, .. }] => break *spent,
                [DialOrder::Dial { .. }] => dials += 1,
                other => panic!("one dial at a time, always: {other:?}"),
            }
            assert!(dials < 64, "the budget must be reached in a bounded run");
        };
        assert_eq!(spent, dials);
        assert_eq!(schedule.len(), 0, "a spent attempt is forgotten");
        assert!(
            spent > 10,
            "the budget bought many openers, not one long wait"
        );
    }

    /// A `0xA1` corrects where the dial goes and re-dials at once — but never
    /// alongside a dial already in flight, and never with a burst: the datagram
    /// just proved the mapping alive.
    #[test]
    fn a_punch_corrects_the_endpoint_and_redials_into_a_free_slot_only() {
        let t0 = Instant::now();
        let mut schedule = DialSchedule::default();
        schedule.arm(hash(1), at(9, 4001), t0, t0);

        assert_eq!(schedule.arm(hash(1), at(9, 32100), t0, t0), None);
        assert_eq!(
            schedule.target(hash(1)),
            Some(at(9, 32100)),
            "the correction is kept for the next dial"
        );

        let settled = t0 + DIAL_ATTEMPT_TIMEOUT;
        schedule.settled(hash(1), settled);
        assert_eq!(
            schedule.arm(hash(1), at(9, 32100), t0, settled),
            Some(DialOrder::Dial {
                peer: hash(1),
                at: at(9, 32100),
                burst: false
            }),
            "a punch re-dials immediately, ahead of the cadence"
        );
        assert!(schedule.in_flight(hash(1)));
    }

    /// Two peers behind one address are two attempts: the schedule is keyed by
    /// the target, not by the address a CGNAT made them share.
    #[test]
    fn two_targets_behind_one_address_are_dialed_independently() {
        let t0 = Instant::now();
        let mut schedule = DialSchedule::default();
        assert!(schedule.arm(hash(1), at(9, 4001), t0, t0).is_some());
        assert!(schedule.arm(hash(2), at(9, 4002), t0, t0).is_some());
        assert_eq!(schedule.len(), 2);
    }

    /// A dial ordered but never started — its path already held a Tunnel —
    /// frees its slot: the cadence still comes round and the budget still
    /// ends the attempt, where a slot left in flight had no deadline at all.
    #[test]
    fn a_skipped_dial_keeps_the_cadence_and_the_budget() {
        let t0 = Instant::now();
        let mut schedule = DialSchedule::default();
        schedule.arm(hash(1), at(9, 4001), t0, t0);
        schedule.skipped(hash(1));
        assert!(!schedule.in_flight(hash(1)));
        assert!(matches!(
            schedule.due(t0 + REDIAL_INTERVAL).as_slice(),
            [DialOrder::Dial { .. }]
        ));
        schedule.skipped(hash(1));
        assert!(matches!(
            schedule.due(t0 + DIAL_BUDGET).as_slice(),
            [DialOrder::Exhausted { .. }]
        ));
    }

    /// A risen tunnel ends its attempt, and the cadence never re-dials a target
    /// that already has one.
    #[test]
    fn a_risen_tunnel_ends_its_attempt() {
        let t0 = Instant::now();
        let mut schedule = DialSchedule::default();
        schedule.arm(hash(1), at(9, 4001), t0, t0);
        assert_eq!(schedule.risen(hash(1)), Some(1));
        assert!(schedule.due(t0 + REDIAL_INTERVAL * 4).is_empty());
        assert_eq!(schedule.risen(hash(1)), None);
    }

    /// The budget bounds the attempt, not the dial. A dial a
    /// server introduction armed fifteen seconds after Begin is spent at
    /// Begin + 120 s, not fifteen seconds later; one armed past it never
    /// starts.
    #[test]
    fn a_late_dial_keeps_only_what_is_left_of_the_attempts_budget() {
        let begin = Instant::now();
        let mut schedule = DialSchedule::default();
        let late = begin + Duration::from_secs(15);
        assert!(matches!(
            schedule.arm(hash(1), at(9, 4001), begin, late),
            Some(DialOrder::Dial { .. })
        ));

        assert!(matches!(
            schedule.settled(hash(1), begin + DIAL_BUDGET),
            Some(DialOrder::Exhausted { dials: 1, .. })
        ));
        assert!(matches!(
            schedule.arm(hash(2), at(9, 4002), begin, begin + DIAL_BUDGET),
            Some(DialOrder::Exhausted { dials: 0, .. })
        ));
    }
}
