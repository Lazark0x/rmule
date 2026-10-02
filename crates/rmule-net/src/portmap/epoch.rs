//! Gateway **epoch validation** (ADR-0086): reading a router reboot out of the
//! uptime counter PCP and NAT-PMP put in every response.
//!
//! A gateway that reboots forgets every mapping it granted. Nothing else tells
//! a client that: the lease it handed out is still nominally alive, the next
//! renewal will happily succeed against a *new* mapping table, and in between
//! the node is silently firewalled again. Both RFCs therefore carry the
//! gateway's seconds-since-start in every response and state — differently —
//! how to compare it against the client's own clock.
//!
//! `crab_nat` parses both fields and validates neither (its own doc comment
//! describes the algorithm and then leaves it to the caller), so this is the
//! piece rmule owns. It is pure and explicit-time: `now` is a parameter, so a
//! test drives an hour of gateway uptime in a microsecond.
//!
//! Neither rule is the other's approximation — they disagree on purpose:
//!
//! - **RFC 6887 §8.5** (PCP) is two-sided. It fails a response whose epoch went
//!   *backwards*, and also one whose epoch and the client's clock drifted apart
//!   in **either** direction by more than 1/16 (6.25 %) plus a 2-second
//!   reordering allowance. Catching the "server aged faster than we did" side
//!   matters because that is what a gateway looks like when it restores a saved
//!   epoch after a crash.
//! - **RFC 6886 §3.6** (NAT-PMP) is one-sided and more forgiving: the client
//!   forms a conservative expectation (`previous + 7/8 of the elapsed time`)
//!   and concludes a reboot only when the gateway reports *less* than that.

use std::time::{Duration, Instant};

/// What one epoch reading said about the gateway's state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EpochVerdict {
    /// This protocol carries no epoch at all — UPnP-IGD has no equivalent, so
    /// a UPnP mapping's only reboot signal is its lease running out.
    #[default]
    Absent,
    /// The first reading from this gateway. There is nothing to compare
    /// against yet, so it is neither consistent nor a reset; the value is
    /// simply remembered.
    Anchored,
    /// The epoch advanced in step with our own clock, inside the RFC's
    /// tolerances. Every mapping we hold is still on the router.
    Consistent,
    /// The gateway lost its state — it rebooted, or restored an epoch it had
    /// saved. Every mapping must be re-added; nothing we hold is real.
    Reset,
}

impl EpochVerdict {
    /// Whether this reading means the mappings are gone.
    #[must_use]
    pub const fn is_reset(self) -> bool {
        matches!(self, Self::Reset)
    }
}

/// Which RFC's arithmetic a tracker applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EpochRule {
    /// RFC 6887 §8.5 — two-sided, 1/16 drift plus 2 s reordering.
    Pcp,
    /// RFC 6886 §3.6 — one-sided, 7/8 conservative expectation.
    NatPmp,
}

/// The remembered epoch of one gateway under one protocol, and the rule that
/// reads a reboot out of the next response.
///
/// One tracker per (gateway, protocol): the two protocols count from different
/// events on some firmware, and two gateways are two counterparties. A backend
/// owns its trackers because the epoch is state about the *counterparty*, not
/// policy — core is told only the verdict.
#[derive(Clone, Copy, Debug)]
pub struct EpochTracker {
    rule: EpochRule,
    /// The last reading: the gateway's seconds-since-start and our own clock
    /// when it arrived. `None` until the first response.
    anchor: Option<(u32, Instant)>,
}

impl EpochTracker {
    /// The two-second reordering allowance of RFC 6887 §8.5 — a response that
    /// overtook another must not read as drift.
    const PCP_REORDERING_ALLOWANCE: u64 = 2;

    /// The drift divisor both RFC 6887 §8.5 comparisons use: 1/16 of the delta,
    /// i.e. a 6.25 % clock-skew allowance in each direction.
    const PCP_DRIFT_DIVISOR: u64 = 16;

    /// A tracker applying RFC 6887 §8.5 (PCP).
    #[must_use]
    pub const fn pcp() -> Self {
        Self {
            rule: EpochRule::Pcp,
            anchor: None,
        }
    }

    /// A tracker applying RFC 6886 §3.6 (NAT-PMP).
    #[must_use]
    pub const fn nat_pmp() -> Self {
        Self {
            rule: EpochRule::NatPmp,
            anchor: None,
        }
    }

    /// Read one response's epoch at `now` and remember it.
    ///
    /// A [`Reset`](EpochVerdict::Reset) re-anchors on the new value, so the
    /// reading after a reboot is [`Consistent`](EpochVerdict::Consistent)
    /// again rather than a second reset — the gateway is not still rebooting,
    /// it has rebooted once.
    pub fn observe(&mut self, epoch_seconds: u32, now: Instant) -> EpochVerdict {
        let verdict = match self.anchor {
            None => EpochVerdict::Anchored,
            Some((previous, seen_at)) => {
                let elapsed = now.saturating_duration_since(seen_at);
                match self.rule {
                    EpochRule::Pcp => pcp_verdict(previous, epoch_seconds, elapsed),
                    EpochRule::NatPmp => nat_pmp_verdict(previous, epoch_seconds, elapsed),
                }
            }
        };
        self.anchor = Some((epoch_seconds, now));
        verdict
    }

    /// Forget the gateway — the next reading anchors afresh. Used when the
    /// gateway address itself changes, where comparing two different routers'
    /// uptimes would manufacture a reset out of nothing.
    pub const fn forget(&mut self) {
        self.anchor = None;
    }
}

/// RFC 6887 §8.5: a backwards epoch, or client and server clocks that drifted
/// apart by more than 1/16 plus 2 s in either direction, means lost state.
fn pcp_verdict(previous: u32, current: u32, elapsed: Duration) -> EpochVerdict {
    if current < previous {
        return EpochVerdict::Reset;
    }
    let server_delta = u64::from(current - previous);
    let client_delta = elapsed.as_secs();
    let drifted = |slow: u64, fast: u64| {
        slow + EpochTracker::PCP_REORDERING_ALLOWANCE
            < fast.saturating_sub(fast / EpochTracker::PCP_DRIFT_DIVISOR)
    };
    if drifted(client_delta, server_delta) || drifted(server_delta, client_delta) {
        EpochVerdict::Reset
    } else {
        EpochVerdict::Consistent
    }
}

/// RFC 6886 §3.6: the client's conservative expectation is the previous epoch
/// plus 7/8 of the elapsed time; a gateway reporting less than that rebooted.
fn nat_pmp_verdict(previous: u32, current: u32, elapsed: Duration) -> EpochVerdict {
    let expected = u64::from(previous) + elapsed.as_secs() * 7 / 8;
    if u64::from(current) < expected {
        EpochVerdict::Reset
    } else {
        EpochVerdict::Consistent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn the_first_reading_anchors_and_judges_nothing() {
        // There is no previous value to compare against, and guessing one
        // would make every fresh session start with a spurious reset.
        let t0 = Instant::now();
        let mut pcp = EpochTracker::pcp();
        assert_eq!(pcp.observe(1_000, t0), EpochVerdict::Anchored);
        assert_eq!(
            pcp.observe(1_060, t0 + secs(60)),
            EpochVerdict::Consistent,
            "the second reading is the first that can be judged"
        );
    }

    #[test]
    fn a_pcp_epoch_that_went_backwards_is_a_reset() {
        // RFC 6887 §8.5 rule 1: uptime never decreases on a box that stayed up.
        let t0 = Instant::now();
        let mut pcp = EpochTracker::pcp();
        pcp.observe(10_000, t0);
        assert_eq!(pcp.observe(5, t0 + secs(30)), EpochVerdict::Reset);
    }

    #[test]
    fn a_pcp_reset_re_anchors_so_the_next_reading_is_consistent() {
        // The gateway rebooted once, not continuously: after the reset the new
        // low epoch is the truth, and re-adding the mappings must not be
        // triggered again on the very next renewal.
        let t0 = Instant::now();
        let mut pcp = EpochTracker::pcp();
        pcp.observe(10_000, t0);
        assert_eq!(pcp.observe(5, t0 + secs(30)), EpochVerdict::Reset);
        assert_eq!(pcp.observe(65, t0 + secs(90)), EpochVerdict::Consistent);
    }

    #[test]
    fn pcp_tolerates_drift_inside_one_sixteenth_plus_two_seconds() {
        // 3600 s of client time against 3400 s of gateway time: the gap is
        // 200 s, and the allowance is 3600/16 + 2 = 227 s, so this still reads
        // as one continuously running gateway with a slow clock.
        let t0 = Instant::now();
        let mut pcp = EpochTracker::pcp();
        pcp.observe(0, t0);
        assert_eq!(
            pcp.observe(3_400, t0 + secs(3_600)),
            EpochVerdict::Consistent
        );
    }

    #[test]
    fn pcp_flags_drift_beyond_the_allowance_in_both_directions() {
        // Server far behind the client: the gateway restored a saved epoch.
        let t0 = Instant::now();
        let mut slow_server = EpochTracker::pcp();
        slow_server.observe(0, t0);
        assert_eq!(
            slow_server.observe(3_000, t0 + secs(3_600)),
            EpochVerdict::Reset
        );

        // Server far ahead of the client — the other side of §8.5's two-sided
        // test, and the one a naive "did it go backwards" check misses.
        let mut fast_server = EpochTracker::pcp();
        fast_server.observe(0, t0);
        assert_eq!(
            fast_server.observe(3_600, t0 + secs(3_000)),
            EpochVerdict::Reset
        );
    }

    #[test]
    fn pcp_absorbs_a_two_second_reordering() {
        // Two responses that overtook each other: the epoch advanced 2 s while
        // the client's clock did not move at all. Inside the reordering
        // allowance, so not a reboot.
        let t0 = Instant::now();
        let mut pcp = EpochTracker::pcp();
        pcp.observe(500, t0);
        assert_eq!(pcp.observe(502, t0), EpochVerdict::Consistent);
    }

    #[test]
    fn nat_pmp_accepts_an_epoch_that_kept_seven_eighths_of_our_clock() {
        // RFC 6886 §3.6's conservative estimate: 3600 s elapsed expects at
        // least 3150 s of gateway uptime.
        let t0 = Instant::now();
        let mut pmp = EpochTracker::nat_pmp();
        pmp.observe(100, t0);
        assert_eq!(
            pmp.observe(3_250, t0 + secs(3_600)),
            EpochVerdict::Consistent
        );
    }

    #[test]
    fn nat_pmp_flags_an_epoch_below_the_conservative_estimate() {
        // 3600 s elapsed, gateway claims only 3000 s more — below 100 + 3150.
        let t0 = Instant::now();
        let mut pmp = EpochTracker::nat_pmp();
        pmp.observe(100, t0);
        assert_eq!(pmp.observe(3_100, t0 + secs(3_600)), EpochVerdict::Reset);
    }

    #[test]
    fn nat_pmp_ignores_a_gateway_clock_running_fast() {
        // Unlike PCP's two-sided test, RFC 6886 never concludes a reboot from a
        // gateway that counted *more* than we did — the rule is one-sided and
        // this is the divergence that makes the two trackers different types.
        let t0 = Instant::now();
        let mut pmp = EpochTracker::nat_pmp();
        pmp.observe(0, t0);
        assert_eq!(pmp.observe(9_000, t0 + secs(60)), EpochVerdict::Consistent);
    }

    #[test]
    fn forgetting_the_gateway_re_anchors_instead_of_manufacturing_a_reset() {
        // A renumber points the same backend at a different router; comparing
        // the two boxes' uptimes would report a reboot that never happened.
        let t0 = Instant::now();
        let mut pcp = EpochTracker::pcp();
        pcp.observe(90_000, t0);
        pcp.forget();
        assert_eq!(pcp.observe(12, t0 + secs(5)), EpochVerdict::Anchored);
    }
}
