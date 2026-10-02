//! Lease clamps, the two RFC renewal ladders, and the failure backoff
//! (ADR-0086). Pure arithmetic — every rule here is a function of a lifetime,
//! an attempt number and a jitter draw, with no clock in sight.
//!
//! **The clamps are a security control, not tidiness.** RFC 6887 §7.4 tells a
//! client not to repeat a failed request for the lifetime the *error* carried,
//! and both protocols let a gateway state a lifetime of `0xFFFFFFFF` — so an
//! unclamped hold-off disables port mapping for 136 years, and an unclamped
//! success lifetime means a mapping that is never renewed and silently lapses.
//! RFC 6887 §15 says as much outright: on an absurd lifetime, "behave as if it
//! received a more sane value (e.g., 24 hours)".
//!
//! **The two ladders are different because the two RFCs are.** RFC 6887
//! §11.2.1 gives PCP three widening windows measured from the grant — 1/2 to
//! 5/8, then 3/4 to 3/4+1/16, then 7/8 to 7/8+1/32 — with a hard floor of four
//! seconds between renewals. RFC 6886 says only "begin trying to renew
//! halfway to expiry time, like DHCP" and states no retry schedule at all;
//! rmule takes its half-life for the first attempt and borrows the §11.2.1
//! rungs for the retries, because a failed NAT-PMP renewal that re-fired at the
//! same instant would spin against a gateway that is already refusing.
//!
//! A **permanent** lease (IGD1's `PortMappingLeaseDuration` of 0) has no expiry
//! to measure a fraction of. It is re-verified by a slow 30-minute poll
//! instead: the router can still have forgotten it, and nothing else would ever
//! notice.

use std::time::Duration;

use rmule_net::portmap::MappingProtocol;

/// The ceiling a granted lifetime is clamped to (RFC 6887 §15's "more sane
/// value"). A gateway claiming more is claiming a mapping rmule would never
/// renew.
pub(crate) const MAX_LEASE: Duration = Duration::from_secs(24 * 60 * 60);

/// The shortest lifetime rmule asks a gateway for. A requested lifetime of
/// zero is not a short mapping but a *delete* in both UDP protocols (RFC 6887
/// §15, RFC 6886 §3.4), so an unchecked zero would turn every map into a
/// release; and miniupnpd raises anything under two minutes to this anyway.
pub(crate) const MIN_ASKED_LEASE: Duration = Duration::from_secs(120);

/// The ceiling an error's hold-off is clamped to (RFC 6887 §7.4). Half an hour
/// is long enough to stop hammering a refusing router and short enough that a
/// re-enabled UPnP setting is noticed within one coffee break.
pub(crate) const MAX_ERROR_HOLD_OFF: Duration = Duration::from_secs(30 * 60);

/// The floor between two renewals of one mapping (RFC 6887 §11.2.1: "renewal
/// requests MUST NOT be sent less than four seconds apart"). A gateway that
/// grants a four-second lease would otherwise become a renewal flood.
pub(crate) const MIN_RENEW_GAP: Duration = Duration::from_secs(4);

/// How often a permanent (IGD1) mapping is re-verified, since it has no expiry
/// to renew against.
pub(crate) const PERMANENT_POLL: Duration = Duration::from_secs(30 * 60);

/// The first re-probe delay after a failed race.
pub(crate) const BACKOFF_FLOOR: Duration = Duration::from_secs(30);

/// The re-probe delay ceiling. Beyond this a router that came back would take
/// too long to be noticed.
pub(crate) const BACKOFF_CEILING: Duration = Duration::from_secs(30 * 60);

/// Consecutive renewal failures on one mapping before the whole subsystem
/// re-probes. Three, not one: a single lost datagram is normal, and a full
/// re-race is expensive enough that it must mean something.
pub(crate) const MAX_RENEW_FAILURES: u32 = 3;

/// One jitter draw, read as `draw / u32::MAX` of a ladder rung's span.
///
/// Integer rather than a float so the window endpoints are exactly assertable:
/// `0` is the bottom of the rung and [`u32::MAX`] is the top, with no rounding
/// argument about either.
pub(crate) type JitterDraw = u32;

/// Clamp a granted lifetime. `None` — a permanent mapping — stays `None`,
/// because there is no lifetime to clamp and a permanent mapping is not a
/// 24-hour one.
pub(crate) fn clamp_lease(granted: Option<Duration>) -> Option<Duration> {
    granted.map(|lease| lease.min(MAX_LEASE))
}

/// Clamp an error's hold-off, defaulting a protocol that carried none to the
/// backoff floor so every refusal has a pace.
pub(crate) fn clamp_hold_off(raw: Option<Duration>) -> Duration {
    raw.unwrap_or(BACKOFF_FLOOR).min(MAX_ERROR_HOLD_OFF)
}

/// When the next renewal of a mapping granted `lease` is due, measured **from
/// the grant** — the anchor both RFCs' fractions are of.
pub(crate) fn renewal_delay(
    protocol: MappingProtocol,
    lease: Option<Duration>,
    attempt: u32,
    jitter: JitterDraw,
) -> Duration {
    let Some(lease) = lease else {
        return PERMANENT_POLL;
    };
    let millis = u64::try_from(lease.as_millis()).unwrap_or(u64::MAX);
    // RFC 6886's half-life for NAT-PMP's first attempt; the RFC 6887 §11.2.1
    // rungs for every other case, including NAT-PMP's retries.
    let (base, span) = match (protocol, attempt) {
        (MappingProtocol::NatPmp, 0) => (millis / 2, 0),
        (_, 0) => (millis / 2, millis / 8),
        (_, 1) => (millis * 3 / 4, millis / 16),
        (_, _) => (millis * 7 / 8, millis / 32),
    };
    let offset = span.saturating_mul(u64::from(jitter)) / u64::from(u32::MAX);
    Duration::from_millis(base.saturating_add(offset)).max(MIN_RENEW_GAP)
}

/// How long to wait before re-probing after `failures` consecutive failed
/// races: 30 s, 60 s, 120 s … capped at 30 minutes.
pub(crate) fn backoff_delay(failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(16);
    let scaled = BACKOFF_FLOOR
        .as_secs()
        .saturating_mul(1u64 << doublings)
        .min(BACKOFF_CEILING.as_secs());
    Duration::from_secs(scaled)
}

/// The renewal ladder's jitter source: a `splitmix64` step, seeded once per
/// mapper.
///
/// Injected rather than drawn from the OS so a test can replay an exact
/// schedule, which is the only way the §11.2.1 windows can be asserted at all.
/// The quality bar is low by construction — this decorrelates renewal storms
/// across clients, it does not protect anything.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Jitter(u64);

impl Jitter {
    /// A source that replays the same sequence for the same `seed`.
    pub(crate) const fn seeded(seed: u64) -> Self {
        Self(seed)
    }

    /// The next draw.
    pub(crate) fn draw(&mut self) -> JitterDraw {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        // The shift leaves 32 significant bits, so the narrowing is exact.
        ((z ^ (z >> 31)) >> 32) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: Duration = Duration::from_secs(3600);

    #[test]
    fn a_granted_lifetime_is_clamped_at_twenty_four_hours() {
        // The spoofed-0xFFFFFFFF case: a gateway claiming 136 years would
        // otherwise be believed, and the mapping would never be renewed.
        assert_eq!(
            clamp_lease(Some(Duration::from_secs(u64::from(u32::MAX)))),
            Some(MAX_LEASE)
        );
        assert_eq!(clamp_lease(Some(HOUR)), Some(HOUR));
        assert_eq!(
            clamp_lease(None),
            None,
            "a permanent mapping is not a 24-hour one"
        );
    }

    #[test]
    fn an_error_hold_off_is_clamped_at_thirty_minutes_and_floors_at_the_backoff() {
        assert_eq!(clamp_hold_off(Some(HOUR)), MAX_ERROR_HOLD_OFF);
        assert_eq!(
            clamp_hold_off(Some(Duration::from_secs(90))),
            Duration::from_secs(90)
        );
        assert_eq!(
            clamp_hold_off(None),
            BACKOFF_FLOOR,
            "a protocol that carried no hold-off still gets a pace"
        );
    }

    #[test]
    fn the_pcp_ladder_walks_the_three_rfc_6887_windows() {
        // §11.2.1's windows of a 3600 s lease, endpoints exactly: 1800..2250,
        // 2700..2925, 3150..3262.5.
        let rungs = [(0, 1_800, 2_250), (1, 2_700, 2_925), (2, 3_150, 3_262)];
        for (attempt, low, high) in rungs {
            assert_eq!(
                renewal_delay(MappingProtocol::Pcp, Some(HOUR), attempt, 0),
                Duration::from_secs(low),
                "rung {attempt} bottom"
            );
            let top = renewal_delay(MappingProtocol::Pcp, Some(HOUR), attempt, u32::MAX);
            assert!(
                top >= Duration::from_secs(high) && top <= Duration::from_millis(high * 1000 + 500),
                "rung {attempt} top was {top:?}"
            );
        }
    }

    #[test]
    fn nat_pmp_renews_at_the_half_life_with_no_jitter_then_joins_the_ladder() {
        // RFC 6886 states only "halfway to expiry" and no retry schedule; the
        // first attempt is exactly that, and the retries borrow §11.2.1 so a
        // refused renewal does not re-fire at the same instant.
        for jitter in [0, u32::MAX] {
            assert_eq!(
                renewal_delay(MappingProtocol::NatPmp, Some(HOUR), 0, jitter),
                Duration::from_secs(1_800)
            );
        }
        assert_eq!(
            renewal_delay(MappingProtocol::NatPmp, Some(HOUR), 1, 0),
            Duration::from_secs(2_700)
        );
    }

    #[test]
    fn the_ladder_never_schedules_two_renewals_inside_four_seconds() {
        // §11.2.1's hard floor. A gateway granting a 4 s lease would otherwise
        // turn the renewal timer into a flood.
        let tiny = Some(Duration::from_secs(4));
        for attempt in 0..3 {
            assert_eq!(
                renewal_delay(MappingProtocol::Pcp, tiny, attempt, 0),
                MIN_RENEW_GAP,
                "attempt {attempt}"
            );
        }
    }

    #[test]
    fn a_permanent_lease_is_polled_rather_than_renewed() {
        // IGD1's lease of 0 has no expiry to take a fraction of, and the router
        // can still have forgotten it.
        for attempt in 0..4 {
            assert_eq!(
                renewal_delay(MappingProtocol::Upnp, None, attempt, u32::MAX),
                PERMANENT_POLL
            );
        }
    }

    #[test]
    fn the_backoff_doubles_from_thirty_seconds_and_stops_at_thirty_minutes() {
        assert_eq!(backoff_delay(1), Duration::from_secs(30));
        assert_eq!(backoff_delay(2), Duration::from_secs(60));
        assert_eq!(backoff_delay(3), Duration::from_secs(120));
        assert_eq!(backoff_delay(7), Duration::from_secs(1_800));
        assert_eq!(
            backoff_delay(64),
            BACKOFF_CEILING,
            "the ladder saturates rather than overflowing"
        );
    }

    #[test]
    fn jitter_is_replayable_and_spreads_across_the_span() {
        // Replayability is the point: without it the §11.2.1 windows could not
        // be asserted at all. Spread is the other half — a source stuck at one
        // value would put every client's renewal on the same instant.
        let replay: Vec<_> = (0..8).map(|_| Jitter::seeded(42).draw()).collect();
        assert!(
            replay.windows(2).all(|pair| pair[0] == pair[1]),
            "the same seed must replay the same draw"
        );
        let mut source = Jitter::seeded(42);
        let sequence: Vec<_> = (0..64).map(|_| source.draw()).collect();
        let distinct: std::collections::BTreeSet<_> = sequence.iter().collect();
        assert!(distinct.len() > 60, "draws collapsed: {distinct:?}");
    }
}
