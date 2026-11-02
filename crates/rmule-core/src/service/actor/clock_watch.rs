//! Noticing a suspend (ADR-0095, "A dead link"): a look every
//! [`CLOCK_LOOK`] at the time gone by on the monotonic clock and on the wall.
//! `Instant` stands still in sleep on macOS and Linux, and runs on through it
//! on Windows, so either clock running far past the look says the machine was
//! away; a wall stepped back says nothing.

use std::time::{Duration, Instant, SystemTime};

/// How often the clocks are compared.
pub(super) const CLOCK_LOOK: Duration = Duration::from_secs(30);

/// How far past a look the clocks must run to count as a suspend: as long as
/// the kernel's keepalive takes to call a link dead, which covers anything
/// shorter.
const SUSPEND_GAP: Duration = Duration::from_secs(120);

/// The two clocks at the last look.
#[derive(Debug)]
pub(super) struct ClockWatch {
    monotonic: Instant,
    wall: SystemTime,
}

impl ClockWatch {
    /// Watch from `monotonic` and `wall`.
    pub(super) const fn new(monotonic: Instant, wall: SystemTime) -> Self {
        Self { monotonic, wall }
    }

    /// Take this look; `true` when either clock ran a suspend past the last.
    pub(super) fn jumped(&mut self, monotonic: Instant, wall: SystemTime) -> bool {
        let on_the_monotonic = monotonic.saturating_duration_since(self.monotonic);
        let on_the_wall = wall.duration_since(self.wall).unwrap_or_default();
        self.monotonic = monotonic;
        self.wall = wall;
        on_the_monotonic.max(on_the_wall) > CLOCK_LOOK + SUSPEND_GAP
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn looked(monotonic: Duration, wall_gone: impl Fn(SystemTime) -> SystemTime) -> bool {
        let (at, wall) = (Instant::now(), SystemTime::now());
        ClockWatch::new(at, wall).jumped(at + monotonic, wall_gone(wall))
    }

    #[test]
    fn a_look_on_time_and_a_late_one_are_no_suspend() {
        assert!(!looked(CLOCK_LOOK, |wall| wall + CLOCK_LOOK));
        assert!(!looked(SUSPEND_GAP, |wall| wall + SUSPEND_GAP));
    }

    #[test]
    fn a_suspend_is_seen_on_whichever_clock_ran_through_it() {
        let away = Duration::from_secs(3600);
        assert!(looked(CLOCK_LOOK, |wall| wall + away), "macOS and Linux");
        assert!(looked(away, |wall| wall + away), "Windows");
    }

    #[test]
    fn a_wall_stepped_back_is_no_suspend() {
        let back = Duration::from_secs(3600);
        assert!(!looked(CLOCK_LOOK, |wall| wall - back));
    }
}
