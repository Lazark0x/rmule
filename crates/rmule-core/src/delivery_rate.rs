//! The **Delivery Rate** of one link: bytes over windows of at least one
//! second, smoothed by a quarter per window (ADR-0026, ADR-0029). Time is an
//! argument, so the worker's request pipeline and the download's Tail Race
//! read the same measure from the instants they are handed.

use std::time::{Duration, Instant};

/// The shortest span one sample covers.
const WINDOW: Duration = Duration::from_secs(1);

/// Bytes per second delivered over a link, `None` until one window closed.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DeliveryRate {
    /// The open window: when it opened and the bytes counted since.
    window: Option<(Instant, u64)>,
    bytes_per_sec: Option<u64>,
}

impl DeliveryRate {
    /// Count `bytes` that arrived at `now`. The first arrival opens the window
    /// and is not counted: its bytes were on the wire before the window began.
    pub(crate) fn record(&mut self, now: Instant, bytes: u64) {
        let Some((opened, counted)) = self.window else {
            self.window = Some((now, 0));
            return;
        };
        let counted = counted.saturating_add(bytes);
        let span = now.saturating_duration_since(opened);
        if span < WINDOW {
            self.window = Some((opened, counted));
            return;
        }
        let sample = u64::try_from(u128::from(counted) * 1_000_000 / span.as_micros().max(1))
            .unwrap_or(u64::MAX);
        self.bytes_per_sec = Some(match self.bytes_per_sec {
            Some(old) => old - old / 4 + sample / 4,
            None => sample,
        });
        self.window = Some((now, 0));
    }

    /// Close the open window without a sample: the link went quiet for a
    /// reason of its own (between parts), and that wait is no slowness.
    pub(crate) fn pause(&mut self) {
        self.window = None;
    }

    /// The smoothed rate, once one window closed.
    pub(crate) const fn bytes_per_sec(&self) -> Option<u64> {
        self.bytes_per_sec
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_window_shorter_than_a_second_gives_no_rate_and_a_full_one_does() {
        let start = Instant::now();
        let mut rate = DeliveryRate::default();
        rate.record(start, 10_000);
        rate.record(start + Duration::from_millis(500), 50_000);
        assert_eq!(rate.bytes_per_sec(), None);
        rate.record(start + Duration::from_secs(2), 150_000);
        assert_eq!(rate.bytes_per_sec(), Some(100_000));
    }

    #[test]
    fn later_windows_move_the_rate_a_quarter_of_the_way() {
        let start = Instant::now();
        let mut rate = DeliveryRate::default();
        rate.record(start, 0);
        rate.record(start + Duration::from_secs(1), 100_000);
        rate.record(start + Duration::from_secs(2), 500_000);
        assert_eq!(rate.bytes_per_sec(), Some(200_000));
    }

    #[test]
    fn a_pause_leaves_the_quiet_span_out_of_the_rate() {
        let start = Instant::now();
        let mut rate = DeliveryRate::default();
        rate.record(start, 0);
        rate.record(start + Duration::from_secs(1), 100_000);
        rate.pause();
        rate.record(start + Duration::from_secs(60), 0);
        rate.record(start + Duration::from_secs(61), 100_000);
        assert_eq!(rate.bytes_per_sec(), Some(100_000));
    }
}
