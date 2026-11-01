//! The session-rate history the Statistics graphs plot, in fixed memory, so a
//! run left for days can say how the night went.
//!
//! Three tiers: the last ten minutes tick by tick, a day of minutes and a month
//! of hours, each a ring. A column of a coarse tier is the mean of the ticks in
//! it, so its area is the bytes moved. A span no tick landed in is a gap and
//! keeps its column: the axis stays linear and an outage reads as one.
//!
//! Sampling happens where the levels land, not per frame, so the graph replays
//! facts a tick established and can never disagree with the status bar's
//! meters that came off the same tick. A stopped core simply stops appending —
//! the graph freezes on what was observed instead of inventing a tail.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::UiState;
use crate::rates::TransferRates;

/// Ticks kept one by one: 10 wall-clock minutes at the bridge's 1 Hz data tick
/// ([`crate::bridge::BridgeConfig::snapshot_interval`]). A column is a tick, so
/// this is also the widest pane this tier fills.
const SECONDS_CAP: usize = 600;

/// Minutes kept: a day.
const MINUTES_CAP: usize = 1_440;

/// Hours kept: thirty days.
const HOURS_CAP: usize = 720;

/// What a graph column stands for: the window key walks these.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RateWindow {
    /// A tick a column.
    #[default]
    Seconds,
    /// A minute a column.
    Hours,
    /// An hour a column.
    Days,
}

impl RateWindow {
    /// The next window along; after the longest, the shortest.
    #[must_use]
    pub const fn next(self) -> Self {
        match self {
            Self::Seconds => Self::Hours,
            Self::Hours => Self::Days,
            Self::Days => Self::Seconds,
        }
    }
}

/// The session-wide rates of one column.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rates {
    /// Every byte arriving from peers, bytes/sec (the status bar's ▼).
    pub down_bps: f64,
    /// Every byte served to peers, bytes/sec (the status bar's ▲).
    pub up_bps: f64,
}

/// One column of a graph.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RateColumn {
    /// When the span it covers began, on the injected clock.
    pub at: Instant,
    /// What the ticks in it read; `None` when no tick landed.
    pub rates: Option<Rates>,
}

/// The ticks of a span still filling.
#[derive(Clone, Copy, Debug)]
struct OpenSpan {
    at: Instant,
    down_sum: f64,
    up_sum: f64,
    ticks: u32,
}

impl OpenSpan {
    const fn at(at: Instant) -> Self {
        Self {
            at,
            down_sum: 0.0,
            up_sum: 0.0,
            ticks: 0,
        }
    }

    fn column(&self) -> RateColumn {
        let ticks = f64::from(self.ticks);
        RateColumn {
            at: self.at,
            rates: (self.ticks > 0).then(|| Rates {
                down_bps: self.down_sum / ticks,
                up_bps: self.up_sum / ticks,
            }),
        }
    }
}

/// One coarse tier: closed spans in a ring, and the span filling.
#[derive(Clone, Debug)]
struct Tier {
    span: Duration,
    cap: usize,
    closed: VecDeque<RateColumn>,
    open: Option<OpenSpan>,
}

impl Tier {
    fn new(span: Duration, cap: usize) -> Self {
        Self {
            span,
            cap,
            closed: VecDeque::new(),
            open: None,
        }
    }

    fn close(&mut self, column: RateColumn) {
        self.closed.push_back(column);
        if self.closed.len() > self.cap {
            self.closed.pop_front();
        }
    }

    fn record(&mut self, at: Instant, rates: Rates) {
        let mut open = self.open.unwrap_or_else(|| OpenSpan::at(at));
        let elapsed = at.saturating_duration_since(open.at).as_nanos();
        let spans = u32::try_from(elapsed / self.span.as_nanos()).unwrap_or(u32::MAX);
        if spans > 0 {
            self.close(open.column());
            // Only the newest gaps can stay in the ring, however long the gap.
            let cap = u32::try_from(self.cap).unwrap_or(u32::MAX);
            for gap in spans.saturating_sub(cap).max(1)..spans {
                self.close(RateColumn {
                    at: open.at + self.span * gap,
                    rates: None,
                });
            }
            open = OpenSpan::at(open.at + self.span * spans);
        }
        open.down_sum += rates.down_bps;
        open.up_sum += rates.up_bps;
        open.ticks += 1;
        self.open = Some(open);
    }

    /// The newest `count` columns, oldest first, the span filling last.
    fn newest(&self, count: usize) -> Vec<RateColumn> {
        let open = self.open.as_ref().map(OpenSpan::column);
        let closed = count.saturating_sub(usize::from(open.is_some()));
        let skip = self.closed.len().saturating_sub(closed);
        self.closed.iter().skip(skip).copied().chain(open).collect()
    }
}

/// The history: three tiers, one for each [`RateWindow`].
#[derive(Clone, Debug)]
pub struct RateHistory {
    ticks: VecDeque<RateColumn>,
    minutes: Tier,
    hours: Tier,
}

impl Default for RateHistory {
    fn default() -> Self {
        Self {
            ticks: VecDeque::new(),
            minutes: Tier::new(Duration::from_secs(60), MINUTES_CAP),
            hours: Tier::new(Duration::from_secs(3_600), HOURS_CAP),
        }
    }
}

impl RateHistory {
    fn record(&mut self, at: Instant, rates: Rates) {
        self.ticks.push_back(RateColumn {
            at,
            rates: Some(rates),
        });
        if self.ticks.len() > SECONDS_CAP {
            self.ticks.pop_front();
        }
        self.minutes.record(at, rates);
        self.hours.record(at, rates);
    }

    /// The newest `count` columns of `window`, oldest first: exactly what a
    /// `count`-wide graph has room for.
    #[must_use]
    pub fn newest(&self, window: RateWindow, count: usize) -> Vec<RateColumn> {
        match window {
            RateWindow::Seconds => {
                let skip = self.ticks.len().saturating_sub(count);
                self.ticks.iter().skip(skip).copied().collect()
            }
            RateWindow::Hours => self.minutes.newest(count),
            RateWindow::Days => self.hours.newest(count),
        }
    }

    /// What the last tick read, whatever the window.
    #[must_use]
    pub fn latest(&self) -> Option<Rates> {
        self.ticks.back().and_then(|column| column.rates)
    }
}

impl UiState {
    /// Add this tick's session rates to the history.
    ///
    /// Sampling belongs *here*, at the one place a tick's levels land, not in
    /// the view: a sample is a derived-at-tick fact with the tick's own
    /// injected time on it, so redrawing the graph twice — or not at all —
    /// cannot change its shape.
    pub(super) fn push_rate_sample(&mut self, rates: &TransferRates, at: Instant) {
        self.rate_history.record(
            at,
            Rates {
                down_bps: rates.down_total_bps,
                up_bps: rates.up_total_bps,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use rmule_core::DownloadEvent;
    use rmule_core::diagnostics::DiagnosticsSnapshot;

    use super::*;
    use crate::action::Action;
    use crate::bridge::BridgeSnapshot;
    use crate::fixture::{download_event, download_id};

    fn flat(bps: f64) -> Rates {
        Rates {
            down_bps: bps,
            up_bps: bps / 2.0,
        }
    }

    fn reading(columns: &[RateColumn]) -> Vec<Option<f64>> {
        columns
            .iter()
            .map(|column| column.rates.map(|rates| rates.down_bps))
            .collect()
    }

    /// Edges are not ticks: folding an event must not fabricate a sample.
    #[test]
    fn only_a_data_tick_adds_to_the_history() {
        let mut state = UiState::default();
        let t0 = Instant::now();
        for tick in 0..3u64 {
            let at = t0 + Duration::from_secs(tick);
            state.apply(
                Action::Snapshot(BridgeSnapshot {
                    diagnostics: DiagnosticsSnapshot::default(),
                    rates: TransferRates {
                        down_total_bps: tick as f64 * 1024.0,
                        up_total_bps: tick as f64 * 512.0,
                        ..TransferRates::default()
                    },
                    taken_at: at,
                }),
                at,
            );
        }
        state.apply(
            Action::Core(download_event(DownloadEvent::DownloadPaused {
                download_id: download_id(1),
            })),
            t0,
        );
        state.apply(Action::CoreClosed, t0);

        let columns = state.rate_history.newest(RateWindow::Seconds, 100);
        assert_eq!(columns.len(), 3);
        assert_eq!(columns[2].at, t0 + Duration::from_secs(2));
        assert_eq!(
            state.rate_history.latest(),
            Some(Rates {
                down_bps: 2048.0,
                up_bps: 1024.0
            })
        );
    }

    /// A night in one reading: a coarse column is the mean of its ticks, and the
    /// hours of quiet read apart from the hours of traffic.
    #[test]
    fn a_coarse_column_is_the_mean_of_the_ticks_in_it() {
        let mut history = RateHistory::default();
        let base = Instant::now();
        for tick in 0..(3 * 3_600u64) {
            // Half the first hour idle, half at 200: the mean is what the
            // bytes say.
            let bps = match tick {
                0..1_800 => 0.0,
                1_800..3_600 => 200.0,
                3_600..7_200 => 300.0,
                _ => 0.0,
            };
            history.record(base + Duration::from_secs(tick), flat(bps));
        }
        history.record(base + Duration::from_secs(3 * 3_600), flat(40.0));

        assert_eq!(
            reading(&history.newest(RateWindow::Days, 10)),
            [Some(100.0), Some(300.0), Some(0.0), Some(40.0)],
            "the span filling is the newest column"
        );
        let minutes = history.newest(RateWindow::Hours, 2);
        assert_eq!(reading(&minutes), [Some(0.0), Some(40.0)]);
    }

    /// Days of ticks stay in fixed memory, and the month's oldest hour is what
    /// goes first.
    #[test]
    fn a_month_of_ticks_stays_in_fixed_memory() {
        let mut history = RateHistory::default();
        let base = Instant::now();
        let hours = HOURS_CAP as u64 + 24;
        for hour in 0..hours {
            for tick in (0..3_600).step_by(60) {
                history.record(
                    base + Duration::from_secs(hour * 3_600 + tick),
                    flat(hour as f64),
                );
            }
        }
        assert_eq!(history.minutes.closed.len(), MINUTES_CAP);
        assert_eq!(history.hours.closed.len(), HOURS_CAP);
        let days = history.newest(RateWindow::Days, usize::MAX);
        assert_eq!(days.len(), HOURS_CAP + 1);
        assert_eq!(days[0].rates.map(|rates| rates.down_bps), Some(23.0));
    }

    /// No tick for a while (a stall, a stopped bridge): the span keeps its
    /// column and says nothing was metered.
    #[test]
    fn a_span_no_tick_landed_in_stays_a_gap() {
        let mut history = RateHistory::default();
        let base = Instant::now();
        history.record(base, flat(10.0));
        history.record(base + Duration::from_secs(180), flat(20.0));
        assert_eq!(
            reading(&history.newest(RateWindow::Hours, 10)),
            [Some(10.0), None, None, Some(20.0)]
        );
    }

    /// A gap longer than a ring costs a ring of blanks, not a walk of its length.
    #[test]
    fn a_gap_longer_than_the_ring_leaves_its_newest_spans() {
        let mut history = RateHistory::default();
        let base = Instant::now();
        history.record(base, flat(1.0));
        let later = base + Duration::from_secs(60 * 86_400);
        history.record(later, flat(2.0));
        let hours = history.newest(RateWindow::Days, usize::MAX);
        assert_eq!(hours.len(), HOURS_CAP + 1);
        assert_eq!(
            hours[HOURS_CAP].rates.map(|rates| rates.down_bps),
            Some(2.0)
        );
        assert_eq!(hours[HOURS_CAP - 1].at + Duration::from_secs(3_600), later);
    }
}
