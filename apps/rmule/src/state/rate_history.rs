//! The session-rate history the Statistics graphs plot: one sample per data
//! tick, capped at a ten-minute window.
//!
//! Sampling happens where the levels land, not per frame, so the graph replays
//! facts a tick established and can never disagree with the status bar's
//! meters that came off the same tick. A stopped core simply stops appending —
//! the graph freezes on what was observed instead of inventing a tail.

use std::time::Instant;

use super::UiState;
use crate::rates::TransferRates;

/// Ring capacity of the Statistics rate history (§6 return): 600 samples
/// = 10 wall-clock minutes at the bridge's 1 Hz data tick
/// ([`crate::bridge::BridgeConfig::snapshot_interval`]), the window aMule's
/// statistics graphs default to.
///
/// The graph plots one sample per column, so the capacity is also the widest
/// pane that can be drawn without running out of history — 600 columns is
/// wider than any real terminal, which is why the window is stated in *time*
/// and the pane never has to interpolate.
const RATE_HISTORY_CAP: usize = 600;

/// One data tick's session-wide rate observation — the Statistics graphs'
/// datum.
///
/// Sampled where the levels land ([`UiState::apply_snapshot`]) rather than
/// rebuilt per frame: the graph replays facts a tick established, so it can
/// never disagree with the status bar's ▼/▲ meters that came off the same
/// tick.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RateSample {
    /// The injected `apply` instant — monotonic, never a wall clock.
    pub at: Instant,
    /// Every byte arriving from peers, bytes/sec (the status bar's ▼).
    pub down_bps: f64,
    /// Every byte served to peers, bytes/sec (the status bar's ▲).
    pub up_bps: f64,
}

impl UiState {
    /// Append this tick's session rates to the history ring, evicting the
    /// oldest beyond [`RATE_HISTORY_CAP`].
    ///
    /// Sampling belongs *here*, at the one place a tick's levels land, not in
    /// the view: a sample is a derived-at-tick fact with the tick's own
    /// injected time on it, so redrawing the graph twice — or not at all —
    /// cannot change its shape.
    pub(super) fn push_rate_sample(&mut self, rates: &TransferRates, at: Instant) {
        self.rate_history.push_back(RateSample {
            at,
            down_bps: rates.down_total_bps,
            up_bps: rates.up_total_bps,
        });
        while self.rate_history.len() > RATE_HISTORY_CAP {
            self.rate_history.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rmule_core::DownloadEvent;
    use rmule_core::diagnostics::DiagnosticsSnapshot;

    use super::*;
    use crate::action::Action;
    use crate::bridge::BridgeSnapshot;
    use crate::fixture::{download_event, download_id};

    /// The Statistics graphs' datum is taken on the tick, not at draw time
    /// One sample per snapshot, carrying that tick's session rates and
    /// its injected instant.
    #[test]
    fn every_data_tick_appends_exactly_one_rate_sample() {
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
        let samples: Vec<RateSample> = state.rate_history.iter().copied().collect();
        assert_eq!(samples.len(), 3);
        assert_eq!(samples[2].down_bps, 2048.0);
        assert_eq!(samples[2].up_bps, 1024.0);
        assert_eq!(samples[2].at, t0 + Duration::from_secs(2));

        // Edges are not ticks: folding an event must not fabricate a sample.
        state.apply(
            Action::Core(download_event(DownloadEvent::DownloadPaused {
                download_id: download_id(1),
            })),
            t0,
        );
        state.apply(Action::CoreClosed, t0);
        assert_eq!(state.rate_history.len(), 3, "only the data tick samples");
    }

    #[test]
    fn the_rate_history_caps_at_ten_minutes_dropping_oldest_first() {
        let mut state = UiState::default();
        let t0 = Instant::now();
        for tick in 0..(RATE_HISTORY_CAP as u64 + 50) {
            let at = t0 + Duration::from_secs(tick);
            state.apply_snapshot(
                BridgeSnapshot {
                    diagnostics: DiagnosticsSnapshot::default(),
                    rates: TransferRates {
                        down_total_bps: tick as f64,
                        ..TransferRates::default()
                    },
                    taken_at: at,
                },
                at,
            );
        }
        assert_eq!(state.rate_history.len(), RATE_HISTORY_CAP);
        // 650 pushed, 600 kept ⇒ the first 50 evicted.
        assert_eq!(state.rate_history.front().unwrap().down_bps, 50.0);
        assert_eq!(state.rate_history.back().unwrap().down_bps, 649.0);
    }
}
