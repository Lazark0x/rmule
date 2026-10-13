//! The §5 measurement of ADR-0112: the verified prefix — the bytes from
//! offset 0 every one of whose parts verified — over time, read off the
//! downloader's positional part map (ADR-0079) as rmule-tools ticks it, beside
//! the verified bytes, so a run shows how far the prefix lags what arrived.

use std::fmt::Write as _;

use rmule_primitives::ED2K_PART_SIZE;
use serde::Serialize;

use super::replay::Replay;

/// The §5 measurement, off the downloader's part-map ticks. Times are seconds
/// after the first tick that shows a part in flight.
#[derive(Debug, Default, Serialize)]
pub(crate) struct Measurement {
    pub(crate) ticks: usize,
    pub(crate) first_part_in_flight_after_start_s: Option<f64>,
    pub(crate) first_part_verified_s: Option<f64>,
    pub(crate) prefix_quarter_s: Option<f64>,
    pub(crate) prefix_half_s: Option<f64>,
    pub(crate) prefix_three_quarters_s: Option<f64>,
    pub(crate) prefix_whole_s: Option<f64>,
    /// Verified bytes minus prefix bytes, averaged over the ticks from the
    /// first part in flight to the last part verified (or the last tick).
    pub(crate) mean_prefix_lag_bytes: Option<u64>,
}

/// The §5 measurement and its series, `t_s prefix_bytes verified_bytes parts`
/// per tick.
pub(crate) fn measure(run: &Replay, size: u64) -> (Measurement, String) {
    let mut series = String::from("t_s\tprefix_bytes\tverified_bytes\tparts\n");
    let Some(start) = run.ticks.first().map(|(at, _)| *at) else {
        return (Measurement::default(), series);
    };
    let origin = run
        .ticks
        .iter()
        .find(|(_, map)| map.chars().any(|letter| letter != 'M'))
        .map(|(at, _)| *at);
    let bytes = |parts: usize| (parts as u64 * ED2K_PART_SIZE).min(size);
    let mut measurement = Measurement {
        ticks: run.ticks.len(),
        first_part_in_flight_after_start_s: origin.map(|at| at - start),
        ..Measurement::default()
    };
    let Some(origin) = origin else {
        return (measurement, series);
    };
    let mut lag_sum = 0_u128;
    let mut lag_ticks = 0_u128;
    let mut thresholds: [(u64, Option<f64>); 4] = [
        (size / 4, None),
        (size / 2, None),
        (size * 3 / 4, None),
        (size, None),
    ];
    for (at, map) in &run.ticks {
        let t = at - origin;
        let prefix = bytes(map.chars().take_while(|letter| *letter == 'V').count());
        let verified = bytes(map.chars().filter(|letter| *letter == 'V').count());
        let _ = writeln!(series, "{t:.3}\t{prefix}\t{verified}\t{map}");
        if *at < origin {
            continue;
        }
        if verified > 0 && measurement.first_part_verified_s.is_none() {
            measurement.first_part_verified_s = Some(t);
        }
        for (threshold, reached) in &mut thresholds {
            if reached.is_none() && prefix >= *threshold {
                *reached = Some(t);
            }
        }
        if thresholds[3].1.is_none() || thresholds[3].1 == Some(t) {
            lag_sum += u128::from(verified - prefix);
            lag_ticks += 1;
        }
    }
    measurement.prefix_quarter_s = thresholds[0].1;
    measurement.prefix_half_s = thresholds[1].1;
    measurement.prefix_three_quarters_s = thresholds[2].1;
    measurement.prefix_whole_s = thresholds[3].1;
    measurement.mean_prefix_lag_bytes =
        (lag_ticks > 0).then(|| u64::try_from(lag_sum / lag_ticks).unwrap_or(u64::MAX));
    (measurement, series)
}

#[cfg(test)]
mod tests;
