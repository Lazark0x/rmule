//! The §5 measurement of ADR-0112: the verified prefix — the bytes from
//! offset 0 every one of whose parts verified — over time, beside the verified
//! bytes, so a run shows how far the prefix lags what arrived.
//!
//! Two sources on the one host clock: the downloader's part-map ticks
//! (ADR-0079), which show what is in flight, and the core's own `part
//! verified` trace lines, stamped as each part is persisted, which time every
//! verify exactly. A tick lands up to one period after a verify and none
//! follows the last one (the row leaves with the download), so the verifies
//! time the prefix; a run without the trace falls back to the ticks.

use std::fmt::Write as _;

use rmule_primitives::ED2K_PART_SIZE;
use serde::Serialize;

use super::replay::Replay;

/// The §5 measurement. Times are seconds after the first tick that shows a
/// part in flight.
#[derive(Debug, Default, Serialize)]
pub(crate) struct Measurement {
    pub(crate) ticks: usize,
    /// Verifies timed by the core's trace; `0` when they came off the ticks.
    pub(crate) traced_verifies: usize,
    pub(crate) first_part_in_flight_after_start_s: Option<f64>,
    pub(crate) first_part_verified_s: Option<f64>,
    pub(crate) prefix_quarter_s: Option<f64>,
    pub(crate) prefix_half_s: Option<f64>,
    pub(crate) prefix_three_quarters_s: Option<f64>,
    pub(crate) prefix_whole_s: Option<f64>,
    pub(crate) last_part_verified_s: Option<f64>,
    /// Verified bytes minus prefix bytes, averaged over time from the first
    /// part in flight to the last verify.
    pub(crate) mean_prefix_lag_bytes: Option<u64>,
}

/// Every `part verified` line of download `id` in rmule's trace, as unix
/// seconds and part index, in order.
pub(crate) fn traced_verifies(trace: &str, id: u64) -> Vec<(f64, u32)> {
    let id = id.to_string();
    trace
        .lines()
        .filter(|line| line.contains("part verified"))
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let at = unix_secs(words.next()?)?;
            let fields: std::collections::BTreeMap<&str, &str> =
                words.filter_map(|word| word.split_once('=')).collect();
            (fields.get("download_id") == Some(&id.as_str()))
                .then(|| Some((at, fields.get("part_index")?.parse().ok()?)))?
        })
        .collect()
}

/// An RFC 3339 UTC instant as tracing stamps it (`2026-10-13T02:19:12.217174Z`)
/// in unix seconds.
fn unix_secs(stamp: &str) -> Option<f64> {
    let (date, time) = stamp.strip_suffix('Z')?.split_once('T')?;
    let mut date = date.split('-').map(str::parse::<i64>);
    let (year, month, day) = (date.next()?.ok()?, date.next()?.ok()?, date.next()?.ok()?);
    let mut time = time.split(':');
    let hour: f64 = time.next()?.parse().ok()?;
    let minute: f64 = time.next()?.parse().ok()?;
    let second: f64 = time.next()?.parse().ok()?;
    // Days from 1970-01-01 to the civil date (Howard Hinnant's algorithm).
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Some(days as f64 * 86_400.0 + hour * 3_600.0 + minute * 60.0 + second)
}

/// The §5 measurement and its series: one row per tick and per verify,
/// `t_s prefix_bytes verified_bytes event`.
pub(crate) fn measure(run: &Replay, traced: &[(f64, u32)], size: u64) -> (Measurement, String) {
    let mut series = String::from("t_s\tprefix_bytes\tverified_bytes\tevent\n");
    let Some(start) = run.ticks.first().map(|(at, _)| *at) else {
        return (Measurement::default(), series);
    };
    let origin = run
        .ticks
        .iter()
        .find(|(_, map)| map.chars().any(|letter| letter != 'M'))
        .map(|(at, _)| *at);
    let mut measurement = Measurement {
        ticks: run.ticks.len(),
        traced_verifies: traced.len(),
        first_part_in_flight_after_start_s: origin.map(|at| at - start),
        ..Measurement::default()
    };
    let Some(origin) = origin else {
        return (measurement, series);
    };
    let bytes = |parts: usize| (parts as u64 * ED2K_PART_SIZE).min(size);
    let mut verifies = if traced.is_empty() {
        tick_verifies(run)
    } else {
        traced.to_vec()
    };
    verifies.sort_by(|a, b| a.0.total_cmp(&b.0));

    let mut rows: Vec<(f64, u64, u64, String)> = run
        .ticks
        .iter()
        .map(|(at, map)| {
            let prefix = bytes(map.chars().take_while(|letter| *letter == 'V').count());
            let verified = bytes(map.chars().filter(|letter| *letter == 'V').count());
            (*at, prefix, verified, format!("tick {map}"))
        })
        .collect();
    let mut thresholds: [(u64, Option<f64>); 4] = [
        (size / 4, None),
        (size / 2, None),
        (size * 3 / 4, None),
        (size, None),
    ];
    let mut held = vec![false; rmule_primitives::part_count(size) as usize];
    let (mut last_at, mut last_lag, mut lag_area) = (origin, 0_u64, 0_f64);
    for (at, part) in &verifies {
        if let Some(slot) = held.get_mut(*part as usize) {
            *slot = true;
        }
        let prefix = bytes(held.iter().take_while(|held| **held).count());
        let verified = bytes(held.iter().filter(|held| **held).count());
        let t = at - origin;
        lag_area += last_lag as f64 * (at - last_at).max(0.0);
        (last_at, last_lag) = (*at, verified - prefix);
        measurement.first_part_verified_s.get_or_insert(t);
        measurement.last_part_verified_s = Some(t);
        for (threshold, reached) in &mut thresholds {
            if reached.is_none() && prefix >= *threshold {
                *reached = Some(t);
            }
        }
        rows.push((*at, prefix, verified, format!("verify {part}")));
    }
    measurement.prefix_quarter_s = thresholds[0].1;
    measurement.prefix_half_s = thresholds[1].1;
    measurement.prefix_three_quarters_s = thresholds[2].1;
    measurement.prefix_whole_s = thresholds[3].1;
    let span = last_at - origin;
    measurement.mean_prefix_lag_bytes = (span > 0.0).then(|| (lag_area / span) as u64);
    rows.sort_by(|a, b| a.0.total_cmp(&b.0));
    for (at, prefix, verified, event) in rows {
        let _ = writeln!(series, "{:.3}\t{prefix}\t{verified}\t{event}", at - origin);
    }
    (measurement, series)
}

/// Each part's first tick reading `V`, for a run whose trace is missing.
fn tick_verifies(run: &Replay) -> Vec<(f64, u32)> {
    let mut seen = std::collections::BTreeSet::new();
    let mut verifies = Vec::new();
    for (at, map) in &run.ticks {
        for (part, letter) in (0_u32..).zip(map.chars()) {
            if letter == 'V' && seen.insert(part) {
                verifies.push((*at, part));
            }
        }
    }
    verifies
}

#[cfg(test)]
mod tests;
