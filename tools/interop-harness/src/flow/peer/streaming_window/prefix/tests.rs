//! The verified-prefix measurement over hand-built ticks and trace lines.

use rmule_primitives::ED2K_PART_SIZE;

use super::super::replay::Replay;
use super::{measure, traced_verifies};

const P: u64 = ED2K_PART_SIZE;

fn run(ticks: &[(f64, &str)]) -> Replay {
    Replay {
        ticks: ticks
            .iter()
            .map(|(at, map)| (*at, (*map).to_owned()))
            .collect(),
        ..Replay::default()
    }
}

/// The prefix counts verified parts from offset 0 only; a verified part past
/// a gap adds to the verified bytes and to the lag, not to the prefix. Times
/// run from the first tick with a part in flight; without a trace, each
/// part's first `V` times its verify.
#[test]
fn the_prefix_is_the_verified_run_from_offset_zero() {
    let ticks = run(&[
        (100.0, "MMMM"),
        (101.0, "IMMI"),
        (103.0, "IMMV"),
        (105.0, "VIMV"),
        (107.0, "VVVV"),
    ]);
    let (measurement, series) = measure(&ticks, &[], 4 * P);
    assert_eq!(measurement.first_part_in_flight_after_start_s, Some(1.0));
    assert_eq!(measurement.first_part_verified_s, Some(2.0));
    assert_eq!(measurement.prefix_quarter_s, Some(4.0));
    assert_eq!(measurement.prefix_half_s, Some(6.0));
    assert_eq!(measurement.prefix_whole_s, Some(6.0));
    // One part of lag from 2 s to 6 s, over the 6 s from the first in flight.
    assert_eq!(measurement.mean_prefix_lag_bytes, Some(4 * P / 6));
    assert!(series.contains(&format!("4.000\t{P}\t{}\tverify 0", 2 * P)));
}

/// The core's `part verified` lines time each verify to the microsecond and
/// outrank the ticks, which miss the last verify; another download's lines
/// are not read.
#[test]
fn the_trace_times_each_verify() {
    let trace = "\
2026-10-13T02:19:12.217174Z  INFO download{download_id=1}: rmule_core::download::persist: part verified download_id=1 part_index=1
2026-10-13T02:19:13.000000Z  INFO download{download_id=2}: rmule_core::download::persist: part verified download_id=2 part_index=0
2026-10-13T02:19:14.500000Z  INFO download{download_id=1}: rmule_core::download::persist: part verified download_id=1 part_index=0
";
    let traced = traced_verifies(trace, 1);
    assert_eq!(
        traced,
        vec![(1_791_857_952.217_174, 1), (1_791_857_954.5, 0)]
    );
    let ticks = run(&[(1_791_857_950.5, "II"), (1_791_857_953.5, "IV")]);
    let (measurement, _) = measure(&ticks, &traced, 2 * P);
    assert_eq!(measurement.prefix_whole_s, Some(4.0));
    assert_eq!(measurement.traced_verifies, 2);
}
