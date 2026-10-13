use rmule_primitives::ED2K_PART_SIZE;

use super::super::replay::Replay;
use super::measure;

const P: u64 = ED2K_PART_SIZE;

/// The prefix counts verified parts from offset 0 only; a verified part past
/// a gap adds to the verified bytes and to the lag, not to the prefix. Times
/// run from the first tick with a part in flight.
#[test]
fn the_prefix_is_the_verified_run_from_offset_zero() {
    let ticks = [
        (100.0, "MMMM"),
        (101.0, "IMMI"),
        (103.0, "IMMV"),
        (105.0, "VIMV"),
        (107.0, "VVVV"),
    ];
    let run = Replay {
        ticks: ticks
            .iter()
            .map(|(at, map)| (*at, (*map).to_owned()))
            .collect(),
        ..Replay::default()
    };
    let (measurement, series) = measure(&run, 4 * P);
    assert_eq!(measurement.first_part_in_flight_after_start_s, Some(1.0));
    assert_eq!(measurement.first_part_verified_s, Some(2.0));
    assert_eq!(measurement.prefix_quarter_s, Some(4.0));
    assert_eq!(measurement.prefix_half_s, Some(6.0));
    assert_eq!(measurement.prefix_whole_s, Some(6.0));
    // Lag over the four ticks from the first in flight: 0, P, P, 0.
    assert_eq!(measurement.mean_prefix_lag_bytes, Some(P / 2));
    assert!(series.contains(&format!("4.000\t{P}\t{}\tVIMV", 2 * P)));
}
