//! The rank replay over hand-built logs and statuses: each seed's first part,
//! the reading bounds, shared parts, retirements and the log format.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use rmule_primitives::ED2K_PART_SIZE;

use super::{LogEvent, Pick, Topology, parse_log, replay};

const A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
/// Six parts, the last one byte short: band `{0, 5}`.
const SIZE: u64 = 6 * ED2K_PART_SIZE - 1;

fn set(parts: &[u32]) -> BTreeSet<u32> {
    parts.iter().copied().collect()
}

/// A holds `{0, 1, 2, 3, 5}`, B `{0, 3, 4, 5}`: very rare are A's 1 and 2
/// and B's 4, and the band `{0, 5}` is held by both.
fn advertised() -> BTreeMap<Ipv4Addr, BTreeSet<u32>> {
    BTreeMap::from([(A, set(&[0, 1, 2, 3, 5])), (B, set(&[0, 3, 4, 5]))])
}

fn tick(at: f64) -> LogEvent {
    LogEvent::Tick {
        at,
        parts: String::new(),
    }
}

fn assigned(peer: Ipv4Addr, part: u32) -> LogEvent {
    LogEvent::Assigned { peer, part }
}

/// Both statuses read before the first assignment: each seed is first asked
/// for a part only it holds, ahead of the band; once its very rare parts are
/// gone, the band part inside the window comes before the one outside it.
#[test]
fn a_seed_is_first_asked_for_a_part_only_it_holds() {
    let advertised = advertised();
    let first_status_at = BTreeMap::from([(A, 1.0), (B, 1.1)]);
    let topology = Topology {
        size: SIZE,
        window_parts: 2,
        advertised: &advertised,
        first_status_at: &first_status_at,
    };
    let events = [
        tick(10.0),
        assigned(A, 1),
        assigned(B, 4),
        LogEvent::Verified { part: 4 },
        assigned(B, 0),
        tick(20.0),
    ];
    let run = replay(&events, &topology);
    let picks: Vec<(Pick, bool, bool, bool)> = run
        .decisions
        .iter()
        .map(|d| (d.actual, d.matched(), d.ambiguous(), d.very_rare))
        .collect();
    assert_eq!(
        picks,
        vec![
            (Pick::Fresh(1), true, false, true),
            (Pick::Fresh(4), true, false, true),
            (Pick::Fresh(0), true, false, false),
        ]
    );
    assert!(run.decisions[2].band && run.decisions[2].in_window);
}

/// B's status crossed the tap between the ticks around A's first
/// assignment: read, A's first part is its very rare 1; unread, every part of
/// A's is very rare and the band's 0 leads. Either is the rank, and the
/// decision says it is ambiguous; a part neither reading names is not.
#[test]
fn an_unknown_reading_is_tried_both_ways() {
    let advertised = advertised();
    let first_status_at = BTreeMap::from([(A, 1.0), (B, 10.2)]);
    let topology = Topology {
        size: SIZE,
        window_parts: 2,
        advertised: &advertised,
        first_status_at: &first_status_at,
    };
    let run = replay(&[tick(10.0), assigned(A, 0), tick(10.5)], &topology);
    assert!(run.decisions[0].matched() && run.decisions[0].ambiguous());
    assert_eq!(
        run.decisions[0].expected,
        BTreeSet::from([Pick::Fresh(0), Pick::Fresh(1)])
    );
    let run = replay(&[tick(10.0), assigned(A, 2), tick(10.5)], &topology);
    assert!(!run.decisions[0].matched());
}

/// `NoNeededParts` names what the seed still held that the file lacked: none
/// once every advertised part verified, the rest when it came early.
#[test]
fn a_retirement_records_what_the_seed_still_held() {
    let advertised = BTreeMap::from([(A, set(&[0, 1])), (B, set(&[0, 1, 2, 3, 4, 5]))]);
    let first_status_at = BTreeMap::from([(A, 1.0), (B, 1.0)]);
    let topology = Topology {
        size: SIZE,
        window_parts: 4,
        advertised: &advertised,
        first_status_at: &first_status_at,
    };
    let retired = |peer| LogEvent::Retired {
        peer,
        reason: "no_needed_parts".to_owned(),
    };
    let events = [
        tick(5.0),
        LogEvent::Verified { part: 0 },
        retired(A),
        LogEvent::Verified { part: 1 },
        retired(A),
        tick(6.0),
    ];
    let run = replay(&events, &topology);
    assert_eq!(run.retirements[0].lacked, set(&[1]));
    assert!(run.retirements[1].lacked.is_empty());
    assert_eq!(run.retirements[1].not_before, Some(5.0));
    assert_eq!(run.retirements[1].not_after, Some(6.0));
}

/// The replay reads the record codes rmule-tools prints and the tick line,
/// and drops another download's lines.
#[test]
fn the_log_reads_as_rmule_tools_prints_it() {
    let log = "\
download.peer_selected id=1 peer=10.0.0.2:4662
download.part_assigned id=1 peer=10.0.0.2:4662 part_index=3
download.part_assigned id=2 peer=10.0.0.2:4662 part_index=9
download.part_released id=1 peer=10.0.0.3:4662 part_index=0 reason=peer_retired retired=peer_disconnected
download.part_verified id=1 part_index=3
download.peer_retired id=1 peer=10.0.0.2:4662 reason=no_needed_parts
download.source_remote_queued id=1 peer=10.0.0.2:4662 rank=0
download parts_tick id=1 at_unix_ms=1500 parts=VIM
download.completed id=1
";
    assert_eq!(
        parse_log(log, 1),
        vec![
            assigned(A, 3),
            LogEvent::Released {
                peer: B,
                part: 0,
                retired: Some("peer_disconnected".to_owned())
            },
            LogEvent::Verified { part: 3 },
            LogEvent::Retired {
                peer: A,
                reason: "no_needed_parts".to_owned()
            },
            LogEvent::RemoteQueued { peer: A },
            LogEvent::Tick {
                at: 1.5,
                parts: "VIM".to_owned()
            },
            LogEvent::Completed,
        ]
    );
}

/// A seed whose link ended with no queue standing leaves the book, and its
/// parts leave Part Frequency: A's parts B also held turn very rare, and the
/// band's 0 leads again.
#[test]
fn a_departed_seed_stops_counting() {
    let advertised = advertised();
    let first_status_at = BTreeMap::from([(A, 1.0), (B, 1.1)]);
    let topology = Topology {
        size: SIZE,
        window_parts: 2,
        advertised: &advertised,
        first_status_at: &first_status_at,
    };
    let events = [
        tick(10.0),
        assigned(B, 4),
        LogEvent::Released {
            peer: B,
            part: 4,
            retired: Some("peer_disconnected".to_owned()),
        },
        assigned(A, 0),
        tick(20.0),
    ];
    let run = replay(&events, &topology);
    assert_eq!(run.decisions[1].expected, BTreeSet::from([Pick::Fresh(0)]));
    assert!(run.decisions[1].matched());
}

/// A seed may be handed a part another worker started when it ranks ahead
/// of every part nobody holds (ADR-0117: its unclaimed blocks are invisible
/// to the log), and the first part nobody holds — the band's last part here;
/// skipping part 1 for part 3 is not the rank's.
#[test]
fn a_seed_shares_a_started_part_ranked_ahead_of_every_untouched_one() {
    let every = set(&[0, 1, 2, 3, 4, 5]);
    let advertised = BTreeMap::from([(A, every.clone()), (B, every)]);
    let first_status_at = BTreeMap::from([(A, 1.0), (B, 1.1)]);
    let topology = Topology {
        size: SIZE,
        window_parts: 0,
        advertised: &advertised,
        first_status_at: &first_status_at,
    };
    let events = [
        tick(10.0),
        assigned(A, 0),
        assigned(B, 0),
        assigned(A, 5),
        assigned(B, 3),
        tick(20.0),
    ];
    let run = replay(&events, &topology);
    let picks: Vec<(Pick, bool)> = run
        .decisions
        .iter()
        .map(|d| (d.actual, d.matched()))
        .collect();
    assert_eq!(
        picks,
        vec![
            (Pick::Fresh(0), true),
            (Pick::Shared(0), true),
            (Pick::Fresh(5), true),
            (Pick::Fresh(3), false),
        ]
    );
}

/// The End Game's sets are read off the log as rmule-tools prints them.
#[test]
fn an_end_game_set_reads_off_the_log() {
    let log =
        "download.end_game_blocks id=1 peer=10.0.0.2:4662 part_index=4 blocks=3 bytes=552960\n";
    assert_eq!(
        parse_log(log, 1),
        vec![LogEvent::EndGame {
            peer: A,
            part: 4,
            blocks: 3,
            bytes: 552_960
        }]
    );
}

/// A part that fails its check with no root writes `part_corrupt` and no
/// `part_released`: its holders let it go there, so the next tick reads it
/// missing and the next worker on it starts it fresh.
#[test]
fn a_corrupt_part_is_let_go_at_its_part_corrupt_record() {
    let every = set(&[0, 1, 2, 3, 4, 5]);
    let advertised = BTreeMap::from([(A, every.clone()), (B, every)]);
    let first_status_at = BTreeMap::from([(A, 1.0), (B, 1.1)]);
    let topology = Topology {
        size: SIZE,
        window_parts: 0,
        advertised: &advertised,
        first_status_at: &first_status_at,
    };
    let log = "download parts_tick id=1 at_unix_ms=10000 parts=MMMMMM\n\
               download.part_assigned id=1 peer=10.0.0.2:4662 part_index=0\n\
               download.part_assigned id=1 peer=10.0.0.3:4662 part_index=0\n\
               download.part_corrupt id=1 part_index=0 writers=2 named=0\n\
               download parts_tick id=1 at_unix_ms=20000 parts=MMMMMM\n\
               download.part_assigned id=1 peer=10.0.0.3:4662 part_index=0\n";
    let run = replay(&parse_log(log, 1), &topology);
    assert_eq!(run.tick_mismatches, 0);
    assert_eq!(run.decisions.last().map(|d| d.actual), Some(Pick::Fresh(0)));
}
