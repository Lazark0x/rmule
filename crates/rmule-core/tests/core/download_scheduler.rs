//! Part assignment across a download's peers: whole ED2K parts in index
//! order when every source holds every part, verified parts skipped on resume,
//! one part in flight per peer, the end-game race that hands a single
//! remaining part to every idle peer and clears the losers when one wins, the
//! Tail Race of a peer that delivered a part — and
//! the rank a peer's Advertised Parts are chosen by (ADR-0112): very rare
//! first, then the Preview Band, then the Streaming Window, then rarest.
use rmule_core::diagnostics::PartState;
use rmule_core::{Assignment, DownloadScheduler, Pace, PartOrder, PartPlan};
use rmule_peer::PartBitmap;
use rmule_primitives::{ED2K_PART_SIZE, Ipv4Endpoint, PeerEndpoint, part_count};

/// A rarest-first scheduler over `file_size` bytes, `verified` already done.
fn rarest(file_size: u64, verified: impl IntoIterator<Item = u32>) -> DownloadScheduler {
    DownloadScheduler::new(file_size, verified, PartOrder::Rarest)
}

/// What `peer`, holding every part of the scheduler's file as every other
/// source does, is handed: today's decision sequence.
fn take(scheduler: &mut DownloadScheduler, peer: PeerEndpoint) -> Option<PartPlan> {
    let parts = PartBitmap::all_present(scheduler.part_states().len() as u32);
    handed(scheduler.assign_next(peer, &parts, &[], 0, &()))
}

fn handed(assignment: Assignment) -> Option<PartPlan> {
    match assignment {
        Assignment::Fresh(plan) | Assignment::Raced(plan) => Some(plan),
        Assignment::Busy | Assignment::Nothing { .. } => None,
    }
}

#[test]
fn assigns_missing_whole_ed2k_parts_in_order() {
    let mut scheduler = rarest(ED2K_PART_SIZE * 2 + 1, []);
    let first_peer = peer(1);
    let second_peer = peer(2);

    let first = take(&mut scheduler, first_peer).unwrap();
    let second = take(&mut scheduler, second_peer).unwrap();

    assert_eq!(first.part_index, 0);
    assert_eq!(first.offset, 0);
    assert_eq!(first.len, ED2K_PART_SIZE);
    assert_eq!(second.part_index, 1);
    assert_eq!(second.offset, ED2K_PART_SIZE);
    assert_eq!(second.len, ED2K_PART_SIZE);
}

#[test]
fn excludes_already_verified_parts_from_resume() {
    let mut scheduler = rarest(ED2K_PART_SIZE * 2 + 1, [0]);

    let assignment = take(&mut scheduler, peer(1)).unwrap();

    assert_eq!(assignment.part_index, 1);
}

#[test]
fn races_remaining_part_across_idle_peers_when_no_fresh_part_remains() {
    // ADR-0026 (amended): when there are fewer missing parts than idle
    // peers, an extra peer races an already in-flight part instead of
    // sitting idle. First peer to deliver a verified copy wins, so a slow
    // or queue-stuck peer cannot stall a scarce-part download.
    let mut scheduler = rarest(ED2K_PART_SIZE, []);

    let first = take(&mut scheduler, peer(1)).unwrap();
    let second = take(&mut scheduler, peer(2)).unwrap();

    assert_eq!(first.part_index, 0);
    assert_eq!(
        second.part_index, 0,
        "the second idle peer races the only remaining part"
    );
}

#[test]
fn completing_a_raced_part_finishes_download_and_clears_losing_racers() {
    let mut scheduler = rarest(ED2K_PART_SIZE, []);
    let winner = peer(1);
    let loser = peer(2);
    take(&mut scheduler, winner).unwrap();
    take(&mut scheduler, loser).unwrap();

    scheduler.complete_verified(winner).unwrap();

    assert!(scheduler.is_complete(), "the only part is verified");
    // The losing racer was working an already-verified part: reporting its
    // later failure must be a no-op, never re-queue the verified part.
    assert!(scheduler.release_for_retry(loser).is_none());
    assert!(scheduler.is_complete());
}

#[test]
fn releasing_one_racer_keeps_the_part_covered_by_the_others() {
    let mut scheduler = rarest(ED2K_PART_SIZE, []);
    let a = peer(1);
    let b = peer(2);
    take(&mut scheduler, a).unwrap();
    take(&mut scheduler, b).unwrap();

    // `a` drops out, but `b` still races the part, so there is nothing to
    // reassign and the part is not back in the missing pool.
    assert!(scheduler.release_for_retry(a).is_none());
    assert!(!scheduler.is_complete());

    scheduler.complete_verified(b).unwrap();
    assert!(scheduler.is_complete());
}

#[test]
fn allows_only_one_in_flight_part_per_peer() {
    let mut scheduler = rarest(ED2K_PART_SIZE * 2, []);
    let source = peer(1);

    let first = take(&mut scheduler, source).unwrap();
    let second = take(&mut scheduler, source);

    assert_eq!(first.part_index, 0);
    assert!(second.is_none());
}

#[test]
fn reuses_peer_after_verified_part_is_completed() {
    let mut scheduler = rarest(ED2K_PART_SIZE * 2, []);
    let source = peer(1);

    let first = take(&mut scheduler, source).unwrap();
    scheduler.complete_verified(source).unwrap();
    let second = take(&mut scheduler, source).unwrap();

    assert_eq!(first.part_index, 0);
    assert_eq!(second.part_index, 1);
}

#[test]
fn releases_in_flight_part_after_peer_failure_for_reassignment() {
    let mut scheduler = rarest(ED2K_PART_SIZE, []);
    let failed = peer(1);
    let replacement = peer(2);

    let first = take(&mut scheduler, failed).unwrap();
    scheduler.release_for_retry(failed).unwrap();
    let second = take(&mut scheduler, replacement).unwrap();

    assert_eq!(first.part_index, 0);
    assert_eq!(second.part_index, 0);
}

#[test]
fn part_states_place_each_part_by_index_through_a_whole_download() {
    // Four parts, part 1 already verified from a previous session (ADR-0079:
    // a resumed part is Verified positionally, never merely "one of N done").
    let mut scheduler = rarest(ED2K_PART_SIZE * 3 + 1, [1]);
    assert_eq!(
        scheduler.part_states(),
        vec![
            PartState::Missing,
            PartState::Verified,
            PartState::Missing,
            PartState::Missing,
        ],
    );

    // Two peers take the two lowest unheld parts: 0 and 2 (1 is not tracked).
    let first = peer(1);
    let second = peer(2);
    take(&mut scheduler, first).unwrap();
    take(&mut scheduler, second).unwrap();
    assert_eq!(
        scheduler.part_states(),
        vec![
            PartState::InFlight,
            PartState::Verified,
            PartState::InFlight,
            PartState::Missing,
        ],
    );

    // A released part falls back to Missing at its own index, not at the end.
    scheduler.release_for_retry(first).unwrap();
    assert_eq!(scheduler.part_states()[0], PartState::Missing);

    // Completed: every index reads Verified, and the vector still spans the
    // whole file — the count of a finished download comes from this, so it
    // cannot report short.
    take(&mut scheduler, first).unwrap();
    scheduler.complete_verified(first).unwrap();
    scheduler.complete_verified(second).unwrap();
    let third = peer(3);
    take(&mut scheduler, third).unwrap();
    scheduler.complete_verified(third).unwrap();
    assert!(scheduler.is_complete());
    assert_eq!(scheduler.part_states(), vec![PartState::Verified; 4]);
}

/// Advertised Parts over `count` parts, holding `held`.
fn holding(count: u32, held: &[u32]) -> PartBitmap {
    let mut bytes = vec![0_u8; (count as usize).div_ceil(8)];
    for &part in held {
        bytes[(part / 8) as usize] |= 1 << (part % 8);
    }
    PartBitmap::decode(count, &bytes).unwrap()
}

/// The fresh parts successive peers, each advertising every part of a
/// `file_size`-byte file, are handed in turn under Part Frequency `frequency`
/// over `known` sources.
fn fresh_order(
    scheduler: &mut DownloadScheduler,
    file_size: u64,
    frequency: &[u32],
    known: u32,
) -> Vec<u32> {
    let parts = PartBitmap::all_present(part_count(file_size));
    (1..=u8::MAX)
        .map_while(
            |n| match scheduler.assign_next(peer(n), &parts, frequency, known, &()) {
                Assignment::Fresh(plan) => Some(plan.part_index),
                _ => None,
            },
        )
        .collect()
}

/// Very rare is `frequency ≤ max(1, m × n / 100)` (aMule `PartFile.cpp:1926-1939`)
/// and ranks first, ahead of the Preview Band: at 20 sources a part two hold
/// is very rare, at 19 it is not. The band of a file whose 1-byte last part is
/// short holds the last-but-one too.
#[test]
fn a_very_rare_part_goes_first_ahead_of_the_preview_band() {
    let size = 3 * ED2K_PART_SIZE + 1;
    let frequency = [3, 2, 3, 3];
    for (known, order) in [(20, vec![1, 0, 2, 3]), (19, vec![0, 2, 3, 1])] {
        let mut scheduler =
            DownloadScheduler::new(size, [], PartOrder::Streaming { window_parts: 0 });
        assert_eq!(
            fresh_order(&mut scheduler, size, &frequency, known),
            order,
            "{known} sources"
        );
    }
}

/// The band goes ahead of the window, the window fills from its anchor up
/// whatever the frequency, and past it the lower frequency wins, then the
/// lower index.
#[test]
fn the_band_beats_the_window_which_ascends_before_the_rarest() {
    let size = 6 * ED2K_PART_SIZE + ED2K_PART_SIZE / 2;
    let mut scheduler = DownloadScheduler::new(size, [], PartOrder::Streaming { window_parts: 3 });
    assert_eq!(
        fresh_order(&mut scheduler, size, &[5, 9, 4, 3, 8, 3, 5], 20),
        vec![0, 6, 1, 2, 3, 5, 4]
    );
}

/// A resumed run anchors its window at its lowest unverified part, and its
/// verified band members are no candidates.
#[test]
fn a_resumed_run_anchors_its_window_at_its_lowest_unverified_part() {
    let size = 6 * ED2K_PART_SIZE - 1;
    let mut scheduler =
        DownloadScheduler::new(size, [0, 1, 5], PartOrder::Streaming { window_parts: 2 });
    assert_eq!(
        fresh_order(&mut scheduler, size, &[0, 0, 9, 7, 5, 0], 20),
        vec![2, 3, 4]
    );
}

/// With no window the tuple is `(very rare, frequency, i)`.
#[test]
fn no_window_ranks_very_rare_then_frequency_then_index() {
    let size = 6 * ED2K_PART_SIZE - 1;
    let mut scheduler =
        DownloadScheduler::new(size, [0, 1, 5], PartOrder::Streaming { window_parts: 0 });
    assert_eq!(
        fresh_order(&mut scheduler, size, &[0, 0, 2, 7, 5, 0], 20),
        vec![2, 4, 3]
    );
}

/// A download outside Streaming Priority whose sources each hold every part
/// fills in index order, as before Advertised Parts were read.
#[test]
fn a_rarest_download_from_complete_sources_fills_in_index_order() {
    let size = 3 * ED2K_PART_SIZE + 1;
    let mut scheduler = rarest(size, []);
    assert_eq!(
        fresh_order(&mut scheduler, size, &[3, 3, 3, 3], 3),
        vec![0, 1, 2, 3]
    );
}

/// A peer is handed only parts its Advertised Parts hold — fresh or raced —
/// and says when it holds nothing the file lacks.
#[test]
fn a_peer_is_handed_only_parts_it_advertised() {
    let mut scheduler = rarest(2 * ED2K_PART_SIZE + 1, []);
    let every = holding(3, &[0, 1, 2]);
    let plan = |assignment: Assignment| handed(assignment).map(|plan| plan.part_index);

    assert_eq!(
        plan(scheduler.assign_next(peer(1), &every, &[], 0, &())),
        Some(0)
    );
    let last_only = scheduler.assign_next(peer(2), &holding(3, &[2]), &[], 0, &());
    assert!(matches!(last_only, Assignment::Fresh(plan) if plan.part_index == 2));
    assert_eq!(
        plan(scheduler.assign_next(peer(3), &every, &[], 0, &())),
        Some(1)
    );

    let racer = scheduler.assign_next(peer(4), &holding(3, &[1]), &[], 0, &());
    assert!(matches!(racer, Assignment::Raced(plan) if plan.part_index == 1));
    assert_eq!(
        scheduler.assign_next(peer(5), &holding(3, &[]), &[], 0, &()),
        Assignment::Nothing { lacked: false }
    );

    scheduler.complete_verified(peer(1)).unwrap();
    assert_eq!(
        scheduler.assign_next(peer(1), &every, &[], 0, &()),
        Assignment::Nothing { lacked: true },
        "a peer that delivered idles: the parts it holds are in flight"
    );
    assert_eq!(
        scheduler.assign_next(peer(6), &holding(3, &[0]), &[], 0, &()),
        Assignment::Nothing { lacked: false },
        "it holds only a verified part"
    );
}

fn peer(last_octet: u8) -> PeerEndpoint {
    PeerEndpoint::V4(Ipv4Endpoint::new(
        format!("127.0.0.{last_octet}").parse().unwrap(),
        4663,
    ))
}

/// Delivery Rates by peer, every part still whole to come.
struct Rates(Vec<(PeerEndpoint, u64)>);

impl Pace for Rates {
    fn rate(&self, peer: PeerEndpoint) -> Option<u64> {
        self.0
            .iter()
            .find(|(p, _)| *p == peer)
            .map(|(_, rate)| *rate)
    }
    fn remaining(&self, plan: &PartPlan) -> u64 {
        plan.len
    }
}

/// Three parts on `peer(1)`, `peer(2)` and `peer(3)`; `peer(1)` delivers its
/// part, and every part left is in flight.
fn tail(peers_on_last: &[u8]) -> DownloadScheduler {
    let mut scheduler = rarest(ED2K_PART_SIZE * 3, []);
    for n in 1..=3 {
        take(&mut scheduler, peer(n)).unwrap();
    }
    for &n in peers_on_last {
        let raced = scheduler.assign_next(peer(n), &holding(3, &[2]), &[], 0, &());
        assert!(matches!(raced, Assignment::Raced(plan) if plan.part_index == 2));
    }
    scheduler.complete_verified(peer(1)).unwrap();
    scheduler
}

fn every_part() -> PartBitmap {
    PartBitmap::all_present(3)
}

/// A finished peer races the in-flight part whose lone worker would finish
/// it last (ADR-0026 "Bounded racing"), and keeps its slot.
#[test]
fn a_finished_peer_races_the_part_that_would_finish_last() {
    let mut scheduler = tail(&[]);
    let rates = Rates(vec![
        (peer(1), 1_000_000),
        (peer(2), 100_000),
        (peer(3), 10_000),
    ]);
    let raced = scheduler.assign_next(peer(1), &every_part(), &[], 0, &rates);
    assert!(
        matches!(raced, Assignment::Raced(plan) if plan.part_index == 2),
        "{raced:?}"
    );
}

/// A part's lone worker faster than the finished peer keeps its part alone:
/// the finished peer has nothing it may race and gives its slot back.
#[test]
fn a_finished_peer_never_races_a_faster_worker() {
    let mut scheduler = tail(&[]);
    let rates = Rates(vec![
        (peer(1), 50_000),
        (peer(2), 100_000),
        (peer(3), 60_000),
    ]);
    assert_eq!(
        scheduler.assign_next(peer(1), &every_part(), &[], 0, &rates),
        Assignment::Nothing { lacked: true }
    );
}

/// A Tail Race never makes a part's third racer, and a finished peer whose
/// own rate is unmeasured races nothing.
#[test]
fn a_tail_race_joins_only_a_lone_worker_and_only_when_measured() {
    // `peer(4)` is a backup racer on part 2, the slowest.
    let mut scheduler = tail(&[4]);
    let rates = Rates(vec![
        (peer(1), 1_000_000),
        (peer(2), 100_000),
        (peer(3), 10_000),
    ]);
    let raced = scheduler.assign_next(peer(1), &every_part(), &[], 0, &rates);
    assert!(
        matches!(raced, Assignment::Raced(plan) if plan.part_index == 1),
        "part 2 already has two racers: {raced:?}"
    );

    let mut unmeasured = tail(&[]);
    assert_eq!(
        unmeasured.assign_next(peer(1), &every_part(), &[], 0, &()),
        Assignment::Nothing { lacked: true }
    );
}
