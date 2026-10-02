//! Part assignment across a download's peers: whole ED2K parts in index
//! order, verified parts skipped on resume, one part in flight per peer, and
//! the end-game race that hands a single remaining part to every idle peer
//! and clears the losers when one wins.
use rmule_core::DownloadScheduler;
use rmule_core::diagnostics::PartState;
use rmule_primitives::{ED2K_PART_SIZE, Ipv4Endpoint, PeerEndpoint};

#[test]
fn assigns_missing_whole_ed2k_parts_in_order() {
    let mut scheduler = DownloadScheduler::new(ED2K_PART_SIZE * 2 + 1, []);
    let first_peer = peer(1);
    let second_peer = peer(2);

    let first = scheduler.assign_next(first_peer).unwrap();
    let second = scheduler.assign_next(second_peer).unwrap();

    assert_eq!(first.part_index, 0);
    assert_eq!(first.offset, 0);
    assert_eq!(first.len, ED2K_PART_SIZE);
    assert_eq!(second.part_index, 1);
    assert_eq!(second.offset, ED2K_PART_SIZE);
    assert_eq!(second.len, ED2K_PART_SIZE);
}

#[test]
fn excludes_already_verified_parts_from_resume() {
    let mut scheduler = DownloadScheduler::new(ED2K_PART_SIZE * 2 + 1, [0]);

    let assignment = scheduler.assign_next(peer(1)).unwrap();

    assert_eq!(assignment.part_index, 1);
}

#[test]
fn races_remaining_part_across_idle_peers_when_no_fresh_part_remains() {
    // ADR-0026 (amended): when there are fewer missing parts than idle
    // peers, an extra peer races an already in-flight part instead of
    // sitting idle. First peer to deliver a verified copy wins, so a slow
    // or queue-stuck peer cannot stall a scarce-part download.
    let mut scheduler = DownloadScheduler::new(ED2K_PART_SIZE, []);

    let first = scheduler.assign_next(peer(1)).unwrap();
    let second = scheduler.assign_next(peer(2)).unwrap();

    assert_eq!(first.part_index, 0);
    assert_eq!(
        second.part_index, 0,
        "the second idle peer races the only remaining part"
    );
}

#[test]
fn completing_a_raced_part_finishes_download_and_clears_losing_racers() {
    let mut scheduler = DownloadScheduler::new(ED2K_PART_SIZE, []);
    let winner = peer(1);
    let loser = peer(2);
    scheduler.assign_next(winner).unwrap();
    scheduler.assign_next(loser).unwrap();

    scheduler.complete_verified(winner).unwrap();

    assert!(scheduler.is_complete(), "the only part is verified");
    // The losing racer was working an already-verified part: reporting its
    // later failure must be a no-op, never re-queue the verified part.
    assert!(scheduler.release_for_retry(loser).is_none());
    assert!(scheduler.is_complete());
}

#[test]
fn releasing_one_racer_keeps_the_part_covered_by_the_others() {
    let mut scheduler = DownloadScheduler::new(ED2K_PART_SIZE, []);
    let a = peer(1);
    let b = peer(2);
    scheduler.assign_next(a).unwrap();
    scheduler.assign_next(b).unwrap();

    // `a` drops out, but `b` still races the part, so there is nothing to
    // reassign and the part is not back in the missing pool.
    assert!(scheduler.release_for_retry(a).is_none());
    assert!(!scheduler.is_complete());

    scheduler.complete_verified(b).unwrap();
    assert!(scheduler.is_complete());
}

#[test]
fn allows_only_one_in_flight_part_per_peer() {
    let mut scheduler = DownloadScheduler::new(ED2K_PART_SIZE * 2, []);
    let source = peer(1);

    let first = scheduler.assign_next(source).unwrap();
    let second = scheduler.assign_next(source);

    assert_eq!(first.part_index, 0);
    assert!(second.is_none());
}

#[test]
fn reuses_peer_after_verified_part_is_completed() {
    let mut scheduler = DownloadScheduler::new(ED2K_PART_SIZE * 2, []);
    let source = peer(1);

    let first = scheduler.assign_next(source).unwrap();
    scheduler.complete_verified(source).unwrap();
    let second = scheduler.assign_next(source).unwrap();

    assert_eq!(first.part_index, 0);
    assert_eq!(second.part_index, 1);
}

#[test]
fn releases_in_flight_part_after_peer_failure_for_reassignment() {
    let mut scheduler = DownloadScheduler::new(ED2K_PART_SIZE, []);
    let failed = peer(1);
    let replacement = peer(2);

    let first = scheduler.assign_next(failed).unwrap();
    scheduler.release_for_retry(failed).unwrap();
    let second = scheduler.assign_next(replacement).unwrap();

    assert_eq!(first.part_index, 0);
    assert_eq!(second.part_index, 0);
}

#[test]
fn part_states_place_each_part_by_index_through_a_whole_download() {
    // Four parts, part 1 already verified from a previous session (ADR-0079:
    // a resumed part is Verified positionally, never merely "one of N done").
    let mut scheduler = DownloadScheduler::new(ED2K_PART_SIZE * 3 + 1, [1]);
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
    scheduler.assign_next(first).unwrap();
    scheduler.assign_next(second).unwrap();
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
    scheduler.assign_next(first).unwrap();
    scheduler.complete_verified(first).unwrap();
    scheduler.complete_verified(second).unwrap();
    let third = peer(3);
    scheduler.assign_next(third).unwrap();
    scheduler.complete_verified(third).unwrap();
    assert!(scheduler.is_complete());
    assert_eq!(scheduler.part_states(), vec![PartState::Verified; 4]);
}

fn peer(last_octet: u8) -> PeerEndpoint {
    PeerEndpoint::V4(Ipv4Endpoint::new(
        format!("127.0.0.{last_octet}").parse().unwrap(),
        4663,
    ))
}
