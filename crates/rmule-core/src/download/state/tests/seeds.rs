//! The run's **Source Seeds** ranking (ADR-0109): bytes, then a rank, then
//! merely held; a peer whose dial failed and that earned nothing is no seed;
//! and the one report of how many seed dials answered.

use super::*;
use crate::download::source_seeds::SeedRank;

#[test]
fn the_ranking_puts_bytes_before_a_rank_before_held_and_drops_a_failed_dial() {
    let mut state = pooled_state(
        file_hash_only_content(ONE_PART),
        &[peer(1), peer(2), peer(3), peer(4)],
        QUIET_POSTURE,
        2,
    );
    assert_eq!(spawned(&state.start(t0())), [peer(1), peer(2)]);
    // Peer 1 never starts: spent, and the refill dials peer 3.
    assert_eq!(spawned(&state.on_spawn_failed(t0(), peer(1))), [peer(3)]);
    connect(&mut state, t0(), peer(2));
    state.on_worker_event(t0(), peer(2), PeerWorkerEvent::Queued { rank: 7 });
    connect(&mut state, t0(), peer(3));
    state.on_worker_event(
        t0(),
        peer(3),
        PeerWorkerEvent::BlockReceived {
            part_index: 0,
            offset: 0,
            bytes: vec![0x5A; 16],
        },
    );
    let ranking: Vec<_> = state
        .source_seeds()
        .into_iter()
        .map(|seed| (seed.endpoint, seed.rank))
        .collect();
    assert_eq!(
        ranking,
        [
            (peer(3), SeedRank::Received),
            (peer(2), SeedRank::Ranked),
            (peer(4), SeedRank::Known),
        ]
    );
}

/// A pause before every seed dial settles still reports them, and ahead of
/// the run's end: the runner enacts nothing past a `Fail`.
#[test]
fn a_pause_before_the_seeds_settle_reports_them_ahead_of_the_end() {
    let seeds = [peer(1), peer(2)];
    let mut state = state_from(
        file_hash_only_content(ONE_PART),
        QUIET_POSTURE,
        2,
        StartingFacts {
            seeds_written: 3,
            ..no_facts()
        },
        vec![(Channel::Seed, plain_sightings(&seeds))],
        Vec::new(),
    );
    let _ = state.start(t0());
    let _ = connect(&mut state, t0(), peer(1));
    let identified =
        state.on_worker_event(t0(), peer(1), identified(UserHash::from_bytes([0x5A; 16])));
    assert!(
        !identified
            .iter()
            .any(|decision| matches!(decision, Decision::Emit(DownloadEvent::SeedsDialled { .. }))),
        "peer 2 has not settled"
    );
    let stopped = state.on_stop(DownloadFailure::Paused);
    let report = stopped
        .iter()
        .position(|decision| {
            matches!(
                decision,
                Decision::Emit(DownloadEvent::SeedsDialled {
                    written: 3,
                    dialled: 2,
                    answered: 1,
                    ..
                })
            )
        })
        .expect("the stop reports the dials");
    let end = stopped
        .iter()
        .position(|decision| matches!(decision, Decision::Fail(_)))
        .unwrap();
    assert!(report < end);
}
