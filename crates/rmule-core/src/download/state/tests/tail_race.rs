//! The Tail Race (ADR-0026 "Bounded racing"): a granted worker that delivered
//! a part, measured faster than the lone worker of an in-flight part, races
//! that part instead of giving its slot back, and the race's loser opens no
//! buffer for a part already assembled.

use std::time::Duration;

use super::*;

const PART: u64 = rmule_primitives::ED2K_PART_SIZE;

/// `peer(1)` on part 0 and `peer(2)` on part 1 of a two-part download.
fn racing_pair() -> DownloadState {
    let mut state = pooled_state(
        set_held_content(2 * PART, Vec::new()),
        &[peer(1), peer(2)],
        QUIET_POSTURE,
        2,
    );
    let _ = state.start(t0());
    let _ = connect(&mut state, t0(), peer(1));
    let _ = connect(&mut state, t0(), peer(2));
    state
}

/// `peer` delivers `len` bytes of `part_index` from `from` at `at`.
fn block(
    state: &mut DownloadState,
    at: Instant,
    peer: PeerEndpoint,
    part_index: u32,
    from: u64,
    len: u64,
) -> Vec<Decision> {
    state.on_worker_event(
        at,
        peer,
        PeerWorkerEvent::BlockReceived {
            part_index,
            offset: u64::from(part_index) * PART + from,
            bytes: vec![0u8; len as usize],
        },
    )
}

/// `peer(2)` trickles part 1 at 10 kB/s while `peer(1)` delivers part 0 at
/// about 4.8 MB/s; part 0 verifies at two seconds. Returns the decisions of
/// that verification.
fn fast_finisher_verifies(state: &mut DownloadState) -> Vec<Decision> {
    let second = Duration::from_secs(1);
    for tick in 0..=2u32 {
        let at = t0() + second * tick;
        let _ = block(state, at, peer(2), 1, u64::from(tick) * 10_000, 10_000);
    }
    let _ = block(state, t0(), peer(1), 0, 0, 100_000);
    let _ = block(state, t0() + second, peer(1), 0, 100_000, 4_800_000);
    let _ = block(
        state,
        t0() + 2 * second,
        peer(1),
        0,
        4_900_000,
        PART - 4_900_000,
    );
    state.on_persist_result(t0() + 2 * second, 0, peer(1), Ok(()))
}

#[test]
fn a_finished_worker_races_the_slower_lone_part_and_keeps_its_slot() {
    let mut state = racing_pair();
    let verified = fast_finisher_verifies(&mut state);
    assert_eq!(
        sent(&verified),
        vec![(
            peer(1),
            PeerWorkerCommand::RequestPart {
                plan: crate::planning::part_plan(2 * PART, 1),
                resume_offset: PART + 30_000,
            }
        )],
        "it joins part 1 at its assembled prefix: {verified:?}"
    );
    assert!(
        !verified
            .iter()
            .any(|d| matches!(d, Decision::EndWorker { .. })),
        "no slot goes back: {verified:?}"
    );
}

#[test]
fn the_losers_late_bytes_open_no_buffer_for_a_part_already_assembled() {
    let mut state = racing_pair();
    let _ = fast_finisher_verifies(&mut state);
    let at = t0() + Duration::from_secs(3);
    let _ = block(&mut state, at, peer(1), 1, 30_000, PART - 30_000);
    let _ = state.on_persist_result(at, 1, peer(1), Ok(()));
    let late = block(&mut state, at, peer(2), 1, 30_000, 10_000);
    assert!(
        !late
            .iter()
            .any(|d| matches!(d, Decision::PersistPart { .. })),
        "{late:?}"
    );
    assert!(state.assembly.is_empty(), "a verified part keeps no buffer");
}
