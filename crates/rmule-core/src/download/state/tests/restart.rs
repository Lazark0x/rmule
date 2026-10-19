//! What a restart resumes (ADR-0117 §4): nothing new persists, so the block
//! set rebuilds from the verified parts the store holds — every block of every
//! other part missing, on the same grid a first run cuts — and a verified part
//! is never asked again.

use super::*;
use rmule_primitives::{ED2K_PART_SIZE, EMBLOCKSIZE as B};

/// Three parts, the last a short tail.
const THREE_PARTS: u64 = 2 * ED2K_PART_SIZE + 1_000;

/// A one-worker run of [`THREE_PARTS`] with `verified` already done, its
/// worker granted and asking room for the whole file; the blocks it is handed.
fn handed_from_the_start(verified: Vec<u32>) -> (DownloadState, Vec<(u32, u64, u64)>) {
    let mut state = pooled_state(
        set_held_content(THREE_PARTS, verified),
        &[peer(1)],
        QUIET_POSTURE,
        1,
    );
    let _ = state.start(t0());
    let mut decisions = connect(&mut state, t0(), peer(1));
    decisions.extend(state.on_worker_event(
        t0(),
        peer(1),
        PeerWorkerEvent::BlocksWanted {
            room: u32::MAX,
            drained: false,
            handout: 1,
        },
    ));
    let handed = sent(&decisions)
        .into_iter()
        .flat_map(|(_, command)| match command {
            PeerWorkerCommand::RequestBlocks { blocks, .. } => blocks,
            _ => Vec::new(),
        })
        .map(|block| (block.part_index, block.start, block.end))
        .collect();
    (state, handed)
}

#[test]
fn a_restart_resumes_every_block_of_each_unverified_part_and_none_of_a_verified_one() {
    // The first run: part 1 verifies, part 0 gets two blocks in, part 2 none.
    let (mut first, every_block) = handed_from_the_start(Vec::new());
    let part_1 = crate::planning::part_plan(THREE_PARTS, 1);
    let _ = first.on_worker_event(
        t0(),
        peer(1),
        PeerWorkerEvent::BlockReceived {
            part_index: 1,
            offset: part_1.offset,
            bytes: vec![0x5A; part_1.len as usize],
        },
    );
    let _ = first.on_persist_result(t0(), 1, peer(1), Ok(()));
    let _ = first.on_worker_event(
        t0(),
        peer(1),
        PeerWorkerEvent::BlockReceived {
            part_index: 0,
            offset: 0,
            bytes: vec![0x5A; 2 * B as usize],
        },
    );

    // The restart reads the store: part 1 verified, nothing else.
    let (_, resumed) = handed_from_the_start(vec![1]);
    let expected: Vec<(u32, u64, u64)> = every_block
        .into_iter()
        .filter(|&(part, _, _)| part != 1)
        .collect();
    assert_eq!(
        resumed, expected,
        "the missing blocks of parts 0 and 2, part 0's arrived ones among them, on the first run's grid"
    );
    assert!(resumed.iter().all(|&(part, _, _)| part != 1));
    assert_eq!(resumed.first(), Some(&(0, 0, B)));
}
