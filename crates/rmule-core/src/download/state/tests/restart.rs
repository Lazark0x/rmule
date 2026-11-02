//! What a restart resumes (ADR-0117 §4): the block set rebuilds from the
//! verified parts the store holds and the **Arrived Checkpoint** — every byte
//! neither claims missing, on the same grid a first run cuts — a verified part
//! is never asked again, and a resumed part is an in-flight one.

use rmule_peer::PartIndex;

use super::*;
use crate::assembly::{ArrivedPart, ArrivedWriter};
use rmule_primitives::{ED2K_PART_SIZE, EMBLOCKSIZE as B};

/// Three parts, the last a short tail.
const THREE_PARTS: u64 = 2 * ED2K_PART_SIZE + 1_000;

/// A one-worker run of [`THREE_PARTS`] with `verified` already done, its
/// worker granted and asking room for the whole file; the blocks it is handed.
fn handed_from_the_start(verified: Vec<u32>) -> (DownloadState, Vec<(u32, u64, u64)>) {
    handed_resuming(verified, Vec::new())
}

/// [`handed_from_the_start`], starting from the checkpoint `arrived`.
fn handed_resuming(
    verified: Vec<u32>,
    arrived: Vec<ArrivedPart>,
) -> (DownloadState, Vec<(u32, u64, u64)>) {
    let content = ContentFacts {
        arrived,
        ..set_held_content(THREE_PARTS, verified)
    };
    let mut state = pooled_state(content, &[peer(1)], QUIET_POSTURE, 1);
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
        .map(|block| (block.part_index.value(), block.start, block.end))
        .collect();
    (state, handed)
}

#[test]
fn a_restart_resumes_every_block_of_each_unverified_part_and_none_of_a_verified_one() {
    // The first run: part 1 verifies, part 0 gets two blocks in, part 2 none.
    let (mut first, every_block) = handed_from_the_start(Vec::new());
    let part_1 = crate::planning::part_plan(THREE_PARTS, PartIndex::new(1));
    let _ = first.on_worker_event(
        t0(),
        peer(1),
        PeerWorkerEvent::BlockReceived {
            part_index: PartIndex::new(1),
            offset: part_1.offset,
            bytes: vec![0x5A; part_1.len as usize],
        },
    );
    let _ = first.on_persist_result(t0(), PartIndex::new(1), Some(peer(1)), Ok(()), None);
    let _ = first.on_worker_event(
        t0(),
        peer(1),
        PeerWorkerEvent::BlockReceived {
            part_index: PartIndex::new(0),
            offset: 0,
            bytes: vec![0x5A; 2 * B as usize],
        },
    );

    // A restart that found no checkpoint: part 1 verified, nothing else. The
    // first run's two blocks count as absent, whatever the file holds.
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

/// A row of `part` claiming `ranges`, written by `writer`.
fn row(part: u32, ranges: Vec<(u64, u64)>, writer: PeerEndpoint) -> ArrivedPart {
    ArrivedPart {
        part_index: PartIndex::new(part),
        ranges,
        writers: vec![ArrivedWriter {
            endpoint: writer,
            user_hash: Some(UserHash::from_bytes([9; UserHash::BYTE_LEN])),
        }],
        cells: vec![vec![0]; 53],
    }
}

/// What a checkpoint claims is not asked again, and what it does not claim is,
/// on the first run's grid.
#[test]
fn a_resumed_run_asks_only_what_its_checkpoint_does_not_claim() {
    let (_, every_block) = handed_from_the_start(Vec::new());
    let (_, resumed) = handed_resuming(Vec::new(), vec![row(0, vec![(0, 2 * B + 7)], peer(9))]);
    let expected: Vec<(u32, u64, u64)> = every_block
        .into_iter()
        .filter(|&(_, start, _)| start >= 2 * B)
        .map(|(part, start, end)| (part, start.max(2 * B + 7), end))
        .collect();
    assert_eq!(
        resumed, expected,
        "off the grid exactly where the claim ends"
    );
}

/// A checkpoint row of a part a later run verified is no claim.
#[test]
fn a_row_of_a_verified_part_claims_nothing() {
    let (state, handed) = handed_resuming(vec![0], vec![row(0, vec![(0, B)], peer(9))]);
    assert!(handed.iter().all(|&(part, _, _)| part != 0));
    assert!(state.assembly.is_empty());
}

/// A part the checkpoint covers goes to its check before any worker: it stood
/// on the lane as the last run ended. No peer completed it.
#[test]
fn a_part_the_checkpoint_covers_goes_straight_to_its_check() {
    let part = crate::planning::part_plan(THREE_PARTS, PartIndex::new(1));
    let content = ContentFacts {
        arrived: vec![row(1, vec![(part.offset, part.end())], peer(9))],
        ..set_held_content(THREE_PARTS, Vec::new())
    };
    let mut state = pooled_state(content, &[peer(1)], QUIET_POSTURE, 1);
    let decisions = state.start(t0());
    assert!(
        decisions.iter().any(|d| matches!(
            d,
            Decision::PersistPart { part_index, peer: None, offset, len, .. }
                if part_index.value() == 1 && *offset == part.offset && *len == part.len
        )),
        "{decisions:?}"
    );
}

/// A resumed part's writers are the row's: a whole part one writer sent
/// names it after a restart, by the User Hash it wrote under, though it is
/// no longer connected.
#[test]
fn a_resumed_part_that_fails_names_the_writer_its_row_kept() {
    let part = crate::planning::part_plan(THREE_PARTS, PartIndex::new(1));
    let content = ContentFacts {
        arrived: vec![row(1, vec![(part.offset, part.end())], peer(9))],
        ..set_held_content(THREE_PARTS, Vec::new())
    };
    let mut state = pooled_state(content, &[peer(1)], QUIET_POSTURE, 1);
    let _ = state.start(t0());

    let failed = state.on_persist_result(
        t0(),
        PartIndex::new(1),
        None,
        Err(DownloadFailure::PartVerificationFailed),
        Some(vec![[0; 20]; part.cells()]),
    );
    assert!(
        failed.iter().any(|d| matches!(
            d,
            Decision::DistrustPeer { user_hash }
                if *user_hash == UserHash::from_bytes([9; UserHash::BYTE_LEN])
        )),
        "{failed:?}"
    );
}

/// A checkpoint takes what moved, and a part that failed says it holds nothing:
/// the row that claimed its bad bytes goes.
#[test]
fn a_checkpoint_takes_what_moved_and_a_failed_part_clears_its_row() {
    let part = crate::planning::part_plan(THREE_PARTS, PartIndex::new(0));
    let mut state = pooled_state(
        set_held_content(THREE_PARTS, Vec::new()),
        &[peer(1)],
        QUIET_POSTURE,
        1,
    );
    let _ = state.start(t0());
    let _ = connect(&mut state, t0(), peer(1));
    let _ = state.on_worker_event(
        t0(),
        peer(1),
        PeerWorkerEvent::BlockReceived {
            part_index: PartIndex::new(0),
            offset: 0,
            bytes: vec![1; B as usize],
        },
    );
    let rows = state.take_checkpoint();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].ranges, vec![(0, B)]);
    assert!(state.take_checkpoint().is_empty(), "nothing moved since");

    let _ = state.on_worker_event(
        t0(),
        peer(1),
        PeerWorkerEvent::BlockReceived {
            part_index: PartIndex::new(0),
            offset: B,
            bytes: vec![1; (part.len - B) as usize],
        },
    );
    let _ = state.on_persist_result(
        t0(),
        PartIndex::new(0),
        Some(peer(1)),
        Err(DownloadFailure::PartVerificationFailed),
        Some(vec![[0; 20]; part.cells()]),
    );
    assert_eq!(
        state.take_checkpoint(),
        vec![ArrivedPart::none(PartIndex::new(0))]
    );
}
