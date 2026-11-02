//! A part that fails its check with no Trusted AICH Root (ADR-0117 §1): the
//! workers that shared it keep their slots, the writer both failures point to
//! is set aside from the part and the verified part proves it, an honest
//! writer never leaves with a bad one, and a part whose recovery ask is never
//! answered is fetched again rather than stranded.

use std::cell::RefCell;

use rmule_peer::PartIndex;

use super::*;
use crate::assembly::CellHash;
use rmule_primitives::EMBLOCKSIZE as B;

/// A one-part file of nine cells: each of three workers is handed three at
/// its grant.
const NINE_CELLS: u64 = 9 * B;

/// The User Hash `peer(n)`'s hello names.
fn hash_of(n: u8) -> UserHash {
    UserHash::from_bytes([n; UserHash::BYTE_LEN])
}

/// The file's true bytes `start..end`, the first one flipped when `bad`.
fn bytes_of(start: u64, end: u64, bad: bool) -> Vec<u8> {
    let mut bytes: Vec<u8> = (start..end).map(|at| (at % 251) as u8).collect();
    if bad {
        bytes[0] ^= 0xFF;
    }
    bytes
}

thread_local! {
    /// The part file these brains write: what the lane would read back.
    static FILE: RefCell<Vec<u8>> = RefCell::new(vec![0; NINE_CELLS as usize]);
}

/// Each cell's hash as the lane would read it from the file.
fn file_cells() -> Vec<CellHash> {
    FILE.with_borrow(|file| {
        file.chunks(B as usize)
            .map(rmule_primitives::aich_block_hash)
            .collect()
    })
}

/// `from` delivers `start..end` of part 0, corrupt when `bad`; what is new
/// reaches the file.
fn deliver(
    state: &mut DownloadState,
    from: PeerEndpoint,
    (start, end): (u64, u64),
    bad: bool,
) -> Vec<Decision> {
    let decisions = state.on_worker_event(
        t0(),
        from,
        PeerWorkerEvent::BlockReceived {
            part_index: PartIndex::new(0),
            offset: start,
            bytes: bytes_of(start, end, bad),
        },
    );
    FILE.with_borrow_mut(|file| {
        for decision in &decisions {
            if let Decision::WriteBytes { offset, bytes } = decision {
                let at = *offset as usize;
                file[at..at + bytes.len()].copy_from_slice(bytes);
            }
        }
    });
    decisions
}

/// A started download of `size` bytes from `peer(1..=writers)`, each
/// identified by its own User Hash and granted, under `content`.
fn writers_of(content: ContentFacts, writers: u8) -> DownloadState {
    let pool: Vec<PeerEndpoint> = (1..=writers).map(peer).collect();
    let mut state = pooled_state(content, &pool, QUIET_POSTURE, pool.len());
    let _ = state.start(t0());
    for n in 1..=writers {
        let _ = state.on_worker_event(t0(), peer(n), identified(hash_of(n)));
        let _ = connect(&mut state, t0(), peer(n));
    }
    state
}

/// The nine-cell file's first attempt: `peer(1)` writes cells 0-2, `peer(2)`
/// cells 3-5 and `peer(3)` cells 6-8, each its grant's handout, and the
/// part fails its check.
fn first_attempt_fails(state: &mut DownloadState, bad: &[PeerEndpoint]) -> Vec<Decision> {
    for (n, first) in [(1, 0), (2, 3), (3, 6)] {
        for cell in first..first + 3 {
            let _ = deliver(
                state,
                peer(n),
                (cell * B, (cell + 1) * B),
                bad.contains(&peer(n)),
            );
        }
    }
    state.on_persist_result(
        t0(),
        PartIndex::new(0),
        Some(peer(3)),
        Err(DownloadFailure::PartVerificationFailed),
        Some(file_cells()),
    )
}

/// The workers in `workers` ask for room in turn and deliver what they are
/// handed — corrupt from those in `bad` — until the part is whole; the
/// decisions, and each worker's cells, in the order it was handed them.
fn refetch(
    state: &mut DownloadState,
    workers: &[PeerEndpoint],
    bad: &[PeerEndpoint],
) -> (Vec<Decision>, Vec<(PeerEndpoint, Vec<u64>)>) {
    let mut out = Vec::new();
    let mut cells: Vec<(PeerEndpoint, Vec<u64>)> =
        workers.iter().map(|&w| (w, Vec::new())).collect();
    for _ in 0..9 {
        for (worker, taken) in &mut cells {
            let handout = state.handouts.get(worker).copied().unwrap_or(0);
            let wanted = state.on_worker_event(
                t0(),
                *worker,
                PeerWorkerEvent::BlocksWanted {
                    room: 3,
                    drained: true,
                    handout,
                },
            );
            for (to, command) in sent(&wanted) {
                let PeerWorkerCommand::RequestBlocks { blocks, .. } = command else {
                    continue;
                };
                assert_eq!(to, *worker);
                for block in blocks {
                    taken.push(block.start / B);
                    out.extend(deliver(
                        state,
                        to,
                        (block.start, block.end),
                        bad.contains(&to),
                    ));
                }
            }
            out.extend(wanted);
            if out
                .iter()
                .any(|d| matches!(d, Decision::PersistPart { .. }))
            {
                return (out, cells);
            }
        }
    }
    panic!("the part never completed: {out:?}");
}

/// Whether `decisions` retire `at` for bad data.
fn retired_for_bad_data(decisions: &[Decision], at: PeerEndpoint) -> bool {
    decisions.iter().any(|d| {
        matches!(
            d,
            Decision::Emit(DownloadEvent::PeerRetired {
                peer: p,
                reason: PeerRetirementReason::PartVerificationFailed,
                ..
            }) if *p == at
        )
    })
}

/// Three workers share a part and it fails its check with no root: nothing
/// names the bad cell's sender, so nobody is retired. Every worker keeps its
/// slot, and the part is fetched again.
#[test]
fn a_shared_part_failing_with_no_root_keeps_every_workers_slot() {
    let mut state = writers_of(file_hash_only_content(NINE_CELLS), 3);
    let failed = first_attempt_fails(&mut state, &[peer(1)]);
    for n in 1..=3 {
        assert!(!retired_for_bad_data(&failed, peer(n)), "{failed:?}");
        assert!(
            state.worker_slots.contains_key(&peer(n)),
            "peer {n} keeps its slot"
        );
    }
    assert!(
        !failed
            .iter()
            .any(|d| matches!(d, Decision::DistrustPeer { .. })),
        "{failed:?}"
    );
    let (again, _) = refetch(&mut state, &[peer(1), peer(2), peer(3)], &[]);
    assert!(
        again.iter().any(
            |d| matches!(d, Decision::PersistPart { part_index, .. } if part_index.value() == 0)
        ),
        "{again:?}"
    );
}

/// `peer(1)` corrupts every cell it sends. The first failure moves nobody;
/// the refetch asks each worker for cells it did not write; the second
/// failure points to `peer(1)` alone, which sets it aside from the part and
/// nothing more; and once the others' third attempt verifies, its corrupt
/// cells prove it, and with no good bytes it is convicted.
#[test]
fn a_writer_both_failures_point_to_is_set_aside_and_the_verified_part_convicts_it() {
    let (bad, honest) = (peer(1), [peer(2), peer(3)]);
    let mut state = writers_of(file_hash_only_content(NINE_CELLS), 3);
    let _ = first_attempt_fails(&mut state, &[bad]);

    let (second, cells) = refetch(&mut state, &[bad, peer(2), peer(3)], &[bad]);
    for (worker, taken) in &cells {
        let own = match *worker {
            w if w == bad => 0..3,
            w if w == peer(2) => 3..6,
            _ => 6..9,
        };
        assert!(
            !own.contains(&taken[0]),
            "{worker:?} is asked first for a cell it did not write: {cells:?}"
        );
    }
    assert!(!retired_for_bad_data(&second, bad));
    let failed = state.on_persist_result(
        t0(),
        PartIndex::new(0),
        Some(peer(3)),
        Err(DownloadFailure::PartVerificationFailed),
        Some(file_cells()),
    );
    assert!(
        failed.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::SourceSetAside { peer: p, proven: false, .. })
                if *p == bad
        )),
        "{failed:?}"
    );
    assert!(
        !punished(&failed, bad, hash_of(1)),
        "pointed to by elimination, not proven: {failed:?}"
    );
    for at in honest {
        assert!(!punished(&failed, at, hash_of(2)), "{failed:?}");
        assert!(
            state.worker_slots.contains_key(&at),
            "{at:?} keeps its slot"
        );
    }

    let (_, _) = refetch(&mut state, &honest, &[]);
    let verified = state.on_persist_result(
        t0(),
        PartIndex::new(0),
        Some(peer(3)),
        Ok(()),
        Some(file_cells()),
    );
    assert!(
        verified
            .iter()
            .any(|d| matches!(d, Decision::DistrustPeer { user_hash } if *user_hash == hash_of(1))),
        "the verified part proves its old cells corrupt: {verified:?}"
    );
    assert!(
        verified
            .iter()
            .any(|d| matches!(d, Decision::BanSender { peer: at } if *at == peer(1))),
        "a convicted sender is banned across the node \
         (`CorruptionBlackBox.cpp:217-225`): {verified:?}"
    );
}

/// One worker wrote the whole part, and the recovery ask goes to it; it ends
/// before it answers. Its end stands for an empty answer: the part takes the
/// rootless path, its sole writer is distrusted, and the other worker fetches
/// it again to the end.
#[test]
fn an_unshared_part_whose_recovery_ask_goes_unanswered_is_fetched_again() {
    let file = 6 * B;
    let truth = bytes_of(0, file, false);
    let root = AichHashSet::from_bytes(&truth).master_root();
    let mut state = writers_of(
        ContentFacts {
            aich_root: crate::download::state::AichRootAuthority::Link(root),
            ..file_hash_only_content(file)
        },
        2,
    );
    for (start, end) in [(0, 3 * B), (3 * B, file)] {
        let _ = deliver(&mut state, peer(1), (start, end), true);
    }
    let _ = state.on_worker_event(
        t0(),
        peer(1),
        PeerWorkerEvent::AichFileHashReceived { root },
    );
    let failed = state.on_persist_result(
        t0() + MIN_REQUEST_TIME,
        PartIndex::new(0),
        Some(peer(1)),
        Err(DownloadFailure::PartVerificationFailed),
        Some(vec![[0; 20]; 6]),
    );
    assert!(
        sent(&failed).iter().any(|(to, command)| *to == peer(1)
            && matches!(command, PeerWorkerCommand::RequestAich { .. })),
        "{failed:?}"
    );
    let ended = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Disconnected);
    assert!(
        ended
            .iter()
            .any(|d| matches!(d, Decision::DistrustPeer { user_hash } if *user_hash == hash_of(1))),
        "{ended:?}"
    );
    let (again, _) = refetch(&mut state, &[peer(2)], &[]);
    assert!(
        again.iter().any(
            |d| matches!(d, Decision::PersistPart { part_index, .. } if part_index.value() == 0)
        ),
        "{again:?}"
    );
}

/// Whether `decisions` set `at` apart from a working source in any way a
/// source's record survives only by luck: a ban, a distrust or a retirement
/// for bad data.
fn punished(decisions: &[Decision], at: PeerEndpoint, user_hash: UserHash) -> bool {
    retired_for_bad_data(decisions, at)
        || decisions.iter().any(|d| match d {
            Decision::BanSender { peer: p } => *p == at,
            Decision::DistrustPeer { user_hash: h } => *h == user_hash,
            _ => false,
        })
}

/// `peer(2)` wrote the head of cell 3 and the bad `peer(1)` its tail, so the
/// cell the verified part disproves has two writers. Stock charges both and
/// bans neither on that alone: the bad seed goes, on the cells it wrote by
/// itself, and the honest one that shared its cell stays a source.
#[test]
fn an_honest_writer_of_a_shared_corrupt_cell_stays_a_source() {
    let (bad, honest) = (peer(1), peer(2));
    let mut state = writers_of(file_hash_only_content(NINE_CELLS), 3);
    for cell in 0..3 {
        let _ = deliver(&mut state, bad, (cell * B, (cell + 1) * B), true);
    }
    let _ = deliver(&mut state, honest, (3 * B, 3 * B + 4_096), false);
    let _ = deliver(&mut state, bad, (3 * B + 4_096, 4 * B), true);
    for cell in 4..6 {
        let _ = deliver(&mut state, honest, (cell * B, (cell + 1) * B), false);
    }
    for cell in 6..9 {
        let _ = deliver(&mut state, peer(3), (cell * B, (cell + 1) * B), false);
    }
    let failed = state.on_persist_result(
        t0(),
        PartIndex::new(0),
        Some(peer(3)),
        Err(DownloadFailure::PartVerificationFailed),
        Some(file_cells()),
    );
    assert!(!punished(&failed, honest, hash_of(2)), "{failed:?}");

    let (_, _) = refetch(&mut state, &[honest, peer(3)], &[]);
    let verified = state.on_persist_result(
        t0(),
        PartIndex::new(0),
        Some(peer(3)),
        Ok(()),
        Some(file_cells()),
    );
    assert!(retired_for_bad_data(&verified, bad), "{verified:?}");
    assert!(!punished(&verified, honest, hash_of(2)), "{verified:?}");
    assert!(
        state.worker_slots.contains_key(&honest),
        "the honest seed keeps its slot"
    );
}

/// Two writers alone on a part dispute each other's cells: nothing tells
/// them apart, so neither is retired, the part narrows to one of them, and
/// that writer's own attempt settles it. Here it is the bad one: it is
/// convicted, the honest one is asked again, and the part verifies. A bad
/// seed cannot take the honest one with it.
#[test]
fn two_writers_alone_narrow_to_one_and_its_attempt_settles_it() {
    let (bad, honest) = (peer(1), peer(2));
    let mut state = writers_of(file_hash_only_content(NINE_CELLS), 2);
    let both = [bad, honest];
    for cell in 0..3 {
        let _ = deliver(&mut state, bad, (cell * B, (cell + 1) * B), true);
        let _ = deliver(&mut state, honest, ((cell + 3) * B, (cell + 4) * B), false);
    }
    let attempt = |state: &mut DownloadState| {
        let _ = refetch(state, &both, &[bad]);
        state.on_persist_result(
            t0(),
            PartIndex::new(0),
            Some(honest),
            Err(DownloadFailure::PartVerificationFailed),
            Some(file_cells()),
        )
    };
    let first = attempt(&mut state);
    assert!(!punished(&first, bad, hash_of(1)), "{first:?}");
    let second = attempt(&mut state);
    assert!(!punished(&second, bad, hash_of(1)), "{second:?}");
    assert!(!punished(&second, honest, hash_of(2)), "{second:?}");

    let (alone, cells) = refetch(&mut state, &both, &[bad]);
    assert!(
        cells.iter().any(|(_, taken)| taken.is_empty()),
        "one writer is asked for nothing: {cells:?} {alone:?}"
    );
    let third = state.on_persist_result(
        t0(),
        PartIndex::new(0),
        Some(bad),
        Err(DownloadFailure::PartVerificationFailed),
        Some(file_cells()),
    );
    assert!(retired_for_bad_data(&third, bad), "{third:?}");
    assert!(!punished(&third, honest, hash_of(2)), "{third:?}");
    assert!(
        !third
            .iter()
            .any(|d| matches!(d, Decision::Emit(DownloadEvent::DownloadFailed { .. }))),
        "the honest source is still in the book: {third:?}"
    );
}

/// `peer(1)` is set aside with blocks still draining from its pipeline: what
/// lands writes nothing, or its bad bytes would fail the next attempt too.
#[test]
fn a_block_draining_from_a_source_set_aside_writes_nothing() {
    let bad = peer(1);
    let mut state = writers_of(file_hash_only_content(NINE_CELLS), 3);
    let _ = first_attempt_fails(&mut state, &[bad]);
    let _ = refetch(&mut state, &[bad, peer(2), peer(3)], &[bad]);
    let _ = state.on_persist_result(
        t0(),
        PartIndex::new(0),
        Some(peer(3)),
        Err(DownloadFailure::PartVerificationFailed),
        Some(file_cells()),
    );
    let drained = deliver(&mut state, bad, (0, B), true);
    assert!(
        !drained
            .iter()
            .any(|d| matches!(d, Decision::WriteBytes { .. })),
        "{drained:?}"
    );
}

/// Two writers narrow to one and that one ends: the suspect left out is the
/// last worker holding the part, so it is asked again. A bad seed that leaves
/// cannot strand a part with the honest source that stayed.
#[test]
fn a_suspect_is_asked_again_when_the_worker_left_open_ends() {
    let (bad, honest) = (peer(1), peer(2));
    let mut state = writers_of(file_hash_only_content(NINE_CELLS), 2);
    let both = [bad, honest];
    for cell in 0..3 {
        let _ = deliver(&mut state, bad, (cell * B, (cell + 1) * B), true);
        let _ = deliver(&mut state, honest, ((cell + 3) * B, (cell + 4) * B), false);
    }
    for _ in 0..2 {
        let _ = refetch(&mut state, &both, &[bad]);
        let _ = state.on_persist_result(
            t0(),
            PartIndex::new(0),
            Some(honest),
            Err(DownloadFailure::PartVerificationFailed),
            Some(file_cells()),
        );
    }
    let _ = state.on_worker_event(t0(), bad, PeerWorkerEvent::Disconnected);
    let (again, cells) = refetch(&mut state, &[honest], &[]);
    assert_eq!(cells[0].1.len(), 9, "{cells:?} {again:?}");
}

/// `peer(1)` has verified bytes behind it and wrote a whole part that failed:
/// it is proven, within stock's limit, so it stays a source, as stock reports
/// it and moves nothing, but it is not asked for that part again.
#[test]
fn a_proven_sender_within_the_limit_stays_a_source_set_aside_from_the_part() {
    let bad = peer(1);
    let mut state = writers_of(file_hash_only_content(NINE_CELLS), 2);
    state.ledger.credit(bad, 6 * B);
    for cell in 0..9 {
        let _ = deliver(&mut state, bad, (cell * B, (cell + 1) * B), true);
    }
    let failed = state.on_persist_result(
        t0(),
        PartIndex::new(0),
        Some(bad),
        Err(DownloadFailure::PartVerificationFailed),
        Some(file_cells()),
    );
    assert!(!punished(&failed, bad, hash_of(1)), "{failed:?}");
    assert!(
        failed.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::BadDataCounted { peer: p, bad_bytes, .. })
                if *p == bad && *bad_bytes == B
        )),
        "{failed:?}"
    );
    assert!(
        failed.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::SourceSetAside { peer: p, proven: true, .. })
                if *p == bad
        )),
        "{failed:?}"
    );
    let (_, cells) = refetch(&mut state, &[bad, peer(2)], &[]);
    assert!(cells[0].1.is_empty(), "{cells:?}");
}
