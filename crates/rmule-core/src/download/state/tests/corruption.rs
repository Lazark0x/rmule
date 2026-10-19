//! A part that fails its check with no Trusted AICH Root (ADR-0117 §1): the
//! workers that shared it keep their slots, the refetch names the writer both
//! failures point to and the verified part proves it, and a part whose
//! recovery ask is never answered is fetched again rather than stranded.

use super::*;
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

/// `from` delivers `start..end` of part 0, corrupt when `bad`.
fn deliver(
    state: &mut DownloadState,
    from: PeerEndpoint,
    (start, end): (u64, u64),
    bad: bool,
) -> Vec<Decision> {
    state.on_worker_event(
        t0(),
        from,
        PeerWorkerEvent::BlockReceived {
            part_index: 0,
            offset: start,
            bytes: bytes_of(start, end, bad),
        },
    )
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
        0,
        peer(3),
        Err(DownloadFailure::PartVerificationFailed),
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
        again
            .iter()
            .any(|d| matches!(d, Decision::PersistPart { part_index: 0, .. })),
        "{again:?}"
    );
}

/// `peer(1)` corrupts every cell it sends. The first failure retires nobody;
/// the refetch asks each worker for cells it did not write; the second
/// failure names `peer(1)` alone and retires it; and once the others' third
/// attempt verifies, its corrupt cells prove it, so it is distrusted.
#[test]
fn a_writer_whose_cells_fail_again_on_the_refetch_is_retired() {
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
        0,
        peer(3),
        Err(DownloadFailure::PartVerificationFailed),
    );
    assert!(retired_for_bad_data(&failed, bad), "{failed:?}");
    for at in honest {
        assert!(!retired_for_bad_data(&failed, at), "{failed:?}");
        assert!(
            state.worker_slots.contains_key(&at),
            "{at:?} keeps its slot"
        );
    }
    assert!(
        !failed
            .iter()
            .any(|d| matches!(d, Decision::DistrustPeer { .. })),
        "named by elimination, not proven: {failed:?}"
    );

    let (_, _) = refetch(&mut state, &honest, &[]);
    let verified = state.on_persist_result(t0(), 0, peer(3), Ok(()));
    assert!(
        verified
            .iter()
            .any(|d| matches!(d, Decision::DistrustPeer { user_hash } if *user_hash == hash_of(1))),
        "the verified part proves its old cells corrupt: {verified:?}"
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
    let failed = state.on_persist_result(
        t0(),
        0,
        peer(1),
        Err(DownloadFailure::PartVerificationFailed),
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
        again
            .iter()
            .any(|d| matches!(d, Decision::PersistPart { part_index: 0, .. })),
        "{again:?}"
    );
}
