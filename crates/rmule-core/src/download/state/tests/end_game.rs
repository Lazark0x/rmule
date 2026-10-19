//! The End Game (ADR-0117): a granted worker with nothing unclaimed left is
//! handed a Duplicate Set of a slower worker's blocks instead of giving its
//! slot back; the first copy to arrive wins and the other is dropped.

use super::*;
use rmule_primitives::EMBLOCKSIZE as B;

/// A one-part file of six blocks.
const SIX_BLOCKS: u64 = 6 * B;

/// `bytes` of part 0 at `offset` from `from`, at `at`.
fn deliver(
    state: &mut DownloadState,
    at: Instant,
    from: PeerEndpoint,
    offset: u64,
    len: u64,
) -> Vec<Decision> {
    state.on_worker_event(
        at,
        from,
        PeerWorkerEvent::BlockReceived {
            part_index: 0,
            offset,
            bytes: vec![0x5A; len as usize],
        },
    )
}

/// `peer` has room for `room` more blocks.
fn wants(
    state: &mut DownloadState,
    at: Instant,
    peer: PeerEndpoint,
    room: u32,
    drained: bool,
) -> Vec<Decision> {
    state.on_worker_event(at, peer, PeerWorkerEvent::BlocksWanted { room, drained })
}

/// The blocks `decisions` hand `to`.
fn handed(decisions: &[Decision], to: PeerEndpoint) -> Vec<(u64, u64)> {
    sent(decisions)
        .into_iter()
        .filter(|(peer, _)| *peer == to)
        .flat_map(|(_, command)| match command {
            PeerWorkerCommand::RequestBlocks { blocks } => blocks,
            _ => Vec::new(),
        })
        .map(|block| (block.start, block.end))
        .collect()
}

/// A fast worker that drained its own blocks doubles the slow worker's last
/// three — only what has not arrived of them, the latest expected first —
/// keeps its slot, is handed no second set while the first is unsettled, and
/// completes the part with its copies; the slow worker's late bytes open
/// nothing.
#[test]
fn a_drained_fast_worker_doubles_the_slow_workers_last_blocks_within_the_bound() {
    let (fast, slow) = (peer(1), peer(2));
    let mut state = pooled_state(
        file_hash_only_content(SIX_BLOCKS),
        &[fast, slow],
        QUIET_POSTURE,
        2,
    );
    let _ = state.start(t0());
    assert_eq!(handed(&connect(&mut state, t0(), fast), fast).len(), 3);
    assert_eq!(handed(&connect(&mut state, t0(), slow), slow).len(), 3);

    // The fast worker delivers a block a second; the slow one 1,000 bytes.
    let second = Duration::from_secs(1);
    for (n, at) in [t0(), t0() + second, t0() + 2 * second]
        .into_iter()
        .enumerate()
    {
        let _ = deliver(&mut state, at, fast, n as u64 * B, B);
    }
    let _ = deliver(&mut state, t0(), slow, 3 * B, 1_000);
    let _ = deliver(&mut state, t0() + second, slow, 3 * B + 1_000, 1_000);

    let at = t0() + 2 * second;
    let doubled = wants(&mut state, at, fast, 3, true);
    assert_eq!(
        handed(&doubled, fast),
        vec![(5 * B, 6 * B), (4 * B, 5 * B), (3 * B + 2_000, 4 * B)],
        "the slow worker's blocks, latest first, its arrived bytes left out: {doubled:?}"
    );
    assert!(
        doubled.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::EndGameBlocks { peer: p, part_index: 0, blocks: 3, bytes, .. })
                if *p == fast && *bytes == 3 * B - 2_000
        )),
        "{doubled:?}"
    );
    assert!(
        !doubled
            .iter()
            .any(|d| matches!(d, Decision::Emit(DownloadEvent::PeerRetired { .. }))),
        "nobody gives a slot back: {doubled:?}"
    );

    let again = wants(&mut state, at, fast, 1, false);
    assert!(
        handed(&again, fast).is_empty(),
        "one unsettled set at a time"
    );

    let mut last = Vec::new();
    for (start, end) in [(5 * B, 6 * B), (4 * B, 5 * B), (3 * B + 2_000, 4 * B)] {
        last = deliver(&mut state, at, fast, start, end - start);
    }
    assert!(
        last.iter()
            .any(|d| matches!(d, Decision::PersistPart { part_index: 0, .. })),
        "the fast worker's copies complete the part: {last:?}"
    );
    let late = deliver(&mut state, at, slow, 3 * B + 2_000, 1_000);
    assert!(
        !late
            .iter()
            .any(|d| matches!(d, Decision::PersistPart { .. })),
        "a late copy opens nothing: {late:?}"
    );
}
