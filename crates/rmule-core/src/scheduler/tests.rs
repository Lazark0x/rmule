//! Block handouts across a download's workers (ADR-0117): unclaimed blocks cut
//! on each part's grid, one worker per block, verified parts skipped on
//! resume, claims settled by whoever delivers, freed by a worker's end or a
//! lost range — and the rank a worker's Advertised Parts are chosen by
//! (ADR-0112): very rare first, then the Preview Band, then the Streaming
//! Window, then rarest.

use rmule_peer::PartIndex;

use rmule_peer::PartBitmap;
use rmule_primitives::{ED2K_PART_SIZE, EMBLOCKSIZE as B, Ipv4Endpoint, PeerEndpoint, part_count};

use super::*;

/// How many blocks one full part is cut into.
const PART_BLOCKS: usize = ED2K_PART_SIZE.div_ceil(B) as usize;

fn peer(last_octet: u8) -> PeerEndpoint {
    PeerEndpoint::V4(Ipv4Endpoint::new(
        std::net::Ipv4Addr::new(127, 0, 0, last_octet),
        4663,
    ))
}

/// A rarest-first scheduler over `file_size` bytes, `verified` already done.
/// The set of parts numbered `indexes`.
fn parts<const N: usize>(indexes: [u32; N]) -> BTreeSet<PartIndex> {
    indexes.map(PartIndex::new).into()
}

fn rarest(file_size: u64, verified: impl IntoIterator<Item = u32>) -> DownloadScheduler {
    DownloadScheduler::new(
        file_size,
        verified.into_iter().map(PartIndex::new),
        PartOrder::Rarest,
    )
}

/// Advertised Parts over `count` parts, holding `held`.
fn holding(count: u32, held: &[u32]) -> PartBitmap {
    let mut bytes = vec![0_u8; (count as usize).div_ceil(8)];
    for &part in held {
        bytes[(part / 8) as usize] |= 1 << (part % 8);
    }
    PartBitmap::decode(count, &bytes).unwrap()
}

/// The blocks `peer`, holding every part, is handed for `room`.
fn hand(scheduler: &mut DownloadScheduler, peer: PeerEndpoint, room: usize) -> Vec<(u64, u64)> {
    let parts = PartBitmap::all_present(scheduler.total_parts);
    match scheduler.hand(peer, room, &parts, &[], 0, &()) {
        Handout::Blocks { blocks, .. } => blocks.iter().map(|b| (b.start, b.end)).collect(),
        Handout::Nothing { .. } => Vec::new(),
    }
}

/// What a part's Arrived Ranges show.
struct Arrived(BTreeMap<PartIndex, ByteRanges>);

impl Progress for Arrived {
    fn rate(&self, _: PeerEndpoint) -> Option<u64> {
        None
    }
    fn arrived(&self, part_index: PartIndex) -> Option<&ByteRanges> {
        self.0.get(&part_index)
    }
}

#[test]
fn hands_unclaimed_blocks_on_each_parts_grid_one_worker_per_block() {
    let mut scheduler = rarest(ED2K_PART_SIZE * 2 + 1, []);
    assert_eq!(
        hand(&mut scheduler, peer(1), 3),
        vec![(0, B), (B, 2 * B), (2 * B, 3 * B)]
    );
    let second = hand(&mut scheduler, peer(2), PART_BLOCKS);
    assert_eq!(
        second.first(),
        Some(&(3 * B, 4 * B)),
        "the next unclaimed block"
    );
    let part_end = second
        .iter()
        .position(|&(_, end)| end == ED2K_PART_SIZE)
        .expect("part 0's last block is clipped to the part's end");
    assert_eq!(second[part_end].0, (PART_BLOCKS as u64 - 1) * B);
    assert_eq!(
        second[part_end + 1],
        (ED2K_PART_SIZE, ED2K_PART_SIZE + B),
        "the room carries on into the next-ranked part"
    );
    assert_eq!(scheduler.parts_of(peer(2)), parts([0, 1]));
}

#[test]
fn excludes_already_verified_parts_from_resume() {
    let mut scheduler = rarest(ED2K_PART_SIZE * 2 + 1, [0]);
    assert_eq!(
        hand(&mut scheduler, peer(1), 1),
        vec![(ED2K_PART_SIZE, ED2K_PART_SIZE + B)]
    );
}

/// A claim ends when its range has arrived, whoever delivered it; a gap the
/// arrivals left off the grid is cut as its own block (ADR-0117).
#[test]
fn arrivals_settle_claims_and_off_grid_gaps_are_handed_exactly() {
    let mut scheduler = rarest(ED2K_PART_SIZE, []);
    assert_eq!(hand(&mut scheduler, peer(1), 2), vec![(0, B), (B, 2 * B)]);
    let mut arrived = ByteRanges::default();
    // Another worker's copy a byte short of the grid, and the second block.
    arrived.insert(0, B - 1);
    arrived.insert(B, 2 * B);
    scheduler.settle(PartIndex::new(0), &arrived);
    assert_eq!(
        scheduler.parts_of(peer(1)),
        parts([0]),
        "block 0 is a byte short"
    );
    let progress = Arrived(BTreeMap::from([(PartIndex::new(0), arrived.clone())]));
    let parts = PartBitmap::all_present(1);
    let Handout::Blocks { blocks, .. } = scheduler.hand(peer(2), 2, &parts, &[], 0, &progress)
    else {
        panic!("blocks are left");
    };
    let blocks: Vec<(u64, u64)> = blocks.iter().map(|b| (b.start, b.end)).collect();
    assert_eq!(
        blocks,
        vec![(2 * B, 3 * B), (3 * B, 4 * B)],
        "block 0 is still claimed"
    );
    arrived.insert(B - 1, B);
    scheduler.settle(PartIndex::new(0), &arrived);
    assert!(!scheduler.holds_claims(peer(1)));
}

/// A worker's end frees its blocks for the next worker; a lost range frees
/// only what it covers.
#[test]
fn a_release_frees_every_block_and_a_loss_only_its_range() {
    let mut scheduler = rarest(ED2K_PART_SIZE, []);
    let first = hand(&mut scheduler, peer(1), 3);
    assert_eq!(scheduler.release(peer(1)), vec![PartIndex::new(0)]);
    assert_eq!(hand(&mut scheduler, peer(2), 3), first);

    scheduler.lose(peer(2), B + 10, 2 * B);
    assert_eq!(
        hand(&mut scheduler, peer(3), 1),
        vec![(B + 10, 2 * B)],
        "only the lost tail of block 1 is free"
    );
}

#[test]
fn part_states_place_each_part_by_index_through_a_whole_download() {
    // Four parts, part 1 already verified from a previous session (ADR-0079).
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
    hand(&mut scheduler, peer(1), PART_BLOCKS + 1);
    assert_eq!(
        scheduler.part_states(),
        vec![
            PartState::InFlight,
            PartState::Verified,
            PartState::InFlight,
            PartState::Missing,
        ],
    );
    // A freed part falls back to Missing at its own index.
    scheduler.release(peer(1));
    assert_eq!(scheduler.part_states()[0], PartState::Missing);
    // A part whose bytes are all in is in flight while it verifies, and never
    // handed meanwhile.
    scheduler.verifying(PartIndex::new(0));
    assert_eq!(scheduler.part_states()[0], PartState::InFlight);
    assert_eq!(
        hand(&mut scheduler, peer(2), 1),
        vec![(2 * ED2K_PART_SIZE, 2 * ED2K_PART_SIZE + B)]
    );
    scheduler.release(peer(2));
    for part in [0, 2, 3] {
        assert!(scheduler.complete_verified(PartIndex::new(part)).is_some());
    }
    assert!(scheduler.is_complete());
    assert_eq!(scheduler.part_states(), vec![PartState::Verified; 4]);
}

/// The parts successive workers, each advertising every part of a
/// `file_size`-byte file and taking a whole part's room, start in turn under
/// Part Frequency `frequency` over `known` sources.
fn fresh_order(
    scheduler: &mut DownloadScheduler,
    file_size: u64,
    frequency: &[u32],
    known: u32,
) -> Vec<u32> {
    let parts = PartBitmap::all_present(part_count(file_size));
    (1..=u8::MAX)
        .map_while(
            |n| match scheduler.hand(peer(n), PART_BLOCKS, &parts, frequency, known, &()) {
                Handout::Blocks { blocks, .. } => Some(blocks[0].part_index.value()),
                Handout::Nothing { .. } => None,
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
    let mut scheduler = DownloadScheduler::new(
        size,
        [0, 1, 5].map(PartIndex::new),
        PartOrder::Streaming { window_parts: 2 },
    );
    assert_eq!(
        fresh_order(&mut scheduler, size, &[0, 0, 9, 7, 5, 0], 20),
        vec![2, 3, 4]
    );
}

/// With no window the tuple is `(very rare, frequency, i)`, and from
/// complete sources outside Streaming Priority that is index order.
#[test]
fn no_window_ranks_very_rare_then_frequency_then_index() {
    let size = 6 * ED2K_PART_SIZE - 1;
    let mut scheduler = DownloadScheduler::new(
        size,
        [0, 1, 5].map(PartIndex::new),
        PartOrder::Streaming { window_parts: 0 },
    );
    assert_eq!(
        fresh_order(&mut scheduler, size, &[0, 0, 2, 7, 5, 0], 20),
        vec![2, 4, 3]
    );
    let size = 3 * ED2K_PART_SIZE + 1;
    let mut scheduler = rarest(size, []);
    assert_eq!(
        fresh_order(&mut scheduler, size, &[3, 3, 3, 3], 3),
        vec![0, 1, 2, 3]
    );
}

/// A worker is handed only blocks of parts its Advertised Parts hold, and
/// says when it holds nothing the file lacks.
#[test]
fn a_worker_is_handed_only_parts_it_advertised() {
    let mut scheduler = rarest(2 * ED2K_PART_SIZE + 1, []);
    let part = |handout: Handout| match handout {
        Handout::Blocks { blocks, .. } => Some(blocks[0].part_index.value()),
        Handout::Nothing { .. } => None,
    };
    let every = holding(3, &[0, 1, 2]);
    assert_eq!(
        part(scheduler.hand(peer(1), PART_BLOCKS, &every, &[], 0, &())),
        Some(0)
    );
    assert_eq!(
        part(scheduler.hand(peer(2), 1, &holding(3, &[2]), &[], 0, &())),
        Some(2)
    );
    assert_eq!(
        scheduler.hand(peer(3), 1, &holding(3, &[0]), &[], 0, &()),
        Handout::Nothing { lacked: true },
        "every block of the part it holds is claimed"
    );
    assert_eq!(
        scheduler.hand(peer(4), 1, &holding(3, &[]), &[], 0, &()),
        Handout::Nothing { lacked: false }
    );
    scheduler.complete_verified(PartIndex::new(0));
    assert_eq!(
        scheduler.hand(peer(5), 1, &holding(3, &[0]), &[], 0, &()),
        Handout::Nothing { lacked: false },
        "it holds only a verified part"
    );
}

/// Delivery Rates by worker; nothing arrived.
struct Rates(Vec<(PeerEndpoint, u64)>);

impl Progress for Rates {
    fn rate(&self, peer: PeerEndpoint) -> Option<u64> {
        self.0
            .iter()
            .find(|(p, _)| *p == peer)
            .map(|&(_, rate)| rate)
    }
    fn arrived(&self, _: PartIndex) -> Option<&ByteRanges> {
        None
    }
}

/// The blocks of a Duplicate Set, or nothing.
fn duplicates(handout: Handout) -> Vec<(u64, u64)> {
    match handout {
        Handout::Blocks {
            blocks,
            duplicate: true,
        } => blocks.iter().map(|b| (b.start, b.end)).collect(),
        other => panic!("not a Duplicate Set: {other:?}"),
    }
}

/// With nothing unclaimed left, a worker is handed at most three blocks a
/// slower worker holds alone, latest expected first; a block is doubled once,
/// a worker holds one set at a time, and an unmeasured worker or one slower
/// than every holder doubles nothing (ADR-0117).
#[test]
fn the_end_game_duplicates_only_within_its_bound() {
    let (slow, fast, worker, second) = (peer(1), peer(2), peer(3), peer(4));
    let mut scheduler = rarest(7 * B, []);
    assert_eq!(hand(&mut scheduler, slow, 5).len(), 5);
    assert_eq!(
        hand(&mut scheduler, fast, 2),
        vec![(5 * B, 6 * B), (6 * B, 7 * B)]
    );
    let parts = PartBitmap::all_present(1);
    let rates = Rates(vec![
        (slow, 10),
        (fast, 1_000),
        (worker, 500),
        (second, 600),
    ]);

    let set = duplicates(scheduler.hand(worker, 24, &parts, &[], 0, &rates));
    assert_eq!(
        set,
        vec![(4 * B, 5 * B), (3 * B, 4 * B), (2 * B, 3 * B)],
        "three of the slow worker's blocks, the last it would deliver first"
    );
    assert_eq!(
        duplicates(scheduler.hand(second, 24, &parts, &[], 0, &rates)),
        vec![(B, 2 * B), (0, B)],
        "only the blocks nobody doubled yet"
    );
    assert_eq!(
        scheduler.hand(worker, 24, &parts, &[], 0, &rates),
        Handout::Nothing { lacked: true },
        "one unsettled set at a time"
    );
    let unmeasured = peer(5);
    assert_eq!(
        scheduler.hand(unmeasured, 24, &parts, &[], 0, &rates),
        Handout::Nothing { lacked: true }
    );
    let slowest = Rates(vec![(slow, 10), (fast, 1_000), (peer(6), 5)]);
    assert_eq!(
        scheduler.hand(peer(6), 24, &parts, &[], 0, &slowest),
        Handout::Nothing { lacked: true },
        "a worker slower than every holder doubles nothing"
    );

    // The first copy to arrive settles both claims: the worker's set is
    // settled and it may be handed another.
    let mut arrived = ByteRanges::default();
    for (start, end) in set {
        arrived.insert(start, end);
    }
    scheduler.settle(PartIndex::new(0), &arrived);
    assert_eq!(
        scheduler.parts_of(slow),
        BTreeSet::from([PartIndex::new(0)])
    );
    assert!(!scheduler.holds_claims(worker), "its set settled");
}

/// Of two parts equally rare, the one with more bytes goes first, so a part a
/// source stranded finishes before a new one opens; a rarer part still goes
/// first, and the Streaming Window keeps its own order.
#[test]
fn arrived_bytes_break_a_tie_of_rarity_and_only_a_tie() {
    let size = 4 * ED2K_PART_SIZE;
    let parts_held = PartBitmap::all_present(4);
    let mut arrived = ByteRanges::default();
    arrived.insert(3 * ED2K_PART_SIZE, 3 * ED2K_PART_SIZE + B);
    let progress = Arrived(BTreeMap::from([(PartIndex::new(3), arrived)]));
    let first = |order, frequency: &[u32]| {
        let mut scheduler = DownloadScheduler::new(size, [], order);
        match scheduler.hand(peer(1), 1, &parts_held, frequency, 40, &progress) {
            Handout::Blocks { blocks, .. } => blocks[0].part_index.value(),
            Handout::Nothing { .. } => panic!("blocks are left"),
        }
    };
    assert_eq!(first(PartOrder::Rarest, &[9, 9, 9, 9]), 3, "the tie");
    assert_eq!(first(PartOrder::Rarest, &[8, 9, 9, 9]), 0, "rarity first");
    let window = PartOrder::Streaming { window_parts: 4 };
    assert_eq!(
        first(window, &[9, 9, 9, 9]),
        0,
        "the window keeps its order"
    );
}
