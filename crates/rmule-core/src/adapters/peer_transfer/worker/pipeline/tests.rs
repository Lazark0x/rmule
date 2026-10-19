//! The request pipeline's rules (ADR-0029 "Request pipeline", ADR-0117):
//! handed blocks asked ahead to the Request Depth, one request before the
//! grant's first byte, arrivals credited by offset, the room said once per
//! room and once at the drain, and two parts riding one pipeline.

use super::*;

const BLOCK: u64 = EMBLOCKSIZE;

/// `start..end` cut into handed blocks on the part grid, as core cuts them.
fn handed(start: u64, end: u64) -> Vec<BlockPlan> {
    let mut blocks = Vec::new();
    let mut at = start;
    while at < end {
        let part_end = (at / ED2K_PART_SIZE + 1) * ED2K_PART_SIZE;
        let stop =
            ((at % ED2K_PART_SIZE) / BLOCK + 1) * BLOCK + (at / ED2K_PART_SIZE) * ED2K_PART_SIZE;
        let stop = stop.min(part_end).min(end);
        blocks.push(BlockPlan {
            part_index: (at / ED2K_PART_SIZE) as u32,
            start: at,
            end: stop,
        });
        at = stop;
    }
    blocks
}

/// A pipeline handed `start..end`.
fn handing(start: u64, end: u64) -> Pipeline {
    let mut pipeline = Pipeline::new();
    pipeline.hand(&handed(start, end));
    pipeline
}

/// Deliver block `start..end` whole at `at`, as one chunk.
fn deliver(pipeline: &mut Pipeline, at: Instant, (start, end): (u64, u64)) -> bool {
    pipeline.arrived(at, start, end - start)
}

#[test]
fn a_grant_opens_with_one_request_of_three_blocks_and_waits_for_its_first_byte() {
    let t0 = Instant::now();
    let mut pipeline = handing(0, 10 * BLOCK);
    assert_eq!(
        pipeline.next_request(t0),
        Some(vec![(0, BLOCK), (BLOCK, 2 * BLOCK), (2 * BLOCK, 3 * BLOCK)])
    );
    assert_eq!(pipeline.next_request(t0), None);
    // The first block lands: one more is asked at once, before the link
    // drains the two still queued at the uploader.
    let t1 = t0 + Duration::from_millis(300);
    assert!(deliver(&mut pipeline, t1, (0, BLOCK)));
    assert_eq!(
        pipeline.next_request(t1),
        Some(vec![(3 * BLOCK, 4 * BLOCK)])
    );
    assert_eq!(pipeline.next_request(t1), None);
}

#[test]
fn the_last_block_stops_at_its_end_and_the_pipeline_drains_when_it_lands() {
    let t0 = Instant::now();
    let end = BLOCK + 1_000;
    let mut pipeline = handing(0, end);
    assert_eq!(
        pipeline.next_request(t0),
        Some(vec![(0, BLOCK), (BLOCK, end)])
    );
    assert!(deliver(&mut pipeline, t0, (0, BLOCK)));
    assert!(!pipeline.drained());
    // Chunks land in pieces, as `OP_SENDINGPART` frames do.
    assert!(pipeline.arrived(t0, BLOCK, 400));
    assert!(pipeline.arrived(t0, BLOCK + 400, 600));
    assert!(pipeline.drained());
    assert_eq!(pipeline.want(), Some((3, true)));
}

/// Once everything handed is asked, the room each landing leaves is said
/// once, and the drain once more (ADR-0117).
#[test]
fn the_room_is_said_once_per_room_and_once_at_the_drain() {
    let t0 = Instant::now();
    let mut pipeline = handing(0, 3 * BLOCK);
    pipeline.next_request(t0);
    assert_eq!(pipeline.want(), None, "the grant's first byte has not come");
    assert!(deliver(&mut pipeline, t0, (0, BLOCK)));
    assert_eq!(pipeline.want(), Some((1, false)));
    assert_eq!(pipeline.want(), None, "said once");
    assert!(deliver(&mut pipeline, t0, (BLOCK, 2 * BLOCK)));
    assert_eq!(pipeline.want(), Some((2, false)));
    pipeline.hand(&handed(3 * BLOCK, 4 * BLOCK));
    assert_eq!(pipeline.want(), None, "a handed block waits to be asked");
    pipeline.next_request(t0);
    assert!(deliver(&mut pipeline, t0, (2 * BLOCK, 3 * BLOCK)));
    assert!(deliver(&mut pipeline, t0, (3 * BLOCK, 4 * BLOCK)));
    assert_eq!(pipeline.want(), Some((3, true)));
}

#[test]
fn the_depth_covers_twice_the_rate_times_the_round_trip() {
    let t0 = Instant::now();
    let mut pipeline = handing(0, 100 * BLOCK);
    assert_eq!(pipeline.depth(), 3);
    pipeline.next_request(t0);
    // First byte 800 ms after the ask: the uploader's wake-up after a dry
    // socket. Then 512,000 B/s for two seconds.
    let first = t0 + Duration::from_millis(800);
    pipeline.arrived(first, 0, 10_240);
    for second in 1..=2u64 {
        pipeline.arrived(first + Duration::from_secs(second), 10_240, 512_000);
    }
    // 3 + ⌊2 × 512,000 × 0.8 / 184,320⌋ = 3 + 4.
    assert_eq!(pipeline.depth(), 7);
}

#[test]
fn the_depth_never_passes_twenty_four() {
    let t0 = Instant::now();
    let mut pipeline = handing(0, 100 * BLOCK);
    pipeline.next_request(t0);
    let first = t0 + Duration::from_secs(1);
    pipeline.arrived(first, 0, 1);
    pipeline.arrived(first + Duration::from_secs(1), 1, 100 * 1024 * 1024);
    assert_eq!(pipeline.depth(), 24);
}

/// A part's last blocks and the next part's first ride one request, and no
/// range crosses the part's end (ADR-0117: no part boundary drains it).
#[test]
fn two_parts_ride_one_pipeline_and_no_range_crosses_a_part() {
    let t0 = Instant::now();
    let last = (ED2K_PART_SIZE / BLOCK) * BLOCK;
    let mut pipeline = handing(last - BLOCK, ED2K_PART_SIZE + BLOCK);
    assert_eq!(
        pipeline.next_request(t0),
        Some(vec![
            (last - BLOCK, last),
            (last, ED2K_PART_SIZE),
            (ED2K_PART_SIZE, ED2K_PART_SIZE + BLOCK),
        ])
    );
}

#[test]
fn bytes_inside_no_asked_block_go_nowhere() {
    let t0 = Instant::now();
    let mut pipeline = handing(0, 10 * BLOCK);
    pipeline.next_request(t0);
    assert!(!pipeline.arrived(t0, 5 * BLOCK, 100));
}

/// `OP_OUTOFPARTREQS` empties the pipeline, the blocks handed but not yet
/// asked among them: core frees them all.
#[test]
fn out_of_part_reqs_empties_the_pipeline() {
    let t0 = Instant::now();
    let mut pipeline = handing(0, 10 * BLOCK);
    pipeline.next_request(t0);
    pipeline.requeued();
    assert!(pipeline.drained());
    assert_eq!(pipeline.next_request(t0), None);
    pipeline.granted(&AskedRanges::default());
    pipeline.hand(&handed(0, 10 * BLOCK));
    assert_eq!(
        pipeline.next_request(t0),
        Some(vec![(0, BLOCK), (BLOCK, 2 * BLOCK), (2 * BLOCK, 3 * BLOCK)])
    );
}

/// A lost block stops counting against the depth and answers its range for
/// core to free (ADR-0029 "A lost block is freed"); one never asked is no
/// loss.
#[test]
fn a_lost_block_frees_its_depth_and_answers_its_range() {
    let t0 = Instant::now();
    let mut pipeline = handing(0, 10 * BLOCK);
    assert!(pipeline.next_request(t0).is_some());
    assert!(deliver(&mut pipeline, t0, (0, BLOCK)));
    assert_eq!(
        pipeline.next_request(t0),
        Some(vec![(3 * BLOCK, 4 * BLOCK)])
    );
    assert_eq!(pipeline.lost(BLOCK), Some((BLOCK, 2 * BLOCK)));
    assert_eq!(
        pipeline.next_request(t0),
        Some(vec![(4 * BLOCK, 5 * BLOCK)])
    );
    assert_eq!(pipeline.lost(7 * BLOCK), None);
}

/// The first file's rider asked the first part's grid on the link, then
/// released its slot silently; the uploader still holds those ranges and
/// drops a request repeating one, whatever its file (ADR-0107).
fn first_files_blocks() -> AskedRanges {
    let mut asked = AskedRanges::default();
    for block in 0..4 {
        asked.insert(block * BLOCK, (block + 1) * BLOCK);
    }
    asked
}

#[test]
fn a_grant_after_a_silent_release_asks_no_range_the_link_asked() {
    let t0 = Instant::now();
    let mut pipeline = Pipeline::new();
    pipeline.granted(&first_files_blocks());
    pipeline.hand(&handed(0, 10 * BLOCK));
    let mut asked = pipeline.next_request(t0).expect("the stream asks");
    let mut at = 0;
    while let Some(&(start, end)) = asked.get(at) {
        assert!(deliver(&mut pipeline, t0, (start, end)));
        asked.extend(pipeline.next_request(t0).into_iter().flatten());
        at += 1;
    }
    let held = first_files_blocks();
    assert!(
        asked.iter().all(|&(start, end)| !held.contains(start, end)),
        "every block avoids the held ranges: {asked:?}"
    );
    // The run still covers its range without a gap, to its end.
    assert_eq!(asked.first().map(|&(start, _)| start), Some(0));
    assert!(asked.windows(2).all(|pair| pair[0].1 == pair[1].0));
    assert_eq!(asked.last().map(|&(_, end)| end), Some(10 * BLOCK));
}

/// One handed block that repeats a held range is asked a byte shorter, and the
/// byte it left is asked next as its own range.
#[test]
fn a_held_block_is_asked_short_and_its_last_byte_after() {
    let t0 = Instant::now();
    let mut pipeline = Pipeline::new();
    pipeline.granted(&first_files_blocks());
    pipeline.hand(&handed(0, BLOCK));
    assert_eq!(
        pipeline.next_request(t0),
        Some(vec![(0, BLOCK - 1), (BLOCK - 1, BLOCK)])
    );
}

#[test]
fn an_out_of_part_reqs_forgets_what_the_link_asked() {
    let t0 = Instant::now();
    let mut pipeline = Pipeline::new();
    pipeline.granted(&first_files_blocks());
    pipeline.requeued();
    pipeline.hand(&handed(0, 10 * BLOCK));
    assert_eq!(
        pipeline.next_request(t0),
        Some(vec![(0, BLOCK), (BLOCK, 2 * BLOCK), (2 * BLOCK, 3 * BLOCK)])
    );
}
