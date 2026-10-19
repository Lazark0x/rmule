//! The request pipeline's rules (ADR-0029 "Request pipeline"): blocks asked
//! ahead to the Request Depth, one request before the grant, arrivals credited
//! by offset, and a reassignment's old blocks draining against the depth.

use super::*;

const BLOCK: u64 = EMBLOCKSIZE;

/// Deliver block `start..end` whole at `at`, as one chunk.
fn deliver(pipeline: &mut Pipeline, at: Instant, (start, end): (u64, u64)) -> bool {
    pipeline.arrived(at, start, end - start)
}

#[test]
fn a_stream_opens_with_one_request_of_three_blocks_and_waits_for_the_grant() {
    let t0 = Instant::now();
    let mut pipeline = Pipeline::new();
    pipeline.begin(0, 10 * BLOCK);
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
fn the_last_block_stops_at_the_part_end_and_the_stream_ends_when_it_lands() {
    let t0 = Instant::now();
    let mut pipeline = Pipeline::new();
    let end = BLOCK + 1_000;
    pipeline.begin(0, end);
    assert_eq!(
        pipeline.next_request(t0),
        Some(vec![(0, BLOCK), (BLOCK, end)])
    );
    assert!(deliver(&mut pipeline, t0, (0, BLOCK)));
    assert!(!pipeline.streamed());
    // Chunks land in pieces, as `OP_SENDINGPART` frames do.
    assert!(pipeline.arrived(t0, BLOCK, 400));
    assert!(pipeline.arrived(t0, BLOCK + 400, 600));
    assert!(pipeline.streamed());
}

#[test]
fn the_depth_covers_twice_the_rate_times_the_round_trip() {
    let t0 = Instant::now();
    let mut pipeline = Pipeline::new();
    pipeline.begin(0, 100 * BLOCK);
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
    let mut pipeline = Pipeline::new();
    pipeline.begin(0, 100 * BLOCK);
    pipeline.next_request(t0);
    let first = t0 + Duration::from_secs(1);
    pipeline.arrived(first, 0, 1);
    pipeline.arrived(first + Duration::from_secs(1), 1, 100 * 1024 * 1024);
    assert_eq!(pipeline.depth(), 24);
}

#[test]
fn a_reassignment_leaves_the_old_blocks_draining_against_the_depth() {
    let t0 = Instant::now();
    let mut pipeline = Pipeline::new();
    pipeline.begin(0, 10 * BLOCK);
    pipeline.next_request(t0);
    let old = 10 * BLOCK;
    pipeline.begin(old * 3, old * 4);
    // Three old blocks still fill the depth: nothing new goes out yet.
    assert_eq!(pipeline.next_request(t0), None);
    assert!(
        !deliver(&mut pipeline, t0, (0, BLOCK)),
        "an old block is not the new part's"
    );
    assert_eq!(
        pipeline.next_request(t0),
        Some(vec![(3 * old, 3 * old + BLOCK)])
    );
    // The new stream's first request waits for its first byte.
    assert!(!deliver(&mut pipeline, t0, (BLOCK, 2 * BLOCK)));
    assert_eq!(pipeline.next_request(t0), None);
    assert!(deliver(&mut pipeline, t0, (3 * old, 3 * old + 10)));
    assert_eq!(
        pipeline.next_request(t0),
        Some(vec![(3 * old + BLOCK, 3 * old + 2 * BLOCK)])
    );
}

#[test]
fn bytes_inside_no_asked_block_go_nowhere() {
    let t0 = Instant::now();
    let mut pipeline = Pipeline::new();
    pipeline.begin(0, 10 * BLOCK);
    pipeline.next_request(t0);
    assert!(!pipeline.arrived(t0, 5 * BLOCK, 100));
}

#[test]
fn out_of_part_reqs_empties_the_pipeline() {
    let t0 = Instant::now();
    let mut pipeline = Pipeline::new();
    pipeline.begin(0, 10 * BLOCK);
    pipeline.next_request(t0);
    pipeline.requeued();
    pipeline.begin(0, 10 * BLOCK);
    assert_eq!(
        pipeline.next_request(t0),
        Some(vec![(0, BLOCK), (BLOCK, 2 * BLOCK), (2 * BLOCK, 3 * BLOCK)])
    );
}

#[test]
fn a_lost_block_frees_its_depth_and_is_a_hole_only_in_the_streamed_range() {
    let t0 = Instant::now();
    let mut pipeline = Pipeline::new();
    pipeline.begin(0, 10 * BLOCK);
    assert!(pipeline.next_request(t0).is_some());
    assert!(deliver(&mut pipeline, t0, (0, BLOCK)));
    assert_eq!(
        pipeline.next_request(t0),
        Some(vec![(3 * BLOCK, 4 * BLOCK)])
    );
    assert!(
        pipeline.lost(BLOCK),
        "a block of the streamed range is a hole"
    );

    // A new part: the two blocks still asked of the old one drain against
    // the depth, until one of them is lost.
    pipeline.begin(20 * BLOCK, 30 * BLOCK);
    assert_eq!(
        pipeline.next_request(t0),
        Some(vec![(20 * BLOCK, 21 * BLOCK)])
    );
    assert_eq!(pipeline.next_request(t0), None);
    assert!(!pipeline.lost(2 * BLOCK), "an old part's block is no hole");
    assert!(deliver(&mut pipeline, t0, (20 * BLOCK, 21 * BLOCK)));
    assert_eq!(
        pipeline.next_request(t0),
        Some(vec![(21 * BLOCK, 22 * BLOCK), (22 * BLOCK, 23 * BLOCK)])
    );
}
