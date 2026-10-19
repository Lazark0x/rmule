use super::*;

const PART: u64 = ED2K_PART_SIZE;
const BLOCK: u64 = EMBLOCKSIZE;
/// One whole part and two blocks of a second.
const SIZE: u64 = PART + 2 * BLOCK;

fn roles() -> Vec<String> {
    vec!["a".to_owned(), "b".to_owned()]
}

fn data(at: f64, start: u64, end: u64) -> (f64, LinkEvent) {
    (
        at,
        LinkEvent::Data {
            start,
            len: end - start,
            packed: false,
        },
    )
}

/// Seed a asks the first part; seed b the second part's two blocks and, at
/// `b_cancel`, gives its slot back.
fn links(b_cancel: f64) -> SeedLinks {
    let a = vec![(1.0, LinkEvent::Request(vec![(0, PART)]))];
    let b = vec![
        (2.0, LinkEvent::Request(vec![(PART, PART + BLOCK)])),
        (3.0, LinkEvent::Request(vec![(PART + BLOCK, SIZE)])),
        (b_cancel, LinkEvent::Cancel),
    ];
    vec![vec![a], vec![b]]
}

#[test]
fn a_slot_given_back_once_every_block_was_asked_holds() {
    let blocks = read(&links(4.0), SIZE);
    assert_eq!(blocks.whole_file_asked_at, Some(3.0));
    assert_eq!(blocks.cancels, vec![(4.0, 1, 0)]);
    let claim = no_slot_given_back_early(&blocks, &[], &roles());
    assert_eq!(claim.outcome, "held", "{}", claim.note);
}

#[test]
fn a_slot_given_back_with_a_block_unasked_fails() {
    let blocks = read(&links(2.5), SIZE);
    assert_eq!(blocks.cancels, vec![(2.5, 1, BLOCK)]);
    let claim = no_slot_given_back_early(&blocks, &[], &roles());
    assert_eq!(claim.outcome, "absent", "{}", claim.note);
    assert!(claim.note.contains("to b at 2.500"), "{}", claim.note);
}

#[test]
fn two_seeds_asked_in_one_part_share_it() {
    let one_each = read(&links(4.0), SIZE);
    assert!(one_each.shared_parts.is_empty());
    let mut shared = links(4.0);
    shared[0][0].push((5.0, LinkEvent::Request(vec![(PART + BLOCK, SIZE)])));
    let blocks = read(&shared, SIZE);
    assert_eq!(
        blocks.shared_parts.keys().copied().collect::<Vec<_>>(),
        vec![1]
    );
    let claim = seeds_share_a_part(&blocks, &roles());
    assert_eq!(claim.outcome, "held");
    assert!(claim.note.ends_with("part 1 of a, b"), "{}", claim.note);
}

/// A range a byte short of its block and one starting between grid lines
/// are off the grid; a pipeline naming two parts is one request. Each counts
/// as served only where the link's data covered it.
#[test]
fn off_grid_and_two_part_asks_count_as_served_only_when_delivered() {
    let short = (PART - BLOCK, PART - 1);
    let between = (BLOCK + 10, 2 * BLOCK);
    let events = vec![
        (
            1.0,
            LinkEvent::Request(vec![short, (PART, PART + BLOCK), between]),
        ),
        data(1.1, PART - BLOCK, PART - 1),
        data(1.2, PART, PART + BLOCK),
        data(1.3, BLOCK + 10, BLOCK + 20),
    ];
    let blocks = read(&vec![vec![events]], SIZE);
    assert_eq!(
        blocks.asks,
        AskShapes {
            off_grid_asked: 2,
            off_grid_served: 1,
            two_part_requests: 1,
            two_part_served: 0,
            packed_data_frames: 0,
        }
    );
}
