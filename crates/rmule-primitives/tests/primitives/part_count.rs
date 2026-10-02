//! How many parts a file of a given size has — the 9.28 MiB boundary, the
//! short last part, and the saturation above 4 GiB.

use rmule_primitives::{ED2K_PART_SIZE, part_count};

#[test]
fn empty_file_has_zero_parts() {
    assert_eq!(part_count(0), 0);
}

#[test]
fn part_boundary_files_have_exact_count() {
    assert_eq!(part_count(ED2K_PART_SIZE), 1);
    assert_eq!(part_count(ED2K_PART_SIZE * 5), 5);
}

#[test]
fn partial_last_part_is_counted() {
    assert_eq!(part_count(ED2K_PART_SIZE + 1), 2);
    assert_eq!(part_count(ED2K_PART_SIZE * 3 + 100), 4);
}

#[test]
fn large_file_above_4gb_counts_correctly() {
    let size: u64 = 5_000_000_000;
    assert_eq!(part_count(size), 514);
}

#[test]
fn u64_max_saturates_at_u32_max() {
    assert_eq!(part_count(u64::MAX), u32::MAX);
}
