//! Turning a file size into the ranges a download works: the part at an index,
//! and the blocks a worker is handed inside one (ADR-0117). Parts are counted
//! as `part_count` counts them — an exact multiple of the part size has no
//! trailing empty part — so every consumer sees the same geometry.

use rmule_primitives::ED2K_PART_SIZE;

/// One part's geometry: which part it is and the byte range it covers. Derived
/// from the file size alone, so every consumer computes the same ranges the wire
/// does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartPlan {
    /// The zero-based part index within the file.
    pub part_index: u32,
    /// The part's first byte offset in the file — `part_index * ED2K_PART_SIZE`.
    pub offset: u64,
    /// Its length in bytes: the full part size except for the file's last part,
    /// which is short unless the file is an exact multiple of the part size.
    pub len: u64,
}

/// One block a worker is handed to ask (ADR-0117): an absolute byte range
/// inside one part, at most `EMBLOCKSIZE` long.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockPlan {
    /// The zero-based part the block lies in.
    pub part_index: u32,
    /// Its first byte's offset in the file.
    pub start: u64,
    /// The offset just past its last byte.
    pub end: u64,
}

/// The byte range of a single ED2K part within a file of `file_size`. The
/// last part is short when the file size is not a whole multiple of
/// `ED2K_PART_SIZE`.
pub(crate) fn part_plan(file_size: u64, part_index: u32) -> PartPlan {
    let offset = u64::from(part_index) * ED2K_PART_SIZE;
    let remaining = file_size.saturating_sub(offset);
    PartPlan {
        part_index,
        offset,
        len: remaining.min(ED2K_PART_SIZE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmule_primitives::part_count;

    /// A file of exactly two parts has two full parts and no phantom third,
    /// and a short tail is the last part's whole length.
    #[test]
    fn the_last_part_ends_at_the_file_end() {
        let exact = ED2K_PART_SIZE * 2;
        assert_eq!(part_count(exact), 2);
        assert_eq!(
            part_plan(exact, 1),
            PartPlan {
                part_index: 1,
                offset: ED2K_PART_SIZE,
                len: ED2K_PART_SIZE,
            }
        );
        let short = ED2K_PART_SIZE * 2 + 12_345;
        assert_eq!(part_count(short), 3);
        assert_eq!(part_plan(short, 2).len, 12_345);
    }
}
