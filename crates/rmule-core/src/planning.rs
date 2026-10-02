//! Turning a file size into the part ranges a download works: the full plan, the
//! plan for what a restart still misses, and the single part at an index. aMule's
//! part geometry is the rule — a file that is an exact multiple of the part size
//! carries a trailing zero-length part — so every consumer counts parts the same
//! way the wire does.

use std::collections::HashSet;

use rmule_primitives::{ED2K_PART_SIZE, part_count};

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
    /// which is short and may be zero on an exact multiple.
    pub len: u64,
}

pub(crate) fn plan_part_ranges(file_size: u64) -> Vec<PartPlan> {
    plan_missing_part_ranges(file_size, &[])
}

pub(crate) fn plan_missing_part_ranges(file_size: u64, verified_parts: &[u32]) -> Vec<PartPlan> {
    let verified_parts = verified_parts.iter().copied().collect::<HashSet<_>>();
    let count = part_count(file_size);
    (0..count)
        .filter(|part_index| !verified_parts.contains(part_index))
        .map(|part_index| part_plan(file_size, part_index))
        .collect()
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
    use rmule_primitives::ED2K_PART_SIZE;

    #[test]
    fn plans_one_range_per_ed2k_part() {
        let plans = plan_part_ranges(ED2K_PART_SIZE + 10);

        assert_eq!(plans.len(), 2);
        assert_eq!(plans[0].part_index, 0);
        assert_eq!(plans[0].offset, 0);
        assert_eq!(plans[0].len, ED2K_PART_SIZE);
        assert_eq!(plans[1].part_index, 1);
        assert_eq!(plans[1].offset, ED2K_PART_SIZE);
        assert_eq!(plans[1].len, 10);
    }

    #[test]
    fn plans_only_unverified_parts_for_resume() {
        let plans = plan_missing_part_ranges(ED2K_PART_SIZE + 10, &[0]);

        assert_eq!(
            plans,
            vec![PartPlan {
                part_index: 1,
                offset: ED2K_PART_SIZE,
                len: 10,
            }]
        );
    }

    /// Regression for the "ceil twin" boundary: a naive
    /// `(file_size + ED2K_PART_SIZE) / ED2K_PART_SIZE` ceil division would
    /// report a bogus third, zero-length part for a file that is *exactly*
    /// two parts long. Single-part flows (file sizes below one
    /// `ED2K_PART_SIZE`) never cross a part boundary at all, so they can
    /// never expose this.
    #[test]
    fn plans_exact_multiple_of_part_size_without_a_phantom_trailing_part() {
        let file_size = ED2K_PART_SIZE * 2;

        let plans = plan_part_ranges(file_size);

        assert_eq!(plans.len(), 2, "no phantom third part at an exact multiple");
        assert_eq!(
            plans,
            vec![
                PartPlan {
                    part_index: 0,
                    offset: 0,
                    len: ED2K_PART_SIZE,
                },
                PartPlan {
                    part_index: 1,
                    offset: ED2K_PART_SIZE,
                    len: ED2K_PART_SIZE,
                },
            ]
        );
        let last = plans.last().unwrap();
        assert_eq!(
            last.offset + last.len,
            file_size,
            "last range must end exactly at file_size"
        );
    }

    /// Regression for the "ceil twin" boundary: a multi-part
    /// file whose last part is short must agree between `plan_part_ranges`
    /// and `plan_missing_part_ranges` at every combination of verified
    /// parts, including when the *partial* last part is the one being
    /// isolated (as opposed to a whole, full-size part). A single-part flow
    /// never produces this shape, since it has no "other part" to keep
    /// separate from the one being resumed.
    #[test]
    fn plan_missing_part_ranges_agrees_with_plan_part_ranges_across_the_partial_last_part() {
        let file_size = ED2K_PART_SIZE * 2 + 12_345;
        let full = plan_part_ranges(file_size);

        // The twins must agree when nothing is excluded.
        assert_eq!(full, plan_missing_part_ranges(file_size, &[]));
        assert_eq!(full.len(), 3);
        let last = *full.last().unwrap();
        assert_eq!(
            last,
            PartPlan {
                part_index: 2,
                offset: ED2K_PART_SIZE * 2,
                len: 12_345,
            }
        );
        assert_eq!(
            last.offset + last.len,
            file_size,
            "last range must end exactly at file_size"
        );

        // Verifying the two full parts must leave exactly the partial last
        // part missing, with its short length intact.
        let missing_after_full_parts = plan_missing_part_ranges(file_size, &[0, 1]);
        assert_eq!(missing_after_full_parts, vec![last]);

        // Verifying only the partial last part must leave exactly the two
        // full parts missing, unchanged from the twin's own numbers.
        let missing_after_partial_part = plan_missing_part_ranges(file_size, &[2]);
        assert_eq!(missing_after_partial_part, full[..2].to_vec());

        // Verifying everything leaves nothing missing.
        assert!(plan_missing_part_ranges(file_size, &[0, 1, 2]).is_empty());
    }
}
