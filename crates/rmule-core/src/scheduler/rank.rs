//! The rank a candidate part is chosen by (ADR-0112 §4), one pure function
//! beside the scheduler: of the parts a peer advertised, the minimum of
//! `(very rare, band, window, key)` wins, with `key = (0, i)` inside the
//! **Streaming Window** and `(frequency[i], i)` outside it. The part index sits
//! in every key, so no two candidates tie and no randomness is needed where
//! aMule draws `rand()` (stock 2.3.3 `PartFile.cpp:2025-2054`): the same
//! inputs always give the same part.

use std::collections::BTreeSet;
use std::ops::Range;

use rmule_primitives::{ED2K_PART_SIZE, part_count};

/// What one candidate's rank reads besides its index.
pub(super) struct RankInputs<'a> {
    /// **Part Frequency**: per part, how many sources' Advertised Parts hold it.
    pub(super) frequency: &'a [u32],
    /// The frequency at or under which a part is very rare.
    pub(super) very_rare_bound: u32,
    /// The **Preview Band**.
    pub(super) band: &'a BTreeSet<u32>,
    /// The **Streaming Window**.
    pub(super) window: Range<u32>,
}

/// A candidate's rank; the minimum wins. Its fields compare in the order
/// they are declared, `false` ahead of `true`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Rank {
    /// Its frequency is above the very-rare bound.
    common: bool,
    /// It lies outside the **Preview Band**.
    outside_band: bool,
    /// It lies outside the **Streaming Window**.
    outside_window: bool,
    /// `0` inside the window, its frequency outside it.
    frequency: u32,
    /// Its index, so no two candidates tie.
    part: u32,
}

/// The rank of candidate `part`.
pub(super) fn rank(part: u32, inputs: &RankInputs<'_>) -> Rank {
    let frequency = inputs
        .frequency
        .get(part as usize)
        .copied()
        .unwrap_or_default();
    let in_window = inputs.window.contains(&part);
    Rank {
        common: frequency > inputs.very_rare_bound,
        outside_band: !inputs.band.contains(&part),
        outside_window: !in_window,
        frequency: if in_window { 0 } else { frequency },
        part,
    }
}

/// aMule's very-rare bound for `known` sources whose parts are known:
/// `max(1, m × known / 100)`, `m` 10, 5 above 200 sources and 2 above 800
/// (stock 2.3.3 `PartFile.cpp:1926-1939`). Below 20 sources it is 1: a part
/// only one source holds.
pub(super) fn very_rare_bound(known: u32) -> u32 {
    let percent: u64 = if known > 800 {
        2
    } else if known > 200 {
        5
    } else {
        10
    };
    let bound = percent * u64::from(known) / 100;
    u32::try_from(bound).unwrap_or(u32::MAX).max(1)
}

/// aMule's preview parts for a `file_size`-byte file (stock 2.3.3
/// `PartFile.cpp:1958-1972`): the first, the last, and the last-but-one when
/// the last part's length plus one is below `PARTSIZE / 3` — at most
/// 3,242,664 bytes.
pub(super) fn preview_band(file_size: u64) -> BTreeSet<u32> {
    let parts = part_count(file_size);
    let mut band = BTreeSet::new();
    let Some(last) = parts.checked_sub(1) else {
        return band;
    };
    band.insert(0);
    band.insert(last);
    let last_len = file_size - u64::from(last) * ED2K_PART_SIZE;
    if last >= 1 && last_len + 1 < ED2K_PART_SIZE / 3 {
        band.insert(last - 1);
    }
    band
}

#[cfg(test)]
mod tests {
    use super::*;

    /// aMule's preview parts (`PartFile.cpp:1958-1972`): one part is `{0}`,
    /// two are `{0, 1}`, and the last-but-one joins only while the last
    /// part's length plus one is under `PARTSIZE / 3`.
    #[test]
    fn the_preview_band_is_the_head_and_the_tail() {
        assert_eq!(preview_band(ED2K_PART_SIZE), BTreeSet::from([0]));
        assert_eq!(preview_band(2 * ED2K_PART_SIZE), BTreeSet::from([0, 1]));
        assert_eq!(
            preview_band(2 * ED2K_PART_SIZE + 3_242_664),
            BTreeSet::from([0, 1, 2])
        );
        assert_eq!(
            preview_band(2 * ED2K_PART_SIZE + 3_242_665),
            BTreeSet::from([0, 2])
        );
    }
}
