//! Block-level parts on the wire (ADR-0117), read off the tap: which parts
//! rmule asked of two or more seeds, when its asks first covered the whole
//! file, when it gave a seed's granted slot back, and how a stock seed served
//! the asks that leave the 180 KiB grid or reach into two parts.
//!
//! aMule files each range of an `OP_REQUESTPARTS` as it stands
//! (`UploadClient.cpp:495-524`, stock 2.3.3) and reads a block from its own
//! start offset (`:219-230`), so its source draws no line at the grid or at a
//! part boundary; the counts here say whether the wire agrees.

use std::collections::{BTreeMap, BTreeSet};

use rmule_primitives::{ED2K_PART_SIZE, EMBLOCKSIZE};
use serde::Serialize;

use super::pace::{LinkEvent, SeedLinks, union_len};
use super::replay::LogEvent;
use crate::flow::nat::claims::{Claim, Evidence};

/// What the tap shows of block-level parts.
#[derive(Debug, Default)]
pub(crate) struct Blocks {
    /// Per part, the seeds (by index) rmule asked for a range in it, kept only
    /// where two or more were.
    pub(crate) shared_parts: BTreeMap<u32, BTreeSet<usize>>,
    /// When the union of every range rmule asked first covered the file.
    pub(crate) whole_file_asked_at: Option<f64>,
    /// The bytes no ask had covered yet at each of rmule's
    /// `OP_CANCELTRANSFER`s: (time, seed index, bytes).
    pub(crate) cancels: Vec<(f64, usize, u64)>,
    /// How the seeds served the asks off the grid or across two parts.
    pub(crate) asks: AskShapes,
}

/// The asks a stock uploader had to take as ordinary requests, and whether
/// it served them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct AskShapes {
    /// Ranges that start off their part's 180 KiB grid or end short of their
    /// block's end.
    pub(crate) off_grid_asked: usize,
    /// Of those, the ones the seed's data on the same link covered.
    pub(crate) off_grid_served: usize,
    /// `OP_REQUESTPARTS` frames whose ranges fall in two or more parts.
    pub(crate) two_part_requests: usize,
    /// Of those, the ones whose every range the same link's data covered.
    pub(crate) two_part_served: usize,
    /// Requests that left the link's queue of asked, unbegun blocks holding
    /// two or more parts.
    pub(crate) two_part_pipelines: usize,
    /// Of those, the ones whose every queued range the link's data covered.
    pub(crate) two_part_pipelines_served: usize,
    /// Compressed data frames: their unpacked bytes are not on the wire, so
    /// the bytes landing twice count only the plain frames.
    pub(crate) packed_data_frames: usize,
}

/// Read the block-level picture of `links` for a file of `size` bytes.
pub(crate) fn read(links: &SeedLinks, size: u64) -> Blocks {
    let mut blocks = Blocks::default();
    let mut asked: Vec<(f64, usize, u64, u64)> = Vec::new();
    let mut cancels: Vec<(f64, usize)> = Vec::new();
    let mut seeds_by_part: BTreeMap<u32, BTreeSet<usize>> = BTreeMap::new();
    for (seed, connections) in links.iter().enumerate() {
        for events in connections {
            let served = Served::of(events);
            // Asked and not yet begun: aMule's queue of requested blocks.
            let mut pipeline: Vec<(u64, u64)> = Vec::new();
            for (at, event) in events {
                match event {
                    LinkEvent::Request(ranges) => {
                        for range in ranges {
                            if !pipeline.contains(range) {
                                pipeline.push(*range);
                            }
                        }
                        let pipeline_parts: BTreeSet<u32> =
                            pipeline.iter().map(|&(start, _)| part_of(start)).collect();
                        if pipeline_parts.len() > 1 {
                            blocks.asks.two_part_pipelines += 1;
                            blocks.asks.two_part_pipelines_served += usize::from(
                                pipeline
                                    .iter()
                                    .all(|&(start, end)| served.covers(start, end)),
                            );
                        }
                        let parts: BTreeSet<u32> =
                            ranges.iter().map(|&(start, _)| part_of(start)).collect();
                        for &(start, end) in ranges {
                            asked.push((*at, seed, start, end));
                            if off_grid(start, end, size) {
                                blocks.asks.off_grid_asked += 1;
                                blocks.asks.off_grid_served +=
                                    usize::from(served.covers(start, end));
                            }
                        }
                        for &part in &parts {
                            seeds_by_part.entry(part).or_default().insert(seed);
                        }
                        if parts.len() > 1 {
                            blocks.asks.two_part_requests += 1;
                            blocks.asks.two_part_served += usize::from(
                                ranges.iter().all(|&(start, end)| served.covers(start, end)),
                            );
                        }
                    }
                    LinkEvent::Cancel => cancels.push((*at, seed)),
                    LinkEvent::Data { start, packed, .. } => {
                        pipeline.retain(|&(from, to)| !(from <= *start && *start < to));
                        blocks.asks.packed_data_frames += usize::from(*packed);
                    }
                    LinkEvent::Segment => {}
                }
            }
        }
    }
    blocks.shared_parts = seeds_by_part
        .into_iter()
        .filter(|(_, seeds)| seeds.len() > 1)
        .collect();
    asked.sort_by(|a, b| a.0.total_cmp(&b.0));
    // The bytes the first `n` asks leave uncovered, falling as `n` grows.
    let unasked = |n: usize| {
        let mut covered: Vec<(u64, u64)> = asked[..n]
            .iter()
            .map(|&(_, _, start, end)| (start, end.min(size)))
            .collect();
        size.saturating_sub(union_len(&mut covered))
    };
    blocks.cancels = cancels
        .into_iter()
        .map(|(at, seed)| (at, seed, unasked(asked.partition_point(|ask| ask.0 < at))))
        .collect();
    let whole = (0..=asked.len()).collect::<Vec<_>>();
    let first_whole = whole.partition_point(|&n| unasked(n) > 0);
    blocks.whole_file_asked_at = first_whole
        .checked_sub(1)
        .filter(|_| first_whole <= asked.len())
        .map(|n| asked[n].0);
    blocks
}

/// ADR-0117: a part's blocks are shared among the granted seeds that hold it.
pub(crate) fn seeds_share_a_part(blocks: &Blocks, roles: &[String]) -> Claim {
    let widest = blocks
        .shared_parts
        .iter()
        .max_by_key(|(_, seeds)| seeds.len());
    Claim::about(
        "two-or-more-seeds-ask-blocks-of-one-part",
        widest.is_some(),
        Evidence::Captured,
        widest.map_or_else(
            || "every part's ranges went to one seed".to_owned(),
            |(part, seeds)| {
                format!(
                    "{} parts asked of two or more seeds; part {part} of {}",
                    blocks.shared_parts.len(),
                    seeds
                        .iter()
                        .map(|&seed| roles.get(seed).map_or("?", String::as_str))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            },
        ),
    )
}

/// ADR-0117: a granted worker keeps its slot while an unclaimed block is left.
/// A block is claimed before it is asked, so a slot given back once every
/// block was asked was given back after every block was claimed; a slot given
/// back earlier fails the reading, though the block may have been claimed
/// and not yet asked.
pub(crate) fn no_slot_given_back_early(
    blocks: &Blocks,
    events: &[LogEvent],
    roles: &[String],
) -> Claim {
    let retired = events
        .iter()
        .filter(
            |event| matches!(event, LogEvent::Retired { reason, .. } if reason == "no_free_part"),
        )
        .count();
    let early: Vec<&(f64, usize, u64)> = blocks
        .cancels
        .iter()
        .filter(|&&(_, _, unasked)| unasked > 0)
        .collect();
    Claim::about(
        "no-seed-is-retired-no-free-part-before-every-block-is-claimed",
        early.is_empty(),
        Evidence::Captured,
        format!(
            "{retired} no_free_part retirements logged, {} OP_CANCELTRANSFER on the tap; every \
             block asked at {}; {} cancels came earlier{}",
            blocks.cancels.len(),
            blocks
                .whole_file_asked_at
                .map_or_else(|| "no instant".to_owned(), |at| format!("{at:.3}")),
            early.len(),
            early
                .first()
                .map_or_else(String::new, |&&(at, seed, unasked)| {
                    format!(
                        ", the first to {} at {at:.3} with {unasked} bytes unasked",
                        roles.get(seed).map_or("?", String::as_str)
                    )
                })
        ),
    )
}

/// The part `offset` falls in.
fn part_of(offset: u64) -> u32 {
    u32::try_from(offset / ED2K_PART_SIZE).unwrap_or(u32::MAX)
}

/// Whether `[start, end)` leaves its part's 180 KiB grid: it starts between
/// two grid lines, or ends short of the block it starts.
fn off_grid(start: u64, end: u64, size: u64) -> bool {
    let part_start = u64::from(part_of(start)) * ED2K_PART_SIZE;
    let part_end = (part_start + ED2K_PART_SIZE).min(size);
    let block_end = (start + EMBLOCKSIZE).min(part_end);
    (start - part_start) % EMBLOCKSIZE != 0 || end != block_end
}

/// The file bytes one link delivered.
struct Served {
    /// The plain frames' ranges, merged and sorted.
    plain: Vec<(u64, u64)>,
    /// The start offsets compressed frames named: aMule names a packed
    /// block's start in each of its frames.
    packed_starts: BTreeSet<u64>,
}

impl Served {
    fn of(events: &[(f64, LinkEvent)]) -> Self {
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        let mut packed_starts = BTreeSet::new();
        for (_, event) in events {
            match *event {
                LinkEvent::Data {
                    start,
                    len,
                    packed: false,
                } => ranges.push((start, start + len)),
                LinkEvent::Data {
                    start,
                    packed: true,
                    ..
                } => {
                    packed_starts.insert(start);
                }
                _ => {}
            }
        }
        ranges.sort_unstable();
        let mut plain: Vec<(u64, u64)> = Vec::new();
        for (start, end) in ranges {
            match plain.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => plain.push((start, end)),
            }
        }
        Self {
            plain,
            packed_starts,
        }
    }

    /// Whether the link delivered all of `[start, end)`.
    fn covers(&self, start: u64, end: u64) -> bool {
        if self.packed_starts.contains(&start) {
            return true;
        }
        let at = self.plain.partition_point(|&(_, to)| to <= start);
        self.plain
            .get(at)
            .is_some_and(|&(from, to)| from <= start && end <= to)
    }
}

#[cfg(test)]
mod tests;
