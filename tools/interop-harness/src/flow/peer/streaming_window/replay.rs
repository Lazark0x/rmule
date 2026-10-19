//! The download's part decisions, replayed from rmule's own log against the
//! parts each seed advertised on the wire (ADR-0112 §4, §6).
//!
//! The log orders every `download.part_assigned`, `part_released`,
//! `part_verified` and `peer_retired` exactly as the scheduler made them; the
//! wire says what each seed advertised. An assignment is a worker's first
//! handout in a part (ADR-0117): every handout fills from the first-ranked
//! part that still has an unclaimed block, by the minimum of `(very rare,
//! band, window, key)` over the parts the worker's seed advertised, `key =
//! (0, i)` inside the **Streaming Window** and `(frequency, i)` outside it.
//! The log does not say when a started part's blocks are all claimed, so a
//! part nobody started is the bound: an assignment matches when its part ranks
//! no lower than every unverified part the seed advertised that no worker
//! holds — a started part ahead of them, or the first of them. The
//! scheduler's own rank is not called: the bench restates it from the ADR, so
//! a drift in either shows.
//!
//! **Part Frequency** counts the sources whose status rmule has read. The log
//! carries no time, so the `download parts_tick` lines around an assignment
//! bound it: a seed whose status crossed the tap before the tick ahead of the
//! line (less a margin) was surely read, one whose status crossed after the
//! tick behind it surely was not, and every set between the two is tried. An
//! assignment matches when one of them names its part, and is ambiguous when
//! they disagree.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddrV4};

use rmule_primitives::{ED2K_PART_SIZE, part_count};

/// The retirement code of a source that holds nothing we need: its record
/// stays in the book (ADR-0112 §6).
const NO_NEEDED_PARTS: &str = "no_needed_parts";
/// How long after a status crosses the tap rmule is taken to have read it.
const STATUS_READ_MARGIN_SECS: f64 = 0.5;

/// One line of rmule's log the replay reads.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum LogEvent {
    /// `download.part_assigned`.
    Assigned {
        /// The worker's peer.
        peer: Ipv4Addr,
        /// The part.
        part: u32,
    },
    /// `download.part_released`.
    Released {
        /// The worker's peer.
        peer: Ipv4Addr,
        /// The part.
        part: u32,
        /// Why the worker was retired, when that released the part.
        retired: Option<String>,
    },
    /// `download.end_game_blocks`: a Duplicate Set handed (ADR-0117).
    EndGame {
        /// The worker's peer.
        peer: Ipv4Addr,
        /// The part.
        part: u32,
        /// How many blocks.
        blocks: u32,
        /// Their bytes.
        bytes: u64,
    },
    /// `download.part_verified`.
    Verified {
        /// The part.
        part: u32,
    },
    /// `download.part_corrupt`: the part failed its check with no root to
    /// name its bad cells, its bytes are dropped and every worker lets it go
    /// at once, with no `part_released` of its own (ADR-0117 §1).
    Corrupt {
        /// The part.
        part: u32,
    },
    /// `download.peer_retired`.
    Retired {
        /// The worker's peer.
        peer: Ipv4Addr,
        /// The reason's code, as `no_needed_parts`.
        reason: String,
    },
    /// `download.source_reasked_over_tcp`: the Remote-Queued Pool's TCP full
    /// ask.
    ReaskedOverTcp {
        /// The source.
        peer: Ipv4Addr,
    },
    /// `download.source_remote_queued`.
    RemoteQueued {
        /// The source.
        peer: Ipv4Addr,
    },
    /// `download parts_tick`: the positional part map at a wall-clock instant.
    Tick {
        /// Unix seconds.
        at: f64,
        /// One letter per part: `V`, `I` or `M`.
        parts: String,
    },
    /// `download.completed`.
    Completed,
}

/// The log lines of download `id` the replay reads, in order.
pub(crate) fn parse_log(text: &str, id: u64) -> Vec<LogEvent> {
    text.lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let head = words.next()?;
            let head = if head == "download" {
                words.next()?
            } else {
                head.strip_prefix("download.")?
            };
            let fields: BTreeMap<&str, &str> =
                words.filter_map(|word| word.split_once('=')).collect();
            if fields.get("id")?.parse::<u64>().ok()? != id {
                return None;
            }
            let peer = || {
                fields
                    .get("peer")
                    .and_then(|peer| peer.parse::<SocketAddrV4>().ok())
                    .map(|peer| *peer.ip())
            };
            let part = || fields.get("part_index").and_then(|part| part.parse().ok());
            Some(match head {
                "part_assigned" => LogEvent::Assigned {
                    peer: peer()?,
                    part: part()?,
                },
                "part_released" => LogEvent::Released {
                    peer: peer()?,
                    part: part()?,
                    retired: fields.get("retired").map(|why| (*why).to_owned()),
                },
                "end_game_blocks" => LogEvent::EndGame {
                    peer: peer()?,
                    part: part()?,
                    blocks: fields.get("blocks")?.parse().ok()?,
                    bytes: fields.get("bytes")?.parse().ok()?,
                },
                "part_verified" => LogEvent::Verified { part: part()? },
                "part_corrupt" => LogEvent::Corrupt { part: part()? },
                "peer_retired" => LogEvent::Retired {
                    peer: peer()?,
                    reason: (*fields.get("reason")?).to_owned(),
                },
                "source_remote_queued" => LogEvent::RemoteQueued { peer: peer()? },
                "source_reasked_over_tcp" => LogEvent::ReaskedOverTcp { peer: peer()? },
                "parts_tick" => LogEvent::Tick {
                    at: fields.get("at_unix_ms")?.parse::<f64>().ok()? / 1000.0,
                    parts: (*fields.get("parts")?).to_owned(),
                },
                "completed" => LogEvent::Completed,
                _ => return None,
            })
        })
        .collect()
}

/// What the replay reads besides the log.
pub(crate) struct Topology<'a> {
    /// The stream file's size.
    pub(crate) size: u64,
    /// The Streaming Window's width `N`.
    pub(crate) window_parts: u32,
    /// Each seed's advertised parts, off the wire.
    pub(crate) advertised: &'a BTreeMap<Ipv4Addr, BTreeSet<u32>>,
    /// When each seed's first status crossed the tap.
    pub(crate) first_status_at: &'a BTreeMap<Ipv4Addr, f64>,
}

/// What the scheduler may hand a worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Pick {
    /// A part no worker holds blocks of.
    Fresh(u32),
    /// A part another worker started, whose blocks it shares (ADR-0117).
    Shared(u32),
}

/// One assignment, replayed.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Decision {
    /// The worker's peer.
    pub(crate) peer: Ipv4Addr,
    /// What it was handed.
    pub(crate) actual: Pick,
    /// What the rank allows, over every reading of what rmule knew.
    pub(crate) expected: BTreeSet<Pick>,
    /// The readings disagree on what the rank allows.
    pub(crate) readings_disagree: bool,
    /// The peer's first assignment.
    pub(crate) first_for_peer: bool,
    /// The part lay in the Streaming Window.
    pub(crate) in_window: bool,
    /// The part was very rare, under the first reading that named it.
    pub(crate) very_rare: bool,
    /// The part is in the Preview Band.
    pub(crate) band: bool,
}

impl Decision {
    /// The rank names this assignment under some reading.
    pub(crate) fn matched(&self) -> bool {
        self.expected.contains(&self.actual)
    }

    /// The readings disagree.
    pub(crate) fn ambiguous(&self) -> bool {
        self.readings_disagree
    }
}

/// One `NoNeededParts` retirement.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Retirement {
    /// The retired peer.
    pub(crate) peer: Ipv4Addr,
    /// Advertised parts still unverified when it was retired — empty is §6.
    pub(crate) lacked: BTreeSet<u32>,
    /// The last tick before the line: the earliest it can have happened.
    pub(crate) not_before: Option<f64>,
    /// The first tick after the line: the latest it can have happened.
    pub(crate) not_after: Option<f64>,
}

/// The replayed run.
#[derive(Debug, Default)]
pub(crate) struct Replay {
    /// Every assignment, in order.
    pub(crate) decisions: Vec<Decision>,
    /// Every `NoNeededParts` retirement, in order.
    pub(crate) retirements: Vec<Retirement>,
    /// Every Duplicate Set the End Game handed, in order: blocks and bytes.
    pub(crate) end_game_sets: Vec<(u32, u64)>,
    /// Sources that entered the Remote-Queued Pool.
    pub(crate) remote_queued: BTreeSet<Ipv4Addr>,
    /// Sources the Remote-Queued Pool re-asked by the TCP full ask.
    pub(crate) reasked_over_tcp: BTreeSet<Ipv4Addr>,
    /// Every tick, in order: unix seconds and the part map.
    pub(crate) ticks: Vec<(f64, String)>,
    /// Ticks whose part map disagrees with the replayed one.
    pub(crate) tick_mismatches: usize,
    /// Assignments to a peer whose status the tap never showed.
    pub(crate) unjudged: usize,
    /// The download completed.
    pub(crate) completed: bool,
}

/// The scheduler's partition as the log moves it: the verified parts, and
/// who started each part not yet verified and has not let it go.
#[derive(Default)]
struct Parts {
    verified: BTreeSet<u32>,
    holders: BTreeMap<u32, BTreeSet<Ipv4Addr>>,
}

impl Parts {
    /// `peer` let `part` go.
    fn release(&mut self, peer: Ipv4Addr, part: u32) {
        if let Some(holders) = self.holders.get_mut(&part) {
            holders.remove(&peer);
            if holders.is_empty() {
                self.holders.remove(&part);
            }
        }
    }

    /// `peer`'s worker ended: it holds nothing.
    fn leave(&mut self, peer: Ipv4Addr) {
        self.holders.retain(|_, holders| {
            holders.remove(&peer);
            !holders.is_empty()
        });
    }

    fn letter(&self, part: u32) -> char {
        if self.verified.contains(&part) {
            'V'
        } else if self.holders.contains_key(&part) {
            'I'
        } else {
            'M'
        }
    }
}

/// Replay `events` against `topology`.
pub(crate) fn replay(events: &[LogEvent], topology: &Topology<'_>) -> Replay {
    let tick_at: Vec<Option<f64>> = events
        .iter()
        .map(|event| match event {
            LogEvent::Tick { at, .. } => Some(*at),
            _ => None,
        })
        .collect();
    let tick_before = |index: usize| tick_at[..index].iter().rev().find_map(|at| *at);
    let tick_after = |index: usize| tick_at[index + 1..].iter().find_map(|at| *at);
    let total = part_count(topology.size);
    let band = preview_band(topology.size);
    let mut parts = Parts::default();
    let mut assigned_peers: BTreeSet<Ipv4Addr> = BTreeSet::new();
    // Peers whose worker ended with no queue standing: their record left the
    // book, and its Advertised Parts left Part Frequency (ADR-0112 §2), until
    // a fresh status brings them back.
    let mut departed: BTreeSet<Ipv4Addr> = BTreeSet::new();
    let mut out = Replay::default();
    for (index, event) in events.iter().enumerate() {
        match event {
            LogEvent::Assigned { peer, part } => {
                departed.remove(peer);
                let Some(held) = topology.advertised.get(peer) else {
                    out.unjudged += 1;
                    parts.holders.entry(*part).or_default().insert(*peer);
                    continue;
                };
                let known = known_bounds(
                    topology,
                    &assigned_peers,
                    &departed,
                    *peer,
                    tick_before(index),
                    tick_after(index),
                );
                let window = window(&parts, total, topology.window_parts);
                let mut expected = BTreeSet::new();
                let mut allowed_by_reading: Vec<BTreeSet<Pick>> = Vec::new();
                let mut class = None;
                let actual = if parts.holders.contains_key(part) {
                    Pick::Shared(*part)
                } else {
                    Pick::Fresh(*part)
                };
                for reading in &known {
                    let frequency = frequency(topology.advertised, reading, total);
                    let bound = very_rare_bound(reading.len());
                    let rank = |candidate: u32| {
                        let count = frequency[candidate as usize];
                        let in_window = window.contains(&candidate);
                        (
                            count > bound,
                            !band.contains(&candidate),
                            !in_window,
                            if in_window { 0 } else { count },
                            candidate,
                        )
                    };
                    let allowed = picks(&parts, held, total, rank);
                    if allowed.contains(&actual) && class.is_none() {
                        class = Some(frequency[*part as usize] <= bound);
                    }
                    expected.extend(allowed.iter().copied());
                    allowed_by_reading.push(allowed);
                }
                out.decisions.push(Decision {
                    peer: *peer,
                    actual,
                    expected,
                    readings_disagree: allowed_by_reading.windows(2).any(|pair| pair[0] != pair[1]),
                    first_for_peer: !assigned_peers.contains(peer),
                    in_window: window.contains(part),
                    very_rare: class.unwrap_or(false),
                    band: band.contains(part),
                });
                assigned_peers.insert(*peer);
                parts.holders.entry(*part).or_default().insert(*peer);
            }
            LogEvent::Released {
                peer,
                part,
                retired,
            } => {
                parts.release(*peer, *part);
                if retired.as_deref().is_some_and(|why| why != NO_NEEDED_PARTS) {
                    departed.insert(*peer);
                }
            }
            LogEvent::EndGame { blocks, bytes, .. } => {
                out.end_game_sets.push((*blocks, *bytes));
            }
            LogEvent::Verified { part } => {
                parts.holders.remove(part);
                parts.verified.insert(*part);
            }
            LogEvent::Corrupt { part } => {
                parts.holders.remove(part);
            }
            LogEvent::Retired { peer, reason } => {
                if reason != NO_NEEDED_PARTS {
                    departed.insert(*peer);
                } else {
                    let lacked = topology
                        .advertised
                        .get(peer)
                        .map(|held| held.difference(&parts.verified).copied().collect())
                        .unwrap_or_default();
                    out.retirements.push(Retirement {
                        peer: *peer,
                        lacked,
                        not_before: tick_before(index),
                        not_after: tick_after(index),
                    });
                }
                parts.leave(*peer);
            }
            LogEvent::ReaskedOverTcp { peer } => {
                out.reasked_over_tcp.insert(*peer);
            }
            LogEvent::RemoteQueued { peer } => {
                departed.remove(peer);
                out.remote_queued.insert(*peer);
            }
            LogEvent::Tick { at, parts: map } => {
                let replayed: String = (0..total).map(|part| parts.letter(part)).collect();
                if *map != replayed {
                    out.tick_mismatches += 1;
                }
                out.ticks.push((*at, map.clone()));
            }
            LogEvent::Completed => out.completed = true,
        }
    }
    out
}

/// Every set of seeds rmule may have read the status of at this assignment:
/// from the surely-read to the possibly-read, each subset between.
fn known_bounds(
    topology: &Topology<'_>,
    assigned: &BTreeSet<Ipv4Addr>,
    departed: &BTreeSet<Ipv4Addr>,
    peer: Ipv4Addr,
    tick_before: Option<f64>,
    tick_after: Option<f64>,
) -> Vec<BTreeSet<Ipv4Addr>> {
    let mut surely: BTreeSet<Ipv4Addr> = assigned
        .iter()
        .chain([&peer])
        .filter(|seed| topology.advertised.contains_key(seed) && !departed.contains(seed))
        .copied()
        .collect();
    let mut maybe = Vec::new();
    for (seed, at) in topology.first_status_at {
        if surely.contains(seed)
            || departed.contains(seed)
            || !topology.advertised.contains_key(seed)
        {
            continue;
        }
        if tick_before.is_some_and(|before| *at < before - STATUS_READ_MARGIN_SECS) {
            surely.insert(*seed);
        } else if tick_after.is_none_or(|after| *at <= after) {
            maybe.push(*seed);
        }
    }
    (0..1_usize << maybe.len())
        .map(|mask| {
            let mut reading = surely.clone();
            reading.extend(
                maybe
                    .iter()
                    .enumerate()
                    .filter(|(bit, _)| mask >> bit & 1 == 1)
                    .map(|(_, seed)| *seed),
            );
            reading
        })
        .collect()
}

/// Per part, how many of the `known` seeds advertised it.
fn frequency(
    advertised: &BTreeMap<Ipv4Addr, BTreeSet<u32>>,
    known: &BTreeSet<Ipv4Addr>,
    total: u32,
) -> Vec<u32> {
    let mut frequency = vec![0; total as usize];
    for held in known.iter().filter_map(|seed| advertised.get(seed)) {
        for part in held.iter().filter(|part| **part < total) {
            frequency[*part as usize] += 1;
        }
    }
    frequency
}

/// What the scheduler may open for a worker whose seed advertised `held`
/// (ADR-0117): an unverified part it advertised that ranks no lower than every
/// such part nobody holds — the first of those, or a started part ahead of
/// them, whose unclaimed blocks the log cannot see. With every such part
/// started, any of them.
fn picks(
    parts: &Parts,
    held: &BTreeSet<u32>,
    total: u32,
    rank: impl Fn(u32) -> (bool, bool, bool, u32, u32),
) -> BTreeSet<Pick> {
    let candidates: Vec<u32> = (0..total)
        .filter(|part| held.contains(part) && !parts.verified.contains(part))
        .collect();
    let bound = candidates
        .iter()
        .copied()
        .filter(|part| !parts.holders.contains_key(part))
        .map(&rank)
        .min();
    candidates
        .into_iter()
        .filter(|&part| bound.is_none_or(|bound| rank(part) <= bound))
        .map(|part| {
            if parts.holders.contains_key(&part) {
                Pick::Shared(part)
            } else {
                Pick::Fresh(part)
            }
        })
        .collect()
}

/// The Streaming Window: `n` parts from the lowest unverified one.
fn window(parts: &Parts, total: u32, n: u32) -> std::ops::Range<u32> {
    match (0..total).find(|part| !parts.verified.contains(part)) {
        Some(anchor) => anchor..anchor.saturating_add(n),
        None => 0..0,
    }
}

/// aMule's very-rare bound for `known` sources (ADR-0112 §4): `max(1, m ×
/// known / 100)`, `m` 10, 5 above 200 sources and 2 above 800.
fn very_rare_bound(known: usize) -> u32 {
    let modif = match known {
        0..=200 => 10,
        201..=800 => 5,
        _ => 2,
    };
    u32::try_from(modif * known / 100)
        .unwrap_or(u32::MAX)
        .max(1)
}

/// The Preview Band (ADR-0112 §5): part `0`, the last, and the last but one
/// when the last part's length plus one is below a third of a part.
pub(crate) fn preview_band(size: u64) -> BTreeSet<u32> {
    let total = part_count(size);
    let Some(last) = total.checked_sub(1) else {
        return BTreeSet::new();
    };
    let mut band = BTreeSet::from([0, last]);
    let last_len = size - u64::from(last) * ED2K_PART_SIZE;
    if last >= 1 && last_len + 1 < ED2K_PART_SIZE / 3 {
        band.insert(last - 1);
    }
    band
}

#[cfg(test)]
mod tests;
