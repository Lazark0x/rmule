//! How busy each seed's link kept, read off the tap: the measurement the
//! request depth (ADR-0029 "Request pipeline") and the Tail Race (ADR-0026
//! "Bounded racing") are scored by. Per seed: the payload it sent and over
//! what span, the share of that span its link sat idle (gaps over 50 ms
//! between data frames), the time from each `OP_REQUESTPARTS` to the seed's
//! next data, how many asked blocks waited behind the one arriving, and the
//! `OP_CANCELTRANSFER` rmule sent it. Across seeds: the bytes delivered twice.
//!
//! Frames are read by the harness's own reader: `OP_SENDINGPART` (`0xE3
//! 0x46`, 32-bit start and end), `OP_SENDINGPART_I64` (`0xC5 0xA2`),
//! `OP_COMPRESSEDPART` (`0xC5 0x40`, 32-bit start, then the packed length)
//! and `OP_COMPRESSEDPART_I64` (`0xC5 0xA1`); stock 2.3.3
//! `UploadClient.cpp:246-341`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::Result;
use serde::Serialize;

use crate::flow::pcap::{Ed2kFrame, records, tcp_capture};

const OP_EDONKEYPROT: u8 = 0xE3;
const OP_EMULEPROT: u8 = 0xC5;
const OP_COMPRESSEDPART: u8 = 0x40;
const OP_SENDINGPART: u8 = 0x46;
const OP_REQUESTPARTS: u8 = 0x47;
const OP_CANCELTRANSFER: u8 = 0x56;
const OP_COMPRESSEDPART_I64: u8 = 0xA1;
const OP_SENDINGPART_I64: u8 = 0xA2;
const OP_REQUESTPARTS_I64: u8 = 0xA3;
const HASH_LEN: usize = 16;
const SEED_TCP_PORT: u16 = 4662;
/// A pause between two data frames longer than this is idle link.
const IDLE_GAP_S: f64 = 0.05;
/// The line between a short idle gap and a long one.
const LONG_GAP_S: f64 = 0.5;

/// One thing a link carried that the pace reads.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum LinkEvent {
    /// Part bytes from the seed: the frame's first file offset and its
    /// payload length (packed, for a compressed frame).
    Data { start: u64, len: u64, packed: bool },
    /// An `OP_REQUESTPARTS` from rmule, its non-empty ranges.
    Request(Vec<(u64, u64)>),
    /// An `OP_CANCELTRANSFER` from rmule.
    Cancel,
    /// A TCP segment that carried the seed's bytes: the idle share is read
    /// off these, since one throttled data frame spans many.
    Segment,
}

/// One seed's link, as the tap saw it.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub(crate) struct LinkPace {
    pub(crate) role: String,
    pub(crate) payload_bytes: u64,
    /// From the first data frame to the last, summed over the seed's links.
    pub(crate) span_s: f64,
    pub(crate) kib_per_s: f64,
    /// Gaps over 50 ms between the seed's segments, over the span.
    pub(crate) idle_share: f64,
    /// Those gaps up to 500 ms, and longer: an aMule uploader's two wake-ups
    /// after a dry socket fall one in each.
    pub(crate) idle_gaps_short: usize,
    pub(crate) idle_gaps_long: usize,
    pub(crate) requests: usize,
    pub(crate) request_to_data_p50_ms: Option<f64>,
    pub(crate) request_to_data_p90_ms: Option<f64>,
    /// The most blocks asked and not yet begun at any request: 1 is one
    /// block in flight.
    pub(crate) most_blocks_asked_ahead: usize,
    pub(crate) cancels: usize,
}

/// The whole download, as the tap saw it.
#[derive(Debug, Default, Serialize)]
pub(crate) struct Pace {
    pub(crate) links: Vec<LinkPace>,
    /// Uncompressed bytes that landed on an offset another frame had already
    /// delivered — what racing spent.
    pub(crate) duplicate_bytes: u64,
    /// The file over the sum of the seeds' caps: the end if every link ran
    /// at its cap to the last byte.
    pub(crate) ideal_s: Option<f64>,
}

/// Read every seed link of `pcap` between `rmule` and `seeds` (role, address).
///
/// # Errors
/// If the capture cannot be read.
pub(crate) fn read(
    pcap: &Path,
    rmule: Ipv4Addr,
    seeds: &[(String, Ipv4Addr)],
    file_hash: &[u8; 16],
) -> Result<Pace> {
    let capture = tcp_capture(&records(pcap)?)?;
    let seed_of = |address: SocketAddr| match address.ip() {
        IpAddr::V4(ip) if address.port() == SEED_TCP_PORT => {
            seeds.iter().position(|(_, seed)| *seed == ip)
        }
        _ => None,
    };
    let is_rmule = |address: SocketAddr| address.ip() == IpAddr::V4(rmule);
    // Per seed, per connection (keyed by rmule's port): the timed events.
    let mut per_seed: Vec<Vec<(u16, Vec<(f64, LinkEvent)>)>> = vec![Vec::new(); seeds.len()];
    for stream in &capture.streams {
        let (seed, rmule_port) = match (seed_of(stream.source), seed_of(stream.destination)) {
            (Some(seed), None) if is_rmule(stream.destination) => (seed, stream.destination.port()),
            (None, Some(seed)) if is_rmule(stream.source) => (seed, stream.source.port()),
            _ => continue,
        };
        if !stream.opens_plain() {
            continue;
        }
        let links = &mut per_seed[seed];
        let index = match links.iter().position(|(port, _)| *port == rmule_port) {
            Some(index) => index,
            None => {
                links.push((rmule_port, Vec::new()));
                links.len() - 1
            }
        };
        for frame in stream.ed2k_frames() {
            if let Some(event) = link_event(&frame, file_hash) {
                links[index].1.push((frame.at, event));
            }
        }
        if seed_of(stream.source).is_some() {
            let segments = stream.segment_times().map(|at| (at, LinkEvent::Segment));
            links[index].1.extend(segments);
        }
    }
    let mut delivered: Vec<(u64, u64)> = Vec::new();
    let mut links = Vec::new();
    for ((role, _), connections) in seeds.iter().zip(per_seed) {
        let mut connections: Vec<Vec<(f64, LinkEvent)>> =
            connections.into_iter().map(|(_, events)| events).collect();
        for events in &mut connections {
            events.sort_by(|a, b| a.0.total_cmp(&b.0));
            for (_, event) in events.iter() {
                if let LinkEvent::Data {
                    start,
                    len,
                    packed: false,
                } = event
                {
                    delivered.push((*start, start + len));
                }
            }
        }
        let mut pace = link_pace(&connections);
        pace.role.clone_from(role);
        links.push(pace);
    }
    let payload: u64 = delivered.iter().map(|(start, end)| end - start).sum();
    Ok(Pace {
        links,
        duplicate_bytes: payload.saturating_sub(union_len(&mut delivered)),
        ideal_s: None,
    })
}

/// The pace of one seed over its connections, each a timed event list in
/// capture order.
pub(crate) fn link_pace(connections: &[Vec<(f64, LinkEvent)>]) -> LinkPace {
    let mut pace = LinkPace::default();
    let mut idle_s = 0.0;
    let mut latencies = Vec::new();
    for events in connections {
        let data_at: Vec<f64> = events
            .iter()
            .filter(|(_, event)| matches!(event, LinkEvent::Data { .. }))
            .map(|(at, _)| *at)
            .collect();
        let (Some(&first), Some(&last)) = (data_at.first(), data_at.last()) else {
            continue;
        };
        pace.span_s += last - first;
        let segments: Vec<f64> = events
            .iter()
            .filter(|(at, event)| *event == LinkEvent::Segment && (first..=last).contains(at))
            .map(|(at, _)| *at)
            .collect();
        let by_segment = !segments.is_empty();
        let arrivals = if by_segment { &segments } else { &data_at };
        for gap in arrivals.windows(2).map(|pair| pair[1] - pair[0]) {
            if gap > IDLE_GAP_S {
                idle_s += gap;
                if gap > LONG_GAP_S {
                    pace.idle_gaps_long += 1;
                } else {
                    pace.idle_gaps_short += 1;
                }
            }
        }
        // Asked blocks not yet begun: a block begins at its first data frame.
        let mut asked: Vec<(u64, u64)> = Vec::new();
        let mut waiting_since: Option<f64> = None;
        for (at, event) in events {
            match event {
                LinkEvent::Data { start, len, .. } => {
                    pace.payload_bytes += len;
                    asked.retain(|(from, to)| !(*from <= *start && *start < *to));
                    if !by_segment && let Some(since) = waiting_since.take() {
                        latencies.push((at - since) * 1_000.0);
                    }
                }
                LinkEvent::Request(ranges) => {
                    pace.requests += 1;
                    for range in ranges {
                        if !asked.contains(range) {
                            asked.push(*range);
                        }
                    }
                    pace.most_blocks_asked_ahead = pace.most_blocks_asked_ahead.max(asked.len());
                    waiting_since.get_or_insert(*at);
                }
                LinkEvent::Cancel => pace.cancels += 1,
                LinkEvent::Segment => {
                    if let Some(since) = waiting_since.take() {
                        latencies.push((at - since) * 1_000.0);
                    }
                }
            }
        }
    }
    if pace.span_s > 0.0 {
        pace.kib_per_s = pace.payload_bytes as f64 / 1_024.0 / pace.span_s;
        pace.idle_share = idle_s / pace.span_s;
    }
    latencies.sort_by(f64::total_cmp);
    pace.request_to_data_p50_ms = percentile(&latencies, 50);
    pace.request_to_data_p90_ms = percentile(&latencies, 90);
    pace
}

/// The `pct`th percentile of sorted `values`, nearest rank.
fn percentile(values: &[f64], pct: usize) -> Option<f64> {
    let rank = (values.len() * pct).div_ceil(100).max(1);
    values.get(rank - 1).copied()
}

/// The length the union of `intervals` covers.
fn union_len(intervals: &mut [(u64, u64)]) -> u64 {
    intervals.sort_unstable();
    let mut covered = 0;
    let mut reach = 0;
    for &(start, end) in intervals.iter() {
        let from = start.max(reach);
        if end > from {
            covered += end - from;
        }
        reach = reach.max(end);
    }
    covered
}

/// What `frame` is to the pace, if anything: part bytes or a request for
/// `file_hash`, or a cancel.
fn link_event(frame: &Ed2kFrame, file_hash: &[u8; 16]) -> Option<LinkEvent> {
    let payload = frame.payload();
    let for_file = || payload.get(..HASH_LEN) == Some(file_hash.as_slice());
    let read = |at: usize, width: usize| {
        let bytes = payload.get(at..at + width)?;
        let mut wide = [0_u8; 8];
        wide[..width].copy_from_slice(bytes);
        Some(u64::from_le_bytes(wide))
    };
    match (frame.protocol, frame.opcode) {
        (OP_EDONKEYPROT, OP_CANCELTRANSFER) => Some(LinkEvent::Cancel),
        (OP_EDONKEYPROT, OP_SENDINGPART) | (OP_EMULEPROT, OP_SENDINGPART_I64) if for_file() => {
            let width = if frame.opcode == OP_SENDINGPART { 4 } else { 8 };
            let start = read(HASH_LEN, width)?;
            let end = read(HASH_LEN + width, width)?;
            Some(LinkEvent::Data {
                start,
                len: end.saturating_sub(start),
                packed: false,
            })
        }
        (OP_EMULEPROT, OP_COMPRESSEDPART | OP_COMPRESSEDPART_I64) if for_file() => {
            let width = if frame.opcode == OP_COMPRESSEDPART {
                4
            } else {
                8
            };
            let header = HASH_LEN + width + 4;
            Some(LinkEvent::Data {
                start: read(HASH_LEN, width)?,
                len: payload.len().saturating_sub(header) as u64,
                packed: true,
            })
        }
        (OP_EDONKEYPROT, OP_REQUESTPARTS) | (OP_EMULEPROT, OP_REQUESTPARTS_I64) if for_file() => {
            let width = if frame.opcode == OP_REQUESTPARTS {
                4
            } else {
                8
            };
            let ranges = (0..3)
                .filter_map(|range| {
                    let start = read(HASH_LEN + range * width, width)?;
                    let end = read(HASH_LEN + (range + 3) * width, width)?;
                    (end > start).then_some((start, end))
                })
                .collect();
            Some(LinkEvent::Request(ranges))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOCK: u64 = 184_320;

    fn data(at: f64, start: u64) -> (f64, LinkEvent) {
        (
            at,
            LinkEvent::Data {
                start,
                len: 10_240,
                packed: false,
            },
        )
    }

    /// One block in flight: each block waits out the seed's wake-up after its
    /// request, so the link idles between blocks.
    #[test]
    fn one_block_in_flight_idles_between_blocks() {
        let events = vec![
            (0.0, LinkEvent::Request(vec![(0, BLOCK)])),
            data(0.8, 0),
            data(1.0, 10_240),
            (1.0, LinkEvent::Request(vec![(BLOCK, 2 * BLOCK)])),
            data(1.2, BLOCK),
            data(1.4, BLOCK + 10_240),
        ];
        let pace = link_pace(&[events]);
        assert_eq!(pace.most_blocks_asked_ahead, 1);
        assert!((pace.span_s - 0.6).abs() < 1e-9);
        assert!((pace.idle_share - 1.0).abs() < 1e-9, "{pace:?}");
        assert_eq!(pace.request_to_data_p50_ms.map(f64::round), Some(200.0));
        assert_eq!(pace.request_to_data_p90_ms.map(f64::round), Some(800.0));
    }

    /// Three blocks asked at once, then one more as each lands.
    #[test]
    fn blocks_asked_ahead_show_on_the_wire() {
        let events = vec![
            (
                0.0,
                LinkEvent::Request(vec![(0, BLOCK), (BLOCK, 2 * BLOCK), (2 * BLOCK, 3 * BLOCK)]),
            ),
            data(0.01, 0),
            data(0.02, BLOCK),
            (0.02, LinkEvent::Request(vec![(3 * BLOCK, 4 * BLOCK)])),
            data(0.03, 2 * BLOCK),
            (0.04, LinkEvent::Cancel),
        ];
        let pace = link_pace(&[events]);
        assert_eq!(pace.most_blocks_asked_ahead, 3);
        assert_eq!(pace.idle_share, 0.0);
        assert_eq!(pace.cancels, 1);
    }

    #[test]
    fn overlapping_deliveries_count_once() {
        let mut delivered = vec![(0, 100), (50, 150), (200, 300)];
        assert_eq!(union_len(&mut delivered), 250);
    }
}
