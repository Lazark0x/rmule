//! The two-download emit leg's standing verdict (ADR-0107, "One peer, one
//! queue standing"): one rmule core holds two downloads queued at one stock
//! aMule sharer, and the sharer must be asked once per reask cycle, not once
//! per download.
//!
//! Every slot ask (`OP_STARTUPLOADREQ`, `0xE3 0x54`) and UDP reask
//! (`OP_REASKFILEPING`, `0xC5 0x90`) rmule sent the sharer is read off the
//! retained tap on rmule's namespace, with the file each names, and aMule's
//! own scoring of them is replayed: an ask under `MIN_REQUESTTIME` (590 s)
//! after the last adds 3, a polite one takes 1 off, and 10 bans
//! (`CheckForAggressive`, stock 2.3.3 `UploadClient.cpp:795-825`, called at
//! `ClientTCPSocket.cpp:601` and `ClientUDPSocket.cpp:194`). A banned client's
//! slot ask is answered nothing (`ClientTCPSocket.cpp:601-604`), so the
//! sharer's rank or grant after rmule's last slot ask is the counterparty's
//! word that rmule was not banned. What rmule sent is stimulus (ADR-0045).

use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::flow::identity::hex_lower;
use crate::flow::nat::claims::{Claim, Evidence, label};
use crate::flow::pcap::{tcp_streams, udp4_datagrams};
use crate::flow::wire_filter::OP_EDONKEYPROT;

/// The eMule extension protocol byte.
const OP_EMULEPROT: u8 = 0xC5;
/// `OP_STARTUPLOADREQ`: the slot ask, its body the file hash.
const OP_STARTUPLOADREQ: u8 = 0x54;
/// `OP_ACCEPTUPLOADREQ`: the grant.
const OP_ACCEPTUPLOADREQ: u8 = 0x55;
/// `OP_QUEUERANKING`: the rank, on the eMule protocol.
const OP_QUEUERANKING: u8 = 0x60;
/// `OP_REASKFILEPING`: the UDP reask, its body opening with the file hash.
const OP_REASKFILEPING: u8 = 0x90;
/// aMule `MIN_REQUESTTIME` (`Constants.h:67`), seconds.
const MIN_REQUEST_SECS: f64 = 590.0;
/// aMule `FILEREASKTIME` (`Constants.h:35`), seconds: the reask cycle.
const FILE_REASK_SECS: f64 = 1300.0;
/// The UDP ping leads the TCP full ask by 20 s; a slot ask this soon after an
/// unanswered ping is that ping's fallback, which aMule's own downloader also
/// sends (`PartFile.cpp:1449-1483`).
const UDP_LEAD_SECS: f64 = 20.0;
/// aMule bans at this aggressiveness (`UploadClient.cpp:810`).
const BAN_SCORE: u32 = 10;

/// What a retained two-download emit run is scored from.
pub(crate) struct StandingRun<'a> {
    /// The `tcp or udp` tap on rmule's namespace.
    pub(crate) pcap: &'a Path,
    /// The downloading rmule's address.
    pub(crate) rmule: Ipv4Addr,
    /// The sharer aMule's address.
    pub(crate) sharer: Ipv4Addr,
}

/// Which road one ask took.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Road {
    /// `OP_STARTUPLOADREQ` on a link.
    SlotAsk,
    /// `OP_REASKFILEPING` over client UDP.
    Ping,
}

/// One ask rmule sent the sharer.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Ask {
    /// Capture time, seconds since the epoch.
    pub(crate) at: f64,
    pub(crate) road: Road,
    /// The file hash it names.
    pub(crate) file: [u8; 16],
    /// Whether the sharer answered it: a rank or grant on the link after a
    /// slot ask, a UDP reask answer within the lead after a ping.
    pub(crate) answered: bool,
}

/// The asks of one reask cycle: a run of asks each under 590 s after the one
/// before.
#[derive(Debug, Serialize)]
struct Cycle {
    /// Seconds from the first ask.
    starts_at: u64,
    slot_asks: usize,
    pings: usize,
    /// The files the cycle's asks named, by hash.
    files: Vec<String>,
}

/// The verdict file.
#[derive(Debug, Serialize)]
struct StandingVerdict<'a> {
    #[serde(rename = "scenario")]
    flow: &'static str,
    verdict: &'static str,
    detail: String,
    /// Seconds the tap ran past rmule's first ask.
    window_secs: u64,
    cycles: Vec<Cycle>,
    /// aMule's aggressiveness after each ask, replayed.
    aggressiveness: Vec<u32>,
    claim: &'a [Claim],
}

/// Every slot ask and UDP reask rmule sent the sharer in `run`'s tap, in
/// capture order, with whether the sharer answered it.
pub(super) fn asks(run: &StandingRun<'_>) -> Result<Vec<Ask>> {
    let mut asks = Vec::new();
    let streams = tcp_streams(run.pcap)?;
    let answers: Vec<f64> = streams
        .iter()
        .filter(|stream| addressed(stream.source, stream.destination, run.sharer, run.rmule))
        .flat_map(|stream| stream.ed2k_frames())
        .filter(|frame| {
            (frame.protocol == OP_EMULEPROT && frame.opcode == OP_QUEUERANKING)
                || (frame.protocol == OP_EDONKEYPROT && frame.opcode == OP_ACCEPTUPLOADREQ)
        })
        .map(|frame| frame.at)
        .collect();
    for stream in streams
        .iter()
        .filter(|stream| addressed(stream.source, stream.destination, run.rmule, run.sharer))
    {
        let frames = stream.ed2k_frames();
        for (index, frame) in frames.iter().enumerate() {
            if frame.protocol != OP_EDONKEYPROT || frame.opcode != OP_STARTUPLOADREQ {
                continue;
            }
            let Some(file) = file_hash(frame.payload()) else {
                continue;
            };
            let next_ask = frames[index + 1..]
                .iter()
                .find(|later| later.opcode == OP_STARTUPLOADREQ)
                .map_or(f64::INFINITY, |later| later.at);
            asks.push(Ask {
                at: frame.at,
                road: Road::SlotAsk,
                file,
                answered: answers.iter().any(|&at| at >= frame.at && at < next_ask),
            });
        }
    }
    let datagrams = udp4_datagrams(run.pcap)?;
    let udp_answers: Vec<f64> = datagrams
        .iter()
        .filter(|datagram| {
            *datagram.source.ip() == run.sharer
                && *datagram.destination.ip() == run.rmule
                && datagram.payload.first() == Some(&OP_EMULEPROT)
                && matches!(datagram.payload.get(1), Some(0x91..=0x93))
        })
        .map(|datagram| datagram.at)
        .collect();
    for datagram in &datagrams {
        if *datagram.source.ip() != run.rmule
            || *datagram.destination.ip() != run.sharer
            || datagram.payload.get(..2) != Some(&[OP_EMULEPROT, OP_REASKFILEPING])
        {
            continue;
        }
        let Some(file) = file_hash(&datagram.payload[2..]) else {
            continue;
        };
        asks.push(Ask {
            at: datagram.at,
            road: Road::Ping,
            file,
            answered: udp_answers
                .iter()
                .any(|&at| at >= datagram.at && at - datagram.at <= UDP_LEAD_SECS),
        });
    }
    asks.sort_by(|a, b| a.at.total_cmp(&b.at));
    Ok(asks)
}

fn addressed(source: SocketAddr, destination: SocketAddr, from: Ipv4Addr, to: Ipv4Addr) -> bool {
    matches!((source, destination), (SocketAddr::V4(s), SocketAddr::V4(d)) if *s.ip() == from && *d.ip() == to)
}

fn file_hash(body: &[u8]) -> Option<[u8; 16]> {
    body.get(..16)?.try_into().ok()
}

/// aMule's aggressiveness after each of `asks`, replayed from its rule.
pub(super) fn aggressiveness(asks: &[Ask]) -> Vec<u32> {
    let mut score = 0_u32;
    let mut last: Option<f64> = None;
    asks.iter()
        .map(|ask| {
            if let Some(last) = last {
                if ask.at - last < MIN_REQUEST_SECS {
                    score += 3;
                } else {
                    score = score.saturating_sub(1);
                }
            }
            last = Some(ask.at);
            score
        })
        .collect()
}

/// `asks` cut into reask cycles: a new cycle opens at an ask 590 s or more
/// after the one before.
fn cycles(asks: &[Ask]) -> Vec<Vec<&Ask>> {
    let mut cycles: Vec<Vec<&Ask>> = Vec::new();
    for ask in asks {
        match cycles.last_mut() {
            Some(cycle)
                if cycle
                    .last()
                    .is_some_and(|last| ask.at - last.at < MIN_REQUEST_SECS) =>
            {
                cycle.push(ask);
            }
            _ => cycles.push(vec![ask]),
        }
    }
    cycles
}

/// Whether one cycle's asks are one ask of the peer: a single ask, or a ping
/// the sharer left unanswered and the slot ask that fell back on it within
/// the lead.
fn one_ask(cycle: &[&Ask]) -> bool {
    match cycle {
        [_] => true,
        [ping, ask] => {
            ping.road == Road::Ping
                && !ping.answered
                && ask.road == Road::SlotAsk
                && ask.at - ping.at <= UDP_LEAD_SECS
        }
        _ => false,
    }
}

/// The claims over `asks`, the tap having run `window` seconds past the
/// first.
fn claims(asks: &[Ask], window: f64) -> Vec<Claim> {
    let cycles = cycles(asks);
    let scores = aggressiveness(asks);
    let peak = scores.iter().copied().max().unwrap_or(0);
    let past_first = cycles.get(1..).unwrap_or_default();
    let crowded: Vec<String> = past_first
        .iter()
        .filter(|cycle| !one_ask(cycle))
        .map(|cycle| {
            format!(
                "{} asks from +{:.0} s",
                cycle.len(),
                cycle[0].at - asks[0].at
            )
        })
        .collect();
    let last_slot_ask = asks.iter().rev().find(|ask| ask.road == Road::SlotAsk);
    vec![
        Claim::about(
            "queued-past-a-reask-cycle",
            window >= FILE_REASK_SECS * 2.0 && !past_first.is_empty(),
            Evidence::Captured,
            format!(
                "the tap ran {window:.0} s past rmule's first ask and holds {} reask cycles",
                cycles.len()
            ),
        ),
        Claim::about(
            "one-ask-a-cycle",
            !past_first.is_empty() && crowded.is_empty(),
            Evidence::RmuleOnly,
            if crowded.is_empty() {
                format!(
                    "every cycle past the first asked the sharer once ({} cycles)",
                    past_first.len()
                )
            } else {
                format!(
                    "cycles past the first asked more than once: {}",
                    crowded.join(", ")
                )
            },
        ),
        Claim::about(
            "aggressiveness-under-the-ban",
            peak < BAN_SCORE,
            Evidence::RmuleOnly,
            format!("aMule's replayed score peaked at {peak} of {BAN_SCORE}"),
        ),
        Claim::about(
            "sharer-answered-the-last-slot-ask",
            last_slot_ask.is_some_and(|ask| ask.answered),
            Evidence::Captured,
            match last_slot_ask {
                Some(ask) if ask.answered => format!(
                    "the sharer ranked or granted rmule's slot ask at +{:.0} s",
                    ask.at - asks[0].at
                ),
                Some(ask) => format!(
                    "the sharer answered nothing to rmule's slot ask at +{:.0} s",
                    ask.at - asks[0].at
                ),
                None => "rmule sent the sharer no slot ask".to_owned(),
            },
        ),
    ]
}

/// Score `run` and write `peer-udp-reask-emit-standing-verdict.toml` under
/// `root`; the verdict.
///
/// # Errors
/// If the tap cannot be read or the verdict cannot be written.
pub(crate) fn write(root: &Path, run: &StandingRun<'_>) -> Result<&'static str> {
    let asks = asks(run)?;
    let window = crate::flow::pcap::records(run.pcap)?
        .last()
        .zip(asks.first())
        .map_or(0.0, |(last, first)| last.at - first.at);
    let claims = claims(&asks, window);
    let (verdict, detail) = label(&claims);
    let origin = asks.first().map_or(0.0, |ask| ask.at);
    let text = toml::to_string_pretty(&StandingVerdict {
        flow: "peer-udp-reask-emit-standing",
        verdict,
        detail,
        window_secs: window.max(0.0) as u64,
        cycles: cycles(&asks)
            .iter()
            .map(|cycle| {
                let mut files: Vec<String> = cycle.iter().map(|ask| hex_lower(&ask.file)).collect();
                files.dedup();
                Cycle {
                    starts_at: (cycle[0].at - origin).max(0.0) as u64,
                    slot_asks: cycle.iter().filter(|a| a.road == Road::SlotAsk).count(),
                    pings: cycle.iter().filter(|a| a.road == Road::Ping).count(),
                    files,
                }
            })
            .collect(),
        aggressiveness: aggressiveness(&asks),
        claim: &claims,
    })
    .context("serialize the standing verdict")?;
    let path = root.join("peer-udp-reask-emit-standing-verdict.toml");
    fs::write(&path, &text).with_context(|| format!("write {}", path.display()))?;
    println!("peer_udp_reask_emit standing_verdict={verdict}");
    Ok(verdict)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ask(at: f64, road: Road, file: u8, answered: bool) -> Ask {
        Ask {
            at,
            road,
            file: [file; 16],
            answered,
        }
    }

    fn held(claims: &[Claim], name: &str) -> bool {
        claims
            .iter()
            .find(|claim| claim.name == name)
            .is_some_and(|claim| claim.outcome == "held")
    }

    /// Both downloads asking at the start, then one slot ask a cycle naming
    /// one file: the cycles past the first hold one ask each and aMule's score
    /// decays from the one crowded start.
    #[test]
    fn one_ask_a_cycle_holds_past_a_crowded_start() {
        let asks = [
            ask(0.0, Road::SlotAsk, 1, true),
            ask(3.0, Road::SlotAsk, 2, true),
            ask(1303.0, Road::SlotAsk, 2, true),
            ask(2606.0, Road::Ping, 2, false),
            ask(2626.0, Road::SlotAsk, 2, true),
            ask(3926.0, Road::SlotAsk, 2, true),
        ];
        let claims = claims(&asks, 4000.0);
        assert!(held(&claims, "one-ask-a-cycle"), "{claims:?}");
        assert!(held(&claims, "aggressiveness-under-the-ban"), "{claims:?}");
        assert!(held(&claims, "sharer-answered-the-last-slot-ask"));
    }

    /// Two downloads each re-asking seconds apart every cycle: every cycle is
    /// crowded, and aMule's replayed score, two points up a cycle, reaches its
    /// ban in the fifth.
    #[test]
    fn two_downloads_reasking_each_cycle_are_scored_into_a_ban() {
        let asks: Vec<Ask> = (0..5)
            .flat_map(|cycle| {
                let at = f64::from(cycle) * 1300.0;
                [
                    ask(at, Road::SlotAsk, 1, true),
                    ask(at + 10.0, Road::SlotAsk, 2, true),
                ]
            })
            .collect();
        let claims = claims(&asks, 6500.0);
        assert!(!held(&claims, "one-ask-a-cycle"));
        assert!(!held(&claims, "aggressiveness-under-the-ban"));
        assert_eq!(aggressiveness(&asks).last(), Some(&11));
    }
}
