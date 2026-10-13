//! The claims on the asks a downloader makes of a source it already knows
//! (ADR-0113 §"What each ask is answered"): the UDP reask, answered with the
//! Verified Range, and the source exchange, answered from the download's own
//! pool.

use std::net::{IpAddr, Ipv4Addr};

use super::answers::{TICK_SECS, parts};
use super::{Claim, Run, Verdict, id_addresses};
use crate::flow::peer::partial_share::wire::{Item, Said, Udp};

fn ip(item: &Item) -> Ipv4Addr {
    match item.peer.ip() {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
    }
}

/// A queued downloader's `0x90` for the partial draws an `0x91` carrying the
/// Verified Range and the file's count, not the complete form.
pub(super) fn reask_ack(run: &Run<'_>) -> Claim {
    const NAME: &str = "a-reask-is-answered-with-the-verified-range";
    let completed = run.completed_at().unwrap_or(f64::INFINITY);
    let reoffered = run.reoffered_at().unwrap_or(f64::INFINITY);
    let mut pings = 0;
    let mut failures = Vec::new();
    let mut acked = Vec::new();
    // A reask from a peer rmule queued in the same leg: one it never queued
    // (a downloader reasking the restarted node) is not this claim's.
    let queued_by = |peer: Ipv4Addr, at: f64| {
        run.trail.named("serve.peer_queued").any(|mark| {
            mark.peer() == Some(peer)
                && mark
                    .at
                    .is_some_and(|queued| queued <= at && run.leg_at(queued) == run.leg_at(at))
        })
    };
    for ping in run.wire.datagrams.iter().filter(|datagram| {
        matches!(&datagram.said, Udp::Ping { hash } if *hash == run.stream_hash)
            && queued_by(datagram.peer, datagram.at)
    }) {
        pings += 1;
        let answer = run.wire.datagrams.iter().find(|datagram| {
            datagram.peer == ping.peer
                && datagram.at >= ping.at
                && datagram.at - ping.at < 3.0
                && !matches!(datagram.said, Udp::Ping { .. })
        });
        let leg = run.leg_at(ping.at);
        let before_check = leg == 2 && ping.at < reoffered;
        match answer.map(|datagram| &datagram.said) {
            Some(Udp::Ack {
                status: Some(status),
                rank,
            }) => {
                acked.push(format!("{} {} rank {rank}", ping.peer, parts(&status.held)));
                if ping.at >= completed {
                    continue;
                }
                if status.count != run.count {
                    failures.push(format!(
                        "{:.3} to {}: count {} not {}",
                        ping.at, ping.peer, status.count, run.count
                    ));
                }
                let verified = run.trail.verified_after(ping.at, leg).unwrap_or_default();
                if before_check && !status.held.is_empty()
                    || !before_check && !status.held.is_subset(&verified)
                {
                    failures.push(format!(
                        "{:.3} to {}: parts {} against the verified {}",
                        ping.at,
                        ping.peer,
                        parts(&status.held),
                        parts(&verified)
                    ));
                }
            }
            Some(Udp::Ack { status: None, rank }) => failures.push(format!(
                "{:.3} to {}: rank {rank} with no status",
                ping.at, ping.peer
            )),
            Some(other) if before_check => {
                acked.push(format!("{} {other:?} before the check", ping.peer))
            }
            Some(other) => failures.push(format!("{:.3} to {}: {other:?}", ping.at, ping.peer)),
            None if before_check => {
                acked.push(format!("{} unanswered before the check", ping.peer))
            }
            None => failures.push(format!("{:.3} from {}: no answer", ping.at, ping.peer)),
        }
    }
    if pings == 0 {
        return Claim::new(
            NAME,
            Verdict::NotRun,
            "no 0x90 for the stream file reached rmule",
        );
    }
    Claim::judged(
        NAME,
        &failures,
        format!("{pings} reasks: {}", acked.join(", ")),
    )
}

/// What rmule answered a source ask for the partial: its download's pool
/// (the seeds it fetches from or waits at), or nothing when that pool is
/// empty — said which. A download not yet offered answers none.
pub(super) fn source_exchange(run: &Run<'_>) -> Claim {
    const NAME: &str = "a-source-ask-is-answered-from-the-download-pool";
    let asks: Vec<&Item> = run
        .wire
        .items
        .iter()
        .filter(|item| {
            !item.from_rmule
                && match &item.said {
                    Said::NameAsk {
                        hash,
                        sources_asked: true,
                    }
                    | Said::SourcesAsk { hash } => *hash == run.stream_hash,
                    _ => false,
                }
        })
        .collect();
    if asks.is_empty() {
        return Claim::new(
            NAME,
            Verdict::NotRun,
            "no source ask for the stream file reached rmule",
        );
    }
    let offered = run
        .first_verified()
        .map_or(f64::INFINITY, |at| at - TICK_SECS);
    let mut failures = Vec::new();
    let mut said = Vec::new();
    for ask in &asks {
        let answer = run.wire.items.iter().find_map(|item| match &item.said {
            Said::Sources { hash, ids }
                if item.from_rmule
                    && item.peer.ip() == ask.peer.ip()
                    && *hash == run.stream_hash
                    && item.at >= ask.at
                    && item.at - ask.at < 3.0 =>
            {
                Some(ids)
            }
            _ => None,
        });
        match answer {
            Some(ids) => {
                if ask.at < offered {
                    failures.push(format!(
                        "{:.3} from {}: answered before the offer",
                        ask.at,
                        ip(ask)
                    ));
                }
                let named: Vec<String> = ids.iter().map(|id| role_of(run, *id)).collect();
                said.push(format!(
                    "{:.3} {} -> [{}]",
                    ask.at,
                    ip(ask),
                    named.join(",")
                ));
            }
            None => said.push(format!("{:.3} {} -> nothing", ask.at, ip(ask))),
        }
    }
    let verdict = if failures.is_empty() {
        Verdict::Observed
    } else {
        Verdict::Fail
    };
    let detail = if failures.is_empty() {
        said.join("; ")
    } else {
        failures.join("; ")
    };
    Claim::new(NAME, verdict, detail)
}

/// The body a source record's ID names, else its address.
fn role_of(run: &Run<'_>, id: u32) -> String {
    let addresses = id_addresses(id);
    run.topology
        .seeds
        .iter()
        .chain(&run.topology.downloaders)
        .find(|body| addresses.contains(&body.ip))
        .map_or_else(|| format!("{}", addresses[0]), |body| body.role.clone())
}
