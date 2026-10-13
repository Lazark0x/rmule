//! The claims on what rmule uploads from its download (ADR-0113 §"Reading a
//! part file", §"A paused download", §"Completion"): only verified bytes,
//! the file's own; a request past the Verified Range ends the slot and
//! nothing else; a pause keeps the slot and the queue; the completion move
//! keeps a mid-session upload going from the final path.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use rmule_primitives::ED2K_PART_SIZE;

use super::offers::{lists_partial, lists_whole};
use super::{Claim, Run, STRADDLE, Verdict};
use crate::flow::peer::partial_share::wire::{Item, Said, Udp};

/// How far the harness's clock and the tap's may drift apart.
const CLOCK_MARGIN_SECS: f64 = 10.0;
/// A close this soon after the straddle is rmule's answer to it, not an
/// idle link's end.
const REACTION_SECS: f64 = 5.0;

fn ip(item: &Item) -> Ipv4Addr {
    match item.peer.ip() {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
    }
}

/// The blocks rmule sent: when, to whom, which file, where, how long.
fn blocks<'a>(run: &'a Run<'_>) -> impl Iterator<Item = (&'a Item, [u8; 16], u64, &'a [u8])> + 'a {
    run.wire.items.iter().filter_map(|item| match &item.said {
        Said::Block { hash, start, bytes } if item.from_rmule => {
            Some((item, *hash, *start, bytes.as_slice()))
        }
        _ => None,
    })
}

/// The parts a block of `len` bytes at `start` touches.
fn touched(start: u64, len: usize) -> BTreeSet<u32> {
    let last = start + len.max(1) as u64 - 1;
    ((start / ED2K_PART_SIZE) as u32..=(last / ED2K_PART_SIZE) as u32).collect()
}

/// aMule is granted a slot and every block rmule sends lies in parts
/// verified at that moment and equals the file's bytes there; the whole
/// file shared beside it equals its own.
pub(super) fn verified_bytes_only(run: &Run<'_>) -> Claim {
    const NAME: &str = "only-verified-parts-go-out-byte-equal";
    let completed = run.completed_at().unwrap_or(f64::INFINITY);
    let downloaders: BTreeSet<Ipv4Addr> = run.downloaders().collect();
    let granted: BTreeSet<Ipv4Addr> = run
        .wire
        .items
        .iter()
        .filter(|item| item.from_rmule && item.said == Said::Accept)
        .map(ip)
        .filter(|address| downloaders.contains(address))
        .collect();
    let mut sent = 0u64;
    let mut count = 0;
    let mut failures = Vec::new();
    for (item, hash, start, bytes) in blocks(run) {
        count += 1;
        sent += bytes.len() as u64;
        let end = start as usize + bytes.len();
        if hash == run.stream_hash {
            if run.stream.get(start as usize..end) != Some(bytes) {
                failures.push(format!(
                    "{:.3} to {}: bytes {start}..{end} differ from the file",
                    item.at,
                    ip(item)
                ));
            }
            if item.at < completed {
                let parts = touched(start, bytes.len());
                match run.trail.verified_after(item.at, run.leg_at(item.at)) {
                    Some(verified) if parts.is_subset(&verified) => {}
                    Some(verified) => failures.push(format!(
                        "{:.3} to {}: bytes {start}..{end} in parts {parts:?}, verified {verified:?}",
                        item.at,
                        ip(item)
                    )),
                    None => failures.push(format!("{:.3}: no part map follows the block", item.at)),
                }
            }
        } else if Some(hash) == run.whole_hash
            && run.whole.and_then(|whole| whole.get(start as usize..end)) != Some(bytes)
        {
            failures.push(format!(
                "{:.3}: whole-file bytes {start}..{end} differ",
                item.at
            ));
        }
    }
    if count == 0 {
        return Claim::new(NAME, Verdict::NotRun, "rmule sent no block");
    }
    if granted.is_empty() {
        failures.push("no stock aMule downloader was granted a slot".to_owned());
    }
    Claim::judged(
        NAME,
        &failures,
        format!("{count} blocks, {sent} bytes; slot granted to {granted:?}"),
    )
}

/// A request straddling the Verified Range's edge ends the slot: no byte of
/// it goes out, nor of the in-range request after it, the slot is released,
/// and rmule keeps the link.
pub(super) fn straddle(run: &Run<'_>) -> Claim {
    const NAME: &str = "a-straddling-request-ends-the-slot-and-keeps-the-link";
    let Some(stimulus) = run.stimulus(STRADDLE) else {
        return Claim::new(NAME, Verdict::NotRun, "no straddle stimulus ran");
    };
    // The window is stamped on the harness's clock, the frames on the tap's:
    // a margin either side absorbs the two drifting apart.
    let within = |item: &&Item| {
        ip(item) == stimulus.ip
            && item.at >= stimulus.started_at - CLOCK_MARGIN_SECS
            && item.at <= stimulus.ended_at + CLOCK_MARGIN_SECS
    };
    let items: Vec<&Item> = run.wire.items.iter().filter(within).collect();
    let Some(&(straddle_start, straddle_end)) = stimulus.ranges.first() else {
        return Claim::new(NAME, Verdict::NotRun, "the stimulus asked for no range");
    };
    let Some(request) = items.iter().find(|item| {
        !item.from_rmule
            && matches!(&item.said, Said::Request { ranges, .. } if ranges.contains(&(straddle_start, straddle_end)))
    }) else {
        return Claim::new(NAME, Verdict::NotRun, "the straddling request never went out: the stimulus held no slot");
    };
    if !items
        .iter()
        .any(|item| item.from_rmule && item.said == Said::Accept && item.at < request.at)
    {
        return Claim::new(
            NAME,
            Verdict::NotRun,
            "the stimulus was never granted a slot",
        );
    }
    let mut failures = Vec::new();
    let after: Vec<String> = items
        .iter()
        .filter(|item| item.from_rmule && item.at > request.at)
        .filter_map(|item| match &item.said {
            Said::Block { start, bytes, .. } => Some(format!("{start}+{}", bytes.len())),
            _ => None,
        })
        .collect();
    if !after.is_empty() {
        failures.push(format!(
            "blocks went out after the straddle: {}",
            after.join(",")
        ));
    }
    let follow_up = items.iter().any(|item| {
        !item.from_rmule && item.at > request.at && matches!(item.said, Said::Request { .. })
    });
    if run.wire.closes.iter().any(|close| {
        close.by_rmule
            && close.peer == request.peer
            && close.at >= request.at
            && close.at - request.at < REACTION_SECS
    }) {
        failures.push("rmule closed the link on the straddle".to_owned());
    }
    let released = run.trail.named("serve.upload_slot_released").any(|mark| {
        mark.peer() == Some(stimulus.ip) && mark.at.is_some_and(|at| at + 1.0 >= request.at)
    });
    if !released {
        failures.push("rmule logged no slot release for the stimulus".to_owned());
    }
    Claim::judged(
        NAME,
        &failures,
        format!(
            "{straddle_start}..{straddle_end} at {:.3}: nothing sent{}, slot released, link kept",
            request.at,
            if follow_up {
                ", nor for the in-range request after it"
            } else {
                ""
            }
        ),
    )
}

/// After the completion move a mid-session upload goes on, from the final
/// path, with no new slot ask or grant; the finished file is offered as a
/// whole row, and the download directory's scan trusts it unread.
pub(super) fn completion(run: &Run<'_>) -> Claim {
    const NAME: &str = "after-the-completion-move-the-upload-goes-on";
    let Some(completed) = run.completed_at() else {
        return Claim::new(
            NAME,
            Verdict::NotRun,
            "the download did not complete in the run",
        );
    };
    let downloaders: BTreeSet<Ipv4Addr> = run.downloaders().collect();
    let mut failures = Vec::new();
    let mut carried = Vec::new();
    for peer in &downloaders {
        let to_peer = |(item, hash, _, _): &(&Item, [u8; 16], u64, &[u8])| {
            ip(item) == *peer && *hash == run.stream_hash
        };
        let Some(before) = blocks(run)
            .filter(to_peer)
            .filter(|(item, ..)| item.at < completed)
            .last()
        else {
            continue;
        };
        let Some(after) = blocks(run)
            .filter(to_peer)
            .find(|(item, ..)| item.at > completed)
        else {
            continue;
        };
        carried.push(*peer);
        if after.0.peer != before.0.peer {
            failures.push(format!("{peer} was served after the move on a new link"));
        }
        if run.wire.items.iter().any(|item| {
            ip(item) == *peer
                && item.at > completed
                && item.at < after.0.at
                && matches!(
                    item.said,
                    Said::SlotAsk { .. } | Said::Accept | Said::Rank { .. }
                )
        }) {
            failures.push(format!("{peer} queued again before its next block"));
        }
    }
    if carried.is_empty() {
        return Claim::new(
            NAME,
            Verdict::NotRun,
            format!("no downloader mid-session at the completion ({completed:.3})"),
        );
    }
    // The announce the completion triggers can reach the tap before rmule
    // prints the completion's line.
    let whole_row = run
        .offers
        .iter()
        .any(|(at, rows)| *at > completed - 1.0 && rows.iter().any(|row| lists_whole(run, row)));
    if !whole_row {
        failures.push("no OP_OFFERFILES after the move offers the file as a whole row".to_owned());
    }
    let trusted = run.trail.named("scan.finished").any(|mark| {
        mark.at.is_some_and(|at| at >= completed - 1.0)
            && mark
                .field("dir")
                .is_some_and(|dir| dir.ends_with(super::super::legs::INCOMING_DIR))
            && mark.field("trusted").is_some_and(|n| n != "0")
            && mark.field("hashed") == Some("0")
    });
    if !trusted {
        failures
            .push("no download-directory scan after the move trusted the file unread".to_owned());
    }
    Claim::judged(
        NAME,
        &failures,
        format!(
            "{carried:?} served on the same link after the move at {completed:.3}; whole row offered; scan trusted it"
        ),
    )
}

/// A pause mid-upload keeps the slot holder receiving verified bytes and the
/// queued peer its rank, and the next announce still lists the partial.
pub(super) fn pause(run: &Run<'_>) -> Claim {
    const NAME: &str = "a-pause-keeps-the-slot-the-queue-and-the-offer";
    let Some(paused) = run.trail.first_at("download paused_at_gate") else {
        return Claim::new(NAME, Verdict::NotRun, "the run did not pause");
    };
    let Some(holder) = run.downloader(super::super::DOWNLOADER).map(|body| body.ip) else {
        return Claim::new(NAME, Verdict::NotRun, "no slot-holding downloader");
    };
    let end = run.reopened_at().unwrap_or(f64::INFINITY);
    let mut failures = Vec::new();
    let served = |from: f64, to: f64| {
        blocks(run)
            .filter(|(item, hash, ..)| ip(item) == holder && *hash == run.stream_hash)
            .filter(|(item, ..)| item.at > from && item.at < to)
            .count()
    };
    // Holding the slot, not a whole block, is what the pause must keep: at a
    // shaped link the first block can complete after it.
    let marked_before = |name: &str| {
        run.trail
            .named(name)
            .filter(|mark| mark.peer() == Some(holder))
            .filter_map(|mark| mark.at)
            .any(|at| at < paused)
    };
    if !marked_before("serve.upload_slot_granted") || marked_before("serve.upload_slot_released") {
        return Claim::new(
            NAME,
            Verdict::NotRun,
            "the downloader held no slot at the pause",
        );
    }
    let after = served(paused, end);
    if after == 0 {
        failures.push("no block reached the slot holder after the pause".to_owned());
    }
    if run.wire.items.iter().any(|item| {
        ip(item) == holder
            && item.from_rmule
            && item.at > paused
            && item.at < end
            && item.said == Said::OutOfParts
    }) || run.wire.closes.iter().any(|close| {
        close.by_rmule
            && close.peer.ip() == IpAddr::V4(holder)
            && close.at > paused
            && close.at < end - 1.0
    }) {
        failures.push("rmule ended the slot holder's transfer after the pause".to_owned());
    }
    let ranks: Vec<u16> = run
        .wire
        .datagrams
        .iter()
        .filter(|datagram| datagram.at > paused && datagram.at < end)
        .filter_map(|datagram| match datagram.said {
            Udp::Ack { rank, .. } => Some(rank),
            _ => None,
        })
        .collect();
    if ranks.contains(&0) {
        failures.push("a reask after the pause was answered with rank 0".to_owned());
    }
    let offered = run.offers.iter().any(|(at, rows)| {
        *at > paused && *at < end && rows.iter().any(|row| lists_partial(run, row))
    });
    if !offered {
        failures.push("no OP_OFFERFILES after the pause lists the partial".to_owned());
    }
    Claim::judged(
        NAME,
        &failures,
        format!(
            "{after} blocks to the slot holder after the pause; reask ranks {ranks:?}; partial still announced"
        ),
    )
}
