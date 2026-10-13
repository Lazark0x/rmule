//! The claims on what rmule answers a probe of its download (ADR-0113
//! §"What each ask is answered"): the name and status before its first
//! part and after, the hash set, and the record of how stock aMule takes
//! the complete-file status form.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use super::{Claim, Run, Verdict};
use crate::flow::peer::partial_share::wire::{Item, Said, Status};

/// How long after a status a link closed by its peer, with nothing said
/// between, reads as the peer refusing it rather than idling out.
const DROP_WINDOW_SECS: f64 = 2.0;
/// rmule's part map lags a verification by up to one tick: a status sent
/// this long before the first map with a part verified is certainly from
/// before the part.
pub(super) const TICK_SECS: f64 = 1.05;

/// rmule's statuses for the stream file, in capture order.
fn statuses<'a>(run: &'a Run<'_>) -> impl Iterator<Item = (&'a Item, &'a Status)> + 'a {
    run.wire.items.iter().filter_map(|item| match &item.said {
        Said::Status { hash, status } if item.from_rmule && *hash == run.stream_hash => {
            Some((item, status))
        }
        _ => None,
    })
}

fn ip(item: &Item) -> Ipv4Addr {
    match item.peer.ip() {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
    }
}

pub(super) fn parts(held: &BTreeSet<u32>) -> String {
    let listed: Vec<String> = held.iter().map(u32::to_string).collect();
    format!("{{{}}}", listed.join(","))
}

/// Before rmule's first verified part a name ask is answered, and a status
/// ask with no part set and the file's own count.
pub(super) fn pre_part_probe(run: &Run<'_>) -> Claim {
    const NAME: &str = "before-the-first-part-a-probe-is-answered-with-no-part";
    let Some(first) = run.first_verified() else {
        return Claim::new(NAME, Verdict::NotRun, "rmule never printed a part verified");
    };
    let cutoff = first - TICK_SECS;
    let before: Vec<_> = statuses(run).filter(|(item, _)| item.at < cutoff).collect();
    if before.is_empty() {
        return Claim::new(
            NAME,
            Verdict::NotRun,
            format!("no status went out before the first part ({first:.3})"),
        );
    }
    let names = run
        .wire
        .items
        .iter()
        .filter(|item| {
            item.from_rmule
                && item.at < cutoff
                && matches!(&item.said, Said::Name { hash, .. } if *hash == run.stream_hash)
        })
        .count();
    let failures: Vec<String> = before
        .iter()
        .filter(|(_, status)| status.count != run.count || !status.held.is_empty())
        .map(|(item, status)| {
            format!(
                "{:.3} to {}: count {} parts {}",
                item.at,
                ip(item),
                status.count,
                parts(&status.held)
            )
        })
        .collect();
    let mut failures = failures;
    if names == 0 {
        failures.push("no name answer before the first part".to_owned());
    }
    Claim::judged(
        NAME,
        &failures,
        format!(
            "{} statuses and {names} name answers before the first part ({first:.3}): count {}, no part set",
            before.len(),
            run.count
        ),
    )
}

/// A slot ask before the first part draws nothing; stock aMule sends none,
/// as it asks no slot of a source holding no part it needs.
pub(super) fn pre_part_slot_ask(run: &Run<'_>) -> Claim {
    const NAME: &str = "before-the-first-part-a-slot-ask-draws-nothing";
    let Some(first) = run.first_verified() else {
        return Claim::new(NAME, Verdict::NotRun, "rmule never printed a part verified");
    };
    let cutoff = first - TICK_SECS;
    let asks: Vec<&Item> = run
        .wire
        .items
        .iter()
        .filter(|item| !item.from_rmule && item.at < cutoff && item.said == Said::SlotAsk)
        .collect();
    if asks.is_empty() {
        return Claim::new(
            NAME,
            Verdict::NotRun,
            "no slot ask before the first part (stock aMule asks none of a source with no part it needs)",
        );
    }
    let mut failures = Vec::new();
    for ask in &asks {
        let next_ask = run
            .wire
            .items
            .iter()
            .find(|item| {
                !item.from_rmule
                    && item.peer == ask.peer
                    && item.at > ask.at
                    && item.said == Said::SlotAsk
            })
            .map_or(f64::INFINITY, |item| item.at);
        if let Some(answer) = run.wire.items.iter().find(|item| {
            item.from_rmule
                && item.peer == ask.peer
                && item.at > ask.at
                && item.at < next_ask
                && matches!(item.said, Said::Accept | Said::Rank { .. })
        }) {
            failures.push(format!(
                "slot ask at {:.3} from {} drew {:?} at {:.3}",
                ask.at,
                ip(ask),
                answer.said,
                answer.at
            ));
        }
    }
    let downloaders: BTreeSet<Ipv4Addr> = run.downloaders().collect();
    let stock = asks
        .iter()
        .filter(|ask| downloaders.contains(&ip(ask)))
        .count();
    Claim::judged(
        NAME,
        &failures,
        format!(
            "{} slot asks before the first part drew nothing ({stock} from stock aMule)",
            asks.len()
        ),
    )
}

/// Once a part is verified every status rmule writes for the partial is its
/// Verified Range, with the file's count — never the complete form; after a
/// restart it names no part until the Offer Check has passed.
pub(super) fn status_is_the_verified_range(run: &Run<'_>) -> Claim {
    const NAME: &str = "every-status-is-the-verified-range";
    let first = run
        .first_verified()
        .map_or(f64::INFINITY, |at| at - TICK_SECS);
    let completed = run.completed_at().unwrap_or(f64::INFINITY);
    let reoffered = run.reoffered_at().unwrap_or(f64::INFINITY);
    let mut judged = 0;
    let mut failures = Vec::new();
    for (item, status) in statuses(run).filter(|(item, _)| item.at >= first) {
        let leg = run.leg_at(item.at);
        if status.count == 0 {
            if item.at < completed {
                failures.push(format!(
                    "{:.3} to {}: count 0 for a partial",
                    item.at,
                    ip(item)
                ));
            }
            continue;
        }
        judged += 1;
        if status.count != run.count {
            failures.push(format!(
                "{:.3} to {}: count {} not {}",
                item.at,
                ip(item),
                status.count,
                run.count
            ));
        }
        if leg == 2 && item.at < reoffered {
            if !status.held.is_empty() {
                failures.push(format!(
                    "{:.3} to {}: parts {} before the Offer Check passed",
                    item.at,
                    ip(item),
                    parts(&status.held)
                ));
            }
            continue;
        }
        match run.trail.verified_after(item.at, leg) {
            Some(after) if !status.held.is_subset(&after) => failures.push(format!(
                "{:.3} to {}: parts {} beyond the verified {}",
                item.at,
                ip(item),
                parts(&status.held),
                parts(&after)
            )),
            Some(_) => {}
            None => failures.push(format!("{:.3}: no part map follows", item.at)),
        }
        if let Some(before) = run.trail.verified_before(item.at, leg)
            && !(leg == 2 || before.is_subset(&status.held))
        {
            failures.push(format!(
                "{:.3} to {}: parts {} short of the verified {}",
                item.at,
                ip(item),
                parts(&status.held),
                parts(&before)
            ));
        }
    }
    if judged == 0 && failures.is_empty() {
        return Claim::new(
            NAME,
            Verdict::NotRun,
            "no status went out once a part was verified",
        );
    }
    Claim::judged(
        NAME,
        &failures,
        format!(
            "{judged} statuses, each the Verified Range of its moment, count {}",
            run.count
        ),
    )
}

/// No stock aMule drops rmule on its status: after every status the
/// downloader says more on the link, or keeps it open past the drop window.
pub(super) fn amule_keeps_rmule(run: &Run<'_>) -> Claim {
    const NAME: &str = "amule-keeps-rmule-as-a-source";
    let downloaders: BTreeSet<Ipv4Addr> = run.downloaders().collect();
    let mut judged = 0;
    let mut failures = Vec::new();
    for (item, status) in statuses(run).filter(|(item, _)| downloaders.contains(&ip(item))) {
        judged += 1;
        if let Some(why) = dropped_after(run, item) {
            failures.push(format!(
                "{} closed the link {why} after the status {} at {:.3}",
                ip(item),
                parts(&status.held),
                item.at
            ));
        }
    }
    if judged == 0 {
        return Claim::new(
            NAME,
            Verdict::NotRun,
            "no status went to a stock aMule downloader",
        );
    }
    Claim::judged(
        NAME,
        &failures,
        format!("{judged} statuses to stock aMule, none answered by a drop"),
    )
}

/// How soon the peer closed the link after `item` with nothing said
/// between, when that was inside the drop window.
fn dropped_after(run: &Run<'_>, item: &Item) -> Option<String> {
    let close = run
        .wire
        .closes
        .iter()
        .find(|close| !close.by_rmule && close.peer == item.peer && close.at >= item.at)?;
    let spoke = run.wire.items.iter().any(|next| {
        !next.from_rmule && next.peer == item.peer && next.at > item.at && next.at <= close.at
    });
    let after = close.at - item.at;
    (!spoke && after < DROP_WINDOW_SECS).then(|| format!("{after:.3} s"))
}

/// A hash-set ask is answered with the whole set once rmule holds it, and
/// never with no-file once the download is offered.
pub(super) fn hash_set(run: &Run<'_>) -> Claim {
    const NAME: &str = "the-hash-set-ask-is-answered-with-the-whole-set";
    let asks = run
        .wire
        .items
        .iter()
        .filter(|item| {
            !item.from_rmule
                && matches!(&item.said, Said::HashSetAsk { hash } if *hash == run.stream_hash)
        })
        .count();
    if asks == 0 {
        return Claim::new(NAME, Verdict::NotRun, "no hash-set ask reached rmule");
    }
    let offered = run
        .first_verified()
        .map_or(f64::INFINITY, |at| at + TICK_SECS);
    let reoffered = run.reoffered_at().unwrap_or(f64::INFINITY);
    let mut answers = 0;
    let mut no_file = 0;
    let mut failures = Vec::new();
    for item in run.wire.items.iter().filter(|item| item.from_rmule) {
        match &item.said {
            Said::HashSet { hash, parts } if *hash == run.stream_hash => {
                answers += 1;
                if *parts != run.part_hashes {
                    failures.push(format!(
                        "{:.3} to {}: {} hashes, not the file's {}",
                        item.at,
                        ip(item),
                        parts.len(),
                        run.part_hashes.len()
                    ));
                }
            }
            Said::NoFile { hash } if *hash == run.stream_hash => {
                no_file += 1;
                let offered_then =
                    item.at >= offered && !(run.leg_at(item.at) == 2 && item.at < reoffered);
                if offered_then {
                    failures.push(format!(
                        "{:.3} to {}: no-file while offered",
                        item.at,
                        ip(item)
                    ));
                }
            }
            _ => {}
        }
    }
    Claim::judged(
        NAME,
        &failures,
        format!(
            "{asks} asks: {answers} answered with all {} part hashes, {no_file} with no-file before the set was held",
            run.part_hashes.len()
        ),
    )
}

/// A record, not a rule: every complete-form status (count `0`) rmule
/// sent a stock aMule, and whether aMule went on with the file or dropped
/// the link.
pub(super) fn complete_form(run: &Run<'_>) -> Claim {
    const NAME: &str = "stock-amule-takes-the-count-0-complete-form";
    let downloaders: BTreeSet<Ipv4Addr> = run.downloaders().collect();
    let mut taken = 0;
    let mut dropped = Vec::new();
    for item in run.wire.items.iter().filter(|item| {
        item.from_rmule
            && downloaders.contains(&ip(item))
            && matches!(&item.said, Said::Status { status, .. } if status.count == 0)
    }) {
        match dropped_after(run, item) {
            Some(why) => dropped.push(format!("{} at {:.3} ({why})", ip(item), item.at)),
            None => taken += 1,
        }
    }
    if taken == 0 && dropped.is_empty() {
        return Claim::new(
            NAME,
            Verdict::NotRun,
            "rmule sent no stock aMule a count-0 status",
        );
    }
    Claim::new(
        NAME,
        Verdict::Observed,
        if dropped.is_empty() {
            format!("{taken} count-0 statuses, none refused")
        } else {
            format!("{taken} taken; refused: {}", dropped.join(", "))
        },
    )
}
