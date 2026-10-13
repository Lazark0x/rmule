//! The claims on what rmule announces (ADR-0113 §"Announce and Kad",
//! §"After a restart: the Offer Check"): the partial under the incomplete
//! marker beside a whole file's complete one when the server grants
//! compression, and after a restart nothing of the partial until its Offer
//! Check has passed.

use super::{Claim, Run, Verdict};
use crate::flow::ed2k_server::search_wire::server_tap::OfferedRow;
use crate::flow::peer::partial_share::wire::Said;

/// `SRV_TCPFLG_COMPRESSION`: a server granting it reads an offer's ID and
/// port as completeness markers.
const SRV_TCPFLG_COMPRESSION: u32 = 0x0000_0001;
const INCOMPLETE: (u32, u16) = (0xFCFC_FCFC, 0xFCFC);
const COMPLETE: (u32, u16) = (0xFBFB_FBFB, 0xFBFB);
/// How long after an event its stamped line may print: an announce the
/// event triggered can reach the tap first.
const STAMP_SLACK_SECS: f64 = 1.0;

fn marker(row: &OfferedRow) -> (u32, u16) {
    (row.client_id, row.port)
}

/// rmule's announce lists the partial with the incomplete marker and the
/// whole file beside it with the complete one, both in one `OP_OFFERFILES`.
pub(super) fn sentinels(run: &Run<'_>) -> Claim {
    const NAME: &str = "the-announce-marks-the-partial-incomplete-beside-a-whole-file";
    let Some(flags) = run.flags else {
        return Claim::new(
            NAME,
            Verdict::NotRun,
            "the tap holds no OP_IDCHANGE to rmule",
        );
    };
    // While offered as a partial: up to its withdrawal, less the slack
    // between the announce leaving and rmule printing the withdrawal's line.
    let completed = run
        .trail
        .first_at("serve.partial_withdrawn")
        .map(|at| at - STAMP_SLACK_SECS)
        .or_else(|| run.completed_at())
        .unwrap_or(f64::INFINITY);
    let partial: Vec<&(f64, Vec<OfferedRow>)> = run
        .offers
        .iter()
        .filter(|(at, rows)| *at < completed && rows.iter().any(|row| row.hash == run.stream_hash))
        .collect();
    if flags & SRV_TCPFLG_COMPRESSION == 0 {
        let markers: Vec<String> = partial
            .iter()
            .flat_map(|(_, rows)| rows.iter().filter(|row| row.hash == run.stream_hash))
            .map(|row| format!("{:#010x}:{:#06x}", row.client_id, row.port))
            .collect();
        return Claim::new(
            NAME,
            Verdict::Observed,
            format!(
                "the server grants no compression (flags {flags:#010x}): the partial rides {}",
                markers.join(", ")
            ),
        );
    }
    if partial.is_empty() {
        return Claim::new(NAME, Verdict::Fail, "no OP_OFFERFILES listed the partial");
    }
    let mut failures = Vec::new();
    for (at, rows) in &partial {
        for row in rows.iter().filter(|row| row.hash == run.stream_hash) {
            if marker(row) != INCOMPLETE {
                failures.push(format!(
                    "{at:.3}: the partial rides {:#010x}:{:#06x}",
                    row.client_id, row.port
                ));
            }
        }
    }
    let beside = run.whole_hash.map(|whole| {
        partial.iter().any(|(_, rows)| {
            rows.iter()
                .any(|row| row.hash == whole && marker(row) == COMPLETE)
        })
    });
    if beside == Some(false) {
        failures.push("no announce lists the whole file as complete beside the partial".to_owned());
    }
    Claim::judged(
        NAME,
        &failures,
        format!(
            "flags {flags:#010x}; {} announces list the partial at 0xFCFCFCFC:0xFCFC{}",
            partial.len(),
            if beside == Some(true) {
                ", the whole file beside it at 0xFBFBFBFB:0xFBFB"
            } else {
                ""
            }
        ),
    )
}

/// After a restart with the download paused, nothing of it is offered and
/// no slot ask for it is granted until its Offer Check has passed; then it
/// is announced, and a downloader asking again is served.
pub(super) fn restart(run: &Run<'_>) -> Claim {
    const NAME: &str = "after-a-restart-the-partial-waits-for-its-offer-check";
    let (true, Some(reopened)) = (run.topology.knobs.restart, run.reopened_at()) else {
        return Claim::new(
            NAME,
            Verdict::NotRun,
            "the run did not restart rmule with its download paused",
        );
    };
    let Some(reoffered) = run.reoffered_at() else {
        return Claim::new(
            NAME,
            Verdict::Fail,
            "the reopened download was never offered again",
        );
    };
    let mut failures = Vec::new();
    let lists = |row: &OfferedRow| row.hash == run.stream_hash;
    for (at, rows) in run
        .offers
        .iter()
        .filter(|(at, _)| *at >= reopened && *at < reoffered)
    {
        if rows.iter().any(lists) {
            failures.push(format!("{at:.3}: announced before the check passed"));
        }
    }
    let flagged = grants_compression(run);
    let announced = run.offers.iter().any(|(at, rows)| {
        *at >= reoffered
            && rows
                .iter()
                .any(|row| lists(row) && (!flagged || marker(row) == INCOMPLETE))
    });
    if !announced {
        failures.push("no announce after the check lists the partial".to_owned());
    }
    for ask in run.wire.items.iter().filter(|item| {
        !item.from_rmule
            && item.at >= reopened
            && item.at < reoffered
            && super::answers::asks_for(run, item)
    }) {
        if run.wire.items.iter().any(|item| {
            item.from_rmule
                && item.peer.ip() == ask.peer.ip()
                && item.at > ask.at
                && item.at < reoffered
                && matches!(item.said, Said::Accept | Said::Rank { .. })
        }) {
            failures.push(format!(
                "{:.3}: a slot ask was answered before the check passed",
                ask.at
            ));
        }
    }
    let served_again = run.wire.items.iter().any(|item| {
        item.from_rmule
            && item.at > reoffered
            && matches!(&item.said, Said::Block { hash, .. } if *hash == run.stream_hash)
    });
    let bound = run
        .trail
        .named("download reoffered")
        .next()
        .map(|mark| {
            format!(
                "offered {} ms after the reopen, {} verified bytes re-read",
                mark.field("after_ms").unwrap_or("?"),
                mark.field("verified_bytes").unwrap_or("?")
            )
        })
        .unwrap_or_default();
    Claim::judged(
        NAME,
        &failures,
        format!(
            "{bound}; nothing offered or granted before it; {}",
            if served_again {
                "served again after it"
            } else {
                "no downloader asked again inside the leg"
            }
        ),
    )
}

/// Whether `row` lists the partial as an incomplete file: under the
/// incomplete marker when the server grants compression, by its hash alone
/// when it does not (both forms then carry rmule's own ID and port).
pub(super) fn lists_partial(run: &Run<'_>, row: &OfferedRow) -> bool {
    row.hash == run.stream_hash && (!grants_compression(run) || marker(row) == INCOMPLETE)
}

/// Whether `row` lists the stream file as a whole file.
pub(super) fn lists_whole(run: &Run<'_>, row: &OfferedRow) -> bool {
    row.hash == run.stream_hash && (!grants_compression(run) || marker(row) == COMPLETE)
}

/// Whether the server granted rmule `SRV_TCPFLG_COMPRESSION`.
fn grants_compression(run: &Run<'_>) -> bool {
    run.flags
        .is_some_and(|flags| flags & SRV_TCPFLG_COMPRESSION != 0)
}
