//! The reciprocity verdict, scored from a retained run dir.
//!
//! **Credit**: the tap in rmule's namespace carries rmule's grant when its
//! slot frees — rmule's own bytes; the tap in S's namespace carries S's grant
//! when its slot frees — the counterparty's, the one that says S's credit
//! for rmule outweighed the waiters that queued before it; and X's own asks and
//! cancels say whether a body capped far below rmule's link held rmule's slot
//! until the flow stopped it (ADR-0031). **Low ID**: rmule's
//! run log dates its rank and its TCP full ask, and the tap carries the part
//! frames S sent on the connection that ask opened (ADR-0116).

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::{ReciprocityLeg, ReciprocityShape, SLOT_LINK};
use crate::flow::bench::AMULE_PEER_TCP_PORT;
use crate::flow::identity::parse_ed2k_file_hash;
use crate::flow::nat::claims::{Claim, Evidence, label};
use crate::flow::pcap::{Ed2kFrame, TcpCapture, records, tcp_capture};
use crate::flow::peer::queue_fanout::run_log::RunLog;
use crate::flow::peer::queue_fanout::verdict::part_of;
use crate::flow::wire_filter::{OP_EDONKEYPROT, OP_EMULEPROT};

/// The flow's name and its verdict file's stem.
pub(crate) const FLOW: &str = "peer-reciprocity";
/// Where the flow's own artifacts sit under the run dir.
pub(crate) const ROOT_DIR: &str = "peer-reciprocity";
/// The tap in rmule's namespace.
pub(crate) const RMULE_PCAP: &str = "rmule.pcap";
/// The tap in S's namespace.
pub(crate) const SHARER_PCAP: &str = "sharer.pcap";
/// The topology and the instants the run marked.
const TOPOLOGY: &str = "topology.toml";

/// `OP_ACCEPTUPLOADREQ`.
const OP_ACCEPTUPLOADREQ: u8 = 0x55;
/// `OP_REQUESTPARTS`.
const OP_REQUESTPARTS: u8 = 0x47;
/// `OP_REQUESTPARTS_I64`, under `OP_EMULEPROT`.
const OP_REQUESTPARTS_I64: u8 = 0xA3;
/// `OP_CANCELTRANSFER`.
const OP_CANCELTRANSFER: u8 = 0x56;
/// aMule's download cap follows a 10 s average of the rate
/// (`DownloadClient.cpp:1162-1177`), so X's first burst runs at link speed for
/// no longer than this: an ask later than it is a block X finished at its cap.
const BURST_SECS: f64 = 10.0;
/// The Low-ID Reask the build under test asks at (ADR-0116), seconds.
const LOW_ID_REASK_SECS: f64 = 900.0;
/// How far the reask may land from it: a sweep runs on the brain's wake, and
/// the TCP full ask waits on the Dial Window.
const REASK_SLACK_SECS: f64 = 30.0;

/// The claim on rmule's choice.
pub(crate) const RECIPROCATED: &str = "rmule-granted-the-sharer-it-queues-at-first";
/// The claim on the gift.
pub(crate) const GIFTED: &str = "the-sharer-holds-the-gift";
/// The claim on S's choice.
pub(crate) const CREDITED: &str = "the-sharer-promoted-rmule-ahead-of-earlier-waiters";
/// The claim on the Low-ID cadence.
pub(crate) const REASKED: &str = "rmule-asked-again-at-fifteen-minutes";
/// The claim on the Low-ID slot.
pub(crate) const SLOT_ON_REASK: &str = "the-sharer-sent-parts-after-the-reask";
/// The claim on the copy.
pub(crate) const BYTE_EQUAL: &str = "the-download-completed-byte-equal";
/// The claim the Low-ID leg stands on: the server gave rmule a Low ID.
pub(crate) const LOW_ID_LOGIN: &str = "rmule-logged-in-with-a-low-id";
/// The claim on X: capped far below rmule's link, it kept asking and never
/// cancelled until the flow stopped it. A stock downloader cancels when no
/// whole part packet lands for 100 s (`DownloadClient.cpp:848`, `:1189-1193`).
pub(crate) const SLOT_KEPT: &str = "the-capped-holder-kept-rmules-slot-until-stopped";

/// The instants a run marked, unix seconds.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq)]
pub(crate) struct Marks {
    /// Credit: W, the body queued at rmule before S.
    pub(crate) rival: Option<Ipv4Addr>,
    /// Credit: when the body holding rmule's slot was stopped.
    pub(crate) slot_freed_at: Option<f64>,
    /// Credit: whether S's copy of the gift was whole before the window
    /// closed.
    pub(crate) gift_complete: bool,
    /// When S's holder was stopped.
    pub(crate) holder_stopped_at: Option<f64>,
}

/// The wall clock now, unix seconds, as the taps and rmule's stamps read it.
pub(crate) fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |since| since.as_secs_f64())
}

/// What the flow stood up and marked, read back by the scorer.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct Topology {
    /// rmule's address.
    pub(crate) rmule: Ipv4Addr,
    /// S's address.
    pub(crate) sharer: Ipv4Addr,
    /// The leg and its timings.
    pub(crate) shape: ReciprocityShape,
    /// The instants it marked.
    pub(crate) marks: Marks,
}

impl Topology {
    /// Write it under the flow's dir `dir`.
    pub(crate) fn write(&self, dir: &Path) -> Result<()> {
        let path = dir.join(TOPOLOGY);
        fs::write(
            &path,
            toml::to_string(self).context("serialize the topology")?,
        )
        .with_context(|| format!("write {}", path.display()))
    }
}

/// The numbers a verdict reports beside its claims.
#[derive(Debug, Default, Serialize, PartialEq)]
pub(crate) struct Rows {
    /// Credit: where rmule's first grant after its slot freed went.
    pub(crate) rmule_granted: String,
    /// Credit: where S's first grant after its slot freed went.
    pub(crate) sharer_granted: String,
    /// Low ID: seconds from rmule's first rank at S to its TCP full ask;
    /// `-1.0` when either is missing.
    pub(crate) reask_after_rank_secs: f64,
    /// Seconds from S's holder stop to the first part frame S sent rmule;
    /// `-1.0` when none came.
    pub(crate) wait_from_stop_to_part_secs: f64,
    /// The ranks S gave rmule, in order: each slot ask's and each reask's
    /// answer that reached the log.
    pub(crate) ranks_at_sharer: Vec<u64>,
    /// The copy's length, `-1` when never written.
    pub(crate) copy_bytes: i64,
    /// Credit: seconds from X's first ask for the slot file to its last one
    /// before the flow stopped it; `-1.0` when it asked nothing.
    pub(crate) holder_asking_secs: f64,
    /// Credit: seconds from X's first ask to its first `OP_CANCELTRANSFER`
    /// before the flow stopped it; `-1.0` when it sent none.
    pub(crate) holder_cancel_secs: f64,
}

/// The verdict file.
#[derive(Debug, Serialize)]
struct Verdict<'a> {
    #[serde(rename = "scenario")]
    flow: &'static str,
    verdict: &'static str,
    detail: String,
    shape: ReciprocityShape,
    rows: &'a Rows,
    claim: &'a [Claim],
}

/// Score the run under `run_dir`, write its verdict file and return the
/// verdict.
///
/// # Errors
/// If the topology, a tap, the staged file or rmule's log cannot be read.
pub fn score_run_dir(run_dir: &Path) -> Result<&'static str> {
    let root = run_dir.join(ROOT_DIR);
    let topology_path = root.join(TOPOLOGY);
    let at: Topology = toml::from_str(
        &fs::read_to_string(&topology_path)
            .with_context(|| format!("read {}", topology_path.display()))?,
    )
    .with_context(|| format!("parse {}", topology_path.display()))?;
    let rmule_tap = tcp_capture(&records(&root.join(RMULE_PCAP))?)?;
    let sharer_tap = match at.shape.leg {
        ReciprocityLeg::Credit => Some(tcp_capture(&records(&root.join(SHARER_PCAP))?)?),
        ReciprocityLeg::LowId => None,
    };
    let synthetic = run_dir.join("synthetic");
    let link_path = synthetic.join("shared.ed2k.txt");
    let link =
        fs::read_to_string(&link_path).with_context(|| format!("read {}", link_path.display()))?;
    let hash = parse_ed2k_file_hash(link.trim())?;
    let staged_path = synthetic.join("shared.bin");
    let staged =
        fs::read(&staged_path).with_context(|| format!("read {}", staged_path.display()))?;
    let copy = fs::read(run_dir.join("rmule").join("output.bin")).map_or((false, -1), |copy| {
        (
            copy == staged,
            i64::try_from(copy.len()).unwrap_or(i64::MAX),
        )
    });
    let log = RunLog::read(run_dir)?;

    let mut rows = Rows {
        wait_from_stop_to_part_secs: at.marks.holder_stopped_at.map_or(-1.0, |stop| {
            first_part_after(&rmule_tap, at.sharer, hash, stop).map_or(-1.0, |at| at - stop)
        }),
        copy_bytes: copy.1,
        ranks_at_sharer: log.ranks(std::net::SocketAddr::from((at.sharer, AMULE_PEER_TCP_PORT))),
        reask_after_rank_secs: -1.0,
        holder_asking_secs: -1.0,
        holder_cancel_secs: -1.0,
        ..Rows::default()
    };
    let mut claims = Vec::new();
    match at.shape.leg {
        ReciprocityLeg::Credit => {
            let rmule_granted = at
                .marks
                .slot_freed_at
                .and_then(|freed| first_grant_from(&rmule_tap, at.rmule, freed));
            let sharer_granted = match (&sharer_tap, at.marks.holder_stopped_at) {
                (Some(tap), Some(stop)) => first_grant_from(tap, at.sharer, stop),
                _ => None,
            };
            rows.rmule_granted = format!("{rmule_granted:?}");
            rows.sharer_granted = format!("{sharer_granted:?}");
            claims.push(reciprocated(&at, rmule_granted));
            let slot_link_path = synthetic.join(SLOT_LINK);
            let slot = parse_ed2k_file_hash(
                fs::read_to_string(&slot_link_path)
                    .with_context(|| format!("read {}", slot_link_path.display()))?
                    .trim(),
            )?;
            let holder = at
                .marks
                .slot_freed_at
                .and_then(|stopped| holder_asks(&rmule_tap, at.rmule, slot, stopped));
            if let Some(holder) = &holder {
                rows.holder_asking_secs = holder.last_ask - holder.first_ask;
                rows.holder_cancel_secs = holder
                    .cancel
                    .map_or(-1.0, |cancel| cancel - holder.first_ask);
            }
            claims.push(slot_kept(&at, holder.as_ref()));
            claims.push(Claim::about(
                GIFTED,
                at.marks.gift_complete,
                Evidence::Captured,
                format!("S's copy of the gift whole: {}", at.marks.gift_complete),
            ));
            claims.push(Claim::about(
                CREDITED,
                sharer_granted == Some(at.rmule),
                Evidence::Captured,
                format!(
                    "S's first OP_ACCEPTUPLOADREQ after its holder stopped went to \
                     {sharer_granted:?}; rmule is {}",
                    at.rmule
                ),
            ));
        }
        ReciprocityLeg::LowId => {
            claims.push(low_id_login(&log));
            let listener = std::net::SocketAddr::from((at.sharer, AMULE_PEER_TCP_PORT));
            let ranked = log.first_naming_at("download.peer_queued", listener);
            let reasked = log.first_naming_at("download.source_reasked_over_tcp", listener);
            if let (Some(ranked), Some(reasked)) = (ranked, reasked) {
                rows.reask_after_rank_secs = reasked - ranked;
            }
            claims.push(Claim::about(
                REASKED,
                (rows.reask_after_rank_secs - LOW_ID_REASK_SECS).abs() <= REASK_SLACK_SECS,
                Evidence::RmuleOnly,
                format!(
                    "rmule's log: ranked at {ranked:?}, asked again over TCP at {reasked:?}: \
                     {} s after (expected {LOW_ID_REASK_SECS} s ± {REASK_SLACK_SECS} s)",
                    rows.reask_after_rank_secs
                ),
            ));
            claims.push(Claim::about(
                SLOT_ON_REASK,
                rows.wait_from_stop_to_part_secs >= 0.0,
                Evidence::Captured,
                format!(
                    "the first part frame from S came {} s after its holder stopped",
                    rows.wait_from_stop_to_part_secs
                ),
            ));
        }
    }
    claims.push(Claim::about(
        BYTE_EQUAL,
        copy.0,
        Evidence::Captured,
        format!("output.bin {} bytes, equal {}", copy.1, copy.0),
    ));
    let (verdict, detail) = label(&claims);
    let text = toml::to_string_pretty(&Verdict {
        flow: FLOW,
        verdict,
        detail,
        shape: at.shape,
        rows: &rows,
        claim: &claims,
    })
    .context("serialize the verdict")?;
    let path = run_dir.join(format!("{FLOW}-verdict.toml"));
    fs::write(&path, &text).with_context(|| format!("write {}", path.display()))?;
    println!("{text}");
    Ok(verdict)
}

/// The claim on rmule's choice, given where its first grant after its slot
/// freed went.
fn reciprocated(at: &Topology, rmule_granted: Option<Ipv4Addr>) -> Claim {
    if at.shape.gift_first {
        return Claim::blocked(
            RECIPROCATED,
            "the gift went first, on rmule's free slot: no rival queued and no slot \
             freed, so rmule's choice was not drawn",
        );
    }
    Claim::about(
        RECIPROCATED,
        rmule_granted == Some(at.sharer),
        Evidence::RmuleOnly,
        format!(
            "rmule's first OP_ACCEPTUPLOADREQ after its slot freed went to \
             {rmule_granted:?}; S is {}, W is {:?}",
            at.sharer, at.marks.rival
        ),
    )
}

/// When X, the body asking rmule for the slot file, first and last asked for
/// it and first sent `OP_CANCELTRANSFER`, before the flow stopped it.
struct HolderAsks {
    first_ask: f64,
    last_ask: f64,
    cancel: Option<f64>,
}

/// X's asks for `slot` on rmule's tap and its first cancel, before `stopped`;
/// X is whoever asked rmule for `slot` first. `None` when nobody did.
fn holder_asks(
    tap: &TcpCapture,
    rmule: Ipv4Addr,
    slot: [u8; 16],
    stopped: f64,
) -> Option<HolderAsks> {
    let to_rmule: Vec<Ed2kFrame> = frames(tap)
        .into_iter()
        .filter(|frame| frame.at < stopped && frame.destination.ip() == IpAddr::V4(rmule))
        .collect();
    let asks_slot = |frame: &Ed2kFrame| {
        matches!(
            (frame.protocol, frame.opcode),
            (OP_EDONKEYPROT, OP_REQUESTPARTS) | (OP_EMULEPROT, OP_REQUESTPARTS_I64)
        ) && frame.payload().get(..16) == Some(&slot[..])
    };
    let holder = to_rmule.iter().find(|frame| asks_slot(frame))?.source.ip();
    let from_holder: Vec<&Ed2kFrame> = to_rmule
        .iter()
        .filter(|frame| frame.source.ip() == holder)
        .collect();
    let asks: Vec<f64> = from_holder
        .iter()
        .filter(|frame| asks_slot(frame))
        .map(|frame| frame.at)
        .collect();
    Some(HolderAsks {
        first_ask: *asks.first()?,
        last_ask: *asks.last()?,
        cancel: from_holder
            .iter()
            .find(|frame| (frame.protocol, frame.opcode) == (OP_EDONKEYPROT, OP_CANCELTRANSFER))
            .map(|frame| frame.at),
    })
}

/// The claim on X: it sent no cancel before the flow stopped it, and it asked
/// again after its first burst, so a block finished at its cap.
fn slot_kept(at: &Topology, holder: Option<&HolderAsks>) -> Claim {
    if at.shape.gift_first {
        return Claim::blocked(
            SLOT_KEPT,
            "the gift went first, on rmule's free slot: no capped body held it",
        );
    }
    let Some(holder) = holder else {
        return Claim::about(
            SLOT_KEPT,
            false,
            Evidence::Captured,
            "no body asked rmule for the slot file before the flow stopped X",
        );
    };
    Claim::about(
        SLOT_KEPT,
        holder.cancel.is_none() && holder.last_ask - holder.first_ask > BURST_SECS,
        Evidence::Captured,
        format!(
            "X at {} KiB/s asked for the slot file over {:.1} s (more than {BURST_SECS} s \
             is a block finished at its cap); its first OP_CANCELTRANSFER before the \
             stop came {}",
            at.shape.x_kib,
            holder.last_ask - holder.first_ask,
            holder.cancel.map_or_else(
                || "never".to_owned(),
                |cancel| format!("{:.1} s after its first ask", cancel - holder.first_ask),
            ),
        ),
    )
}

/// Whether every server rmule logged in to gave it a Low ID, read off its
/// `server.connected` records: a High ID lets S call rmule back, and the
/// cadence the leg measures is then not the Low-ID one.
fn low_id_login(log: &RunLog) -> Claim {
    let ids = log.client_ids();
    Claim::about(
        LOW_ID_LOGIN,
        !ids.is_empty() && ids.iter().all(|id| id.is_low_id()),
        Evidence::RmuleOnly,
        format!(
            "rmule's servers gave it the client ids {:?}",
            ids.iter().map(|id| id.as_u32()).collect::<Vec<_>>()
        ),
    )
}

/// The frames `tap` delivered, in capture order.
fn frames(tap: &TcpCapture) -> Vec<Ed2kFrame> {
    let mut frames: Vec<Ed2kFrame> = tap
        .streams
        .iter()
        .flat_map(|stream| stream.ed2k_frames())
        .collect();
    frames.sort_by(|a, b| a.at.total_cmp(&b.at));
    frames
}

/// Whom the first `OP_ACCEPTUPLOADREQ` `from` sent at or after `since` went to.
fn first_grant_from(tap: &TcpCapture, from: Ipv4Addr, since: f64) -> Option<Ipv4Addr> {
    frames(tap)
        .into_iter()
        .filter(|frame| frame.at >= since && frame.source.ip() == IpAddr::V4(from))
        .find(|frame| (frame.protocol, frame.opcode) == (OP_EDONKEYPROT, OP_ACCEPTUPLOADREQ))
        .and_then(|frame| match frame.destination.ip() {
            IpAddr::V4(to) => Some(to),
            IpAddr::V6(_) => None,
        })
}

/// When the first part frame of `hash` from `sharer` arrived at or after
/// `since`.
fn first_part_after(tap: &TcpCapture, sharer: Ipv4Addr, hash: [u8; 16], since: f64) -> Option<f64> {
    frames(tap)
        .into_iter()
        .filter(|frame| frame.at >= since && frame.source.ip() == IpAddr::V4(sharer))
        .find(|frame| part_of(frame) == Some(hash))
        .map(|frame| frame.at)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A gift-first run frees no slot and queues no rival, so rmule's choice
    /// is not drawn: blocked, never a failure of the choice it never made.
    #[test]
    fn a_gift_first_run_leaves_rmules_choice_undrawn() {
        let mut at = Topology {
            rmule: Ipv4Addr::new(172, 19, 0, 8),
            sharer: Ipv4Addr::new(172, 19, 0, 3),
            shape: ReciprocityShape {
                leg: ReciprocityLeg::Credit,
                slot_kib: 10,
                holder_kib: None,
                x_kib: 2,
                gift_first: true,
                step_secs: 60,
                run_window_secs: 1200,
            },
            marks: Marks::default(),
        };
        assert_eq!(reciprocated(&at, None).outcome, "blocked");
        at.shape.gift_first = false;
        at.marks.slot_freed_at = Some(1.0);
        let rival = Ipv4Addr::new(172, 19, 0, 10);
        at.marks.rival = Some(rival);
        assert_eq!(reciprocated(&at, Some(rival)).outcome, "absent");
    }

    /// A login answered with a High ID (172.20.0.6, little-endian) is no
    /// Low-ID run, whatever its reask cadence; one answered with a Low ID is.
    #[test]
    fn the_low_id_leg_stands_only_on_a_low_id_login() {
        let high = RunLog::parse(
            "server.connected server=eserver:4661 client_id=100668588 at_unix_ms=1792383861850\n",
        );
        assert_eq!(low_id_login(&high).outcome, "absent");
        let low = RunLog::parse(
            "server.connected server=eserver:4661 client_id=7 at_unix_ms=1792383861850\n",
        );
        assert_eq!(low_id_login(&low).outcome, "held");
        assert_eq!(low_id_login(&RunLog::parse("")).outcome, "absent");
    }
}
