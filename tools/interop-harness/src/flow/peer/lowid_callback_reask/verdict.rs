//! The Low-ID callback re-ask verdict, scored from a retained run dir.
//!
//! Two taps carry the bytes: one in `ed2ksrv`'s namespace (the sharer's
//! `OP_IDCHANGE`, each `OP_CALLBACKREQUEST` that reached the server and each
//! `OP_CALLBACKREQUESTED` it relayed), one in rmule's (the sharer's dial-backs,
//! its `OP_QUEUERANKING` and source answer, every dial rmule made, and the
//! reask datagrams between the two). The server's relay, the sharer's dials,
//! its rank, its source answer — which closes aMule's source-ask gate, the
//! ping's precondition — and its `OP_REASKACK` are counterparty bytes; the timing of rmule's `0x90` to the
//! called-back sharer is rmule's own decision, scored `rmule-only`, and the
//! second callback request that must not come is a documented absence
//! (ADR-0045).

use std::collections::BTreeSet;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

mod observed;

use observed::{Observed, is_v4, observe, rank_of, u32_at_start};

use crate::flow::ed2k_server::search_wire::server_tap::OP_IDCHANGE;
use crate::flow::nat::claims::{Claim, Evidence, label};
use crate::flow::pcap::Udp4Datagram;
use crate::flow::peer::udp_reask::tap::{OP_REASKACK, OP_REASKFILEPING};
use crate::flow::wire_filter::{OP_EDONKEYPROT, OP_EMULEPROT};

/// The flow's name, its run-dir subdirectory and its verdict file's stem.
pub(crate) const FLOW: &str = "peer-lowid-callback-reask";
/// Where the flow's own artifacts sit under the run dir.
pub(crate) const ROOT_DIR: &str = "lowid-callback-reask";
/// The tap in `ed2ksrv`'s namespace.
pub(crate) const SERVER_PCAP: &str = "server.pcap";
/// The tap in rmule's namespace.
pub(crate) const RMULE_PCAP: &str = "rmule.pcap";
/// The addresses the run stood its bodies at.
pub(crate) const ADDRESSES: &str = "addresses.toml";

/// `OP_CALLBACKREQUEST`: the low id rmule asks the server to call back.
const OP_CALLBACKREQUEST: u8 = 0x1C;
/// `OP_CALLBACKREQUESTED`: the server tells the Low-ID client whom to dial.
const OP_CALLBACKREQUESTED: u8 = 0x35;
/// `OP_PACKEDPROT`: an eMule frame zlib-packed.
const PACKED: u8 = 0xD4;
/// `OP_ANSWERSOURCES`: the SX1 source answer.
const OP_ANSWERSOURCES: u8 = 0x82;
/// `OP_ANSWERSOURCES2`: the SX2 source answer.
const OP_ANSWERSOURCES2: u8 = 0x84;
/// Ids under this are Low IDs.
const LOW_ID_LIMIT: u32 = 0x0100_0000;
/// aMule `FILEREASKTIME` (`Constants.h`) less the 20 s the UDP ping leads
/// the TCP full ask by (`PartFile.cpp:1461`), and rmule's Source Book window.
const PING_WINDOW_SECS: f64 = 1280.0;
/// How early the ping may land against the last rank frame: the brain stamps
/// the standing when it reads the frame, a moment after the tap does.
const REASK_EARLY_SLACK_SECS: f64 = 2.0;
/// How late it may land: the brain wakes at the instant itself.
const REASK_LATE_SLACK_SECS: f64 = 30.0;
/// How soon after a request the server's relay — or after a ping, its
/// answer — counts as its reply.
const RELAY_WINDOW_SECS: f64 = 10.0;

/// The claim that the sharer answered rmule's source ask, which closes
/// aMule's source-ask gate so the reask may be a ping.
pub(crate) const SX_ANSWERED: &str = "the-sharer-answered-rmules-source-ask";
/// The claim on rmule's `0x90` to the called-back sharer.
pub(crate) const PINGED: &str = "rmule-pinged-the-called-back-sharer-at-the-reask-window";
/// The claim on the sharer's `OP_REASKACK`.
pub(crate) const ANSWERED: &str = "the-sharer-answered-the-ping-with-its-rank";
/// The claim that the answered standing asked for no second callback.
pub(crate) const NO_SECOND_CALLBACK: &str =
    "rmule-asked-for-no-second-callback-while-its-standing-was-fresh";

/// The bodies' addresses, written by the flow and read back by the scorer.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Addresses {
    /// rmule's address.
    pub(crate) rmule: Ipv4Addr,
    /// The port rmule's inbound listener holds — where a dial-back lands.
    pub(crate) rmule_port: u16,
    /// The Low-ID aMule sharer's address.
    pub(crate) sharer: Ipv4Addr,
    /// `ed2ksrv`'s TCP endpoint.
    pub(crate) server: SocketAddrV4,
    /// The `ed2ksrv` pin the run stood on.
    pub(crate) ed2ksrv_pin: String,
}

/// The counts a verdict reports beside its claims.
#[derive(Debug, Default, Serialize, PartialEq)]
pub(crate) struct Rows {
    /// The id `ed2ksrv`'s `OP_IDCHANGE` gave the sharer, `-1` when none was read.
    pub(crate) sharer_id: i64,
    /// `OP_CALLBACKREQUEST`s for the sharer's id that reached the server.
    pub(crate) callback_requests_server_tap: usize,
    /// `OP_CALLBACKREQUESTED`s the server sent the sharer.
    pub(crate) callback_relays_server_tap: usize,
    /// The sharer's dials to rmule's listener.
    pub(crate) dial_backs_rmule_tap: usize,
    /// Queue-rank frames the sharer sent rmule.
    pub(crate) rank_frames_rmule_tap: usize,
    /// Source answers (`OP_ANSWERSOURCES`/`2`, plain or packed) the sharer
    /// sent rmule.
    pub(crate) sx_answers_rmule_tap: usize,
    /// `OP_REASKFILEPING`s rmule sent the sharer, which aMule 2.3.3 sends any
    /// queued source with a UDP port (`DownloadClient.cpp:1269-1296`).
    pub(crate) udp_reask_pings_rmule_tap: usize,
    /// `OP_REASKACK`s the sharer sent rmule.
    pub(crate) udp_reask_acks_rmule_tap: usize,
    /// The endpoint the sharer's first ranked link came in from.
    pub(crate) old_inbound_endpoint: String,
    /// The client-UDP endpoint rmule's first ping went to.
    pub(crate) ping_destination: String,
    /// Seconds from the last rank frame to the first ping after it, `-1`
    /// when there was none.
    pub(crate) ping_delay_secs: f64,
}

/// The verdict file.
#[derive(Debug, Serialize)]
struct Verdict<'a> {
    #[serde(rename = "scenario")]
    flow: &'static str,
    verdict: &'static str,
    detail: String,
    ed2ksrv_pin: &'a str,
    rows: &'a Rows,
    claim: &'a [Claim],
}

/// The verdict file's path under `run_dir`.
pub(crate) fn verdict_path(run_dir: &Path) -> std::path::PathBuf {
    run_dir.join(format!("{FLOW}-verdict.toml"))
}

/// Score the retained run at `run_dir`: write its verdict file, print it, and
/// return the label.
///
/// # Errors
/// If an address file, a tap or a log the run must have kept is missing or
/// unreadable — a broken run, never a zero.
pub fn score_run_dir(run_dir: &Path) -> Result<&'static str> {
    let root = run_dir.join(ROOT_DIR);
    let addresses_path = root.join(ADDRESSES);
    let addresses: Addresses = toml::from_str(
        &fs::read_to_string(&addresses_path)
            .with_context(|| format!("read {}", addresses_path.display()))?,
    )
    .with_context(|| format!("parse {}", addresses_path.display()))?;
    let observed = observe(run_dir, &addresses)?;
    let (claims, rows) = claims(&addresses, &observed);
    let (verdict, detail) = label(&claims);
    let text = toml::to_string_pretty(&Verdict {
        flow: FLOW,
        verdict,
        detail,
        ed2ksrv_pin: &addresses.ed2ksrv_pin,
        rows: &rows,
        claim: &claims,
    })
    .context("serialize the verdict")?;
    let path = verdict_path(run_dir);
    fs::write(&path, &text).with_context(|| format!("write {}", path.display()))?;
    println!("{text}");
    Ok(verdict)
}

/// The flow's claims and rows over what a run observed.
pub(crate) fn claims(at: &Addresses, seen: &Observed) -> (Vec<Claim>, Rows) {
    let server = SocketAddr::V4(at.server);
    let listener = SocketAddr::V4(SocketAddrV4::new(at.rmule, at.rmule_port));
    let sharer_id = seen
        .server_frames
        .iter()
        .filter(|f| {
            f.source == server
                && is_v4(f.destination, at.sharer)
                && (f.protocol, f.opcode) == (OP_EDONKEYPROT, OP_IDCHANGE)
        })
        .filter_map(u32_at_start)
        .next_back();
    let asks: Vec<f64> = seen
        .server_frames
        .iter()
        .filter(|f| {
            is_v4(f.source, at.rmule)
                && f.destination == server
                && (f.protocol, f.opcode) == (OP_EDONKEYPROT, OP_CALLBACKREQUEST)
                && sharer_id.is_some()
                && u32_at_start(f) == sharer_id
        })
        .map(|f| f.at)
        .collect();
    let relays: Vec<f64> = seen
        .server_frames
        .iter()
        .filter(|f| {
            f.source == server
                && is_v4(f.destination, at.sharer)
                && (f.protocol, f.opcode) == (OP_EDONKEYPROT, OP_CALLBACKREQUESTED)
        })
        .map(|f| f.at)
        .collect();
    let mut dialers = BTreeSet::new();
    let dial_backs: Vec<f64> = seen
        .rmule_opens
        .iter()
        .filter(|o| is_v4(o.source, at.sharer) && o.destination == listener)
        .filter(|o| dialers.insert(o.source))
        .map(|o| o.at)
        .collect();
    let direct_dials: BTreeSet<SocketAddr> = seen
        .rmule_opens
        .iter()
        .filter(|o| is_v4(o.source, at.rmule) && is_v4(o.destination, at.sharer))
        .map(|o| o.destination)
        .collect();
    let sx_answers: Vec<f64> = seen
        .rmule_frames
        .iter()
        .filter(|f| {
            is_v4(f.source, at.sharer)
                && f.destination == listener
                && matches!(f.protocol, OP_EMULEPROT | PACKED)
                && matches!(f.opcode, OP_ANSWERSOURCES | OP_ANSWERSOURCES2)
        })
        .map(|f| f.at)
        .collect();
    let ranks: Vec<(f64, u32, SocketAddr)> = seen
        .rmule_frames
        .iter()
        .filter(|f| is_v4(f.source, at.sharer) && f.destination == listener)
        .filter_map(|f| Some((f.at, rank_of(f)?, f.source)))
        .collect();

    let relayed_after = |ask: f64| {
        relays
            .iter()
            .any(|&relay| relay >= ask && relay - ask <= RELAY_WINDOW_SECS)
    };
    let first_ask = asks.first().copied();
    let first_relay = first_ask.and_then(|ask| relays.iter().copied().find(|&r| r >= ask));
    let dial_back = first_relay.and_then(|relay| dial_backs.iter().copied().find(|&d| d >= relay));
    let queued = dial_back.and_then(|dial| {
        ranks
            .iter()
            .find(|(when, rank, _)| *when >= dial && *rank > 0)
            .copied()
    });
    let pings: Vec<&Udp4Datagram> = seen
        .reask_datagrams
        .iter()
        .filter(|d| {
            *d.source.ip() == at.rmule
                && *d.destination.ip() == at.sharer
                && d.payload.get(..2) == Some(&[OP_EMULEPROT, OP_REASKFILEPING])
        })
        .collect();
    let acks: Vec<(f64, u16)> = seen
        .reask_datagrams
        .iter()
        .filter(|d| {
            *d.source.ip() == at.sharer
                && *d.destination.ip() == at.rmule
                && d.payload.get(..2) == Some(&[OP_EMULEPROT, OP_REASKACK])
        })
        .filter_map(|d| {
            let rank = d.payload.get(2..)?.rchunks_exact(2).next()?;
            Some((d.at, u16::from_le_bytes([rank[0], rank[1]])))
        })
        .collect();
    let ping = queued.and_then(|(when, ..)| pings.iter().copied().find(|p| p.at > when));
    let last_rank = ping.and_then(|ping| {
        ranks
            .iter()
            .filter(|(when, rank, _)| *when < ping.at && *rank > 0)
            .map(|(when, ..)| *when)
            .reduce(f64::max)
    });
    let ping_delay = ping.zip(last_rank).map(|(ping, rank)| ping.at - rank);
    let on_time = ping_delay.is_some_and(|delay| {
        (PING_WINDOW_SECS - REASK_EARLY_SLACK_SECS..=PING_WINDOW_SECS + REASK_LATE_SLACK_SECS)
            .contains(&delay)
    });
    let answer = ping.and_then(|ping| {
        acks.iter().copied().find(|&(when, rank)| {
            when >= ping.at && when - ping.at <= RELAY_WINDOW_SECS && rank > 0
        })
    });
    let old_inbound = queued.map(|(_, _, from)| from);
    let sharer_ip = at.sharer.to_string();
    let record_naming_sharer = |code: &str| {
        seen.rmule_log
            .lines()
            .find(|line| line.contains(code) && line.contains(&format!("peer={sharer_ip}:")))
    };
    let acked_record = record_naming_sharer("download.source_reask_acked");
    let reasked_record = record_naming_sharer("download.source_reasked_over_tcp");
    // Every callback request after the queueing rank, and rmule's own TCP
    // full-ask record: the standing gone stale. `-1` when no rank anchored
    // the window, a zero nobody took.
    let stale = queued.map_or(-1, |(when, ..)| {
        let later = asks.iter().filter(|&&ask| ask > when).count();
        i64::try_from(later + usize::from(reasked_record.is_some())).unwrap_or(i64::MAX)
    });
    let obfuscated = |from: Ipv4Addr, to: SocketAddr| {
        seen.obfuscated
            .iter()
            .any(|&(source, destination)| is_v4(source, from) && destination == to)
    };

    let low_id_status = seen.sharer_log.contains("with LowID");
    let mut claims = vec![Claim::about(
        "the-sharer-logged-in-low-id",
        low_id_status && sharer_id.is_some_and(|id| id < LOW_ID_LIMIT),
        Evidence::Captured,
        format!(
            "the sharer's Status {}; the server's OP_IDCHANGE to it {}",
            if low_id_status {
                "reads `with LowID`"
            } else {
                "does not read `with LowID`"
            },
            sharer_id.map_or_else(|| "was not read".to_owned(), |id| format!("named {id:#x}")),
        ),
    )];
    let unreadable = obfuscated(at.rmule, server);
    let blocked = |name: &str| {
        Claim::blocked(
            name,
            "rmule's server link did not open as plain eD2k, so no OP_CALLBACKREQUEST on it \
             can be read",
        )
    };
    claims.push(if unreadable {
        blocked("the-server-relayed-rmules-callback")
    } else {
        Claim::about(
            "the-server-relayed-rmules-callback",
            first_ask.is_some_and(relayed_after),
            Evidence::Captured,
            match first_ask {
                None => "no OP_CALLBACKREQUEST for the sharer's id reached the server".to_owned(),
                Some(ask) => format!(
                    "OP_CALLBACKREQUEST at {ask:.3}; OP_CALLBACKREQUESTED to the sharer {}",
                    first_relay
                        .map_or_else(|| "never".to_owned(), |r| format!("{:.3} s later", r - ask))
                ),
            },
        )
    });
    claims.push(Claim::about(
        "the-sharer-dialed-rmule-back",
        dial_back.is_some(),
        Evidence::Captured,
        dial_back.map_or_else(
            || format!("no SYN from the sharer to {listener} after the server's relay"),
            |dial| format!("SYN to {listener} at {dial:.3}"),
        ),
    ));
    claims.push(if obfuscated(at.sharer, listener) {
        Claim::blocked(
            "the-sharer-queued-rmule-on-the-callback-link",
            "the sharer's link did not open as plain eD2k, so its rank cannot be read",
        )
    } else {
        Claim::about(
            "the-sharer-queued-rmule-on-the-callback-link",
            queued.is_some(),
            Evidence::Captured,
            queued.map_or_else(
                || "no queue rank above 0 came on a link the sharer dialed".to_owned(),
                |(when, rank, from)| format!("rank {rank} from {from} at {when:.3}"),
            ),
        )
    });
    // aMule leaves a due source ask to the TCP ask and sends no ping
    // (`DownloadClient.cpp:1271-1273`); for a complete source the ask stays
    // due until it answers one (`IsSourceRequestAllowed`, `:179-213`).
    let sx_answer = dial_back.and_then(|dial| {
        sx_answers
            .iter()
            .copied()
            .find(|&when| when >= dial && ping.is_none_or(|p| when < p.at))
    });
    claims.push(Claim::about(
        SX_ANSWERED,
        sx_answer.is_some(),
        Evidence::Captured,
        sx_answer.map_or_else(
            || {
                "no source answer from the sharer before the ping: its source-ask gate stays \
                 open, and aMule leaves the reask to the TCP ask that carries the source ask"
                    .to_owned()
            },
            |when| format!("source answer on the callback link at {when:.3}"),
        ),
    ));
    claims.push(Claim::about(
        PINGED,
        on_time,
        Evidence::RmuleOnly,
        match (ping, ping_delay) {
            (Some(ping), Some(delay)) => format!(
                "OP_REASKFILEPING to {} {delay:.1} s after the last rank; aMule pings any queued \
                 source with a UDP port at the address it connected from \
                 (DownloadClient.cpp:1269-1296)",
                ping.destination
            ),
            _ => "no OP_REASKFILEPING to the sharer after its rank".to_owned(),
        },
    ));
    claims.push(Claim::about(
        ANSWERED,
        answer.is_some() && acked_record.is_some(),
        Evidence::Captured,
        format!(
            "the sharer's OP_REASKACK {}; rmule's record: {}",
            answer.map_or_else(
                || "never came after the ping".to_owned(),
                |(when, rank)| format!(
                    "rank {rank} at {when:.3}, {:.3} s after the ping",
                    when - ping.map_or(when, |p| p.at)
                )
            ),
            acked_record.unwrap_or("none naming the sharer"),
        ),
    ));
    claims.push(if unreadable {
        blocked(NO_SECOND_CALLBACK)
    } else {
        Claim::absence(
            NO_SECOND_CALLBACK,
            stale,
            format!(
                "an answered ping refreshes the reask clock, so the 1300 s TCP full ask never \
                 falls due; callback requests for the sharer after its rank and TCP full-ask \
                 records: {stale} (record: {})",
                reasked_record.unwrap_or("none")
            ),
        )
    });
    claims.push(Claim::absence(
        "rmule-dialed-no-endpoint-of-the-sharer",
        i64::try_from(direct_dials.len()).unwrap_or(i64::MAX),
        format!(
            "a Low-ID source is reached by its callback road alone; rmule's SYNs to the sharer: \
             {direct_dials:?}; the old inbound endpoint was {}",
            old_inbound.map_or_else(|| "never seen".to_owned(), |from| from.to_string())
        ),
    ));

    let rows = Rows {
        sharer_id: sharer_id.map_or(-1, i64::from),
        callback_requests_server_tap: asks.len(),
        callback_relays_server_tap: relays.len(),
        dial_backs_rmule_tap: dial_backs.len(),
        rank_frames_rmule_tap: ranks.len(),
        sx_answers_rmule_tap: sx_answers.len(),
        udp_reask_pings_rmule_tap: pings.len(),
        udp_reask_acks_rmule_tap: acks.len(),
        old_inbound_endpoint: old_inbound.map(|from| from.to_string()).unwrap_or_default(),
        ping_destination: ping.map(|p| p.destination.to_string()).unwrap_or_default(),
        ping_delay_secs: ping_delay.unwrap_or(-1.0),
    };
    (claims, rows)
}

#[cfg(test)]
mod tests;
