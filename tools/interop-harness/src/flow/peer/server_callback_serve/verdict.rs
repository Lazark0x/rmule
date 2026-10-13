//! The server-callback-serve verdict, scored from a retained run dir.
//!
//! Two taps carry the bytes: one in `ed2ksrv`'s namespace (rmule's
//! `OP_IDCHANGE`, the downloader's `OP_CALLBACKREQUEST`, the
//! `OP_CALLBACKREQUESTED` the server relayed to rmule), one in rmule's (rmule's
//! dial to the endpoint the relay named and every frame on that link, and any
//! dial the downloader made at rmule's listener). The server's id, the
//! downloader's ask, the server's relay, the downloader's answer and asks on
//! the dialed link and the file it wrote are counterparty bytes; rmule's dial
//! and its hello on it are rmule's own, scored `rmule-only`; the dial the
//! downloader never made at rmule's listener is a documented absence
//! (ADR-0045).

use std::fs;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::flow::ed2k_server::search_wire::server_tap::OP_IDCHANGE;
use crate::flow::nat::claims::{Claim, Evidence, label};
use crate::flow::pcap::{Ed2kFrame, TcpOpen, TcpStream, records, tcp_capture};
use crate::flow::wire_filter::{OP_EDONKEYPROT, OP_EMULEPROT};

/// The flow's name and its verdict file's stem.
pub(crate) const FLOW: &str = "server-callback-serve";
/// Where the flow's own artifacts sit under the run dir.
pub(crate) const ROOT_DIR: &str = "server-callback-serve";
/// The tap in `ed2ksrv`'s namespace.
pub(crate) const SERVER_PCAP: &str = "server.pcap";
/// The tap in rmule's namespace.
pub(crate) const RMULE_PCAP: &str = "rmule.pcap";
/// The addresses the run stood its bodies at.
pub(crate) const ADDRESSES: &str = "addresses.toml";
/// The downloader's copy of the file, under the run dir.
pub(crate) const DOWNLOADED: &str = "amule/shared.bin";
/// The file rmule shared, under the run dir.
pub(crate) const SHARED: &str = "synthetic/shared.bin";

/// `OP_CALLBACKREQUEST`: the low id the downloader asks the server to call.
const OP_CALLBACKREQUEST: u8 = 0x1C;
/// `OP_CALLBACKREQUESTED`: the server tells the Low-ID client whom to dial.
const OP_CALLBACKREQUESTED: u8 = 0x35;
/// `OP_HELLO`: the dialer's first frame on a peer link.
const OP_HELLO: u8 = 0x01;
/// `OP_HELLOANSWER`: the accepting side's answer to it.
const OP_HELLOANSWER: u8 = 0x4C;
/// The downloader's asks for the file on a link: `OP_REQUESTFILENAME`,
/// `OP_SETREQFILEID`, `OP_STARTUPLOADREQ`, `OP_REQUESTPARTS`.
const FILE_ASKS: [u8; 4] = [0x58, 0x4F, 0x54, 0x47];
/// `OP_REQUESTPARTS_I64` (eMule extension).
const OP_REQUESTPARTS_I64: u8 = 0xA3;
/// `OP_SENDINGPART`.
const OP_SENDINGPART: u8 = 0x46;
/// The eMule-extension part frames: `OP_COMPRESSEDPART`,
/// `OP_SENDINGPART_I64`, `OP_COMPRESSEDPART_I64`.
const EMULE_PART_FRAMES: [u8; 3] = [0x40, 0xA2, 0xA1];
/// Ids under this are Low IDs.
const LOW_ID_LIMIT: u32 = 0x0100_0000;

/// The claim on the server's relay to rmule.
pub(crate) const RELAYED: &str = "the-server-relayed-the-downloaders-ask-to-rmule";
/// The claim on rmule's dial to the endpoint the relay named.
pub(crate) const DIALED: &str = "rmule-dialed-the-relayed-requester-back";
/// The claim on the downloader's byte-equal copy.
pub(crate) const BYTE_EQUAL: &str = "the-downloader-completed-the-file-byte-equal";
/// The claim that the transfer could have ridden no other road.
pub(crate) const NO_DIRECT_DIAL: &str = "the-downloader-never-reached-rmules-listener";

/// The bodies' addresses, written by the flow and read back by the scorer.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Addresses {
    /// rmule's address.
    pub(crate) rmule: Ipv4Addr,
    /// The port rmule's listener holds — the one its forced Low ID blocks.
    pub(crate) rmule_port: u16,
    /// The High-ID aMule downloader's address.
    pub(crate) downloader: Ipv4Addr,
    /// `ed2ksrv`'s TCP endpoint.
    pub(crate) server: SocketAddrV4,
    /// The `ed2ksrv` pin the run stood on.
    pub(crate) ed2ksrv_pin: String,
}

/// What the two taps and the two files hold, read once.
pub(crate) struct Observed {
    /// Every eD2k frame of every TCP direction the server tap reassembled.
    pub(crate) server_frames: Vec<Ed2kFrame>,
    /// Every eD2k frame of every TCP direction the rmule tap reassembled.
    pub(crate) rmule_frames: Vec<Ed2kFrame>,
    /// The directions that did not open as plain eD2k, as `source > destination`.
    pub(crate) obfuscated: Vec<(SocketAddr, SocketAddr)>,
    /// Every SYN without ACK on the rmule tap.
    pub(crate) rmule_opens: Vec<TcpOpen>,
    /// Whether the downloader's copy exists and equals the shared file, and
    /// its length (`-1` when it was never written).
    pub(crate) downloaded: (bool, i64),
}

/// The counts a verdict reports beside its claims.
#[derive(Debug, Default, Serialize, PartialEq)]
pub(crate) struct Rows {
    /// The id `ed2ksrv`'s `OP_IDCHANGE` gave rmule, `-1` when none was read.
    pub(crate) rmule_id: i64,
    /// `OP_CALLBACKREQUEST`s naming rmule's id from the downloader.
    pub(crate) callback_requests_server_tap: usize,
    /// `OP_CALLBACKREQUESTED`s the server sent rmule.
    pub(crate) callback_relays_server_tap: usize,
    /// The requester the first relay named.
    pub(crate) relayed_requester: String,
    /// Whether that relay carried the 17-byte crypt extension.
    pub(crate) relay_carried_crypt_extension: bool,
    /// rmule's SYNs to the relayed requester.
    pub(crate) dial_backs_rmule_tap: usize,
    /// Part frames rmule sent on the dialed link.
    pub(crate) part_frames_rmule_tap: usize,
    /// The downloader's SYNs at rmule's listener.
    pub(crate) direct_dials_rmule_tap: usize,
    /// The downloader's copy's length, `-1` when it was never written.
    pub(crate) downloaded_bytes: i64,
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
/// If the address file or a tap the run must have kept is missing or
/// unreadable — a broken run, never a zero.
pub fn score_run_dir(run_dir: &Path) -> Result<&'static str> {
    let root = run_dir.join(ROOT_DIR);
    let addresses_path = root.join(ADDRESSES);
    let addresses: Addresses = toml::from_str(
        &fs::read_to_string(&addresses_path)
            .with_context(|| format!("read {}", addresses_path.display()))?,
    )
    .with_context(|| format!("parse {}", addresses_path.display()))?;
    let observed = observe(run_dir)?;
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

/// Read the taps and files under `run_dir`.
fn observe(run_dir: &Path) -> Result<Observed> {
    let root = run_dir.join(ROOT_DIR);
    let server = tcp_capture(&records(&root.join(SERVER_PCAP))?)?;
    let rmule = tcp_capture(&records(&root.join(RMULE_PCAP))?)?;
    let frames = |streams: &[TcpStream]| -> Vec<Ed2kFrame> {
        streams.iter().flat_map(TcpStream::ed2k_frames).collect()
    };
    let obfuscated = server
        .streams
        .iter()
        .chain(&rmule.streams)
        .filter(|stream| !stream.opens_plain())
        .map(|stream| (stream.source, stream.destination))
        .collect();
    let shared_path = run_dir.join(SHARED);
    let shared =
        fs::read(&shared_path).with_context(|| format!("read {}", shared_path.display()))?;
    // A copy never written is the downloader not finishing — an observation,
    // not a broken run.
    let downloaded = fs::read(run_dir.join(DOWNLOADED)).map_or((false, -1), |copy| {
        (
            copy == shared,
            i64::try_from(copy.len()).unwrap_or(i64::MAX),
        )
    });
    Ok(Observed {
        server_frames: frames(&server.streams),
        rmule_frames: frames(&rmule.streams),
        obfuscated,
        rmule_opens: rmule.opens,
        downloaded,
    })
}

/// The first little-endian `u32` of a frame's payload.
fn u32_at_start(frame: &Ed2kFrame) -> Option<u32> {
    let bytes = frame.payload().get(..4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// The requester an `OP_CALLBACKREQUESTED` names: four network-order address
/// bytes and a little-endian port.
fn relayed_requester(frame: &Ed2kFrame) -> Option<SocketAddr> {
    let body = frame.payload().get(..6)?;
    let ip = Ipv4Addr::new(body[0], body[1], body[2], body[3]);
    let port = u16::from_le_bytes([body[4], body[5]]);
    Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
}

/// Whether `addr` is an IPv4 endpoint at `ip`.
fn is_v4(addr: SocketAddr, ip: Ipv4Addr) -> bool {
    matches!(addr, SocketAddr::V4(v4) if *v4.ip() == ip)
}

/// The flow's claims and rows over what a run observed.
pub(crate) fn claims(at: &Addresses, seen: &Observed) -> (Vec<Claim>, Rows) {
    let server = SocketAddr::V4(at.server);
    let listener = SocketAddr::V4(SocketAddrV4::new(at.rmule, at.rmule_port));
    let rmule_id = seen
        .server_frames
        .iter()
        .filter(|f| {
            f.source == server
                && is_v4(f.destination, at.rmule)
                && (f.protocol, f.opcode) == (OP_EDONKEYPROT, OP_IDCHANGE)
        })
        .filter_map(u32_at_start)
        .next_back();
    let asks: Vec<f64> = seen
        .server_frames
        .iter()
        .filter(|f| {
            is_v4(f.source, at.downloader)
                && f.destination == server
                && (f.protocol, f.opcode) == (OP_EDONKEYPROT, OP_CALLBACKREQUEST)
                && rmule_id.is_some()
                && u32_at_start(f) == rmule_id
        })
        .map(|f| f.at)
        .collect();
    let relays: Vec<&Ed2kFrame> = seen
        .server_frames
        .iter()
        .filter(|f| {
            f.source == server
                && is_v4(f.destination, at.rmule)
                && (f.protocol, f.opcode) == (OP_EDONKEYPROT, OP_CALLBACKREQUESTED)
        })
        .collect();
    let first_ask = asks.first().copied();
    let relay = first_ask.and_then(|ask| relays.iter().copied().find(|r| r.at >= ask));
    let requester = relay.and_then(relayed_requester);
    let dials: Vec<&TcpOpen> = seen
        .rmule_opens
        .iter()
        .filter(|o| is_v4(o.source, at.rmule) && Some(o.destination) == requester)
        .collect();
    let dial = relay.and_then(|relay| dials.iter().copied().find(|o| o.at >= relay.at));
    // The dialed link, both directions: rmule's ephemeral end to the
    // requester, and back.
    let on_link = |f: &&Ed2kFrame, from_rmule: bool| {
        dial.is_some_and(|dial| {
            if from_rmule {
                f.source == dial.source && f.destination == dial.destination
            } else {
                f.source == dial.destination && f.destination == dial.source
            }
        })
    };
    let first_from_rmule = seen
        .rmule_frames
        .iter()
        .filter(|f| on_link(f, true))
        .min_by(|a, b| a.at.total_cmp(&b.at));
    let answered = seen
        .rmule_frames
        .iter()
        .filter(|f| on_link(f, false))
        .any(|f| (f.protocol, f.opcode) == (OP_EDONKEYPROT, OP_HELLOANSWER));
    let file_asks = seen
        .rmule_frames
        .iter()
        .filter(|f| on_link(f, false))
        .filter(|f| {
            (f.protocol == OP_EDONKEYPROT && FILE_ASKS.contains(&f.opcode))
                || (f.protocol, f.opcode) == (OP_EMULEPROT, OP_REQUESTPARTS_I64)
        })
        .count();
    let part_frames = seen
        .rmule_frames
        .iter()
        .filter(|f| on_link(f, true))
        .filter(|f| {
            (f.protocol, f.opcode) == (OP_EDONKEYPROT, OP_SENDINGPART)
                || (f.protocol == OP_EMULEPROT && EMULE_PART_FRAMES.contains(&f.opcode))
        })
        .count();
    let direct_dials = seen
        .rmule_opens
        .iter()
        .filter(|o| is_v4(o.source, at.downloader) && o.destination == listener)
        .count();
    let obfuscated = |source: SocketAddr, destination: SocketAddr| {
        seen.obfuscated.contains(&(source, destination))
    };

    let mut claims = vec![Claim::about(
        "rmule-logged-in-low-id",
        rmule_id.is_some_and(|id| id < LOW_ID_LIMIT),
        Evidence::Captured,
        rmule_id.map_or_else(
            || "no OP_IDCHANGE from the server to rmule was read".to_owned(),
            |id| format!("the server's OP_IDCHANGE to rmule named {id:#x}"),
        ),
    )];
    let server_link_unreadable = seen.obfuscated.iter().any(|&(source, destination)| {
        destination == server && (is_v4(source, at.rmule) || is_v4(source, at.downloader))
    });
    if server_link_unreadable {
        let why = "a server link did not open as plain eD2k, so its frames cannot be read";
        claims.push(Claim::blocked(
            "the-downloader-asked-the-server-to-call-rmule-back",
            why,
        ));
        claims.push(Claim::blocked(RELAYED, why));
    } else {
        claims.push(Claim::about(
            "the-downloader-asked-the-server-to-call-rmule-back",
            first_ask.is_some(),
            Evidence::Captured,
            first_ask.map_or_else(
                || "no OP_CALLBACKREQUEST naming rmule's id came from the downloader".to_owned(),
                |ask| format!("OP_CALLBACKREQUEST at {ask:.3}"),
            ),
        ));
        claims.push(Claim::about(
            RELAYED,
            requester.is_some_and(|r| is_v4(r, at.downloader)),
            Evidence::Captured,
            match (relay, requester) {
                (Some(relay), Some(requester)) => format!(
                    "OP_CALLBACKREQUESTED at {:.3} naming {requester}, {}-byte body",
                    relay.at,
                    relay.payload().len()
                ),
                _ => "no OP_CALLBACKREQUESTED reached rmule after the ask".to_owned(),
            },
        ));
    }
    claims.push(Claim::about(
        DIALED,
        dial.is_some(),
        Evidence::RmuleOnly,
        dial.map_or_else(
            || "no SYN from rmule to the relayed requester after the relay".to_owned(),
            |dial| {
                format!(
                    "SYN {} > {} at {:.3}",
                    dial.source, dial.destination, dial.at
                )
            },
        ),
    ));
    let link_unreadable = dial.is_some_and(|dial| {
        obfuscated(dial.source, dial.destination) || obfuscated(dial.destination, dial.source)
    });
    if link_unreadable {
        let why = "the dialed link did not open as plain eD2k, so its frames cannot be read";
        claims.push(Claim::blocked("rmule-spoke-first-on-the-dialed-link", why));
        claims.push(Claim::blocked(
            "the-downloader-answered-and-asked-for-the-file-on-it",
            why,
        ));
    } else {
        claims.push(Claim::about(
            "rmule-spoke-first-on-the-dialed-link",
            first_from_rmule.is_some_and(|f| (f.protocol, f.opcode) == (OP_EDONKEYPROT, OP_HELLO)),
            Evidence::RmuleOnly,
            first_from_rmule.map_or_else(
                || "rmule sent no frame on the dialed link".to_owned(),
                |f| format!("first frame {:#04x} {:#04x}", f.protocol, f.opcode),
            ),
        ));
        claims.push(Claim::about(
            "the-downloader-answered-and-asked-for-the-file-on-it",
            answered && file_asks > 0,
            Evidence::Captured,
            format!(
                "OP_HELLOANSWER {}; file asks on the link: {file_asks}; rmule's part frames: \
                 {part_frames}",
                if answered { "came" } else { "never came" }
            ),
        ));
    }
    let (equal, length) = seen.downloaded;
    claims.push(Claim::about(
        BYTE_EQUAL,
        equal,
        Evidence::Captured,
        match length {
            -1 => "the downloader never wrote its copy".to_owned(),
            length if equal => format!("its {length}-byte copy equals the shared file"),
            length => format!("its {length}-byte copy differs from the shared file"),
        },
    ));
    claims.push(Claim::absence(
        NO_DIRECT_DIAL,
        i64::try_from(direct_dials).unwrap_or(i64::MAX),
        format!(
            "rmule's listener {listener} drops inbound TCP, so the transfer rode the dial-back \
             alone; the downloader's SYNs at it: {direct_dials}"
        ),
    ));

    let rows = Rows {
        rmule_id: rmule_id.map_or(-1, i64::from),
        callback_requests_server_tap: asks.len(),
        callback_relays_server_tap: relays.len(),
        relayed_requester: requester.map(|r| r.to_string()).unwrap_or_default(),
        relay_carried_crypt_extension: relay.is_some_and(|r| r.payload().len() >= 23),
        dial_backs_rmule_tap: dials.len(),
        part_frames_rmule_tap: part_frames,
        direct_dials_rmule_tap: direct_dials,
        downloaded_bytes: length,
    };
    (claims, rows)
}

#[cfg(test)]
mod tests;
