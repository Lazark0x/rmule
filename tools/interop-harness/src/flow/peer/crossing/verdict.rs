//! The crossing flow's verdict: every TCP link between rmule and the aMule
//! the leg races (W on the serve side, S on the download side), read off the
//! tap in rmule's namespace as a ledger — who opened it, when, who closed
//! it, and the frames each side wrote — and the leg's claims as predicates
//! over that ledger, rmule's stamped Run Log and its copy.
//!
//! A segment an `iptables` hold dropped in rmule's namespace never reached
//! the tap; the ledger holds what crossed the wire, and the Run Log says what
//! rmule did meanwhile.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::{CrossingLeg, CrossingShape};
use crate::flow::nat::claims::{Claim, Evidence, label};
use crate::flow::pcap::{TcpCapture, records, tcp_capture};

/// The flow's own dir under the run dir.
pub(crate) const ROOT_DIR: &str = "peer-crossing";
/// The tap in rmule's namespace.
pub(crate) const RMULE_PCAP: &str = "rmule.pcap";
const TOPOLOGY: &str = "topology.toml";
const VERDICT: &str = "peer-crossing-verdict.toml";

const OP_HELLO: u8 = 0x01;
const OP_SENDINGPART: u8 = 0x46;
const OP_ACCEPTUPLOADREQ: u8 = 0x55;
/// How soon after a returning waiter's hello its grant must follow.
const GRANT_AFTER_HELLO_SECS: f64 = 1.0;

/// The instants the flow marked.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub(crate) struct Marks {
    /// Serve legs: when X, holding rmule's slot, was stopped.
    pub(crate) holder_stopped_at: Option<f64>,
    /// When the raced aMule was told to open its own link (its `Add`).
    pub(crate) returned_at: Option<f64>,
    /// When each hold was lifted, in lifting order.
    pub(crate) lifted_at: Vec<f64>,
    /// When the watch after the last lift ended: the teardown that follows
    /// closes every link, so a link still up at this instant stayed up.
    pub(crate) watch_ended_at: Option<f64>,
}

/// The wall clock now, unix seconds, as the tap and rmule's stamps read it.
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
    /// The raced aMule's address: W, or S on the download side.
    pub(crate) peer: Ipv4Addr,
    /// The leg and its timings.
    pub(crate) shape: CrossingShape,
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

/// One TCP link between rmule and the raced aMule.
#[derive(Clone, Debug, Serialize, PartialEq)]
struct Link {
    /// rmule's end and the aMule's end.
    rmule_end: String,
    peer_end: String,
    /// Whether rmule dialed it.
    rmule_opened: bool,
    /// The first SYN's capture time.
    opened_at: f64,
    /// The first FIN or RST's capture time and who sent it (`-1`, empty while open).
    closed_at: f64,
    closed_by: String,
    /// The capture time of each side's first hello, of rmule's first
    /// `OP_ACCEPTUPLOADREQ` (`-1` without one), and the `OP_SENDINGPART`
    /// frames each side wrote.
    hello_from_rmule: f64,
    hello_from_peer: f64,
    first_grant: f64,
    parts_from_rmule: usize,
    parts_from_peer: usize,
}

/// Every link between `rmule` and `peer` the tap saw a SYN for, in opening order.
fn ledger(capture: &TcpCapture, rmule: IpAddr, peer: IpAddr) -> Vec<Link> {
    let mut links: Vec<Link> = Vec::new();
    for open in &capture.opens {
        let rmule_opened = open.source.ip() == rmule && open.destination.ip() == peer;
        let peer_opened = open.source.ip() == peer && open.destination.ip() == rmule;
        if !(rmule_opened || peer_opened) {
            continue;
        }
        let (rmule_end, peer_end) = if rmule_opened {
            (open.source, open.destination)
        } else {
            (open.destination, open.source)
        };
        if links.iter().any(|link| {
            link.rmule_end == rmule_end.to_string() && link.peer_end == peer_end.to_string()
        }) {
            continue;
        }
        let close = capture.closes.iter().find(|close| {
            (close.source == rmule_end && close.destination == peer_end)
                || (close.source == peer_end && close.destination == rmule_end)
        });
        let frames = |from: SocketAddr, to: SocketAddr| {
            capture
                .streams
                .iter()
                .filter(|stream| stream.source == from && stream.destination == to)
                .flat_map(|stream| stream.ed2k_frames())
                .map(|frame| (frame.at, frame.opcode))
                .collect::<Vec<_>>()
        };
        let out = frames(rmule_end, peer_end);
        let back = frames(peer_end, rmule_end);
        let first = |frames: &[(f64, u8)], opcode: u8| {
            frames
                .iter()
                .find(|(_, op)| *op == opcode)
                .map_or(-1.0, |(at, _)| *at)
        };
        let parts = |frames: &[(f64, u8)]| {
            frames
                .iter()
                .filter(|(_, op)| *op == OP_SENDINGPART)
                .count()
        };
        links.push(Link {
            rmule_end: rmule_end.to_string(),
            peer_end: peer_end.to_string(),
            rmule_opened,
            opened_at: open.at,
            closed_at: close.map_or(-1.0, |close| close.at),
            closed_by: close.map_or_else(String::new, |close| {
                if close.source == rmule_end {
                    "rmule"
                } else {
                    "peer"
                }
                .to_owned()
            }),
            hello_from_rmule: first(&out, OP_HELLO),
            hello_from_peer: first(&back, OP_HELLO),
            first_grant: first(&out, OP_ACCEPTUPLOADREQ),
            parts_from_rmule: parts(&out),
            parts_from_peer: parts(&back),
        });
    }
    links
}

/// The rows beside the claims.
#[derive(Debug, Serialize)]
struct Rows {
    links: Vec<Link>,
    /// The Run Log records the leg turns on, as they were logged.
    records: Vec<String>,
    /// Links opened after the race began and still up when the watch ended.
    left_open: usize,
    copy_equal: bool,
}

/// The verdict file.
#[derive(Debug, Serialize)]
struct Verdict<'a> {
    #[serde(rename = "scenario")]
    flow: &'static str,
    verdict: &'static str,
    detail: String,
    shape: CrossingShape,
    marks: &'a Marks,
    rows: &'a Rows,
    claim: &'a [Claim],
}

/// The Run Log lines that name the raced aMule, or a crossing record.
fn records_about(log: &str, peer: Ipv4Addr) -> Vec<String> {
    let peer = format!("={peer}:");
    log.lines()
        .filter(|line| {
            (line.starts_with("serve.") || line.starts_with("download.dial_ended"))
                && (line.contains(&peer) || line.starts_with("serve.crossed_link_let_go"))
        })
        .map(str::to_owned)
        .collect()
}

/// Score the run under `run_dir` and write its verdict; the verdict.
///
/// # Errors
/// If the topology, the tap, the staged file or rmule's log cannot be read.
pub fn score_run_dir(run_dir: &Path) -> Result<&'static str> {
    let root = run_dir.join(ROOT_DIR);
    let topology_path = root.join(TOPOLOGY);
    let at: Topology = toml::from_str(
        &fs::read_to_string(&topology_path)
            .with_context(|| format!("read {}", topology_path.display()))?,
    )
    .with_context(|| format!("parse {}", topology_path.display()))?;
    let capture = tcp_capture(&records(&root.join(RMULE_PCAP))?)?;
    let log_path = run_dir.join("rmule").join("stdout.log");
    let log =
        fs::read_to_string(&log_path).with_context(|| format!("read {}", log_path.display()))?;
    let staged_path = run_dir.join("synthetic").join("shared.bin");
    let staged =
        fs::read(&staged_path).with_context(|| format!("read {}", staged_path.display()))?;
    let copy_equal =
        fs::read(run_dir.join("rmule").join("output.bin")).is_ok_and(|copy| copy == staged);

    let links = ledger(&capture, IpAddr::V4(at.rmule), IpAddr::V4(at.peer));
    // On the download side rmule's dial is out before S is told to open its
    // link, and every link with S belongs to the race.
    let race_began = if at.shape.leg.serves() {
        at.marks.holder_stopped_at.unwrap_or(0.0)
    } else {
        0.0
    };
    let watch_ended = at.marks.watch_ended_at.unwrap_or(f64::MAX);
    let raced: Vec<&Link> = links
        .iter()
        .filter(|link| link.opened_at >= race_began)
        .collect();
    let rows = Rows {
        left_open: raced
            .iter()
            .filter(|link| link.closed_at < 0.0 || link.closed_at > watch_ended)
            .count(),
        records: records_about(&log, at.peer),
        links: links.clone(),
        copy_equal,
    };
    let returned = at.marks.returned_at.unwrap_or(f64::MAX);
    // The aMule's own link opened by its `Add`, and rmule's dial raced against it.
    let own = raced
        .iter()
        .find(|link| !link.rmule_opened && link.opened_at >= returned)
        .copied();
    let dial = raced.iter().find(|link| link.rmule_opened).copied();
    let granted_on = raced
        .iter()
        .filter(|link| link.first_grant > 0.0)
        .min_by(|a, b| a.first_grant.total_cmp(&b.first_grant))
        .copied();
    let one_left = Claim::about(
        "no-second-link-stayed-up",
        rows.left_open <= 1,
        Evidence::Captured,
        format!(
            "links opened after the race began and still up when the watch ended: {} of {}",
            rows.left_open,
            raced.len()
        ),
    );
    let describe = |link: Option<&Link>| {
        link.map_or("none".to_owned(), |link| {
            format!(
                "{} -> {} opened by {} at {:.3}",
                link.rmule_end,
                link.peer_end,
                if link.rmule_opened {
                    "rmule"
                } else {
                    "the aMule"
                },
                link.opened_at
            )
        })
    };
    let let_go = rows
        .records
        .iter()
        .any(|line| line.starts_with("serve.crossed_link_let_go"));
    let claims = match at.shape.leg {
        CrossingLeg::ServeCalledOff | CrossingLeg::ServeCrossed => {
            let on_dial = at.shape.leg == CrossingLeg::ServeCrossed;
            let mut claims = vec![
                Claim::about(
                    if on_dial {
                        "the-slot-landed-on-the-dial-back"
                    } else {
                        "the-slot-landed-on-the-waiters-own-link"
                    },
                    granted_on.is_some_and(|link| link.rmule_opened == on_dial),
                    Evidence::Captured,
                    format!(
                        "rmule's first OP_ACCEPTUPLOADREQ after X stopped went on {}",
                        describe(granted_on)
                    ),
                ),
                Claim::about(
                    "the-transfer-ran-on-it",
                    granted_on.is_some_and(|link| link.parts_from_rmule > 0),
                    Evidence::Captured,
                    format!(
                        "OP_SENDINGPART frames rmule wrote on that link: {}",
                        granted_on.map_or(0, |link| link.parts_from_rmule)
                    ),
                ),
                one_left,
            ];
            if on_dial {
                claims.push(Claim::about(
                    "serve-crossed-link-let-go-was-logged",
                    let_go,
                    Evidence::RmuleOnly,
                    format!(
                        "serve.crossed_link_let_go in the Run Log: {let_go}; the waiter's own link: {}",
                        describe(own)
                    ),
                ));
            }
            claims
        }
        CrossingLeg::LowIdReturn => {
            let free_before = raced
                .iter()
                .all(|link| link.first_grant < 0.0 || link.first_grant >= returned);
            let gap = own
                .filter(|link| link.first_grant > 0.0 && link.hello_from_peer > 0.0)
                .map_or(-1.0, |link| link.first_grant - link.hello_from_peer);
            vec![
                Claim::about(
                    "the-slot-sat-free-until-the-waiter-came-back",
                    free_before,
                    Evidence::Captured,
                    format!(
                        "no OP_ACCEPTUPLOADREQ to the waiter between X's stop and its return: {free_before}"
                    ),
                ),
                Claim::about(
                    "granted-within-a-second-of-the-returning-hello",
                    (0.0..=GRANT_AFTER_HELLO_SECS).contains(&gap),
                    Evidence::Captured,
                    format!(
                        "on the returning link ({}), OP_ACCEPTUPLOADREQ {gap:.3} s after the waiter's hello",
                        describe(own)
                    ),
                ),
                Claim::about(
                    "the-transfer-ran-on-it",
                    own.is_some_and(|link| link.parts_from_rmule > 0),
                    Evidence::Captured,
                    format!(
                        "OP_SENDINGPART frames rmule wrote on the returning link: {}",
                        own.map_or(0, |link| link.parts_from_rmule)
                    ),
                ),
            ]
        }
        CrossingLeg::DownloadYield | CrossingLeg::DownloadCrossed => {
            let on_dial = at.shape.leg == CrossingLeg::DownloadCrossed;
            let carrier = raced
                .iter()
                .filter(|link| link.parts_from_peer > 0)
                .max_by_key(|link| link.parts_from_peer)
                .copied();
            vec![
                Claim::about(
                    if on_dial {
                        "the-download-carried-on-over-the-dial"
                    } else {
                        "the-download-rode-the-seeds-own-link"
                    },
                    carrier.is_some_and(|link| link.rmule_opened == on_dial),
                    Evidence::Captured,
                    format!(
                        "the link that carried most of S's OP_SENDINGPART: {} ({} frames); rmule's dial: {}",
                        describe(carrier),
                        carrier.map_or(0, |link| link.parts_from_peer),
                        describe(dial)
                    ),
                ),
                Claim::about(
                    "the-download-completed-byte-equal",
                    copy_equal,
                    Evidence::Captured,
                    format!("output.bin equal to the staged file: {copy_equal}"),
                ),
                one_left,
            ]
        }
    };
    let (verdict, detail) = label(&claims);
    let text = toml::to_string_pretty(&Verdict {
        flow: "peer-crossing",
        verdict,
        detail,
        shape: at.shape,
        marks: &at.marks,
        rows: &rows,
        claim: &claims,
    })
    .context("serialize the crossing verdict")?;
    fs::write(run_dir.join(VERDICT), &text).context("write the crossing verdict")?;
    println!("{text}");
    Ok(verdict)
}
