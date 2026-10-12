//! The flow-L consume verdict: byte-identity checks over the retained tap.
//!
//! The run's own `reask.pcap` holds everything the claims need — the reasker's
//! `0x90`, rmule's `0x91` and every TCP link — so a retained run can be scored
//! again without driving the flow. Each claim is a byte comparison or a
//! counted absence, never a reading of rmule's own log: a verdict that
//! quoted rmule's account of itself would score stimulus as evidence
//! (ADR-0045).

use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::{Context, Result};
use rmule_primitives::UserHash;
use serde::Serialize;

use super::tap::{
    Flip, OP_HELLO, OP_HELLOANSWER, crypt_at, hello_hash, is_obfuscated, open, ping_shape,
};
use crate::flow::identity::{hex_lower, parse_ed2k_file_hash};
use crate::flow::nat::claims::{Claim, Evidence, label};
use crate::flow::pcap::{Udp4Datagram, records, tcp_streams, udp4_datagrams};

/// The 6 bytes aMule itself writes as `OP_REASKACK` to a v1 claimant at queue
/// rank 1, cut whole from the capture promoted as
/// `amule-233-reask-ack-to-rmule-20261001`.
const AMULE_ACK: [u8; 6] = [0xC5, 0x91, 0x00, 0x00, 0x01, 0x00];

/// What a retained consume run is scored from.
pub(crate) struct ReaskRun<'a> {
    /// The `tcp or udp` tap on rmule's namespace.
    pub(crate) pcap: &'a Path,
    /// The serving rmule's address.
    pub(crate) rmule: Ipv4Addr,
    /// The queued, disconnected aMule's address.
    pub(crate) reasker: Ipv4Addr,
    /// The shared file's ED2K hash.
    pub(crate) file_hash: [u8; 16],
    /// The shared file's size in bytes.
    pub(crate) file_size: u64,
    /// Whether the run armed peer obfuscation on both ends at its start.
    pub(crate) crypt: bool,
    /// The obfuscation flips rmule's marker lines recorded, in order. Empty
    /// for a run that held one policy throughout.
    pub(crate) flips: Vec<Flip>,
}

/// The flow's verdict file.
#[derive(Debug, Serialize)]
struct ReaskVerdict<'a> {
    #[serde(rename = "scenario")]
    flow: &'static str,
    verdict: &'static str,
    detail: String,
    crypt: bool,
    /// Seconds after rmule's start of each obfuscation flip the run recorded.
    flips: Vec<u64>,
    claim: &'a [Claim],
}

/// The flow-L consume claims for a retained run.
///
/// # Errors
/// If the pcap cannot be read.
pub(crate) fn claims(run: &ReaskRun<'_>) -> Result<Vec<Claim>> {
    let datagrams = udp4_datagrams(run.pcap)?;
    let toward_rmule =
        |d: &&Udp4Datagram| *d.source.ip() == run.reasker && *d.destination.ip() == run.rmule;
    let toward_reasker =
        |d: &&Udp4Datagram| *d.source.ip() == run.rmule && *d.destination.ip() == run.reasker;
    let ping = datagrams.iter().find(toward_rmule);
    let ack = ping.and_then(|ping| {
        datagrams
            .iter()
            .filter(toward_reasker)
            .find(|d| d.at >= ping.at)
    });

    let hashes = Hashes::read(run)?;
    let started = records(run.pcap)?.first().map_or(0.0, |r| r.at);
    // The reasker sends its ping in the mode rmule's last hello answer
    // advertised, which can be well before the ping; rmule answers in the mode
    // its policy holds at that datagram.
    let ping_crypt = ping.is_some_and(|d| {
        let advertised = hashes.hello_answers.iter().copied().rfind(|at| *at <= d.at);
        crypt_at(run.crypt, &run.flips, started, advertised.unwrap_or(d.at))
    });
    let ack_crypt = ack.is_some_and(|d| crypt_at(run.crypt, &run.flips, started, d.at));
    let flipped = !run.flips.is_empty();
    let side = |crypt: bool| match (flipped, crypt) {
        (false, _) => "",
        (true, true) => " [judged obfuscated]",
        (true, false) => " [judged plain]",
    };
    let opened_ping =
        ping.and_then(|d| open(&d.payload, ping_crypt, hashes.rmule.as_ref(), run.reasker));
    let opened_ack =
        ack.and_then(|d| open(&d.payload, ack_crypt, hashes.reasker.as_ref(), run.rmule));

    let mut claims = vec![
        Claim::about(
            "the-reasker-pinged-rmules-client-udp-port",
            opened_ping
                .as_deref()
                .is_some_and(|bytes| ping_shape(bytes, &run.file_hash, run.file_size)),
            Evidence::Captured,
            match (ping, &opened_ping) {
                (None, _) => "no datagram from the reasker reached rmule".to_owned(),
                (Some(d), Some(bytes)) => format!(
                    "{} bytes on the wire{}; opened to {}{}",
                    d.payload.len(),
                    if ping_crypt { ", obfuscated" } else { "" },
                    hex_lower(bytes),
                    side(ping_crypt)
                ),
                (Some(d), None) => format!(
                    "{} bytes on the wire did not open under rmule's user hash and the \
                     reasker's address{}",
                    d.payload.len(),
                    side(ping_crypt)
                ),
            },
        ),
        Claim::about(
            "rmule-answered-with-the-0x91-aMule-itself-writes",
            opened_ack.as_deref() == Some(&AMULE_ACK[..]),
            Evidence::RmuleOnly,
            match (ack, &opened_ack) {
                (None, _) => "rmule sent the reasker no datagram after the ping".to_owned(),
                (Some(d), Some(bytes)) => format!(
                    "{} bytes {} ms after the ping, opened to {}; aMule's own is {}{}",
                    d.payload.len(),
                    millis(ping, d),
                    hex_lower(bytes),
                    hex_lower(&AMULE_ACK),
                    side(ack_crypt)
                ),
                (Some(d), None) => format!(
                    "{} bytes did not open under the reasker's user hash and rmule's address{}",
                    d.payload.len(),
                    side(ack_crypt)
                ),
            },
        ),
    ];

    if ack_crypt {
        claims.push(Claim::about(
            "the-answer-left-obfuscated",
            ack.is_some_and(|d| is_obfuscated(&d.payload)),
            Evidence::RmuleOnly,
            ack.map_or_else(
                || "no answer".to_owned(),
                |d| {
                    format!(
                        "marker byte {:#04x}",
                        d.payload.first().copied().unwrap_or(0)
                    )
                },
            ),
        ));
        let under_wrong_address =
            ack.and_then(|d| open(&d.payload, true, hashes.reasker.as_ref(), run.reasker));
        claims.push(Claim::about(
            "the-answer-opens-under-no-other-key",
            ack.is_some() && hashes.reasker.is_some() && under_wrong_address.is_none(),
            Evidence::RmuleOnly,
            "the reasker's own address as the sender opens nothing".to_owned(),
        ));
    }

    claims.push(match ack.map(|d| d.at) {
        Some(at) => {
            let fallback = tcp_streams(run.pcap)?
                .iter()
                .filter(|s| {
                    matches!((s.source, s.destination),
                        (SocketAddr::V4(from), SocketAddr::V4(to))
                        if *from.ip() == run.reasker && *to.ip() == run.rmule)
                })
                .filter(|s| s.opened_at() > at)
                .count();
            let end = records(run.pcap)?.iter().map(|r| r.at).fold(at, f64::max);
            Claim::absence(
                "the-reasker-opened-no-tcp-link-after-the-ack",
                i64::try_from(fallback).unwrap_or(i64::MAX),
                format!(
                    "{fallback} TCP links from the reasker in the {:.0} s after the ack",
                    end - at
                ),
            )
        }
        None => Claim::absence(
            "the-reasker-opened-no-tcp-link-after-the-ack",
            -1,
            "no ack was sent, so there is no moment to count from",
        ),
    });
    Ok(claims)
}

/// Score `run` and write `peer-udp-reask-verdict.toml` under `root`, printing the label.
///
/// # Errors
/// If the pcap cannot be read or the verdict cannot be written.
pub(crate) fn write(root: &Path, run: &ReaskRun<'_>) -> Result<&'static str> {
    let claims = claims(run)?;
    let (verdict, detail) = label(&claims);
    let text = toml::to_string_pretty(&ReaskVerdict {
        flow: "peer-udp-reask",
        verdict,
        detail,
        crypt: run.crypt,
        flips: run.flips.iter().map(|f| f.after_secs).collect(),
        claim: &claims,
    })
    .context("serialize the peer-udp-reask verdict")?;
    let path = root.join("peer-udp-reask-verdict.toml");
    fs::write(&path, &text).with_context(|| format!("write {}", path.display()))?;
    println!("peer_udp_reask verdict={verdict}");
    Ok(verdict)
}

/// Score the run dir a finished flow (or an archive) left behind.
///
/// # Errors
/// If an artifact cannot be read or the verdict cannot be written.
pub fn score_run_dir(
    root: &Path,
    rmule: Ipv4Addr,
    reasker: Ipv4Addr,
    crypt: bool,
) -> Result<&'static str> {
    let link = fs::read_to_string(root.join("synthetic/shared.ed2k.txt"))
        .context("read synthetic/shared.ed2k.txt")?;
    let file_size = fs::metadata(root.join("synthetic/shared.bin"))
        .context("stat synthetic/shared.bin")?
        .len();
    write(
        root,
        &ReaskRun {
            pcap: &root.join("reask-capture/reask.pcap"),
            rmule,
            reasker,
            file_hash: parse_ed2k_file_hash(link.trim())?,
            file_size,
            crypt,
            flips: Flip::read_run_dir(root),
        },
    )
}

/// The user hashes each side's hello announced on the tap's TCP links.
struct Hashes {
    rmule: Option<UserHash>,
    reasker: Option<UserHash>,
    /// When each `OP_HELLOANSWER` rmule sent the reasker was captured.
    hello_answers: Vec<f64>,
}

impl Hashes {
    fn read(run: &ReaskRun<'_>) -> Result<Self> {
        let (mut rmule, mut reasker) = (None, None);
        let mut hello_answers = Vec::new();
        for stream in tcp_streams(run.pcap)? {
            let (SocketAddr::V4(from), SocketAddr::V4(to)) = (stream.source, stream.destination)
            else {
                continue;
            };
            for frame in stream.ed2k_frames() {
                if *from.ip() == run.reasker && *to.ip() == run.rmule && frame.opcode == OP_HELLO {
                    reasker = reasker.or_else(|| hello_hash(&frame));
                }
                if *from.ip() == run.rmule
                    && *to.ip() == run.reasker
                    && frame.opcode == OP_HELLOANSWER
                {
                    rmule = rmule.or_else(|| hello_hash(&frame));
                    hello_answers.push(frame.at);
                }
            }
        }
        Ok(Self {
            rmule,
            reasker,
            hello_answers,
        })
    }
}

/// Whole milliseconds from the ping to the answer.
fn millis(ping: Option<&Udp4Datagram>, answer: &Udp4Datagram) -> String {
    ping.map_or_else(
        || "?".to_owned(),
        |ping| format!("{:.1}", (answer.at - ping.at) * 1000.0),
    )
}
