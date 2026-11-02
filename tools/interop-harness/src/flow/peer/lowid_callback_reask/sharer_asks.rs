//! The sharer-asks leg of the Low-ID callback flow: the Low-ID sharer that
//! dialed rmule back adds a file rmule shares and asks for it on that link, so
//! rmule's serve side reads a slot ask on a link adopted for a download. An
//! adopted callback's hello reaches the serve side like any inbound link's
//! (ADR-0107): the ask is seen under that hello's client and its uploads are
//! credited to that hello's User Hash.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Serialize;

use super::verdict::{ADDRESSES, Addresses, RMULE_PCAP, ROOT_DIR};
use crate::flow::bench::{Bench, amulecmd_command, run_checked};
use crate::flow::evidence::read_toml;
use crate::flow::gate::wait_for_container_log;
use crate::flow::identity::{ed2k_link_with_source, parse_ed2k_file_hash};
use crate::flow::nat::claims::{Claim, Evidence, label};
use crate::flow::pcap::{TcpCapture, records, tcp_capture};
use crate::flow::peer::udp_reask_emit::{SECOND_FILE, SECOND_LINK};
use crate::rmule::RMULE_SERVE_TCP_PORT;
use crate::verdict::Verdict;

const VERDICT: &str = "peer-lowid-sharer-asks-verdict.toml";
/// Under the flow's dir: what only rmule shares.
const SERVED_DIR: &str = "served";
/// How long past its `Add` the sharer's slot ask has to be answered.
const ANSWER_BOUND: Duration = Duration::from_secs(60);
const OP_HELLO: u8 = 0x01;
const OP_STARTUPLOADREQ: u8 = 0x54;
const CREDIT_RECORD_LEN: usize = 119;

/// Move the file the sharer will ask for out of the directory it shares,
/// into one only rmule shares: a file it holds, its `Add` is a no-op (run
/// `1793403551`).
pub(super) fn stage(root: &Path, synthetic: &Path) -> Result<()> {
    let dir = root.join(SERVED_DIR);
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    fs::rename(synthetic.join(SECOND_FILE), dir.join(SECOND_FILE)).context("stage rmule's own file")
}

/// What rmule's download gets on this leg: the file the sharer asks for, and
/// `clients.met` at its shutdown.
pub(super) fn rmule_flags() -> Vec<String> {
    vec![
        "--share".to_owned(),
        format!("/w/{ROOT_DIR}/{SERVED_DIR}/{SECOND_FILE}"),
        "--persist-credit".to_owned(),
    ]
}

/// Have `sharer` add rmule's file with rmule as its source, and wait for
/// rmule's answer. Queued at the sharer, rmule's callback link is up: the
/// add runs inside aMule's 40 s idle close.
pub(super) fn ask(
    bench: &Bench,
    synthetic: &Path,
    sharer: &str,
    rmule: &str,
    rmule_ip: Ipv4Addr,
    sharer_ip: Ipv4Addr,
) -> Result<()> {
    let path = synthetic.join(SECOND_LINK);
    let link = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let at_rmule = ed2k_link_with_source(link.trim(), &rmule_ip.to_string(), RMULE_SERVE_TCP_PORT);
    run_checked(
        bench.docker.exec(
            sharer.to_owned(),
            amulecmd_command(&format!("Add {at_rmule}")),
        ),
        "the sharer adds rmule's file",
    )?;
    let granted = format!("serve.upload_slot_granted peer={sharer_ip}:");
    let answered = wait_for_container_log(&bench.docker, rmule, &granted, ANSWER_BOUND).is_ok();
    println!("peer_lowid_callback_reask sharer_slot_granted={answered}");
    Ok(())
}

/// rmule's stop, which is its shutdown: `clients.met` is written then.
pub(super) fn stop_rmule(bench: &Bench, rmule: &str) -> Result<()> {
    run_checked(
        bench.docker.stop_container(rmule.to_owned(), 15),
        "stop rmule",
    )
    .map(|_| ())
}

/// `clients.met`'s totals of bytes served, by User Hash.
fn uploaded(dir: &Path) -> Vec<([u8; 16], u64)> {
    let Ok(bytes) = fs::read(dir.join("clients.met")) else {
        return Vec::new();
    };
    bytes
        .get(5..)
        .unwrap_or_default()
        .chunks_exact(CREDIT_RECORD_LEN)
        .map(|record| {
            let word = |at: usize| {
                u32::from_le_bytes([record[at], record[at + 1], record[at + 2], record[at + 3]])
            };
            let mut hash = [0; 16];
            hash.copy_from_slice(&record[..16]);
            (hash, u64::from(word(16)) | (u64::from(word(28)) << 32))
        })
        .collect()
}

/// The first link the sharer opened to rmule's listener: its callback.
fn callback(capture: &TcpCapture, addresses: &Addresses) -> Option<(SocketAddr, SocketAddr)> {
    capture
        .opens
        .iter()
        .find(|open| {
            open.source.ip() == IpAddr::V4(addresses.sharer)
                && open.destination.ip() == IpAddr::V4(addresses.rmule)
                && open.destination.port() == addresses.rmule_port
        })
        .map(|open| (open.source, open.destination))
}

#[derive(Debug, Serialize)]
struct VerdictFile<'a> {
    #[serde(rename = "scenario")]
    flow: &'static str,
    verdict: Verdict,
    detail: String,
    records: &'a [String],
    claim: &'a [Claim],
}

/// Score the leg under `run_dir` and write its verdict; the verdict.
///
/// # Errors
/// If the addresses, the tap, the link or rmule's log cannot be read.
pub fn score_run_dir(run_dir: &Path) -> Result<Verdict> {
    let root = run_dir.join(ROOT_DIR);
    let addresses: Addresses = read_toml(&root.join(ADDRESSES))?;
    let capture = tcp_capture(&records(&root.join(RMULE_PCAP))?)?;
    let log_path = run_dir.join("rmule").join("stdout.log");
    let log =
        fs::read_to_string(&log_path).with_context(|| format!("read {}", log_path.display()))?;
    let link_path = run_dir.join("synthetic").join(SECOND_LINK);
    let link =
        fs::read_to_string(&link_path).with_context(|| format!("read {}", link_path.display()))?;
    let file_hash = parse_ed2k_file_hash(link.trim())?;

    let peer = format!("peer={}:", addresses.sharer);
    let serve_records: Vec<String> = log
        .lines()
        .filter(|line| line.starts_with("serve.") && line.contains(&peer))
        .map(str::to_owned)
        .collect();
    let on_callback = callback(&capture, &addresses);
    let frames: Vec<_> = capture
        .streams
        .iter()
        .filter(|stream| Some((stream.source, stream.destination)) == on_callback)
        .flat_map(|stream| stream.ed2k_frames())
        .collect();
    let hello_hash: Option<[u8; 16]> = frames
        .iter()
        .find(|frame| frame.protocol == 0xE3 && frame.opcode == OP_HELLO)
        .and_then(|frame| frame.payload().get(1..17)?.try_into().ok());
    let asked = frames
        .iter()
        .any(|frame| frame.opcode == OP_STARTUPLOADREQ && frame.payload() == file_hash);
    let opened = capture
        .opens
        .iter()
        .filter(|open| {
            open.source.ip() == IpAddr::V4(addresses.sharer)
                && open.destination.port() == addresses.rmule_port
        })
        .count();
    let identified = serve_records.iter().any(|line| {
        line.starts_with("serve.upload_slot_granted") && line.contains("software=\"amule\"")
    });
    let credited = hello_hash.and_then(|hash| {
        uploaded(&run_dir.join("rmule"))
            .into_iter()
            .find(|(held, _)| *held == hash)
            .map(|(_, bytes)| bytes)
    });
    let claims = vec![
        Claim::about(
            "the-sharer-asked-on-its-callback-link",
            asked,
            Evidence::Captured,
            format!(
                "OP_STARTUPLOADREQ for rmule's file on the callback link: {asked}; links the sharer opened to rmule: {opened}"
            ),
        ),
        Claim::about(
            "the-slot-went-to-the-client-its-hello-named",
            identified,
            Evidence::Captured,
            format!("serve.upload_slot_granted naming the hello's software: {identified}"),
        ),
        Claim::about(
            "its-uploads-are-credited-to-its-hellos-user-hash",
            credited.is_some_and(|bytes| bytes > 0),
            Evidence::Captured,
            format!("bytes served in clients.met under the hello's User Hash: {credited:?}"),
        ),
    ];
    let (verdict, detail) = label(&claims);
    let text = toml::to_string_pretty(&VerdictFile {
        flow: "peer-lowid-sharer-asks",
        verdict,
        detail,
        records: &serve_records,
        claim: &claims,
    })
    .context("serialize the verdict")?;
    crate::verdict::write(&run_dir.join(VERDICT), &text)?;
    println!("{text}");
    Ok(verdict)
}
