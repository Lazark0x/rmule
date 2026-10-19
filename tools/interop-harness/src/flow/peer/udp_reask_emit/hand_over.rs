//! The two-download emit leg's **hand-over** (ADR-0107, "One peer, one queue
//! standing"): the sharer grants the standing, the holder's file rides the
//! granted link to its end, and the waiter, called to that link, asks its own
//! file there and is granted at once.
//!
//! The reask window cannot draw it: the sharer's slot-holders keep both slots
//! for aMule's hour (`UploadQueue.cpp:580-581`), and at the 3 KB/s cap the
//! holder's part cannot finish before the window ends. So, once rmule is
//! queued, the leg stops one slot-holder (the sharer promotes its next waiter,
//! rmule, `UploadQueue.cpp:206-217`) and, once rmule logs the grant, raises
//! the sharer's upload cap through its own `amulecmd` (`Set BwLimit Up`, an
//! operator preference), so both files finish inside the window. The session
//! kick at 10 MiB (`UploadQueue.cpp:580-581`) ends a slot that carries more,
//! so the leg runs with files whose sum stays under it.
//!
//! The claims: the waiter's `download.link_shared` turns read `waiting` then
//! `riding` (rmule-only); on the granted link, after the holder's last part,
//! the waiter's file request and `OP_STARTUPLOADREQ` drew the sharer's
//! `OP_ACCEPTUPLOADREQ` (the "already downloading" branch, `UploadQueue.cpp:486-493`)
//! and its parts followed; both copies are byte-equal.

use std::ffi::OsString;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::flow::bench::{AMULE_PEER_TCP_PORT, Bench, run_checked};
use crate::flow::gate::wait_for_container_log;
use crate::flow::identity::parse_ed2k_file_hash;
use crate::flow::nat::claims::{Claim, Evidence, label};
use crate::flow::pcap::{TcpCapture, records, tcp_capture};
use crate::flow::peer::one_link::verdict::{Switch, link_switch};
use crate::rmule::RMULE_SERVE_TCP_PORT;

/// The verdict file this leg writes beside the others.
pub(crate) const VERDICT: &str = "peer-udp-reask-emit-hand-over-verdict.toml";
/// Seconds from rmule's first rank to the slot-holder's stop: both downloads
/// have met the sharer and filed under one standing by then.
const SETTLE_SECS: u64 = 20;
/// Seconds `docker stop` waits before it kills the slot-holder.
const HOLDER_STOP_GRACE_SECS: u64 = 10;

/// The waiter's turns on the link.
pub(crate) const WAITED: &str = "the-waiter-waited-on-the-holders-link-then-rode-it";
/// The switch on the granted link.
pub(crate) const GRANTED_AT_ONCE: &str = "the-sharer-granted-the-waiter-at-once-on-the-link";
/// The copies.
pub(crate) const BYTE_EQUAL: &str = "both-downloads-completed-byte-equal";

/// What [`drive`] acts on.
pub(crate) struct Drive<'a> {
    /// The sharer's container.
    pub(crate) sharer: &'a str,
    /// The slot-holder whose stop frees a slot.
    pub(crate) holder: &'a str,
    /// rmule's container.
    pub(crate) rmule: &'a str,
    /// The sharer's upload cap after the grant, KiB/s.
    pub(crate) upload_kib: u64,
    /// How long the grant and each completion may take.
    pub(crate) window: Duration,
}

/// Free a slot, wait for rmule's grant, raise the sharer's cap and wait for
/// both downloads. A download that does not finish in the window is an
/// observation the verdict reads, not a failed run.
///
/// # Errors
/// If the slot-holder cannot be stopped, no grant reaches rmule in the window
/// or the sharer refuses the new cap.
pub(crate) fn drive(bench: &Bench, at: &Drive<'_>) -> Result<()> {
    std::thread::sleep(Duration::from_secs(SETTLE_SECS));
    run_checked(
        bench
            .docker
            .stop_container(at.holder.to_owned(), HOLDER_STOP_GRACE_SECS),
        "stop a slot-holder",
    )?;
    println!("peer_udp_reask_emit hand_over holder_stopped={}", at.holder);
    wait_for_container_log(
        &bench.docker,
        at.rmule,
        "download.peer_slot_granted",
        at.window,
    )?;
    let raised = run_checked(
        bench.docker.exec(
            at.sharer.to_owned(),
            [
                OsString::from("sh"),
                OsString::from("-c"),
                OsString::from(format!(
                    "amulecmd -P \"${{AMULE_EC_PASSWORD:-rmule}}\" -c 'Set BwLimit Up {}'",
                    at.upload_kib
                )),
            ],
        ),
        "raise the sharer's upload cap",
    )?;
    println!(
        "peer_udp_reask_emit hand_over granted upload_kib={} amulecmd={:?}",
        at.upload_kib,
        raised.lines().last().unwrap_or_default()
    );
    for id in [1, 2] {
        let done = wait_for_container_log(
            &bench.docker,
            at.rmule,
            &format!("download.completed id={id}"),
            at.window,
        )
        .is_ok();
        println!("peer_udp_reask_emit hand_over completed id={id} in_window={done}");
    }
    Ok(())
}

/// The rows beside the claims.
#[derive(Debug, Serialize, PartialEq)]
struct Rows {
    /// The download that waited on the link, `0` when none did.
    waiter: u32,
    /// rmule's SYNs to the sharer's listener, and the sharer's to rmule's.
    rmule_dials: usize,
    dial_backs: usize,
    /// How the holder let the slot go, how the sharer answered the waiter's
    /// ask and how long after it, and the waiter's part frames after it.
    switch_release: &'static str,
    switch_answer: &'static str,
    switch_answer_ms: f64,
    parts_after_switch: usize,
    /// Each copy's length, `-1` when never written.
    copy_bytes: [i64; 2],
}

/// The verdict file.
#[derive(Debug, Serialize)]
struct Verdict<'a> {
    #[serde(rename = "scenario")]
    flow: &'static str,
    verdict: &'static str,
    detail: String,
    rows: &'a Rows,
    claim: &'a [Claim],
}

/// The download whose last `download.link_shared` record waited, and whether
/// a `riding` turn of it followed.
fn waiter_turns(log: &str) -> Option<(u32, bool)> {
    let shared: Vec<(u32, &str)> = log
        .lines()
        .filter(|line| line.starts_with("download.link_shared "))
        .filter_map(|line| {
            let field = |key: &str| {
                line.split_whitespace()
                    .find_map(|field| field.strip_prefix(key))
            };
            Some((field("id=")?.parse().ok()?, field("turn=")?))
        })
        .collect();
    let waited = shared.iter().rposition(|(_, turn)| *turn == "waiting")?;
    let waiter = shared[waited].0;
    Some((
        waiter,
        shared[waited..]
            .iter()
            .any(|&(id, turn)| id == waiter && turn == "riding"),
    ))
}

/// The switch on the first link between rmule and the sharer that carried
/// one, dialed by either side, whichever file rode first.
fn link_switch_between(
    capture: &TcpCapture,
    rmule: Ipv4Addr,
    sharer: Ipv4Addr,
    hashes: [[u8; 16]; 2],
) -> Option<Switch> {
    capture
        .streams
        .iter()
        .filter(|stream| {
            stream.source.ip() == IpAddr::V4(rmule) && stream.destination.ip() == IpAddr::V4(sharer)
        })
        .find_map(|to_sharer| {
            let back = capture.streams.iter().find(|stream| {
                stream.source == to_sharer.destination && stream.destination == to_sharer.source
            })?;
            let (sent, heard) = (to_sharer.ed2k_frames(), back.ed2k_frames());
            link_switch(&sent, &heard, hashes)
                .or_else(|| link_switch(&sent, &heard, [hashes[1], hashes[0]]))
        })
}

/// Score the run under `root` (rmule at `rmule`, the sharer at `sharer`) and
/// write [`VERDICT`] there; the verdict.
///
/// # Errors
/// If the tap, a staged file, a link or rmule's log cannot be read.
pub(crate) fn write(root: &Path, rmule: Ipv4Addr, sharer: Ipv4Addr) -> Result<&'static str> {
    let capture = tcp_capture(&records(
        &root.join("emit-reask-capture").join("emit-reask.pcap"),
    )?)?;
    let synthetic = root.join("synthetic");
    let hash_of = |link: &str| -> Result<[u8; 16]> {
        let path = synthetic.join(link);
        parse_ed2k_file_hash(
            fs::read_to_string(&path)
                .with_context(|| format!("read {}", path.display()))?
                .trim(),
        )
    };
    let hashes = [hash_of("shared.ed2k.txt")?, hash_of(super::SECOND_LINK)?];
    let copy = |staged: &str, written: &str| -> Result<(bool, i64)> {
        let path = synthetic.join(staged);
        let staged = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        Ok(
            fs::read(root.join("rmule").join(written)).map_or((false, -1), |copy| {
                (
                    copy == staged,
                    i64::try_from(copy.len()).unwrap_or(i64::MAX),
                )
            }),
        )
    };
    let copies = [
        copy("shared.bin", "output.bin")?,
        copy(super::SECOND_FILE, "output-2.bin")?,
    ];
    let log_path = root.join("rmule").join("stdout.log");
    let log =
        fs::read_to_string(&log_path).with_context(|| format!("read {}", log_path.display()))?;

    let turns = waiter_turns(&log);
    let switch = link_switch_between(&capture, rmule, sharer, hashes);
    let dials = |from: Ipv4Addr, to: SocketAddr| {
        capture
            .opens
            .iter()
            .filter(|open| open.source.ip() == IpAddr::V4(from) && open.destination == to)
            .count()
    };
    let claims = vec![
        Claim::about(
            WAITED,
            turns.is_some_and(|(_, rode)| rode),
            Evidence::RmuleOnly,
            match turns {
                Some((id, rode)) => format!(
                    "download {id} logged download.link_shared turn=waiting, then turn=riding: {rode}"
                ),
                None => "no download logged download.link_shared turn=waiting".to_owned(),
            },
        ),
        Claim::about(
            GRANTED_AT_ONCE,
            switch
                .as_ref()
                .is_some_and(|switch| switch.answer == "accept" && switch.parts_after > 0),
            Evidence::Captured,
            match &switch {
                Some(switch) => format!(
                    "release {}; the waiter's OP_STARTUPLOADREQ answered {} after {:.1} ms; its \
                     part frames after: {}",
                    switch.release,
                    switch.answer,
                    switch.answer_ms.unwrap_or(-1.0),
                    switch.parts_after
                ),
                None => "no link to the sharer carried the waiter's file after the holder's \
                         last part"
                    .to_owned(),
            },
        ),
        Claim::about(
            BYTE_EQUAL,
            copies.iter().all(|(equal, _)| *equal),
            Evidence::Captured,
            format!(
                "output.bin {} bytes, equal {}; output-2.bin {} bytes, equal {}",
                copies[0].1, copies[0].0, copies[1].1, copies[1].0
            ),
        ),
    ];
    let rows = Rows {
        waiter: turns.map_or(0, |(id, _)| id),
        rmule_dials: dials(rmule, SocketAddr::from((sharer, AMULE_PEER_TCP_PORT))),
        dial_backs: dials(sharer, SocketAddr::from((rmule, RMULE_SERVE_TCP_PORT))),
        switch_release: switch.as_ref().map_or("none", |switch| switch.release),
        switch_answer: switch.as_ref().map_or("none", |switch| switch.answer),
        switch_answer_ms: switch
            .as_ref()
            .and_then(|switch| switch.answer_ms)
            .unwrap_or(-1.0),
        parts_after_switch: switch.as_ref().map_or(0, |switch| switch.parts_after),
        copy_bytes: [copies[0].1, copies[1].1],
    };
    let (verdict, detail) = label(&claims);
    let text = toml::to_string_pretty(&Verdict {
        flow: "peer-udp-reask-emit-hand-over",
        verdict,
        detail,
        rows: &rows,
        claim: &claims,
    })
    .context("serialize the hand-over verdict")?;
    let path = root.join(VERDICT);
    fs::write(&path, &text).with_context(|| format!("write {}", path.display()))?;
    println!("{text}");
    println!("peer_udp_reask_emit hand_over_verdict={verdict}");
    Ok(verdict)
}

#[cfg(test)]
mod tests {
    use super::waiter_turns;

    #[test]
    fn the_waiter_is_the_last_download_to_wait_and_rides_only_after_it() {
        let log = "download.link_shared id=1 turn=waiting peer=172.18.0.3:4662\n\
                   download.link_shared id=1 turn=riding peer=172.18.0.3:4662\n\
                   download.peer_slot_granted id=1 peer=172.18.0.3:4662\n\
                   download.link_shared id=2 turn=waiting peer=172.18.0.3:4662\n";
        assert_eq!(waiter_turns(log), Some((2, false)));
        let rode = format!("{log}download.link_shared id=2 turn=riding peer=172.18.0.3:4662\n");
        assert_eq!(waiter_turns(&rode), Some((2, true)));
        assert_eq!(
            waiter_turns("download.link_shared id=1 turn=riding peer=x\n"),
            None
        );
    }
}
