//! The reask-emit flow's `--known-sources` staging: a sharer that has a source
//! to name, so rmule's source ask is answered and its UDP reask is not held
//! back.
//!
//! A complete file's source answer names only clients on the sharer's upload
//! list — uploading from it or queued on it — that are High-ID and hold a
//! complete part the asker lacks (aMule 2.3.3 `CKnownFile::CreateSrcInfoPacket`,
//! `KnownFile.cpp:960-1000`; with no such client it sends nothing). A client
//! that finished the file has left that list, so a sharer whose other source
//! "finished earlier" names nobody. The slot-holders are made into that
//! client: a **seeder** (complete, uncapped) gives each holder at least one
//! complete part and is paused; only then does the sharer start, and each
//! holder is told of it with a link naming it, so its first file request to
//! the sharer carries the part it holds. The sharer grants both its slots to
//! the holders, and a source ask from rmule is answered with the holder.
//!
//! Every aMule here runs with `AMULE_DEBUG_SOURCE_CATEGORIES=1`: a holder's
//! `Finished part` line (`PartFile.cpp:3071`) is how the flow knows it holds a
//! part, and the sharer's trail is where a source ask's fate is read. The
//! debug aMule image is required for either.

use std::fmt::Write as _;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::flow::bench::{AMULE_PEER_TCP_PORT, Bench, amulecmd_command, run_checked};
use crate::flow::gate::wait_for_amule_ready;
use crate::flow::identity::ed2k_link_with_source;
use crate::flow::pcap;
use crate::flow::peer::udp_reask::tap::OP_REASKFILEPING;
use crate::flow::wire_filter::OP_EMULEPROT;

/// Each holder's download cap (KiB/s) while the seeder runs. The seeder is
/// uncapped, so it serves both holders at once; at 40 KiB/s a 9.28 MB part
/// takes about four minutes, so a holder that has finished its first part is
/// minutes from a second and far from the whole file when the seeder is paused.
/// A capped seeder instead starved one holder (run `1790846191`: one holder
/// finished four parts while the other's transfer stalled and was cancelled).
pub(super) const HOLDER_MAX_DOWNLOAD_KIB: &str = "40";
/// The aMule log line a finished, hash-checked part writes.
const FINISHED_PART: &str = "Finished part";
/// How often each holder's logfile is read while the seeder runs.
const PART_POLL: Duration = Duration::from_secs(5);
/// How long the holders get to dial the sharer and take its two slots.
const HOLDER_SETTLE: Duration = Duration::from_secs(45);
/// The environment that turns on the source and part-file trails.
pub(super) const DEBUG_SOURCES: (&str, &str) = ("AMULE_DEBUG_SOURCE_CATEGORIES", "1");

/// Start the seeder sharing `synthetic_dir`; returns its address.
///
/// # Errors
/// If it cannot start or never reports ready.
pub(super) fn start_seeder(
    bench: &mut Bench,
    image: &str,
    name: &str,
    layout: &RunLayout,
    env: &[String],
    timeout: Duration,
) -> Result<String> {
    let container = bench
        .amule_container(image, name)
        .volume(layout.synthetic_dir(), "/incoming")
        .env("AMULE_SHARED_DIR", "/incoming")
        .env(DEBUG_SOURCES.0, DEBUG_SOURCES.1)
        .env_assignments(env);
    bench.start_extra(name, container, "run seeder aMule")?;
    wait_for_amule_ready(&bench.docker, layout, name, timeout, "rmule-amule-ready")?;
    let ip = run_checked(
        bench.docker.container_ip(name.to_owned()),
        "inspect seeder ip",
    )?;
    Ok(ip.trim().to_owned())
}

/// The ed2k link `link` naming `ip` as its one source.
pub(super) fn sourced(link: &str, ip: &str) -> String {
    ed2k_link_with_source(link, ip, AMULE_PEER_TCP_PORT)
}

/// Wait until every holder's logfile names a finished part, then pause the
/// seeder. Returns each holder's first `Finished part` line.
///
/// # Errors
/// If a holder finishes no part within `timeout`, or the seeder cannot be
/// paused.
pub(super) fn wait_for_parts_then_pause_seeder(
    bench: &Bench,
    holders: &[String],
    seeder: &str,
    timeout: Duration,
) -> Result<Vec<String>> {
    let deadline = Instant::now() + timeout;
    loop {
        let lines: Vec<Option<String>> = holders
            .iter()
            .map(|holder| first_finished_part(bench, holder))
            .collect();
        if lines.iter().all(Option::is_some) {
            // Paused, not stopped: a stopped seeder frees its address, the
            // sharer started next takes it, and each holder reads the sharer
            // as the dead seeder's client record until that times out (run
            // `1790846870`: the holders never dialled the sharer).
            run_checked(
                bench.docker.pause_container(seeder.to_owned()),
                "pause the seeder",
            )?;
            return Ok(lines.into_iter().flatten().collect());
        }
        if Instant::now() >= deadline {
            bail!(
                "a slot-holder finished no part from the seeder within {} s",
                timeout.as_secs()
            );
        }
        std::thread::sleep(PART_POLL);
    }
}

fn first_finished_part(bench: &Bench, holder: &str) -> Option<String> {
    let output = bench
        .docker
        .exec(
            holder.to_owned(),
            [
                std::ffi::OsString::from("sh"),
                std::ffi::OsString::from("-c"),
                std::ffi::OsString::from(format!(
                    "grep -m1 '{FINISHED_PART}' /root/.aMule/logfile 2>/dev/null || true"
                )),
            ],
        )
        .to_command()
        .output()
        .ok()?;
    let line = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (!line.is_empty()).then_some(line)
}

/// Tell each holder of the sharer: its download's link again, naming the
/// sharer as a source (aMule adds a re-added link's sources to the running
/// download, `DownloadQueue.cpp:1496-1500`); then give them time to take its
/// slots.
///
/// # Errors
/// If `amulecmd` fails in a holder.
pub(super) fn point_holders_at_sharer(
    bench: &Bench,
    holders: &[(String, String)],
    sharer_ip: &str,
) -> Result<()> {
    for (holder, link) in holders {
        run_checked(
            bench.docker.exec(
                holder.clone(),
                amulecmd_command(&format!("Add {}", sourced(link, sharer_ip))),
            ),
            "tell a slot-holder of the sharer",
        )?;
    }
    std::thread::sleep(HOLDER_SETTLE);
    Ok(())
}

/// The UDP between rmule and the sharer, one line per datagram: each
/// `OP_REASKFILEPING` with the file hash it names, and each answer with its
/// opcode — the per-file routing record.
///
/// # Errors
/// If the tap cannot be read.
pub(super) fn reask_routing(
    tap: &Path,
    rmule: Ipv4Addr,
    sharer: Ipv4Addr,
    files: &[(String, String)],
) -> Result<String> {
    let mut text = String::new();
    for datagram in pcap::udp4_datagrams(tap)? {
        let (from, to) = (*datagram.source.ip(), *datagram.destination.ip());
        let direction = if from == rmule && to == sharer {
            "rmule > sharer"
        } else if from == sharer && to == rmule {
            "sharer > rmule"
        } else {
            continue;
        };
        let payload = &datagram.payload;
        let head = match (payload.first(), payload.get(1)) {
            (Some(&protocol), Some(&opcode)) => format!("{protocol:#04x}/{opcode:#04x}"),
            _ => "short".to_owned(),
        };
        let file = if payload.first() == Some(&OP_EMULEPROT)
            && payload.get(1) == Some(&OP_REASKFILEPING)
        {
            let hash = payload
                .get(2..18)
                .map(|bytes| {
                    bytes.iter().fold(String::new(), |mut hex, byte| {
                        let _ = write!(hex, "{byte:02X}");
                        hex
                    })
                })
                .unwrap_or_default();
            let name = files
                .iter()
                .find(|(_, file_hash)| *file_hash == hash)
                .map_or("unknown file", |(name, _)| name.as_str());
            format!(" hash={hash} ({name})")
        } else {
            String::new()
        };
        let _ = writeln!(
            text,
            "{:.3} {direction} {head} {} bytes{file}",
            datagram.at,
            payload.len()
        );
    }
    Ok(text)
}

/// The upper-case hex hash an ed2k file link names.
///
/// # Errors
/// If the link is not `ed2k://|file|name|size|hash|…`.
pub(super) fn link_hash(link: &str) -> Result<String> {
    link.split('|')
        .nth(4)
        .filter(|hash| hash.len() == 32)
        .map(str::to_uppercase)
        .context("an ed2k file link names its hash fifth")
}
