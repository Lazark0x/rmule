//! The ask-budget leg: sixteen downloads started together in one rmule core
//! put fifteen `OP_GETSOURCES` on the Lugdunum session at once and the
//! sixteenth about 300 s later (ADR-0107's **Source Ask Budget**; aMule's
//! `iMaxFilesPerTcpFrame` = 15 and its `15 × (16 + 4)` s frame spacing, stock
//! 2.3.3 `DownloadQueue.cpp:1044`, `:1127`).
//!
//! A scripted sharer (the sx1-gate fake at SX1 version 3, stimulus only) logs
//! in High ID and offers sixteen files, so Lugdunum has sources to answer each
//! ask with. The counterparty under test is Lugdunum: a tap in its namespace
//! records rmule's asks and its `OP_FOUNDSOURCES`, read per hash, and every
//! FIN or RST on rmule's server link.
//!
//! `--downloads 40 --also-ed2ksrv` draws the Server Pace's round instead: a
//! round passes the connected server over (`DownloadQueue.cpp:887-891`), so
//! rmule logs in to Lugdunum and lists ed2k-server, and a tap on ed2k-server
//! writes `udp-rounds.txt` with rmule's datagrams, their spacing and the files
//! each asked for (at most one datagram a second, 35 files a server,
//! `DownloadQueue.cpp:868-958`). The TCP verdict's fifteen and a sixteenth are
//! read only at sixteen downloads.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::artifacts::RunLayout;
use crate::docker::RunContainer;
use crate::flow::bench::{Bench, CaptureSidecar, DEFAULT_TAP_INTERFACE, ED2K_SERVER_PORT};
use crate::flow::ed2k_server::rmule_tools::run_to_exit;
use crate::flow::ed2k_server::search_wire::{ED2KSRV_IP, start_ed2ksrv};
use crate::flow::pcap;

mod udp_rounds;

/// The bench network's prefix: `RMULE_BENCH_ED2KSRV_SECOND_SUBNET` moves
/// ed2k-server, and this flow's bodies with it, so a Kad bench can run beside.
fn prefix() -> &'static str {
    if std::env::var_os("RMULE_BENCH_ED2KSRV_SECOND_SUBNET").is_some() {
        "198.51.100"
    } else {
        "203.0.113"
    }
}

/// rmule's static address on the bench network.
fn rmule_ip() -> String {
    format!("{}.71", prefix())
}

/// The fake sharer's static address, the one its listener binds.
fn sharer_ip() -> String {
    format!("{}.72", prefix())
}
const PCAP: &str = "lugdunum.pcap";
const ED2KSRV_PCAP: &str = "ed2ksrv-udp.pcap";
/// The fake sharer, shared with the sx1-gate leg.
const FAKE_SOURCE: &str = include_str!("../peer/sx1_gate/fake_source.py");
/// How many downloads the TCP budget's verdict is written for.
pub const DOWNLOADS: u8 = 16;
/// The run outlasts the 300 s window and the sixteenth answer.
const DOWNLOAD_SECS: u64 = 380;
const FAKE_SECS: u64 = DOWNLOAD_SECS + 40;
/// The budget's window, and how far the capture may read it short or long.
const WINDOW_SECS: f64 = 300.0;
const WINDOW_SLACK_SECS: f64 = 5.0;
/// How close together "at once" is on the wire.
const BURST_SECS: f64 = 10.0;
const OP_GETSOURCES: u8 = 0x19;
const OP_GETSOURCES_OBFU: u8 = 0x23;
const OP_FOUNDSOURCES: u8 = 0x42;
const OP_FOUNDSOURCES_OBFU: u8 = 0x44;

/// Options for the ask-budget leg.
pub struct AskBudgetOptions<'a> {
    /// The run dir every artifact is written under.
    pub layout: &'a RunLayout,
    /// The Docker-compatible CLI to invoke.
    pub container_runtime: &'a str,
    /// Leave the containers and network running after the run.
    pub keep_containers: bool,
    /// Per-step readiness budget, in seconds.
    pub timeout_secs: u64,
    /// The Lugdunum eserver image.
    pub server_image: &'a str,
    /// Extra `KEY=VALUE` environment for the eserver container.
    pub server_env: &'a [String],
    /// The `rmule-tools` image, built from the tip under test.
    pub rmule_tools_image: &'a str,
    /// An image carrying `python3`, the fake sharer's interpreter.
    pub probe_image: &'a str,
    /// The tcpdump capture-sidecar image.
    pub capture_image: &'a str,
    /// How many downloads rmule starts.
    pub downloads: u8,
    /// List this ed2k-server, its image and config, beside the login.
    pub also_ed2ksrv: Option<(&'a str, &'a Path)>,
}

/// `count` file hashes, upper-case hex, distinct and asymmetric.
fn hashes(count: u8) -> Vec<String> {
    (0..count)
        .map(|i| format!("B7{i:02X}3E91C04D5A26F8E1B3C7D9A05F{:02X}", 0x40 + i))
        .collect()
}

/// Run the leg and write `ask-budget/verdict.txt`.
pub fn run_ask_budget(options: AskBudgetOptions<'_>) -> Result<()> {
    let mut bench = Bench::new(
        options.container_runtime,
        options.layout,
        options.keep_containers,
    )?;
    let timeout = Duration::from_secs(options.timeout_secs);
    let root = options.layout.root().join("ask-budget");
    fs::create_dir_all(&root).with_context(|| format!("create {}", root.display()))?;
    fs::write(root.join("fake_source.py"), FAKE_SOURCE).context("write fake_source.py")?;
    let hashes = hashes(options.downloads);

    let result = (|| -> Result<()> {
        let subnet = format!("{}.0/24", prefix());
        bench.create_network(options.layout, Some(&subnet))?;
        bench.start_eserver_in_network(
            options.layout,
            options.server_image,
            options.server_env,
            timeout,
        )?;
        let server = bench.names.server_container_name.clone();
        let tap = format!("{server}-tap");
        let bpf = format!("tcp port {ED2K_SERVER_PORT} or udp");
        let sidecar = CaptureSidecar {
            image: options.capture_image,
            name: &tap,
            target_container: &server,
            interface: DEFAULT_TAP_INTERFACE,
            host_dir: root.clone(),
            pcap_file: PCAP,
            bpf: &bpf,
        };
        bench.start_extra(&tap, sidecar.container(), "run the Lugdunum tap")?;
        let listed = options
            .also_ed2ksrv
            .map(|(image, config)| -> Result<String> {
                let ed2ksrv = start_ed2ksrv(&mut bench, image, config, &root, timeout)?;
                let tap = format!("{ed2ksrv}-tap");
                let sidecar = CaptureSidecar {
                    image: options.capture_image,
                    name: &tap,
                    target_container: &ed2ksrv,
                    interface: DEFAULT_TAP_INTERFACE,
                    host_dir: root.clone(),
                    pcap_file: ED2KSRV_PCAP,
                    bpf: "udp",
                };
                bench.start_extra(&tap, sidecar.container(), "run the ed2k-server tap")?;
                Ok(tap)
            })
            .transpose()?;

        let fake = format!("{server}-sharer");
        let container = RunContainer::new(options.probe_image.to_owned())
            .detach()
            .name(&fake)
            .network(bench.names.network_name.clone())
            .ip(sharer_ip())
            .volume(&root, "/w")
            .entrypoint("python3")
            .arg("/w/fake_source.py")
            .arg("3")
            .arg(FAKE_SECS.to_string())
            .arg(bench.names.server_endpoint())
            .arg(hashes.join(","))
            .arg(sharer_ip());
        bench.start_extra(&fake, container, "run the fake sharer")?;
        // The offer reaches the server before rmule asks it.
        std::thread::sleep(Duration::from_secs(5));

        let endpoint = bench.names.server_endpoint();
        let max_seconds = DOWNLOAD_SECS.to_string();
        let mut args: Vec<String> = [
            "ed2k",
            "download",
            "start",
            "--data-dir",
            "/w/data",
            "--server",
            &endpoint,
            "--user-hash",
            "6C1E9A47D2B03F58E7A4C19B0D63F2A5",
            "--max-seconds",
            &max_seconds,
        ]
        .map(str::to_owned)
        .to_vec();
        for (i, hash) in hashes.iter().enumerate() {
            args.push("--file".into());
            args.push(format!(
                "ed2k://|file|ask-budget-{i:02}.bin|9728000|{hash}|/"
            ));
        }
        for i in 0..hashes.len() {
            args.push("--out".into());
            args.push(format!("/w/dl/out-{i:02}.bin"));
        }
        if listed.is_some() {
            args.push("--also-server".into());
            args.push(format!("{ED2KSRV_IP}:4661"));
        }
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let rmule = format!("{server}-rmule16");
        run_to_exit(
            &mut bench,
            options.rmule_tools_image,
            &rmule,
            &rmule_ip(),
            &root,
            &args,
        )?;
        bench.stop_extra(&fake);
        bench.stop_extra(&tap);
        if let Some(tap) = &listed {
            bench.stop_extra(tap);
        }
        write_verdicts(&root, &hashes)
    })();

    if result.is_err() {
        bench.collect_failure_logs(options.layout);
    }
    bench.cleanup_best_effort();
    result
}

/// Score a retained run dir's tap again, without driving the flow, and
/// rewrite its `ask-budget/verdict.txt`.
///
/// # Errors
/// If the pcap cannot be read or the verdict written.
pub fn rescore_ask_budget(run_dir: &std::path::Path, downloads: u8) -> Result<()> {
    let root = run_dir.join("ask-budget");
    write_verdicts(&root, &hashes(downloads))
}

/// Write `verdict.txt` and `udp-rounds.txt` from the tap under `root`.
fn write_verdicts(root: &std::path::Path, hashes: &[String]) -> Result<()> {
    let verdict = score(&root.join(PCAP), hashes)?;
    fs::write(root.join("verdict.txt"), &verdict).context("write verdict")?;
    print!("{verdict}");
    let listed = root.join(ED2KSRV_PCAP);
    let tap = if listed.exists() {
        listed
    } else {
        root.join(PCAP)
    };
    let datagrams = pcap::udp4_datagrams(&tap)?;
    let rounds = udp_rounds::score(&datagrams, rmule_ip().parse()?);
    fs::write(root.join("udp-rounds.txt"), &rounds).context("write the UDP rounds")?;
    print!("{rounds}");
    Ok(())
}

/// Read the tap: rmule's asks per hash and time, Lugdunum's answers per hash,
/// and who closed rmule's server link first.
fn score(pcap_path: &std::path::Path, hashes: &[String]) -> Result<String> {
    let rmule: Ipv4Addr = rmule_ip().parse()?;
    let capture = pcap::tcp_capture(&pcap::records(pcap_path)?)?;
    let hash_of = |payload: &[u8]| payload.get(..16).map(hex_upper);
    let mut asks: Vec<(f64, String)> = Vec::new();
    let mut answers: BTreeMap<String, (f64, u8)> = BTreeMap::new();
    let mut links = 0;
    for stream in &capture.streams {
        let from_rmule = stream.source.ip() == std::net::IpAddr::V4(rmule)
            && stream.destination.port() == ED2K_SERVER_PORT;
        let to_rmule = stream.destination.ip() == std::net::IpAddr::V4(rmule)
            && stream.source.port() == ED2K_SERVER_PORT;
        if from_rmule {
            links += 1;
        }
        for frame in stream.ed2k_frames() {
            match frame.opcode {
                OP_GETSOURCES | OP_GETSOURCES_OBFU if from_rmule => {
                    asks.extend(hash_of(frame.payload()).map(|hash| (frame.at, hash)));
                }
                OP_FOUNDSOURCES | OP_FOUNDSOURCES_OBFU if to_rmule => {
                    if let Some(hash) = hash_of(frame.payload()) {
                        let count = frame.payload().get(16).copied().unwrap_or(0);
                        answers.entry(hash).or_insert((frame.at, count));
                    }
                }
                _ => {}
            }
        }
    }
    asks.sort_by(|a, b| a.0.total_cmp(&b.0));
    // rmule hangs up when its run ends; the server's FIN answering that is
    // no disconnect. Only a close the server sent first counts.
    let rmule_closed_at = capture
        .closes
        .iter()
        .filter(|close| {
            close.source.ip() == std::net::IpAddr::V4(rmule)
                && close.destination.port() == ED2K_SERVER_PORT
        })
        .map(|close| close.at)
        .min_by(f64::total_cmp)
        .unwrap_or(f64::INFINITY);
    let server_closes = capture
        .closes
        .iter()
        .filter(|close| {
            close.destination.ip() == std::net::IpAddr::V4(rmule)
                && close.source.port() == ED2K_SERVER_PORT
                && close.at < rmule_closed_at
        })
        .count();
    let start = asks.first().map_or(0.0, |(at, _)| *at);
    let mut first_ask: BTreeMap<&str, f64> = BTreeMap::new();
    for (at, hash) in &asks {
        first_ask.entry(hash.as_str()).or_insert(*at - start);
    }
    let mut offsets: Vec<f64> = first_ask.values().copied().collect();
    offsets.sort_by(f64::total_cmp);
    let burst = offsets.iter().filter(|&&at| at <= BURST_SECS).count();
    let late = offsets.get(15).copied();
    let in_window =
        late.is_some_and(|at| (at - WINDOW_SECS).abs() <= WINDOW_SLACK_SECS) && burst == 15;
    let answered = hashes.iter().filter(|h| answers.contains_key(*h)).count();
    // The verdict is rmule's budget: one ask per hash, fifteen at once, the
    // sixteenth a window later, the link kept. How many Lugdunum answered is
    // the counterparty's fact, reported beside it (it answers seven of a
    // burst, runs `1790869078` and `1790870643`).
    let pass = asks.len() == hashes.len()
        && first_ask.len() == hashes.len()
        && in_window
        && server_closes == 0
        && links == 1;
    let mut out = format!(
        "verdict={} asks={} distinct_hashes={} burst_within_{BURST_SECS}s={burst} \
         sixteenth_at={} answered={answered}/{} server_closes={server_closes} rmule_links={links}\n",
        if pass { "PASS" } else { "FAIL" },
        asks.len(),
        first_ask.len(),
        late.map_or_else(|| "none".to_owned(), |at| format!("{at:.3}")),
        hashes.len(),
    );
    for hash in hashes {
        let ask = first_ask.get(hash.as_str());
        let answer = answers.get(hash);
        let _ = writeln!(
            out,
            "{hash} ask_at={} answer_at={} sources={}",
            ask.map_or_else(|| "none".to_owned(), |at| format!("{at:.3}")),
            answer.map_or_else(|| "none".to_owned(), |(at, _)| format!("{:.3}", at - start)),
            answer.map_or(0, |(_, count)| *count),
        );
    }
    Ok(out)
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}
