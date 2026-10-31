//! The own-source leg: a server's answer names rmule for a file it shares and
//! downloads, and rmule does not dial itself (ADR-0090, the Own Position;
//! `DownloadQueue.cpp:612-619`, `PartFile.cpp:1609-1615`).
//!
//! One `Core` logs in to Lugdunum High ID, shares a file and downloads that
//! same file, so the only source the server can name is rmule. A dial of its
//! own public address leaves through `lo`, not `eth0`, so a second tap watches
//! `lo` in rmule's namespace, and a control dial from inside that namespace
//! proves the tap would have seen one. A tap on Lugdunum reads the answer.
//! Should the server filter the requester out, the leg says the answer never
//! named rmule and the row is not drawn.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::artifacts::RunLayout;
use crate::docker::RunContainer;
use crate::flow::bench::{
    Bench, CaptureSidecar, DEFAULT_TAP_INTERFACE, ED2K_SERVER_PORT, run_checked,
};
use crate::flow::ed2k_server::search_wire::SUBNET;
use crate::flow::gate::wait_for_container_log;
use crate::flow::identity::parse_ed2k_file_hash;
use crate::flow::nat::synthetic::write_hashed;
use crate::flow::pcap;
use crate::verdict::{self, Verdict};

/// rmule's static address on the bench network.
const RMULE_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 73);
const RMULE_PEER_PORT: u16 = 4662;
const SERVER_PCAP: &str = "lugdunum.pcap";
const LOOPBACK_PCAP: &str = "rmule-lo.pcap";
const FILE_BYTES: u64 = 1_048_576;
/// The core's whole run; the control dials once its window has passed.
const RUN_SECS: u64 = 60;
const WATCH_SECS: u64 = 45;
const OP_FOUNDSOURCES: u8 = 0x42;
const OP_FOUNDSOURCES_OBFU: u8 = 0x44;
const USER_HASH: &str = "6C1E9A47D2B03F58E7A4C19B0D63F2A6";
const CONTROL_HASH: &str = "6C1E9A47D2B03F58E7A4C19B0D63F2A7";

/// Options for the own-source leg.
pub struct OwnSourceOptions<'a> {
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
    /// The tcpdump capture-sidecar image.
    pub capture_image: &'a str,
}

/// Run the leg and write `own-source/own-source-verdict.toml`.
///
/// # Errors
/// If a body cannot be started or a tap read.
pub fn run_own_source(options: OwnSourceOptions<'_>) -> Result<()> {
    let mut bench = Bench::new(
        options.container_runtime,
        options.layout,
        options.keep_containers,
    )?;
    let timeout = Duration::from_secs(options.timeout_secs);
    let root = options.layout.root().join("own-source");
    let shared_dir = root.join("shared");
    fs::create_dir_all(&shared_dir).with_context(|| format!("create {}", shared_dir.display()))?;
    let file = write_hashed(&shared_dir, FILE_BYTES)?;

    let result = (|| -> Result<(Verdict, String)> {
        bench.create_network(options.layout, Some(SUBNET))?;
        bench.start_eserver_in_network(
            options.layout,
            options.server_image,
            options.server_env,
            timeout,
        )?;
        let server = bench.names.server_container_name.clone();
        let server_tap = format!("{server}-tap");
        let bpf = format!("tcp port {ED2K_SERVER_PORT}");
        let sidecar = CaptureSidecar {
            image: options.capture_image,
            name: &server_tap,
            target_container: &server,
            interface: DEFAULT_TAP_INTERFACE,
            host_dir: root.clone(),
            pcap_file: SERVER_PCAP,
            bpf: &bpf,
        };
        bench.start_extra(&server_tap, sidecar.container(), "run the Lugdunum tap")?;
        wait_for_container_log(&bench.docker, &server_tap, "listening on", timeout)?;

        let endpoint = bench.names.server_endpoint();
        let rmule = format!("{server}-own");
        let run_secs = RUN_SECS.to_string();
        let args = [
            "ed2k",
            "download",
            "start",
            "--data-dir",
            "/w/data",
            "--server",
            &endpoint,
            "--file",
            &file.link,
            "--out",
            "/w/dl/own.bin",
            "--serve",
            "--share",
            "/w/shared/shared.bin",
            "--linger",
            "--stamp-events",
            "--max-seconds",
            &run_secs,
            "--user-hash",
            USER_HASH,
        ];
        let container = args.iter().fold(
            RunContainer::new(options.rmule_tools_image.to_owned())
                .detach()
                .name(&rmule)
                .network(bench.names.network_name.clone())
                .ip(RMULE_IP.to_string())
                .env("RMULE_LOG", "info,rmule_core::download=debug")
                .volume(&root, "/w"),
            |container, arg| container.arg(*arg),
        );
        bench.start_extra(&rmule, container, "run rmule")?;

        let loopback_tap = format!("{server}-lo-tap");
        let bpf = format!("tcp port {RMULE_PEER_PORT}");
        let sidecar = CaptureSidecar {
            image: options.capture_image,
            name: &loopback_tap,
            target_container: &rmule,
            interface: "lo",
            host_dir: root.clone(),
            pcap_file: LOOPBACK_PCAP,
            bpf: &bpf,
        };
        bench.start_extra(&loopback_tap, sidecar.container(), "run the loopback tap")?;
        wait_for_container_log(&bench.docker, &loopback_tap, "listening on", timeout)?;

        std::thread::sleep(Duration::from_secs(WATCH_SECS));
        let peer = SocketAddr::from((RMULE_IP, RMULE_PEER_PORT)).to_string();
        // The control may read nothing back; its dial is what it is for.
        let control = bench
            .docker
            .exec(
                rmule.clone(),
                [
                    "/usr/bin/rmule-tools",
                    "ed2k",
                    "peer",
                    "transfer",
                    "capture",
                    "--peer",
                    &peer,
                    "--file",
                    &file.link,
                    "--output-dir",
                    "/w/control",
                    "--user-hash",
                    CONTROL_HASH,
                    "--max-seconds",
                    "5",
                ]
                .map(OsString::from),
            )
            .to_command()
            .output()
            .context("run the control dial")?;
        fs::write(root.join("control.log"), &control.stdout).context("keep the control's log")?;

        run_checked(bench.docker.wait(rmule.clone()), "wait for rmule")?;
        let logs = run_checked(bench.docker.logs(rmule.clone()), "rmule logs")?;
        fs::write(root.join("rmule.log"), format!("{logs}\n")).context("keep rmule's log")?;
        bench.stop_extra(&loopback_tap);
        bench.stop_extra(&server_tap);
        score(&root, &parse_ed2k_file_hash(&file.link)?)
    })();

    if result.is_err() {
        bench.collect_failure_logs(options.layout);
    }
    bench.cleanup_best_effort();
    let (verdict, report) = result?;
    verdict::write_report(&root, "own-source", verdict, &report)?;
    print!("verdict={verdict}\n{report}");
    Ok(())
}

/// The record naming rmule in a found-sources payload.
fn names_rmule(sources: &[u8]) -> bool {
    let mut record = RMULE_IP.octets().to_vec();
    record.extend_from_slice(&RMULE_PEER_PORT.to_le_bytes());
    sources.windows(record.len()).any(|window| window == record)
}

/// Read both taps into the verdict.
fn score(root: &Path, hash: &[u8; 16]) -> Result<(Verdict, String)> {
    let rmule = IpAddr::V4(RMULE_IP);
    let server = pcap::tcp_capture(&pcap::records(&root.join(SERVER_PCAP))?)?;
    let (mut answers, mut naming) = (0, 0);
    for stream in &server.streams {
        if stream.destination.ip() != rmule || stream.source.port() != ED2K_SERVER_PORT {
            continue;
        }
        for frame in stream.ed2k_frames() {
            let found = matches!(frame.opcode, OP_FOUNDSOURCES | OP_FOUNDSOURCES_OBFU);
            if found && frame.payload().get(..16) == Some(hash.as_slice()) {
                answers += 1;
                naming += usize::from(names_rmule(&frame.payload()[16..]));
            }
        }
    }
    let loopback = pcap::tcp_capture(&pcap::records(&root.join(LOOPBACK_PCAP))?)?;
    let own = SocketAddr::from((RMULE_IP, RMULE_PEER_PORT));
    let dials: BTreeSet<u16> = loopback
        .opens
        .iter()
        .filter(|open| open.destination == own)
        .map(|open| open.source.port())
        .collect();
    // The control is one dial, so one distinct port is the control alone.
    let (verdict, reading) = match (naming, dials.len()) {
        (_, 0) => (
            Verdict::Blocked,
            "the control's dial is not on the loopback tap",
        ),
        (0, _) => (Verdict::NotDrawn, "no answer named rmule"),
        (_, 1) => (Verdict::Pass, "rmule left its own listener alone"),
        _ => (Verdict::Fail, "rmule dialed its own listener"),
    };
    Ok((
        verdict,
        format!(
            "{reading}\nanswers={answers}\nanswers_naming_rmule={naming}\n\
             loopback_dial_ports={dials:?}\n"
        ),
    ))
}
