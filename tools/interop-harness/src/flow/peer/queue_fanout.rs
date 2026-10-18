//! The **queue fan-out** flow (ADR-0116, asking and transferring).
//!
//! One rmule download against many stock aMule sharers, some of which queue it
//! and some of which grant it late: what the asking budget costs in
//! connections, and what transferring from every grant buys in throughput.
//!
//! Topology, on the eserver's bridge:
//! 1. The eserver.
//! 2. `sharers` stock aMules, High ID, each sharing rmule's file and held to
//!    two upload slots of `slot_kib` KiB/s (`MaxUpload` 2 × slot,
//!    `SlotAllocation` slot: `UploadQueue.cpp:296-318`).
//! 3. Two slot-holders for each of the first `queued` sharers: stock aMules
//!    downloading that sharer's own holder file from it at `holder_kib`, so
//!    they never finish and the sharer queues rmule. The other sharers grant
//!    at once.
//! 4. **rmule**: `ed2k download start --serve --report-parts-every-ms 1000
//!    --stamp-events`, High ID, with a tap in its namespace on both listeners.
//!
//! `late_after_secs` after rmule's first rank, one holder of each of the first
//! `late` queued sharers stops: that sharer promotes rmule by dialing it back
//! (`UploadQueue.cpp:206-210`), the grant rmule's Awaited Grant takes. The
//! verdict reads the throughput, the connections rmule opened and was opened,
//! the most sources asking, queued and transferring at once, each queued
//! sharer's hang-up and each late sharer's grant becoming a transfer. Run once
//! on the build before the split and once after, the rows are the
//! before/after.

use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::artifacts::{Ed2kHashCommand, RunLayout, write_ed2k_link, write_incompressible_file};
use crate::flow::bench::{
    AMULE_PEER_TCP_PORT, Bench, CaptureSidecar, DEFAULT_TAP_INTERFACE, Eserver, run_checked,
};
use crate::flow::gate::{wait_for_amule_ready, wait_for_container_log};
use crate::flow::identity::ed2k_link_with_source;
use crate::flow::logs::{collect_amule_role_logs, collect_rmule_logs, collect_server_logs};
use crate::rmule::{RMULE_SERVE_TCP_PORT, RmuleClientContainer, release_held_download};

pub(crate) mod run_log;
pub(crate) mod verdict;

pub use self::verdict::score_run_dir;

/// How long a stopped holder gets to close its link.
const HOLDER_STOP_GRACE_SECS: u64 = 10;

/// The holder file of queued sharer `index`: one per sharer, so its holders
/// find no other sharer of it.
fn holder_file(index: usize) -> String {
    format!("holder-{index}.bin")
}

/// [`holder_file`]'s ed2k link.
fn holder_link(index: usize) -> String {
    format!("holder-{index}.ed2k.txt")
}

/// The flow's shape: how many sharers, how many queue rmule and grant late,
/// and the knobs rmule runs under.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FanoutShape {
    /// Stock aMule sharers of rmule's file.
    pub sharers: usize,
    /// The first this many sharers have both slots held: they queue rmule.
    pub queued: usize,
    /// The first this many queued sharers lose a holder after
    /// `late_after_secs`, and grant rmule by dialing it back.
    pub late: usize,
    /// Seconds from rmule's first rank to the late holders' stop.
    pub late_after_secs: u64,
    /// Each sharer's upload slot, KiB/s.
    pub slot_kib: u32,
    /// Each holder's download cap, KiB/s: low enough that no holder finishes.
    pub holder_kib: u32,
    /// Seconds the flow waits for the download to complete.
    pub run_window_secs: u64,
    /// rmule's `--max-connections`; `None` keeps the core's.
    pub max_connections: Option<usize>,
    /// rmule's `--dials-per-window`; `None` keeps the core's.
    pub dials_per_window: Option<u32>,
}

/// Stage rmule's `shared.bin` of `rmule_size` bytes and one `holder_size`
/// holder file per queued sharer, none of them a compressor shrinks, with
/// their ed2k links hashed by `command`.
///
/// # Errors
/// If a file cannot be written or hashed.
pub fn stage_queue_fanout_files(
    layout: &RunLayout,
    rmule_size: u64,
    holder_size: u64,
    queued: usize,
    command: &Ed2kHashCommand,
) -> Result<()> {
    let dir = layout.synthetic_dir();
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    write_incompressible_file(&layout.synthetic_shared_file(), rmule_size, 0x5EED_0F01)?;
    write_ed2k_link(
        command,
        &layout.synthetic_shared_file(),
        &layout.synthetic_ed2k_file(),
    )?;
    for index in 0..queued {
        let holder = dir.join(holder_file(index));
        let seed = 0x5EED_0F10 + u64::try_from(index).unwrap_or(0);
        write_incompressible_file(&holder, holder_size, seed)?;
        write_ed2k_link(command, &holder, &dir.join(holder_link(index)))?;
    }
    Ok(())
}

/// Options for [`run_peer_queue_fanout`].
pub struct PeerQueueFanoutOptions<'a> {
    /// The run dir every artifact is written under.
    pub layout: &'a RunLayout,
    /// The Docker-compatible CLI to invoke.
    pub container_runtime: &'a str,
    /// Build the project-owned images before starting anything.
    pub build_images: bool,
    /// The eserver image.
    pub server_image: &'a str,
    /// The aMule image.
    pub amule_image: &'a str,
    /// The tcpdump capture-sidecar image.
    pub capture_image: &'a str,
    /// Build context for the eserver image.
    pub server_build_context: &'a Path,
    /// Build context for the aMule image.
    pub amule_build_context: &'a Path,
    /// Build context for the capture-sidecar image.
    pub capture_build_context: &'a Path,
    /// Leave the containers and network running after the run.
    pub keep_containers: bool,
    /// Per-step readiness budget, in seconds.
    pub timeout_secs: u64,
    /// Host TCP port the eserver's port is published on.
    pub server_host_port: u16,
    /// The rust image + workspace rmule runs as a client in.
    pub rmule_client_container: &'a RmuleClientContainer,
    /// Extra environment for every aMule (`KEY=VALUE`).
    pub amule_env: &'a [String],
    /// The sharers, the queues and rmule's knobs.
    pub shape: FanoutShape,
}

/// The flow's container names, by role.
struct Names {
    sharers: Vec<String>,
    holders: Vec<[String; 2]>,
    capture: String,
}

impl Names {
    fn of(layout: &RunLayout, shape: FanoutShape) -> Self {
        let suffix = layout
            .root()
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        Self {
            sharers: (0..shape.sharers)
                .map(|index| format!("rmule-interop-amule-sharer-{index}-{suffix}"))
                .collect(),
            holders: (0..shape.queued)
                .map(|index| {
                    ["a", "b"]
                        .map(|role| format!("rmule-interop-amule-holder-{index}{role}-{suffix}"))
                })
                .collect(),
            capture: format!("rmule-interop-queue-fanout-capture-{suffix}"),
        }
    }
}

/// rmule's `download start` flags for the run: the ticks and stamps the
/// verdict reads, and the Connection Budget's knobs when set.
fn rmule_flags(shape: FanoutShape) -> Vec<String> {
    let mut flags = vec![
        "--report-parts-every-ms".to_owned(),
        "1000".to_owned(),
        "--stamp-events".to_owned(),
    ];
    if let Some(connections) = shape.max_connections {
        flags.extend(["--max-connections".to_owned(), connections.to_string()]);
    }
    if let Some(dials) = shape.dials_per_window {
        flags.extend(["--dials-per-window".to_owned(), dials.to_string()]);
    }
    flags
}

/// Run the flow and score it.
///
/// # Errors
/// If a container fails to start, a readiness wait outlasts its budget, or
/// the verdict cannot be written. A download that does not complete inside
/// the run window is scored, not an error.
pub fn run_peer_queue_fanout(options: PeerQueueFanoutOptions<'_>) -> Result<()> {
    let shape = options.shape;
    anyhow::ensure!(
        shape.late <= shape.queued && shape.queued <= shape.sharers,
        "late ({}) <= queued ({}) <= sharers ({}) must hold",
        shape.late,
        shape.queued,
        shape.sharers
    );
    let mut bench = Bench::new(
        options.container_runtime,
        options.layout,
        options.keep_containers,
    )?;
    let names = Names::of(options.layout, shape);
    if options.build_images {
        bench.build_image("server", options.server_image, options.server_build_context)?;
        bench.build_image("aMule", options.amule_image, options.amule_build_context)?;
        bench.build_image(
            "capture",
            options.capture_image,
            options.capture_build_context,
        )?;
    }
    let timeout = Duration::from_secs(options.timeout_secs);
    let root = options.layout.root().join(verdict::ROOT_DIR);
    fs::create_dir_all(&root).with_context(|| format!("create {}", root.display()))?;

    let result = (|| -> Result<()> {
        bench.create_network(options.layout, None)?;
        bench.start_eserver(
            options.layout,
            &Eserver {
                image: options.server_image,
                host_port: options.server_host_port,
                env: &[],
                timeout,
            },
        )?;
        let synthetic = options.layout.synthetic_dir();
        let read_link = |name: &str| -> Result<String> {
            let path = synthetic.join(name);
            fs::read_to_string(&path)
                .map(|link| link.trim().to_owned())
                .with_context(|| format!("read {}", path.display()))
        };
        let rmule_link = read_link("shared.ed2k.txt")?;

        let mut sharer_ips = Vec::new();
        for (index, sharer) in names.sharers.iter().enumerate() {
            // Each sharer's own directory: rmule's file, and its own holder
            // file when it queues.
            let dir = root.join(format!("share-{index}"));
            fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
            fs::copy(
                options.layout.synthetic_shared_file(),
                dir.join("shared.bin"),
            )
            .context("stage rmule's file for a sharer")?;
            if index < shape.queued {
                fs::copy(
                    synthetic.join(holder_file(index)),
                    dir.join(holder_file(index)),
                )
                .context("stage a holder file")?;
            }
            let container = bench
                .amule_container(options.amule_image, sharer)
                .volume(&dir, "/incoming")
                .env("AMULE_SHARED_DIR", "/incoming")
                .env("AMULE_MAX_UPLOAD", (2 * shape.slot_kib).to_string())
                .env("AMULE_SLOT_ALLOCATION", shape.slot_kib.to_string())
                .env_assignments(options.amule_env);
            bench.start_extra(sharer, container, "run sharer aMule")?;
            wait_for_amule_ready(
                &bench.docker,
                options.layout,
                sharer,
                timeout,
                "rmule-amule-ready",
            )?;
            let ip = run_checked(
                bench.docker.container_ip(sharer.clone()),
                "inspect sharer ip",
            )?;
            sharer_ips.push(ip.trim().parse::<Ipv4Addr>().context("sharer address")?);
        }

        // Each queued sharer's holders dial it straight from their link and
        // take both slots before rmule asks.
        for (index, pair) in names.holders.iter().enumerate() {
            let link = read_link(&holder_link(index))?;
            let sourced =
                ed2k_link_with_source(&link, &sharer_ips[index].to_string(), AMULE_PEER_TCP_PORT);
            for holder in pair {
                let container = bench
                    .amule_container(options.amule_image, holder)
                    .env("AMULE_DOWNLOAD_LINK", sourced.as_str())
                    .env("AMULE_EXPECTED_FILE_NAME", holder_file(index))
                    .env("AMULE_DOWNLOAD_NO_WAIT", "1")
                    .env("AMULE_MAX_DOWNLOAD", shape.holder_kib.to_string())
                    .env_assignments(options.amule_env);
                bench.start_extra(holder, container, "run slot-holder aMule")?;
                wait_for_amule_ready(
                    &bench.docker,
                    options.layout,
                    holder,
                    timeout,
                    "rmule-amule-download-sources-ready",
                )?;
            }
        }

        let rmule_name = bench.names.rmule_container_name.clone();
        run_checked(
            options
                .rmule_client_container
                .prebuild_command(&bench.docker)?,
            "prebuild rmule-tools for the download container",
        )?;
        let download = options
            .rmule_client_container
            .download_start_detached_with_args(
                bench.staging(options.layout),
                &rmule_name,
                &bench.names.server_endpoint(),
                &[rmule_link.as_str()],
                true,
                &rmule_flags(shape),
            )?;
        bench.start_rmule_container(download, "run rmule download container")?;
        let tap = CaptureSidecar {
            image: options.capture_image,
            name: &names.capture,
            target_container: &rmule_name,
            interface: DEFAULT_TAP_INTERFACE,
            host_dir: root.clone(),
            pcap_file: verdict::RMULE_PCAP,
            bpf: &format!("tcp port {AMULE_PEER_TCP_PORT} or tcp port {RMULE_SERVE_TCP_PORT}"),
        };
        bench.start_extra(
            &names.capture,
            tap.container(),
            "run queue fan-out tcpdump sidecar",
        )?;
        wait_for_container_log(&bench.docker, &names.capture, "listening on", timeout)?;
        release_held_download(options.layout)?;
        let rmule_ip = run_checked(
            bench.docker.container_ip(rmule_name.clone()),
            "inspect rmule ip",
        )?;
        verdict::Topology {
            rmule: rmule_ip.trim().parse().context("rmule address")?,
            sharers: sharer_ips.clone(),
            shape,
        }
        .write(&root)?;

        // rmule asked a queued sharer and was ranked; the late holders stop
        // `late_after_secs` later, and those sharers dial rmule back.
        if shape.queued > 0 {
            wait_for_container_log(&bench.docker, &rmule_name, "download.peer_queued", timeout)?;
        }
        std::thread::sleep(Duration::from_secs(shape.late_after_secs));
        for pair in names.holders.iter().take(shape.late) {
            run_checked(
                bench
                    .docker
                    .stop_container(pair[0].clone(), HOLDER_STOP_GRACE_SECS),
                "stop a late sharer's slot-holder",
            )?;
        }
        println!(
            "peer_queue_fanout late_holders_stopped={} rmule_ip={}",
            shape.late,
            rmule_ip.trim()
        );
        let completed = wait_for_container_log(
            &bench.docker,
            &rmule_name,
            "download.completed id=1",
            Duration::from_secs(shape.run_window_secs),
        )
        .is_ok();
        println!("peer_queue_fanout completed_in_window={completed}");
        collect_rmule_logs(&bench.docker, options.layout, &rmule_name)?;
        for (index, sharer) in names.sharers.iter().enumerate() {
            collect_amule_role_logs(
                &bench.docker,
                options.layout,
                &format!("sharer-{index}"),
                sharer,
            )?;
        }
        collect_server_logs(
            &bench.docker,
            options.layout,
            &bench.names.server_container_name,
        )?;
        Ok(())
    })();

    if result.is_err() {
        bench.collect_failure_logs(options.layout);
        for (index, sharer) in names.sharers.iter().enumerate() {
            let role = format!("sharer-{index}");
            if let Err(error) =
                collect_amule_role_logs(&bench.docker, options.layout, &role, sharer)
            {
                eprintln!("warning: failed to collect {role}'s logs: {error:#}");
            }
        }
    }
    if options.keep_containers {
        println!("kept_capture_dir={}", root.display());
    }
    bench.cleanup_best_effort();
    result?;
    let verdict = score_run_dir(options.layout.root())?;
    println!("peer_queue_fanout verdict={verdict}");
    Ok(())
}
