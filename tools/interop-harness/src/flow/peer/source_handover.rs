//! The **Source Handover** flow (ADR-0090): one rmule core, two downloads, one
//! stock aMule that has nothing more of the first to give.
//!
//! The sharer holds part 0 of a two-part file and the whole of a second file.
//! rmule asks for the first, is served that part, and from then on the sharer
//! holds no part it lacks. Only then is the second download added, so its fill
//! meets a standing that needs nothing: it waits on it, and asks the peer a
//! period after the peer's last ask (`FILEREASKTIME`, `PartFile.cpp:1472-1483`),
//! as aMule's swap leaves `DS_NONE` for `AskForDownload`
//! (`DownloadClient.cpp:1498`). A sooner ask is scored
//! (`CheckForAggressive`, `UploadClient.cpp:795-825`).
//!
//! The second download goes in through a gate because a file asked for from
//! the start takes the link's next turn instead: that is the `peer-one-link`
//! flow, and it asks at once, as aMule does over a socket a transfer just ended
//! on (`UploadQueue.cpp:486-493`).
//!
//! A tap on rmule's namespace carries every dial, frame and reask; the verdict
//! reads it with rmule's run log and the second copy.

use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};

use super::streaming_window::seed::{
    StreamFile, stage_complete_seed, stage_partial_seed, write_stream_file,
};
use super::streaming_window::{
    AMULE_READY, SEED_INCOMING_MOUNT, SEED_TEMP_MOUNT, wait_for_share, with_sources,
};
use crate::artifacts::RunLayout;
use crate::flow::bench::{Bench, CaptureSidecar, DEFAULT_TAP_INTERFACE, Eserver, run_checked};
use crate::flow::gate::{wait_for_amule_ready, wait_for_container_log};
use crate::flow::logs::{collect_amule_logs, collect_rmule_logs, collect_server_logs};
use crate::rmule::{RmuleClientContainer, release_held_download};

/// The run root as rmule's container sees it.
const CONTAINER_RUN_ROOT: &str = crate::rmule::CONTAINER_RUN_ROOT;

pub(crate) mod verdict;

pub use self::verdict::score_run_dir;

/// The sharer's upload cap (KiB/s): the held part crosses in seconds.
const SHARER_MAX_UPLOAD_KIB: u32 = 1024;
/// The first file's size: two parts, the sharer holding the first.
const FIRST_FILE_SIZE: u64 = rmule_primitives::ED2K_PART_SIZE + 2_000_000;
/// The second file's size.
const SECOND_FILE_SIZE: u64 = 4 << 20;
/// The second file's fill seed; the first's is [`FIRST_FILE_SEED`].
const SECOND_FILE_SEED: u64 = 0x5EED_0B0B;
const FIRST_FILE_SEED: u64 = 0x5EED_0A0A;
/// How long rmule keeps the first download alone after its part verifies, so
/// its worker has let the slot go and the standing reads as needing nothing.
const SETTLE_SECS: u64 = 20;
/// The gate that adds the second download, under the run root.
const ADD_GATE: &str = "add-second-download";

/// Options for [`run_source_handover`].
pub struct SourceHandoverOptions<'a> {
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
    /// Per-step readiness budget, in seconds; the second download's
    /// completion waits under it, and takes a reask period.
    pub timeout_secs: u64,
    /// Host TCP port the eserver's port is published on.
    pub server_host_port: u16,
    /// The rust image + workspace rmule runs as a client in.
    pub rmule_client_container: &'a RmuleClientContainer,
    /// Extra environment for the sharer (`KEY=VALUE`).
    pub amule_env: &'a [String],
}

/// The staged files and the sharer's two directories.
struct Staged {
    first: StreamFile,
    second: StreamFile,
    temp: std::path::PathBuf,
    incoming: std::path::PathBuf,
}

/// Stage the sharer's part file of the first file and its copy of the second.
fn stage(layout: &RunLayout) -> Result<Staged> {
    let root = layout.root().join(verdict::ROOT_DIR);
    let first = write_stream_file(&root.join("first"), FIRST_FILE_SIZE, FIRST_FILE_SEED)?;
    let second = write_stream_file(&root.join("second"), SECOND_FILE_SIZE, SECOND_FILE_SEED)?;
    let temp = root.join("sharer/temp");
    let incoming = root.join("sharer/incoming");
    fs::create_dir_all(&temp).with_context(|| format!("create {}", temp.display()))?;
    stage_partial_seed(&temp, &first, &[0].into_iter().collect())?;
    stage_complete_seed(&incoming, &second)?;
    Ok(Staged {
        first,
        second,
        temp,
        incoming,
    })
}

/// An address on the sharer's subnet nobody answers at, named beside it in the
/// second link. rmule fails a download at its start when its sole source waits
/// on a standing and no discovery channel is armed (run `1793397391`,
/// `download/runner/fleet.rs`), so the bench holds one dial open past that
/// check. It ends on its own and the sharer never sees it.
fn unanswering_neighbour(sharer: Ipv4Addr) -> Ipv4Addr {
    let [a, b, c, _] = sharer.octets();
    Ipv4Addr::new(a, b, c, 250)
}

/// Run the flow and score it.
///
/// # Errors
/// If a container fails to start, a readiness wait or the second download
/// outlasts the budget, or the verdict cannot be written.
pub fn run_source_handover(options: SourceHandoverOptions<'_>) -> Result<()> {
    let mut bench = Bench::new(
        options.container_runtime,
        options.layout,
        options.keep_containers,
    )?;
    let suffix = options
        .layout
        .root()
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_owned();
    let sharer = format!("rmule-interop-amule-sharer-{suffix}");
    let capture = format!("rmule-interop-handover-capture-{suffix}");
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
    let capture_dir = options.layout.root().join(verdict::ROOT_DIR);
    fs::create_dir_all(&capture_dir)
        .with_context(|| format!("create {}", capture_dir.display()))?;
    let staged = stage(options.layout)?;

    let result = (|| -> Result<()> {
        bench.create_network(options.layout, bench.subnet_for(options.server_image))?;
        bench.start_eserver(
            options.layout,
            &Eserver {
                image: options.server_image,
                host_port: options.server_host_port,
                env: &[],
                timeout,
            },
        )?;
        let container = bench
            .amule_container(options.amule_image, &sharer)
            .env("AMULE_SCENARIO_MODE", "ed2k-server")
            .env("AMULE_TEMP_DIR", SEED_TEMP_MOUNT)
            .volume(&staged.temp, SEED_TEMP_MOUNT)
            .env("AMULE_SHARED_DIR", SEED_INCOMING_MOUNT)
            .volume(&staged.incoming, SEED_INCOMING_MOUNT)
            .env("AMULE_MAX_UPLOAD", SHARER_MAX_UPLOAD_KIB.to_string())
            .env_assignments(options.amule_env);
        bench.start_extra(&sharer, container, "run the sharer aMule")?;
        wait_for_amule_ready(&bench.docker, options.layout, &sharer, timeout, AMULE_READY)?;
        wait_for_share(&bench.docker, &sharer, 2, timeout)?;
        let sharer_ip = run_checked(
            bench.docker.container_ip(sharer.clone()),
            "inspect sharer ip",
        )?;
        let sharer_ip: Ipv4Addr = sharer_ip.trim().parse().context("sharer address")?;

        let rmule_name = bench.names.rmule_container_name.clone();
        run_checked(
            options
                .rmule_client_container
                .prebuild_command(&bench.docker)?,
            "prebuild rmule-tools for the download container",
        )?;
        let first_link = with_sources(&staged.first.link, &[sharer_ip]);
        let second_link = with_sources(
            &staged.second.link,
            &[sharer_ip, unanswering_neighbour(sharer_ip)],
        );
        let download = options
            .rmule_client_container
            .download_start_detached_with_args(
                bench.staging(options.layout),
                &rmule_name,
                &bench.names.server_endpoint(),
                &[first_link.as_str()],
                true,
                &[
                    "--stamp-events".to_owned(),
                    "--add-gate".to_owned(),
                    format!("{CONTAINER_RUN_ROOT}/{ADD_GATE}"),
                    "--add-file".to_owned(),
                    second_link,
                    "--add-out".to_owned(),
                    format!("{CONTAINER_RUN_ROOT}/rmule/{}", verdict::SECOND_COPY),
                ],
            )?;
        bench.start_rmule_container(download, "run rmule download container")?;
        let tap = CaptureSidecar {
            image: options.capture_image,
            name: &capture,
            target_container: &rmule_name,
            interface: DEFAULT_TAP_INTERFACE,
            host_dir: capture_dir.clone(),
            pcap_file: verdict::RMULE_PCAP,
            bpf: &format!("host {sharer_ip}"),
        };
        bench.start_extra(&capture, tap.container(), "run the handover tap")?;
        wait_for_container_log(&bench.docker, &capture, "listening on", timeout)?;
        release_held_download(options.layout)?;
        let rmule_ip = run_checked(
            bench.docker.container_ip(rmule_name.clone()),
            "inspect rmule ip",
        )?;
        verdict::Addresses {
            rmule: rmule_ip.trim().parse().context("rmule address")?,
            sharer: sharer_ip,
        }
        .write(&capture_dir)?;

        wait_for_container_log(
            &bench.docker,
            &rmule_name,
            "download.part_verified",
            timeout,
        )?;
        std::thread::sleep(Duration::from_secs(SETTLE_SECS));
        let gate = options.layout.root().join(ADD_GATE);
        fs::write(&gate, b"").with_context(|| format!("write {}", gate.display()))?;
        println!("peer_source_handover second_download_added");
        wait_for_container_log(
            &bench.docker,
            &rmule_name,
            "download.completed id=2",
            timeout,
        )?;
        collect_rmule_logs(&bench.docker, options.layout, &rmule_name)?;
        collect_amule_logs(&bench.docker, options.layout, &sharer)?;
        collect_server_logs(
            &bench.docker,
            options.layout,
            &bench.names.server_container_name,
        )?;
        Ok(())
    })();

    if result.is_err() {
        bench.collect_failure_logs(options.layout);
        if let Err(error) = collect_amule_logs(&bench.docker, options.layout, &sharer) {
            eprintln!("warning: failed to collect the sharer logs: {error:#}");
        }
    }
    bench.cleanup_best_effort();
    result?;
    let verdict = score_run_dir(options.layout.root())?;
    println!("peer_source_handover verdict={verdict}");
    Ok(())
}
