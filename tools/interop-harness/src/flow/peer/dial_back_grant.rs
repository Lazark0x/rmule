//! The **dial-back grant** flow (ADR-0057, "A grant by dial-back is taken").
//!
//! A stock aMule uploader promotes a queued downloader it is no longer
//! connected to by dialing its listen port and sending `OP_ACCEPTUPLOADREQ`
//! once the hellos are done (`UploadQueue.cpp:206-210`,
//! `BaseClient.cpp:1707-1716`). If the downloader does not take it, the
//! uploader times the link out after 40 s, drops the client from its upload
//! list without queueing it again, and the next ask starts the wait from zero
//! (`BaseClient.cpp:1278-1281`, `UploadQueue.cpp:501`, `:522-546`).
//!
//! Topology, on the eserver's bridge:
//! 1. The eserver.
//! 2. The **sharer**: a stock aMule sharing rmule's file and the holders'
//!    file, both no compressor shrinks, capped under 10 KB/s so it keeps
//!    `MIN_UP_CLIENTS_ALLOWED` = 2 upload slots (`UploadQueue.cpp:305-313`).
//! 3. Two **slot-holders**: stock aMules that download the holders' file
//!    from the sharer directly and hold both slots, settle-then-idle.
//! 4. **rmule**: `ed2k download start --serve`, High ID, with a tap in its
//!    namespace on both listeners. It finds the sharer through the eserver,
//!    asks, is queued behind the holders, and hangs up: its record waits in
//!    the RemoteQueued stage (`download.source_remote_queued`).
//!
//! Then the flow stops one holder. Its slot frees, and the sharer promotes
//! the one waiter, rmule, by dialing it back. The window that follows is
//! bounded: a grant rmule takes completes the small file inside it, and one
//! it drops leaves the copy unwritten — an observation the verdict scores,
//! not a broken run.

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::artifacts::{Ed2kHashCommand, RunLayout, write_ed2k_link, write_incompressible_file};
use crate::flow::bench::{
    AMULE_PEER_TCP_PORT, Bench, CaptureSidecar, DEFAULT_TAP_INTERFACE, Eserver, run_checked,
};
use crate::flow::gate::{wait_for_amule_ready, wait_for_container_log};
use crate::flow::identity::ed2k_link_with_source;
use crate::flow::logs::{collect_amule_logs, collect_rmule_logs, collect_server_logs};
use crate::rmule::{
    DownloadCrypt, RMULE_SERVE_TCP_PORT, RmuleClientContainer, release_held_download,
};

pub(crate) mod verdict;

pub use self::verdict::score_run_dir;

/// The sharer's upload-rate cap (KiB/s): under 10 KB/s aMule keeps two
/// upload slots whatever the cap, one per holder.
const SHARER_MAX_UPLOAD_KIB: &str = "8";
/// One slot-holder per upload slot the sharer keeps; the first is stopped to
/// free its slot.
const SLOT_HOLDERS: [&str; 2] = ["holder-a", "holder-b"];
/// The holders' file, and its link, beside rmule's.
pub(crate) const HOLDER_FILE: &str = "holder.bin";
pub(crate) const HOLDER_LINK: &str = "holder.ed2k.txt";
/// How long a stopped holder gets to close its link.
const HOLDER_STOP_GRACE_SECS: u64 = 10;

/// Stage the flow's files in the synthetic dir: rmule's `shared.bin` of
/// `rmule_size` bytes and the holders' `holder.bin` of `holder_size`, neither
/// one a compressor shrinks, with their ed2k links hashed by `command`.
///
/// # Errors
/// If a file cannot be written or hashed.
pub fn stage_dial_back_files(
    layout: &RunLayout,
    rmule_size: u64,
    holder_size: u64,
    command: &Ed2kHashCommand,
) -> Result<()> {
    let dir = layout.synthetic_dir();
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    write_incompressible_file(&layout.synthetic_shared_file(), rmule_size, 0x5EED_0B01)?;
    write_ed2k_link(
        command,
        &layout.synthetic_shared_file(),
        &layout.synthetic_ed2k_file(),
    )?;
    let holder = dir.join(HOLDER_FILE);
    write_incompressible_file(&holder, holder_size, 0x5EED_0B02)?;
    write_ed2k_link(command, &holder, &dir.join(HOLDER_LINK))?;
    Ok(())
}

/// Options for [`run_peer_dial_back_grant`].
pub struct PeerDialBackGrantOptions<'a> {
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
    /// Seconds from the holder's stop to the end of the window the grant is
    /// read in.
    pub grant_window_secs: u64,
    /// Host TCP port the eserver's port is published on.
    pub server_host_port: u16,
    /// The rust image + workspace rmule runs as a client in.
    pub rmule_client_container: &'a RmuleClientContainer,
    /// Extra environment for every aMule (`KEY=VALUE`).
    pub amule_env: &'a [String],
}

/// Run the flow and score it.
///
/// # Errors
/// If a container fails to start, a readiness wait outlasts its budget, or
/// the verdict cannot be written. A download that does not complete inside
/// the grant window is scored, not an error.
pub fn run_peer_dial_back_grant(options: PeerDialBackGrantOptions<'_>) -> Result<()> {
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
    let holders: Vec<String> = SLOT_HOLDERS
        .iter()
        .map(|role| format!("rmule-interop-amule-{role}-{suffix}"))
        .collect();
    let capture = format!("rmule-interop-dial-back-capture-{suffix}");
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
        let read_link = |path: &Path| -> Result<String> {
            fs::read_to_string(path)
                .map(|link| link.trim().to_owned())
                .with_context(|| format!("read {}", path.display()))
        };
        let rmule_link = read_link(&options.layout.synthetic_ed2k_file())?;
        let holder_link = read_link(&options.layout.synthetic_dir().join(HOLDER_LINK))?;

        // The sharer: High ID on the eserver, so rmule's get-sources names it.
        let sharer_container = bench
            .amule_container(options.amule_image, &sharer)
            .volume(options.layout.synthetic_dir(), "/incoming")
            .env("AMULE_SHARED_DIR", "/incoming")
            .env("AMULE_MAX_UPLOAD", SHARER_MAX_UPLOAD_KIB)
            .env_assignments(options.amule_env);
        bench.start_extra(&sharer, sharer_container, "run sharer aMule")?;
        wait_for_amule_ready(
            &bench.docker,
            options.layout,
            &sharer,
            timeout,
            "rmule-amule-ready",
        )?;
        let sharer_ip = run_checked(
            bench.docker.container_ip(sharer.clone()),
            "inspect sharer ip",
        )?;

        // The holders dial the sharer straight from their link and take both
        // slots before rmule asks, so rmule is queued.
        let sourced = ed2k_link_with_source(&holder_link, sharer_ip.trim(), AMULE_PEER_TCP_PORT);
        for holder in &holders {
            let holder_container = bench
                .amule_container(options.amule_image, holder)
                .env("AMULE_DOWNLOAD_LINK", sourced.as_str())
                .env("AMULE_EXPECTED_FILE_NAME", HOLDER_FILE)
                .env("AMULE_DOWNLOAD_NO_WAIT", "1")
                .env_assignments(options.amule_env);
            bench.start_extra(holder, holder_container, "run slot-holder aMule")?;
            wait_for_amule_ready(
                &bench.docker,
                options.layout,
                holder,
                timeout,
                "rmule-amule-download-sources-ready",
            )?;
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
            .download_start_detached_command(
                bench.staging(options.layout),
                &rmule_name,
                &bench.names.server_endpoint(),
                &[rmule_link.as_str()],
                true,
                DownloadCrypt {
                    peer_crypt: None,
                    peer_crypt_flip: &[],
                },
            )?;
        bench.start_rmule_container(download, "run rmule download container")?;
        let tap = CaptureSidecar {
            image: options.capture_image,
            name: &capture,
            target_container: &rmule_name,
            interface: DEFAULT_TAP_INTERFACE,
            host_dir: capture_dir.clone(),
            pcap_file: verdict::RMULE_PCAP,
            bpf: &format!("tcp port {AMULE_PEER_TCP_PORT} or tcp port {RMULE_SERVE_TCP_PORT}"),
        };
        bench.start_extra(&capture, tap.container(), "run dial-back tcpdump sidecar")?;
        wait_for_container_log(&bench.docker, &capture, "listening on", timeout)?;
        release_held_download(options.layout)?;
        let rmule_ip = run_checked(
            bench.docker.container_ip(rmule_name.clone()),
            "inspect rmule ip",
        )?;
        verdict::Addresses {
            rmule: rmule_ip.trim().parse().context("rmule address")?,
            sharer: sharer_ip.trim().parse().context("sharer address")?,
        }
        .write(&capture_dir)?;

        // rmule asked, was queued and hung up: its record waits with no
        // worker, so the sharer reaches it only by dialing it.
        wait_for_container_log(
            &bench.docker,
            &rmule_name,
            "download.source_remote_queued",
            timeout,
        )?;
        run_checked(
            bench
                .docker
                .stop_container(holders[0].clone(), HOLDER_STOP_GRACE_SECS),
            "stop the first slot-holder",
        )?;
        println!(
            "peer_dial_back_grant holder_stopped={} rmule_ip={} sharer_ip={}",
            holders[0],
            rmule_ip.trim(),
            sharer_ip.trim()
        );
        // A grant taken completes the file inside the window; one dropped
        // leaves it unwritten, which the verdict reads off the copy.
        let completed = wait_for_container_log(
            &bench.docker,
            &rmule_name,
            "download.completed id=1",
            Duration::from_secs(options.grant_window_secs),
        )
        .is_ok();
        println!("peer_dial_back_grant completed_in_window={completed}");
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
    if options.keep_containers {
        println!("kept_capture_dir={}", capture_dir.display());
    }
    bench.cleanup_best_effort();
    result?;
    let verdict = score_run_dir(options.layout.root())?;
    println!("peer_dial_back_grant verdict={verdict}");
    Ok(())
}
