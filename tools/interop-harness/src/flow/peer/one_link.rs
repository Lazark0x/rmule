//! The **one link, two downloads** flow (ADR-0107, "One peer, one link").
//!
//! One rmule core downloads two files from one stock aMule sharer. aMule holds
//! one client per peer on one socket, and a second connection from the same
//! address and listen port makes it drop the first (`ClientList.cpp:400-403`,
//! the `two-hellos` flow's `same-port` leg; run `1790798382` of
//! `peer-udp-reask-emit --two-downloads` lost its first download to it). With
//! the Peer Link the second download waits on the first's link and rides it
//! once the first lets go, so the sharer meets one connection that carries
//! both files.
//!
//! The sharer is capped so the first file takes a while: the second download
//! is asked for while the first still rides, and has to wait. A tap on rmule's
//! namespace records every TCP segment to and from the sharer's listener; the
//! verdict reads it with both copies and rmule's run log.

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::artifacts::RunLayout;
use crate::flow::bench::{
    AMULE_PEER_TCP_PORT, Bench, CaptureSidecar, DEFAULT_TAP_INTERFACE, Eserver, run_checked,
};
use crate::flow::gate::{wait_for_amule_ready, wait_for_container_log};
use crate::flow::logs::{
    collect_amule_logs, collect_amule_role_logs, collect_rmule_logs, collect_server_logs,
};
use crate::rmule::{DownloadCrypt, RmuleClientContainer, release_held_download};

mod severed;
mod silent;
pub(crate) mod verdict;

pub use self::severed::score_run_dir as score_severed_run_dir;
pub use self::silent::score_run_dir as score_silent_run_dir;
pub use self::verdict::score_run_dir;

/// The sharer's upload-rate cap (KiB/s): slow enough that the first file is
/// still riding the link when the second download asks for the sharer.
const SHARER_MAX_UPLOAD_KIB: &str = "64";
/// How long the silent leg waits, past both completions, for rmule to end its
/// dial to the frozen sharer: more than the 40 s crypt timeout from any start.
const SILENT_DIAL_END_WAIT_SECS: u64 = 120;
/// How long the silent sharer runs, once ready, before it is frozen: aMule
/// offers its shared files to the server on a one-minute publish tick
/// (`SharedFileList.cpp:757-765`, `ED2KREPUBLISHTIME`), so a sharer frozen at
/// once may never have been offered, and the server would not name it.
const SILENT_OFFER_WAIT_SECS: u64 = 65;

/// Options for [`run_peer_one_link`].
pub struct PeerOneLinkOptions<'a> {
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
    /// Per-step readiness budget, in seconds; each download's completion
    /// waits under it.
    pub timeout_secs: u64,
    /// Host TCP port the eserver's port is published on.
    pub server_host_port: u16,
    /// The rust image + workspace rmule runs as a client in.
    pub rmule_client_container: &'a RmuleClientContainer,
    /// Extra environment for the sharer (`KEY=VALUE`).
    pub amule_env: &'a [String],
    /// Stop the sharer this many seconds after rmule's first part assignment,
    /// so its link ends mid-transfer, and watch rmule keep the source instead
    /// of waiting for the downloads (the severed leg).
    pub sever_after_secs: Option<u64>,
    /// The silent leg: a second sharer is frozen once it has offered both
    /// files and rmule dials under `--peer-crypt requested` (verdict
    /// `peer-one-link-silent-verdict.toml`).
    pub silent_sharer: bool,
}

/// Run the flow: the eserver, a High-ID aMule sharer of the two staged files
/// ([`super::stage_reask_emit_files`] with `two_downloads`), and one rmule
/// core downloading both, a tap on its namespace; then score the run.
///
/// # Errors
/// If a container fails to start, a readiness wait or a download outlasts
/// the budget, or the verdict cannot be written.
pub fn run_peer_one_link(options: PeerOneLinkOptions<'_>) -> Result<()> {
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
    let silent = format!("rmule-interop-amule-silent-{suffix}");
    let capture = format!("rmule-interop-one-link-capture-{suffix}");
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
        let links = [
            options.layout.synthetic_ed2k_file(),
            options.layout.synthetic_dir().join(verdict::SECOND_LINK),
        ]
        .iter()
        .map(|path| {
            fs::read_to_string(path)
                .map(|link| link.trim().to_owned())
                .with_context(|| format!("read {}", path.display()))
        })
        .collect::<Result<Vec<_>>>()?;

        // The sharer: High ID on the eserver, so rmule's get-sources names it
        // for both files.
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
        let silent_ip = if options.silent_sharer {
            // Offered both files and logged in, then frozen: the server still
            // names it, its kernel still takes a connect, and nothing answers.
            let silent_container = bench
                .amule_container(options.amule_image, &silent)
                .volume(options.layout.synthetic_dir(), "/incoming")
                .env("AMULE_SHARED_DIR", "/incoming")
                .env("AMULE_MAX_UPLOAD", SHARER_MAX_UPLOAD_KIB)
                .env_assignments(options.amule_env);
            bench.start_extra(&silent, silent_container, "run the silent sharer aMule")?;
            wait_for_amule_ready(
                &bench.docker,
                options.layout,
                &silent,
                timeout,
                "rmule-amule-ready",
            )?;
            let ip = run_checked(
                bench.docker.container_ip(silent.clone()),
                "inspect silent sharer ip",
            )?;
            std::thread::sleep(Duration::from_secs(SILENT_OFFER_WAIT_SECS));
            run_checked(
                bench.docker.pause_container(silent.clone()),
                "freeze the silent sharer",
            )?;
            println!("peer_one_link silent sharer_frozen ip={}", ip.trim());
            Some(ip)
        } else {
            None
        };

        // One rmule core, both downloads, held until the tap listens.
        let rmule_name = bench.names.rmule_container_name.clone();
        run_checked(
            options
                .rmule_client_container
                .prebuild_command(&bench.docker)?,
            "prebuild rmule-tools for the download container",
        )?;
        let link_refs: Vec<&str> = links.iter().map(String::as_str).collect();
        let download = if options.silent_sharer {
            // Stamped records time the dial's end; `requested` obfuscates every
            // dial to an aMule the server names with its User Hash.
            options
                .rmule_client_container
                .download_start_detached_with_args(
                    bench.staging(options.layout),
                    &rmule_name,
                    &bench.names.server_endpoint(),
                    &link_refs,
                    true,
                    &[
                        "--stamp-events".to_owned(),
                        "--peer-crypt".to_owned(),
                        "requested".to_owned(),
                    ],
                )?
        } else if options.sever_after_secs.is_some() {
            // The severed verdict reads stamped records and per-download ticks.
            options
                .rmule_client_container
                .download_start_detached_with_args(
                    bench.staging(options.layout),
                    &rmule_name,
                    &bench.names.server_endpoint(),
                    &link_refs,
                    true,
                    &[
                        "--report-parts-every-ms".to_owned(),
                        "1000".to_owned(),
                        "--stamp-events".to_owned(),
                    ],
                )?
        } else {
            options
                .rmule_client_container
                .download_start_detached_command(
                    bench.staging(options.layout),
                    &rmule_name,
                    &bench.names.server_endpoint(),
                    &link_refs,
                    true,
                    DownloadCrypt {
                        peer_crypt: None,
                        peer_crypt_flip: &[],
                    },
                )?
        };
        bench.start_rmule_container(download, "run rmule download container")?;
        let tap = CaptureSidecar {
            image: options.capture_image,
            name: &capture,
            target_container: &rmule_name,
            interface: DEFAULT_TAP_INTERFACE,
            host_dir: capture_dir.clone(),
            pcap_file: verdict::RMULE_PCAP,
            bpf: &format!("tcp port {AMULE_PEER_TCP_PORT}"),
        };
        bench.start_extra(&capture, tap.container(), "run one-link tcpdump sidecar")?;
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
        if let Some(ip) = &silent_ip {
            silent::SilentAddresses {
                rmule: rmule_ip.trim().parse().context("rmule address")?,
                sharer: sharer_ip.trim().parse().context("sharer address")?,
                silent: ip.trim().parse().context("silent sharer address")?,
            }
            .write(&capture_dir)?;
        }

        if let Some(secs) = options.sever_after_secs {
            wait_for_container_log(
                &bench.docker,
                &rmule_name,
                "download.part_assigned",
                timeout,
            )?;
            std::thread::sleep(Duration::from_secs(secs));
            run_checked(
                bench.docker.stop_container(sharer.clone(), 0),
                "stop the sharer mid-transfer",
            )?;
            println!("peer_one_link severed sharer_stopped_after_secs={secs}");
            std::thread::sleep(Duration::from_secs(severed::WATCH_SECS));
        } else {
            for id in 1..=links.len() {
                wait_for_container_log(
                    &bench.docker,
                    &rmule_name,
                    &format!("download.completed id={id}"),
                    timeout,
                )?;
            }
        }
        if let Some(ip) = &silent_ip {
            // Another cause, or none inside the wait, is the verdict's to read.
            let ended = wait_for_container_log(
                &bench.docker,
                &rmule_name,
                "cause=crypt_unanswered",
                Duration::from_secs(SILENT_DIAL_END_WAIT_SECS),
            )
            .is_ok();
            println!(
                "peer_one_link silent crypt_unanswered_logged={ended} silent={}",
                ip.trim()
            );
            run_checked(
                bench.docker.unpause_container(silent.clone()),
                "thaw the silent sharer",
            )?;
            collect_amule_role_logs(&bench.docker, options.layout, "silent", &silent)?;
        }
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
        // A readiness wait or a completion wait that ran out is the run's
        // most telling moment: what rmule and the sharer logged up to it.
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
    if options.silent_sharer {
        let verdict = silent::score_run_dir(options.layout.root())?;
        println!("peer_one_link silent_verdict={verdict}");
        return Ok(());
    }
    if options.sever_after_secs.is_some() {
        let verdict = severed::score_run_dir(options.layout.root())?;
        println!("peer_one_link severed_verdict={verdict}");
        return Ok(());
    }
    let verdict = score_run_dir(options.layout.root())?;
    println!("peer_one_link verdict={verdict}");
    Ok(())
}
