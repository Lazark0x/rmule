//! The peer-UDP reask **emit** flow (flow L emit-leg, ADR-0057).
//!
//! The mirror of the consume leg with the roles swapped: rmule is the queued
//! downloader and a stock aMule is an uploader whose every slot is held, so a
//! queued rmule must emit its OWN `OP_REASKFILEPING` (`0x90`) on the
//! `FILEREASKTIME` cycle. The window is anchored at rmule's own
//! `OP_QUEUERANKING` receipt so the reask clock starts inside the wait, and a
//! passive tap on rmule's namespace records the result — a zero count is the
//! honest observation that nothing left rmule.
//!
//! **Why rmule queues.** Run `1790793226` did not queue: the synthetic file is
//! `offset % 251`, which zlib takes from 40 MiB to 163 KB, and aMule sends a
//! part compressed when that saves bytes, so its 3 KB/s cap moved the whole
//! file in 54 s; and an uploader capped under 10 KB/s keeps
//! `MIN_UP_CLIENTS_ALLOWED` = 2 slots (`UploadQueue.cpp:303-313`,
//! `Constants.h:56`), so the one slot-holder left rmule the second. The flow
//! now stages files no compressor shrinks and starts two slot-holders; each
//! holds a slot for the window (a holder is kicked after 10 MB or an hour,
//! `UploadQueue.cpp:580-581`; 1.5 KB/s moves 10 MB in about two hours), and
//! neither finishes a 9.28 MB part inside it, so neither is a source rmule
//! can take a part from.

use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::artifacts::RunLayout;
use crate::artifacts::{Ed2kHashCommand, write_ed2k_link, write_incompressible_file};
use crate::flow::bench::{
    AMULE_PEER_TCP_PORT, Bench, CaptureSidecar, DEFAULT_TAP_INTERFACE, Eserver, run_checked,
};
use crate::flow::gate::{sit_tap_window, wait_for_amule_ready, wait_for_container_log};
use crate::flow::identity::{ed2k_link_with_source, parse_ed2k_file_hash};
use crate::flow::logs::{
    collect_amule_logfile, collect_amule_logs, collect_rmule_logs, collect_server_logs,
};
use crate::rmule::{DownloadCrypt, RmuleClientContainer, release_held_download};

mod known_sources;
mod standing;
mod verdict;

pub use self::verdict::score_run_dir;

/// The sharer's upload-rate cap (KiB/s). Under 10 KB/s aMule keeps
/// `MIN_UP_CLIENTS_ALLOWED` = 2 upload slots whatever the cap, so the flow
/// starts [`SLOT_HOLDERS`] downloaders to hold them both; at 3 KB/s the pair
/// takes about 1.5 KB/s each and no holder completes a part in the window.
const SHARER_MAX_UPLOAD_KIB: &str = "3";
/// One slot-holder per upload slot the sharer keeps.
const SLOT_HOLDERS: [&str; 2] = ["holder-a", "holder-b"];
/// The second file of the two-download leg, and its link, beside the
/// synthetic file.
pub(crate) const SECOND_FILE: &str = "second.bin";
pub(crate) const SECOND_LINK: &str = "second.ed2k.txt";

/// Stage this flow's files in the synthetic dir: `shared.bin` (and, for the
/// two-download leg, `second.bin`) of `size` bytes no compressor shrinks, and
/// their ed2k links, hashed by `command`.
///
/// # Errors
/// If a file cannot be written or hashed.
pub fn stage_reask_emit_files(
    layout: &RunLayout,
    size: u64,
    command: &Ed2kHashCommand,
    two_downloads: bool,
) -> Result<()> {
    fs::create_dir_all(layout.synthetic_dir())
        .with_context(|| format!("create {}", layout.synthetic_dir().display()))?;
    write_incompressible_file(&layout.synthetic_shared_file(), size, 0x5EED_0001)?;
    write_ed2k_link(
        command,
        &layout.synthetic_shared_file(),
        &layout.synthetic_ed2k_file(),
    )?;
    if two_downloads {
        let second = layout.synthetic_dir().join(SECOND_FILE);
        write_incompressible_file(&second, size, 0x5EED_0002)?;
        write_ed2k_link(command, &second, &layout.synthetic_dir().join(SECOND_LINK))?;
    }
    Ok(())
}

/// Options for [`run_peer_udp_reask_emit`] (flow L emit-leg).
pub struct PeerUdpReaskEmitOptions<'a> {
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
    /// Host TCP port the eserver's port is published on (the readiness probe target).
    pub server_host_port: u16,
    /// The rust image + workspace rmule runs as a client in.
    pub rmule_client_container: &'a RmuleClientContainer,
    /// Seconds to sit past the queue before harvesting the tap — cover
    /// `FILEREASKTIME` (~1300 s) plus margin.
    pub reask_window_secs: u64,
    /// Extra environment for every aMule container (`KEY=VALUE`).
    pub amule_env: &'a [String],
    /// Run two downloads in the one rmule core, both from the sharer (the
    /// files [`stage_reask_emit_files`] staged with `two_downloads`).
    pub two_downloads: bool,
    /// Give the sharer a source to name: each slot-holder first takes a
    /// complete part from a seeder that is then paused, and only then meets the
    /// sharer (with `two_downloads`, one holder per file). Needs the debug
    /// aMule image.
    pub known_sources: bool,
    /// The policy the downloading rmule starts under (`ed2k download start
    /// --peer-crypt`); `None` leaves obfuscation off.
    pub peer_crypt: Option<&'a str>,
    /// Timed policy flips the downloading rmule applies mid-run, each
    /// `<secs>:<policy>` from its login (`--peer-crypt-flip`).
    pub peer_crypt_flip: &'a [String],
}

/// The peer-UDP **reask EMIT** flow (flow L emit-leg, ADR-0057).
///
/// The mirror of [`super::run_peer_udp_reask`] with the roles swapped: **rmule
/// is the queued downloader** and a stock aMule is an uploader whose every slot
/// is held.
/// With the shared client-UDP socket bound and the Remote-Queued Pool wired, a
/// **queued** rmule downloader must emit its OWN `OP_REASKFILEPING`
/// (`0x90`, `C5 90 …`) toward the uploader on the ~21.4-min `FILEREASKTIME`
/// cycle. This flow stages that and records it.
///
/// Topology (mirror of consume, roles swapped):
/// 1. eserver (published so readiness is a host TCP probe, as in flow C).
/// 2. **Sharer aMule** — shares the synthetic large file (`/incoming`, and the
///    second file in the two-download leg) and is the future uploader.
///    Connected to the eserver it is High-ID (in-network dial-back), so the
///    eserver returns it to rmule's get-sources as a source. Capped at 3 KB/s
///    it keeps aMule's floor of two upload slots.
/// 3. **Two slot-holder aMules** — each downloads the shared file from the
///    sharer (a link with the sharer as its source, which aMule dials
///    directly, plus `AMULE_DOWNLOAD_NO_WAIT=1`), so the pair holds both slots
///    for the whole window; at about 1.5 KB/s each, neither completes a part.
/// 4. **rmule downloader** — a detached, unbounded `download start --serve`
///    against the eserver. `--serve` binds the inbound listener so the eserver's
///    dial-back makes rmule **High-ID**; rmule finds the sharer via **server
///    get-sources** (its `--file` is the plain synthetic link — the runner's
///    candidate pool is server-sourced, ADR-0030), dials it, and is held
///    **queued** behind the slot-holders. With `two_downloads` the one core
///    runs a second download of the second file from the same sharer. It enters the Remote-Queued Pool, whose
///    server-High-ID-gated sweep UDP-pings on the `FILEREASKTIME` clock. It stays
///    running the whole window.
/// 5. A passive tcpdump on **rmule's own** network namespace records every
///    tcp+udp datagram across the window to `emit-reask.pcap` (the eserver leg
///    included: the UDP reask is server-High-ID-standing-gated, so rmule's
///    server-connection state at due-time is itself evidence).
///
/// The window is anchored at rmule's own `OP_QUEUERANKING` receipt (`download
/// peer_queued`), so the reask clock starts inside the wait and the ~21.4-min
/// `0x90` lands in the capture. The captured fact is the ADR-0045 evidence either
/// way: if rmule emits, the tap shows a `0x90` rmule → sharer (and the sharer's
/// `0x91`/`0x92`/`0x93` reply back), and the collected rmule log shows
/// `source_remote_queued` (Remote-Queued Pool standing) plus, on a reply,
/// `source_reask_acked`. A zero count is the honest observation that no peer-UDP
/// reask left rmule.
///
/// This is the **capture-bearing** slice's live attempt. It is **CLI/sweep-only**
/// (the ~25-min wall-clock wait keeps it out of the `RMULE_BENCH` fast suite).
pub fn run_peer_udp_reask_emit(options: PeerUdpReaskEmitOptions<'_>) -> Result<()> {
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
    let capture = format!("rmule-interop-emit-capture-{suffix}");
    let seeder = format!("rmule-interop-amule-seeder-{suffix}");

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
    let capture_dir = options.layout.root().join("emit-reask-capture");
    fs::create_dir_all(&capture_dir)
        .with_context(|| format!("create {}", capture_dir.display()))?;

    let result = (|| -> Result<()> {
        let subnet = super::udp_reask::crypt_subnet(options.peer_crypt, options.peer_crypt_flip)?;
        bench.create_network(options.layout, subnet.as_deref())?;
        // eserver (published so readiness is a host TCP probe, as in flow C).
        bench.start_eserver(
            options.layout,
            &Eserver {
                image: options.server_image,
                host_port: options.server_host_port,
                env: &[],
                timeout,
            },
        )?;

        // The plain links; the second file's only in the two-download leg.
        let plain_link = fs::read_to_string(options.layout.synthetic_ed2k_file())
            .with_context(|| format!("read {}", options.layout.synthetic_ed2k_file().display()))?;
        let mut links = vec![plain_link.trim().to_owned()];
        if options.two_downloads {
            let second = options.layout.synthetic_dir().join(SECOND_LINK);
            let link = fs::read_to_string(&second)
                .with_context(|| format!("read {}", second.display()))?;
            links.push(link.trim().to_owned());
        }
        // One holder per file in the known-sources two-download leg, so the
        // sharer has a source to name for each; otherwise both hold the first.
        let holder_links: Vec<(String, String)> = holders
            .iter()
            .enumerate()
            .map(|(index, holder)| {
                let link = if options.known_sources && options.two_downloads {
                    &links[index % links.len()]
                } else {
                    &links[0]
                };
                (holder.clone(), link.clone())
            })
            .collect();
        let debug_sources: &[(&str, &str)] = if options.known_sources {
            &[known_sources::DEBUG_SOURCES]
        } else {
            &[]
        };

        if options.known_sources {
            let seeder_ip = known_sources::start_seeder(
                &mut bench,
                options.amule_image,
                &seeder,
                options.layout,
                options.amule_env,
                timeout,
            )?;
            for (holder, link) in &holder_links {
                let holder_container = bench
                    .amule_container(options.amule_image, holder)
                    .env(
                        "AMULE_DOWNLOAD_LINK",
                        known_sources::sourced(link, &seeder_ip),
                    )
                    .env("AMULE_DOWNLOAD_NO_WAIT", "1")
                    .env("AMULE_MAX_DOWNLOAD", known_sources::HOLDER_MAX_DOWNLOAD_KIB)
                    .env(
                        known_sources::DEBUG_SOURCES.0,
                        known_sources::DEBUG_SOURCES.1,
                    )
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
            for line in
                known_sources::wait_for_parts_then_pause_seeder(&bench, &holders, &seeder, timeout)?
            {
                println!("peer_udp_reask_emit holder_part {line}");
            }
        }

        // Sharer: shares the staged files at 3 KB/s, which keeps two upload
        // slots. Connected to the eserver it is High-ID, so rmule's get-sources
        // learns it as a source.
        let sharer_container = debug_sources.iter().fold(
            bench
                .amule_container(options.amule_image, &sharer)
                .volume(options.layout.synthetic_dir(), "/incoming")
                .env("AMULE_SHARED_DIR", "/incoming")
                .env("AMULE_MAX_UPLOAD", SHARER_MAX_UPLOAD_KIB),
            |container, (key, value)| container.env(*key, *value),
        );
        let sharer_container = sharer_container.env_assignments(options.amule_env);
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

        if options.known_sources {
            known_sources::point_holders_at_sharer(&bench, &holder_links, sharer_ip.trim())?;
        } else {
            // The link with the sharer as its source: each slot-holder aMule
            // dials that source directly (aMule honors link sources) to grab
            // the slot. rmule instead finds the sharer via the eserver, so its
            // own `--file` stays the plain synthetic link (the runner's
            // candidate pool is server-sourced).
            let sourced = ed2k_link_with_source(&links[0], sharer_ip.trim(), AMULE_PEER_TCP_PORT);
            // Slot-holders: each downloads from the sharer and holds one of its
            // two slots for the whole window (settle-then-idle; the slot stays
            // occupied).
            for holder in &holders {
                let holder_container = bench
                    .amule_container(options.amule_image, holder)
                    .env("AMULE_DOWNLOAD_LINK", sourced.as_str())
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
        }

        // rmule downloader: detached + unbounded + `--serve` (High-ID). It finds
        // the sharer via server get-sources, is held queued behind the
        // slot-holders, and runs the Remote-Queued Pool reask cycle for the
        // whole window; with two downloads, for both files.
        let link_refs: Vec<&str> = links.iter().map(String::as_str).collect();
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
                &link_refs,
                true,
                DownloadCrypt {
                    peer_crypt: options.peer_crypt,
                    peer_crypt_flip: options.peer_crypt_flip,
                },
            )?;
        bench.start_rmule_container(download, "run rmule download container")?;

        // Passive tap on rmule's own netns: every serve-TCP + UDP datagram, AND
        // the eserver leg (port 4661) — the reask sweep only UDP-pings while rmule
        // holds a server-High-ID standing (ADR-0057), so rmule's server-connection
        // state at due-time is itself evidence.
        let tap = CaptureSidecar {
            image: options.capture_image,
            name: &capture,
            target_container: &rmule_name,
            interface: DEFAULT_TAP_INTERFACE,
            host_dir: capture_dir.clone(),
            pcap_file: "emit-reask.pcap",
            bpf: "tcp or udp",
        };
        bench.start_extra(&capture, tap.container(), "run emit-reask tcpdump sidecar")?;
        // The download container holds rmule-tools until now: the prebuilt
        // binary logs in and dials within a second, and the verdict's keys
        // are read off that first plaintext.
        wait_for_container_log(&bench.docker, &capture, "listening on", timeout)?;
        release_held_download(options.layout)?;

        let rmule_ip = run_checked(
            bench
                .docker
                .container_ip(bench.names.rmule_container_name.clone()),
            "inspect rmule ip",
        )?;

        // Anchor the window at rmule's own OP_QUEUERANKING receipt: `download
        // peer_queued` means the sharer queued rmule, so the reask clock has
        // started and the ~21.4-min FILEREASKTIME 0x90 lands inside the wait.
        wait_for_container_log(
            &bench.docker,
            &bench.names.rmule_container_name,
            "download.peer_queued",
            timeout,
        )?;
        println!(
            "peer_udp_reask_emit rmule_queued_by_sharer=true rmule_ip={} sharer_ip={}",
            rmule_ip.trim(),
            sharer_ip.trim()
        );

        // Sit the FILEREASKTIME window. The tap records whatever rmule emits toward
        // the sharer; the operator lets the CLI run.
        sit_tap_window(
            "peer_udp_reask_emit",
            Duration::from_secs(options.reask_window_secs),
        );

        // Harvest, source/dest swapped from consume: rmule → sharer is the 0x90
        // reask evidence; sharer → rmule is the 0x91/0x92/0x93 answer evidence.
        // Zero on the first ⇒ no peer-UDP reask left rmule.
        let reask_out = run_checked(
            bench.docker.exec(
                capture.clone(),
                [
                    OsString::from("sh"),
                    OsString::from("-c"),
                    // Count only `OP_REASKFILEPING` datagrams — client-UDP
                    // eD2k protocol byte `0xC5` + opcode `0x90` at the payload
                    // head — so a non-zero count proves a reask, not just any
                    // UDP toward the sharer.
                    OsString::from(format!(
                        "tcpdump -nr {} 'udp and src host {} and dst host {} and udp[8] = 0xc5 and udp[9] = 0x90' 2>/dev/null | wc -l",
                        tap.pcap_path(),
                        rmule_ip.trim(),
                        sharer_ip.trim()
                    )),
                ],
            ),
            "count rmule 0x90 reasks toward sharer",
        )?;
        let reask_answers = run_checked(
            bench.docker.exec(
                capture.clone(),
                [
                    OsString::from("sh"),
                    OsString::from("-c"),
                    OsString::from(format!(
                        "tcpdump -nr {} 'udp and src host {} and dst host {}' 2>/dev/null | wc -l",
                        tap.pcap_path(),
                        sharer_ip.trim(),
                        rmule_ip.trim()
                    )),
                ],
            ),
            "count sharer udp toward rmule",
        )?;

        // rmule's own queue-standing evidence (rmule events): the pool entry
        // and, on a reply, the acked rank.
        let rmule_log = collect_rmule_logs(
            &bench.docker,
            options.layout,
            &bench.names.rmule_container_name,
        )?;
        let remote_queued = rmule_log.contains("source_remote_queued");
        let reask_acked = rmule_log.contains("source_reask_acked");
        if !options.peer_crypt_flip.is_empty() {
            println!(
                "peer_udp_reask_emit obfuscation_flips={}",
                crate::flow::evidence::toml_strings(&crate::flow::evidence::obfuscation_flips(
                    &rmule_log
                ))
            );
        }
        println!(
            "peer_udp_reask_emit result reask_udp_datagrams={} answer_udp_datagrams={} \
             source_remote_queued={remote_queued} source_reask_acked={reask_acked} \
             (reask_udp_datagrams counts 0xC5/0x90 only: 0 ⇒ no OP_REASKFILEPING left rmule, \
             >0 ⇒ a genuine reask did)",
            reask_out.trim(),
            reask_answers.trim()
        );

        // Persist the counterparties' own logs before teardown: the sharer's
        // upload-queue lifecycle is the counterparty side of the evidence the pcap
        // alone can't show. (Every aMule writes the one amule log slot; the sharer
        // is collected last so its queue state wins — `--keep-containers` retains
        // every container for full inspection.)
        if options.known_sources {
            let files = links
                .iter()
                .zip(["shared.bin", SECOND_FILE])
                .map(|(link, name)| Ok((name.to_owned(), known_sources::link_hash(link)?)))
                .collect::<Result<Vec<_>>>()?;
            let routing = known_sources::reask_routing(
                &capture_dir.join("emit-reask.pcap"),
                rmule_ip.trim().parse().context("rmule address")?,
                sharer_ip.trim().parse().context("sharer address")?,
                &files,
            )?;
            fs::write(capture_dir.join("reask-routing.txt"), &routing)
                .context("write reask-routing.txt")?;
            println!("peer_udp_reask_emit reask_routing\n{routing}");
            for (role, container) in holders
                .iter()
                .map(|holder| (holder.as_str(), holder.as_str()))
                .chain([("sharer", sharer.as_str())])
            {
                collect_amule_logfile(&bench.docker, options.layout, role, container);
            }
        }
        for holder in &holders {
            collect_amule_logs(&bench.docker, options.layout, holder)?;
        }
        collect_amule_logs(&bench.docker, options.layout, &sharer)?;
        collect_server_logs(
            &bench.docker,
            options.layout,
            &bench.names.server_container_name,
        )?;

        // Score the retained tap: the verdict file is what a re-score reads.
        verdict::write(
            options.layout.root(),
            &verdict::EmitRun {
                pcap: &capture_dir.join("emit-reask.pcap"),
                rmule: rmule_ip.trim().parse().context("rmule address")?,
                sharer: sharer_ip.trim().parse().context("sharer address")?,
                file_hash: parse_ed2k_file_hash(&links[0])?,
                file_size: fs::metadata(options.layout.synthetic_shared_file())
                    .context("stat the shared file")?
                    .len(),
                crypt: options.peer_crypt.is_some(),
                flips: super::udp_reask::tap::Flip::read_run_dir(options.layout.root()),
            },
        )?;
        // Two downloads queued at one sharer: the peer is asked once a cycle,
        // not once per download (ADR-0107, "One peer, one queue standing").
        if options.two_downloads {
            standing::write(
                options.layout.root(),
                &standing::StandingRun {
                    pcap: &capture_dir.join("emit-reask.pcap"),
                    rmule: rmule_ip.trim().parse().context("rmule address")?,
                    sharer: sharer_ip.trim().parse().context("sharer address")?,
                },
            )?;
        }
        Ok(())
    })();

    if options.keep_containers {
        println!("kept_capture_dir={}", capture_dir.display());
    }
    bench.cleanup_best_effort();
    result
}
