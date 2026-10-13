//! The partial-share flow (ADR-0113, with ADR-0115's completion move): rmule
//! serves a download in progress to stock aMule.
//!
//! Topology: an eserver (Lugdunum); one stock aMule per `--seed` in
//! `direct-peer` mode, on no server, so it is reached only through the
//! sources rmule's link names and no downloader can find it but through
//! rmule; rmule `ed2k download start --serve` of the stream file from the
//! `rmule-tools` image, a tap on its namespace; and stock aMule downloaders
//! on the eserver (High ID, which their UDP reask needs), each given the
//! file by a link naming rmule as its only source and carrying no hash set,
//! so they ask rmule for it. The harness adds each link when its claim
//! wants it — the prober's before rmule holds a part, the downloader's once
//! it does, the queued one's once the downloader holds rmule's one slot —
//! and drives the rest by gate files rmule watches (pause, stop) and by
//! `rmule-tools peer transfer capture` stimuli for the asks stock aMule
//! never makes (a slot ask of a source with no part it needs, a request
//! straddling the Verified Range). A restart is a second leg in the same
//! rmule container, `ed2k download reopen`, so rmule's address and the tap
//! outlive it. The verdict ([`verdict`]) is scored from the run dir alone.

mod bodies;
mod drive;
mod legs;
mod marks;
pub(crate) mod verdict;
mod wire;

pub use self::verdict::score_run_dir;

use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rmule_primitives::{FileHashSummary, part_count};

use crate::artifacts::{RunLayout, write_incompressible_file};
use crate::docker::RunContainer;
use crate::flow::bench::{
    AMULE_PEER_TCP_PORT, Bench, CaptureSidecar, DEFAULT_TAP_INTERFACE, Eserver, run_checked,
};
use crate::flow::gate::wait_for_container_log;
use crate::flow::logs::{collect_rmule_logs, collect_server_logs};
use crate::flow::peer::streaming_window::seed::{STREAM_FILE_NAME, SeedHolding, write_stream_file};
use crate::rmule::RMULE_SERVE_TCP_PORT;

use self::bodies::{collect, start_downloader, start_seed};
use self::drive::Drive;
use self::legs::{Legs, RUN_MOUNT};
use self::verdict::{Knobs, RMULE_PCAP, ROOT_DIR, TOPOLOGY_FILE, TopologyFile};

/// The whole file rmule shares beside the download, under the share dir.
pub(crate) const WHOLE_FILE_NAME: &str = "beside.bin";
/// The downloader that takes rmule's slot.
pub(crate) const DOWNLOADER: &str = "downloader";
/// The downloader that asks before rmule holds a part.
const PROBER: &str = "prober";
/// The downloader held in rmule's queue behind the first.
const QUEUED: &str = "queued";
/// The downloader that fetches the whole file rmule shares beside the
/// partial: rmule's complete-form status, count `0`.
const WHOLE_PROBER: &str = "whole-prober";
const STREAM_BYTES_SEED: u64 = 0x5EED_0545;
const WHOLE_BYTES_SEED: u64 = 0x5EED_B5DE;

/// Options for [`run_partial_share`].
pub struct PartialShareOptions<'a> {
    /// The run dir every artifact is written under.
    pub layout: &'a RunLayout,
    /// The Docker-compatible CLI to invoke.
    pub container_runtime: &'a str,
    /// Build the eserver, aMule and capture images first.
    pub build_images: bool,
    /// Reuse the `rmule-tools` image as it is.
    pub skip_build: bool,
    /// Leave the containers and network running after the run.
    pub keep_containers: bool,
    /// Per-step readiness budget, in seconds.
    pub timeout_secs: u64,
    /// The eserver image.
    pub server_image: &'a str,
    /// Build context for the eserver image.
    pub server_build_context: &'a Path,
    /// Host TCP port the eserver's port is published on.
    pub server_host_port: u16,
    /// The seeds' image (stock aMule 2.3.3).
    pub amule_image: &'a str,
    /// Build context for the aMule image.
    pub amule_build_context: &'a Path,
    /// Extra environment for every aMule (`KEY=VALUE`).
    pub amule_env: &'a [String],
    /// The downloaders' image: stock 2.3.3, or kno's.
    pub downloader_image: &'a str,
    /// The tcpdump capture-sidecar image.
    pub capture_image: &'a str,
    /// Build context for the capture-sidecar image.
    pub capture_build_context: &'a Path,
    /// The `rmule-tools` image rmule and the stimuli run from.
    pub rmule_tools_image: &'a str,
    /// Dockerfile for the `rmule-tools` image.
    pub rmule_tools_dockerfile: &'a Path,
    /// Build context for the `rmule-tools` image.
    pub rmule_tools_build_context: &'a Path,
    /// The stream file's size.
    pub file_size: u64,
    /// The whole file shared beside the download; `0` for none.
    pub whole_size: u64,
    /// One seed per entry.
    pub seeds: &'a [SeedHolding],
    /// The seeds' upload caps, KiB/s: one for all, or one per seed.
    pub seed_max_upload_kib: &'a [u32],
    /// The slot-holding downloader's download cap, KiB/s; `0` for none.
    pub downloader_max_download_kib: u32,
    /// rmule's egress to the slot-holding downloader, kbit/s; `0` unshaped.
    pub downloader_link_kbit: u32,
    /// Let rmule's download dial the downloaders it serves; unset, those
    /// dials are dropped on rmule's link.
    pub dial_downloaders: bool,
    /// rmule's peer workers per download; `None` keeps the core's.
    pub peer_concurrency: Option<usize>,
    /// Add the prober before rmule's first part.
    pub prober: bool,
    /// Give rmule one slot and queue a second downloader behind the first.
    pub queued: bool,
    /// Pause rmule's download once the downloader is receiving.
    pub pause: bool,
    /// Restart rmule, its download paused, once the queued downloader has
    /// reasked (or the pause has held a while).
    pub restart: bool,
    /// Restart rmule once the download has completed and the run has served
    /// on, so the reopened node's first pass over the download directory
    /// rules the finished file.
    pub reopen_after_completion: bool,
    /// Run the stimuli: the pre-part slot ask, the straddle, the ask during
    /// the Offer Check.
    pub straddle: bool,
    /// The downloader's link goes out once rmule holds this many parts.
    pub ask_after_verified: usize,
    /// How long after the downloader's slot the pause gate is written.
    pub pause_after_secs: u64,
    /// How long after the queued downloader was queued the run waits for its
    /// reask before going on.
    pub reask_wait_secs: u64,
    /// How long the run serves on once the download has completed.
    pub linger_secs: u64,
    /// rmule's second leg, in seconds.
    pub reopen_secs: u64,
}

/// Run the partial-share flow and score it.
///
/// # Errors
/// If a step fails or a wait runs out.
pub fn run_partial_share(options: PartialShareOptions<'_>) -> Result<()> {
    if options.seeds.is_empty() {
        bail!("a partial-share run needs at least one seed");
    }
    if options.restart && !options.pause {
        bail!("--restart restarts rmule with its download paused: it needs --pause");
    }
    if part_count(options.file_size) < 2 {
        bail!("the stream file must span more than one part to be a Served Download");
    }
    let caps: Vec<u32> = match options.seed_max_upload_kib {
        [cap] => vec![*cap; options.seeds.len()],
        caps if caps.len() == options.seeds.len() => caps.to_vec(),
        caps => bail!(
            "{} upload caps for {} seeds",
            caps.len(),
            options.seeds.len()
        ),
    };
    let mut bench = Bench::new(
        options.container_runtime,
        options.layout,
        options.keep_containers,
    )?;
    if options.build_images {
        bench.build_image("server", options.server_image, options.server_build_context)?;
        bench.build_image("aMule", options.amule_image, options.amule_build_context)?;
        bench.build_image(
            "capture",
            options.capture_image,
            options.capture_build_context,
        )?;
    }
    if !options.skip_build {
        bench.build_rmule_tools_image(
            options.rmule_tools_image,
            options.rmule_tools_dockerfile,
            options.rmule_tools_build_context,
        )?;
    }
    let root = options.layout.root().join(ROOT_DIR);
    for dir in [
        legs::DATA_DIR,
        legs::TEMP_DIR,
        legs::INCOMING_DIR,
        legs::SHARE_DIR,
        "gates",
    ] {
        fs::create_dir_all(root.join(dir)).with_context(|| format!("create {dir}"))?;
    }
    let stream = write_stream_file(
        &options.layout.synthetic_dir(),
        options.file_size,
        STREAM_BYTES_SEED,
    )?;
    let whole = (options.whole_size > 0)
        .then(|| {
            write_whole(
                &root.join(legs::SHARE_DIR).join(WHOLE_FILE_NAME),
                options.whole_size,
            )
        })
        .transpose()?;
    let suffix = options
        .layout
        .root()
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_owned();
    let timeout = Duration::from_secs(options.timeout_secs);
    let rmule = bench.names.rmule_container_name.clone();
    let tap = format!("rmule-interop-partial-tap-{suffix}");
    let mut topology = TopologyFile {
        file_name: STREAM_FILE_NAME.to_owned(),
        file_size: options.file_size,
        file_hash: stream.summary.file_hash().to_hex_upper(),
        part_hashes: stream
            .summary
            .part_hash_set()
            .map(|set| {
                set.hashes()
                    .iter()
                    .map(|hash| hash.to_hex_upper())
                    .collect()
            })
            .unwrap_or_default(),
        whole_size: options.whole_size,
        whole_hash: whole
            .as_ref()
            .map(|summary| summary.file_hash().to_hex_upper()),
        rmule_ip: Ipv4Addr::UNSPECIFIED,
        rmule_container: rmule.clone(),
        tap_container: tap.clone(),
        seeds: Vec::new(),
        downloaders: Vec::new(),
        stimuli: Vec::new(),
        actions: Vec::new(),
        knobs: Knobs {
            prober: options.prober,
            queued: options.queued,
            pause: options.pause,
            restart: options.restart,
            straddle: options.straddle,
            dial_downloaders: options.dial_downloaders,
            downloader_image: options.downloader_image.to_owned(),
        },
    };
    println!(
        "peer_partial_share file_size={} parts={} seeds={} queued={} pause={} restart={}",
        options.file_size,
        part_count(options.file_size),
        options
            .seeds
            .iter()
            .map(SeedHolding::spec)
            .collect::<Vec<_>>()
            .join(" | "),
        options.queued,
        options.pause,
        options.restart
    );
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
        for ((holding, cap), role) in options.seeds.iter().zip(&caps).zip('a'..='z') {
            let body = start_seed(
                &mut bench, &options, &root, &stream, holding, *cap, role, &suffix,
            )?;
            topology.seeds.push(body);
        }
        let mut roles = vec![DOWNLOADER];
        if options.prober {
            roles.insert(0, PROBER);
        }
        if options.queued {
            roles.push(QUEUED);
        }
        if options.prober && options.whole_size > 0 && !options.pause {
            roles.push(WHOLE_PROBER);
        }
        for role in roles {
            topology
                .downloaders
                .push(start_downloader(&mut bench, &options, role, &suffix)?);
        }
        let seed_sources: Vec<String> = topology
            .seeds
            .iter()
            .map(|seed| format!("{}:{AMULE_PEER_TCP_PORT}", seed.ip))
            .collect();
        let rmule_link = link(STREAM_FILE_NAME, &stream.summary, &seed_sources);
        let container_root = format!("{RUN_MOUNT}/{ROOT_DIR}");
        let server = bench.names.server_endpoint();
        let rmule_legs = Legs {
            root: &container_root,
            server: &server,
            link: &rmule_link,
            file_name: STREAM_FILE_NAME,
            whole: whole.is_some().then_some(WHOLE_FILE_NAME),
            whole_after_pause: options.pause,
            upload_slots: options.queued.then_some(1),
            peer_concurrency: options.peer_concurrency,
            pause: options.pause,
            restart: options.restart || options.reopen_after_completion,
            hold_secs: 3 * 3600,
            reopen_secs: options.reopen_secs,
            shaped: match options.downloader_link_kbit {
                0 => None,
                kbit => Some((drive::body_ip(&topology, DOWNLOADER)?, kbit)),
            },
            undialled: if options.dial_downloaders {
                Vec::new()
            } else {
                topology.downloaders.iter().map(|body| body.ip).collect()
            },
        };
        let container = RunContainer::new(options.rmule_tools_image.to_owned())
            .detach()
            .name(&rmule)
            .network(bench.names.network_name.clone())
            .env("RMULE_LOG", "info")
            .volume(options.layout.root(), RUN_MOUNT)
            .cap_add("NET_ADMIN")
            .entrypoint("sh")
            .arg("-c")
            .arg(rmule_legs.script());
        bench.start_rmule_container(bench.docker.run_container(container), "run rmule's legs")?;
        topology.rmule_ip =
            run_checked(bench.docker.container_ip(rmule.clone()), "inspect rmule ip")?
                .trim()
                .parse()
                .context("rmule address")?;
        write_topology(&root, &topology)?;
        let sidecar = CaptureSidecar {
            image: options.capture_image,
            name: &tap,
            target_container: &rmule,
            interface: DEFAULT_TAP_INTERFACE,
            host_dir: root.clone(),
            pcap_file: RMULE_PCAP,
            bpf: "tcp or udp",
        };
        bench.start_extra(&tap, sidecar.container(), "run the rmule tap")?;
        wait_for_container_log(&bench.docker, &tap, "listening on", timeout)?;
        fs::write(root.join(legs::START_GATE), b"").context("write rmule's start gate")?;

        let drive = Drive {
            options: &options,
            root: &root,
            rmule: &rmule,
            suffix: &suffix,
            timeout,
            peer_link: link(
                STREAM_FILE_NAME,
                &stream.summary,
                &[format!("{}:{RMULE_SERVE_TCP_PORT}", topology.rmule_ip)],
            ),
            whole_link: whole.as_ref().map(|summary| {
                link(
                    WHOLE_FILE_NAME,
                    summary,
                    &[format!("{}:{RMULE_SERVE_TCP_PORT}", topology.rmule_ip)],
                )
            }),
        };
        let outcome = drive.run(&mut bench, &mut topology);
        write_topology(&root, &topology)?;
        outcome?;
        collect(&bench.docker, options.layout, &root, &topology)?;
        collect_server_logs(
            &bench.docker,
            options.layout,
            &bench.names.server_container_name,
        )?;
        Ok(())
    })();
    if result.is_err() {
        bench.collect_failure_logs(options.layout);
        let _ = collect_rmule_logs(&bench.docker, options.layout, &rmule);
    }
    bench.cleanup_best_effort();
    result?;
    let verdict = score_run_dir(options.layout.root())?;
    println!("peer_partial_share verdict={verdict}");
    Ok(())
}

/// A file link with no hash set, naming `sources` in aMule's tail form.
fn link(name: &str, summary: &FileHashSummary, sources: &[String]) -> String {
    format!(
        "ed2k://|file|{name}|{}|{}|/|sources,{}|/",
        summary.file_size(),
        summary.file_hash().to_hex_upper(),
        sources.join(",")
    )
}

/// Write the whole file shared beside the download and hash it.
fn write_whole(path: &Path, size: u64) -> Result<FileHashSummary> {
    write_incompressible_file(path, size, WHOLE_BYTES_SEED)?;
    let file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    FileHashSummary::digest_reader(file).with_context(|| format!("hash {}", path.display()))
}

fn write_topology(root: &Path, topology: &TopologyFile) -> Result<()> {
    let path = root.join(TOPOLOGY_FILE);
    fs::write(
        &path,
        toml::to_string_pretty(topology).context("serialize the topology")?,
    )
    .with_context(|| format!("write {}", path.display()))
}
