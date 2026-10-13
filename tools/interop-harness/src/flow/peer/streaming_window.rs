//! The streaming-window flow (ADR-0112): one Streaming Priority file, held in
//! part by stock aMule seeds, downloaded by rmule.
//!
//! Each partial seed loads a harness-written part file, paused, so it shares
//! exactly the parts it was given and fetches nothing ([`seed`]); a complete
//! seed shares the whole file from Incoming. rmule downloads with a chosen
//! Streaming Window width and prints its positional part map on a tick. A tap
//! on rmule's namespace records every status and request. The verdict
//! ([`verdict`]) holds rmule to ADR-0112: a request names only parts its seed
//! advertised (§4), each seed's first part is very rare else a band part,
//! the window is taken in order, both status forms decode (§1), `NoNeededParts`
//! only once a seed holds nothing we lack (§6) — and it measures the verified
//! prefix over time (§5).
//!
//! Topology: an eserver; one stock aMule per `--seed`, High-ID on it; rmule
//! `ed2k download start --serve` from the `rmule-tools` image, finding the
//! seeds through the server's get-sources (and, with `link_sources`, through
//! the link as well). A run whose seeds leave a part unheld never completes:
//! rmule runs its bounded `hold_secs`, which must outlast twice
//! `FILEREASKTIME` for the wait claim.

mod prefix;
mod replay;
pub(crate) mod seed;
pub(crate) mod verdict;
mod wire;

pub use self::seed::{SeedHolding, default_seeds, seed_holding_arg};
pub use self::verdict::score_run_dir;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use rmule_primitives::part_count;

use crate::artifacts::RunLayout;
use crate::docker::{Docker, RunContainer};
use crate::flow::bench::{
    AMULE_PEER_TCP_PORT, Bench, CaptureSidecar, DEFAULT_TAP_INTERFACE, Eserver, amulecmd_command,
    run_checked,
};
use crate::flow::gate::{wait_for_amule_ready, wait_for_container_log};
use crate::flow::logs::{collect_rmule_logs, collect_server_logs};
use crate::rmule::{RMULE_SERVE_TCP_PORT, hold_image_until_released, release_held_download};

use self::seed::{StreamFile, stage_complete_seed, stage_partial_seed, write_stream_file};
use self::verdict::{RMULE_PCAP, SeedRow, TOPOLOGY_FILE, TopologyFile};

/// The run-dir subdirectory every artifact of this flow lands in.
pub(crate) const ROOT_DIR: &str = "streaming-window";
/// The stream file's xorshift seed.
const STREAM_BYTES_SEED: u64 = 0x5EED_5712;
/// Where a seed's Temp and Incoming dirs are mounted.
const SEED_TEMP_MOUNT: &str = "/seed-temp";
const SEED_INCOMING_MOUNT: &str = "/seed-incoming";
/// The stock image's ready line, printed once it is on the server.
const AMULE_READY: &str = "rmule-amule-ready";
/// How long rmule's download runs past the end the flow waits for.
const RMULE_MARGIN_SECS: u64 = 120;

/// Options for [`run_streaming_window`].
pub struct StreamingWindowOptions<'a> {
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
    /// The seeds' aMule image (stock 2.3.3, or kno's).
    pub amule_image: &'a str,
    /// Build context for the aMule image.
    pub amule_build_context: &'a Path,
    /// Extra environment for every seed (`KEY=VALUE`).
    pub amule_env: &'a [String],
    /// The tcpdump capture-sidecar image.
    pub capture_image: &'a str,
    /// Build context for the capture-sidecar image.
    pub capture_build_context: &'a Path,
    /// The `rmule-tools` image rmule downloads from.
    pub rmule_tools_image: &'a str,
    /// Dockerfile for the `rmule-tools` image.
    pub rmule_tools_dockerfile: &'a Path,
    /// Build context for the `rmule-tools` image.
    pub rmule_tools_build_context: &'a Path,
    /// The stream file's size.
    pub file_size: u64,
    /// One seed per entry, in start order.
    pub seeds: &'a [SeedHolding],
    /// rmule's Streaming Window width `N`.
    pub window_parts: u32,
    /// rmule's peer workers per download; `None` keeps the default.
    pub peer_concurrency: Option<usize>,
    /// Each seed's upload cap, KiB/s, so the prefix grows over minutes.
    pub seed_max_upload_kib: u32,
    /// rmule's part-map tick, in milliseconds.
    pub parts_every_ms: u64,
    /// rmule's bounded run, in seconds.
    pub hold_secs: u64,
    /// Also name every seed as a source in rmule's link.
    pub link_sources: bool,
    /// How long this call waits for rmule's run to end before it returns a
    /// kept run for a later collection; `None` waits the whole `hold_secs`.
    pub wait_secs: Option<u64>,
}

/// Run the streaming-window flow and score it.
///
/// # Errors
/// If a step fails, or rmule's run does not end within the wait and the
/// containers are not kept.
pub fn run_streaming_window(options: StreamingWindowOptions<'_>) -> Result<()> {
    let mut bench = Bench::new(
        options.container_runtime,
        options.layout,
        options.keep_containers,
    )?;
    if options.seeds.is_empty() {
        bail!("a streaming-window run needs at least one seed");
    }
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
    fs::create_dir_all(&root).with_context(|| format!("create {}", root.display()))?;
    let stream = write_stream_file(
        &options.layout.synthetic_dir(),
        options.file_size,
        STREAM_BYTES_SEED,
    )?;
    let parts = part_count(options.file_size);
    let staged = stage_seeds(&root, &stream, options.seeds)?;
    let held: BTreeSet<u32> = options
        .seeds
        .iter()
        .flat_map(|seed| seed.parts(parts))
        .collect();
    let expect_complete = held.len() == parts as usize;
    println!(
        "peer_streaming_window file_size={} parts={parts} window={} seeds={} expect_complete={expect_complete}",
        options.file_size,
        options.window_parts,
        options
            .seeds
            .iter()
            .map(SeedHolding::spec)
            .collect::<Vec<_>>()
            .join(" | ")
    );

    let timeout = Duration::from_secs(options.timeout_secs);
    let suffix = options
        .layout
        .root()
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_owned();
    let rmule = bench.names.rmule_container_name.clone();
    let tap = format!("rmule-interop-streaming-tap-{suffix}");
    let mut finished = false;
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
        let mut rows = Vec::new();
        for seed in &staged {
            let name = format!("rmule-interop-amule-seed-{}-{suffix}", seed.role);
            let container = bench
                .amule_container(options.amule_image, &name)
                .env("AMULE_SCENARIO_MODE", "ed2k-server")
                .env("AMULE_TEMP_DIR", SEED_TEMP_MOUNT)
                .volume(&seed.temp, SEED_TEMP_MOUNT)
                .env("AMULE_SHARED_DIR", SEED_INCOMING_MOUNT)
                .volume(&seed.incoming, SEED_INCOMING_MOUNT)
                .env("AMULE_MAX_UPLOAD", options.seed_max_upload_kib.to_string())
                .env_assignments(options.amule_env);
            bench.start_extra(&name, container, "run a seed aMule")?;
            wait_for_amule_ready(&bench.docker, options.layout, &name, timeout, AMULE_READY)?;
            wait_for_share(&bench.docker, &name, timeout)?;
            let ip = run_checked(bench.docker.container_ip(name.clone()), "inspect seed ip")?;
            println!(
                "peer_streaming_window seed={} ip={} holds={}",
                seed.role,
                ip.trim(),
                seed.holding.spec()
            );
            rows.push(SeedRow {
                role: seed.role.clone(),
                ip: ip.trim().parse().context("seed address")?,
                holding: seed.holding.spec(),
                container: name,
            });
        }

        let link = if options.link_sources {
            with_sources(&stream.link, &rows)
        } else {
            stream.link.clone()
        };
        let download = rmule_download(&bench, &options, &rmule, &link);
        bench.start_rmule_container(
            bench.docker.run_container(download),
            "run the rmule download",
        )?;
        let rmule_ip = run_checked(bench.docker.container_ip(rmule.clone()), "inspect rmule ip")?;
        let topology = TopologyFile {
            file_size: options.file_size,
            file_hash: stream.summary.file_hash().to_hex_upper(),
            window_parts: options.window_parts,
            peer_concurrency: options.peer_concurrency.unwrap_or(0),
            rmule_ip: rmule_ip.trim().parse().context("rmule address")?,
            seeds: rows,
            expect_complete,
            rmule_container: rmule.clone(),
            tap_container: tap.clone(),
        };
        let topology_path = root.join(TOPOLOGY_FILE);
        fs::write(
            &topology_path,
            toml::to_string_pretty(&topology).context("serialize the topology")?,
        )
        .with_context(|| format!("write {}", topology_path.display()))?;

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
        release_held_download(options.layout)?;

        let end = if expect_complete {
            "download finalized"
        } else {
            "download deadline_reached"
        };
        let wait = Duration::from_secs(
            options
                .wait_secs
                .unwrap_or(options.hold_secs + RMULE_MARGIN_SECS),
        );
        if let Err(error) = wait_for_container_log(&bench.docker, &rmule, end, wait) {
            if !options.keep_containers {
                return Err(error.context("rmule's run did not end inside the wait"));
            }
            println!(
                "peer_streaming_window pending: rmule's run is still going; collect and score with \
                 peer-streaming-window-score --run-dir {} --collect",
                options.layout.root().display()
            );
            return Ok(());
        }
        collect(&bench.docker, options.layout, &topology)?;
        collect_server_logs(
            &bench.docker,
            options.layout,
            &bench.names.server_container_name,
        )?;
        finished = true;
        Ok(())
    })();
    bench.cleanup_best_effort();
    result?;
    if finished {
        score_run_dir(options.layout.root())?;
    }
    Ok(())
}

/// Collect a kept run's logs off its still-standing containers, so
/// [`score_run_dir`] can score it.
///
/// # Errors
/// If the topology cannot be read or a log cannot be written.
pub fn collect_kept_run(container_runtime: &str, run_dir: &Path) -> Result<()> {
    let layout = RunLayout::create(run_dir)?;
    let path = run_dir.join(ROOT_DIR).join(TOPOLOGY_FILE);
    let topology: TopologyFile = toml::from_str(
        &fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?,
    )
    .with_context(|| format!("parse {}", path.display()))?;
    collect(&Docker::new(container_runtime), &layout, &topology)
}

/// rmule's log into the run dir's `rmule/`, each seed's stdout and aMule
/// logfile beside its fixture.
fn collect(docker: &Docker, layout: &RunLayout, topology: &TopologyFile) -> Result<()> {
    collect_rmule_logs(docker, layout, &topology.rmule_container)?;
    for seed in &topology.seeds {
        let name = &seed.container;
        let dir = layout.root().join(ROOT_DIR).join("seeds").join(&seed.role);
        let output = docker
            .logs(name.clone())
            .to_command()
            .output()
            .with_context(|| format!("docker logs {name}"))?;
        fs::write(dir.join("stdout.log"), &output.stdout)
            .with_context(|| format!("write {} stdout", seed.role))?;
        let logfile = docker
            .exec(name.clone(), amule_logfile_command())
            .to_command()
            .output()
            .with_context(|| format!("read {name}'s aMule logfile"))?;
        fs::write(dir.join("amule-logfile.log"), &logfile.stdout)
            .with_context(|| format!("write {} logfile", seed.role))?;
    }
    Ok(())
}

fn amule_logfile_command() -> [std::ffi::OsString; 3] {
    [
        "sh".into(),
        "-c".into(),
        "cat /root/.aMule/logfile 2>/dev/null || true".into(),
    ]
}

/// One seed's staged dirs.
struct StagedSeed {
    role: String,
    holding: SeedHolding,
    temp: PathBuf,
    incoming: PathBuf,
}

/// Stage every seed's Temp and Incoming dirs under `root/seeds/<role>`.
fn stage_seeds(root: &Path, stream: &StreamFile, seeds: &[SeedHolding]) -> Result<Vec<StagedSeed>> {
    let parts = part_count(stream.summary.file_size());
    seeds
        .iter()
        .zip('a'..='z')
        .map(|(holding, role)| {
            let dir = root.join("seeds").join(role.to_string());
            let temp = dir.join("temp");
            let incoming = dir.join("incoming");
            fs::create_dir_all(&temp).with_context(|| format!("create {}", temp.display()))?;
            fs::create_dir_all(&incoming)
                .with_context(|| format!("create {}", incoming.display()))?;
            match holding {
                SeedHolding::Complete => stage_complete_seed(&incoming, stream)?,
                SeedHolding::Partial(_) => {
                    stage_partial_seed(&temp, stream, &holding.parts(parts))?;
                }
            }
            Ok(StagedSeed {
                role: role.to_string(),
                holding: holding.clone(),
                temp,
                incoming,
            })
        })
        .collect()
}

/// Hold until the seed's `Show shared` lists the stream file: at start when
/// its `.part.met` date held, after its rehash when it did not.
fn wait_for_share(docker: &Docker, container: &str, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let shared = docker
            .exec(container.to_owned(), amulecmd_command("Show shared"))
            .to_command()
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
            .unwrap_or_default();
        if shared.contains(seed::STREAM_FILE_NAME) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "seed {container} never listed {} as shared; last answer:\n{shared}",
                seed::STREAM_FILE_NAME
            );
        }
        thread::sleep(Duration::from_secs(2));
    }
}

/// The link naming every seed as a source as well.
fn with_sources(link: &str, seeds: &[SeedRow]) -> String {
    let sources: Vec<String> = seeds
        .iter()
        .map(|seed| format!("{}:{AMULE_PEER_TCP_PORT}", seed.ip))
        .collect();
    let body = link.strip_suffix('/').unwrap_or(link);
    format!("{body}|sources,{}|/", sources.join(","))
}

/// rmule's held `ed2k download start --serve`, bounded at `hold_secs`, with
/// the window, the concurrency and the part-map tick.
fn rmule_download(
    bench: &Bench,
    options: &StreamingWindowOptions<'_>,
    name: &str,
    link: &str,
) -> RunContainer {
    let mut args = vec![
        "ed2k".to_owned(),
        "download".to_owned(),
        "start".to_owned(),
        "--data-dir".to_owned(),
        "/w/rmule".to_owned(),
        "--server".to_owned(),
        bench.names.server_endpoint(),
        "--file".to_owned(),
        link.to_owned(),
        "--out".to_owned(),
        "/w/rmule/output.bin".to_owned(),
        "--tcp-port".to_owned(),
        RMULE_SERVE_TCP_PORT.to_string(),
        "--serve".to_owned(),
        "--max-seconds".to_owned(),
        options.hold_secs.to_string(),
        "--streaming-window".to_owned(),
        options.window_parts.to_string(),
        "--report-parts-every-ms".to_owned(),
        options.parts_every_ms.to_string(),
    ];
    if let Some(concurrency) = options.peer_concurrency {
        args.extend(["--peer-concurrency".to_owned(), concurrency.to_string()]);
    }
    args.into_iter().fold(
        hold_image_until_released(
            RunContainer::new(options.rmule_tools_image.to_owned())
                .detach()
                .name(name)
                .network(bench.names.network_name.clone())
                .env("RMULE_LOG", "info")
                .volume(options.layout.root(), "/w"),
            "/w",
        ),
        RunContainer::arg,
    )
}
