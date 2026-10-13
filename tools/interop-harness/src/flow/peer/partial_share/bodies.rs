//! The stock aMule bodies of the partial-share flow: the seeds rmule fetches
//! from, in `direct-peer` mode (or on ed2k-server beside rmule) so only
//! rmule's link reaches them, and the
//! downloaders on the eserver that fetch from rmule; and the logs each
//! leaves for the run dir.

use std::fs;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use rmule_primitives::part_count;

use super::verdict::{Body, TopologyFile};
use super::{DOWNLOADER, PartialShareOptions};
use crate::artifacts::RunLayout;
use crate::docker::Docker;
use crate::flow::bench::{Bench, amulecmd_command, run_checked};
use crate::flow::ed2k_server::search_wire::ED2KSRV_IP;
use crate::flow::gate::wait_for_amule_ready;
use crate::flow::logs::collect_rmule_logs;
use crate::flow::peer::streaming_window::seed::{
    STREAM_FILE_NAME, SeedHolding, StreamFile, stage_complete_seed, stage_partial_seed,
};

const SEED_TEMP_MOUNT: &str = "/seed-temp";
const SEED_INCOMING_MOUNT: &str = "/seed-incoming";
const SEED_READY: &str = "rmule-amule-direct-peer-ready";
const DOWNLOADER_READY: &str = "rmule-amule-ready";

/// Start the seed holding `holding` in `direct-peer` mode and hold until
/// it shares the stream file.
#[allow(clippy::too_many_arguments)]
pub(super) fn start_seed(
    bench: &mut Bench,
    options: &PartialShareOptions<'_>,
    root: &Path,
    stream: &StreamFile,
    holding: &SeedHolding,
    cap: u32,
    role: char,
    suffix: &str,
) -> Result<Body> {
    let dir = root.join("seeds").join(role.to_string());
    let (temp, incoming) = (dir.join("temp"), dir.join("incoming"));
    fs::create_dir_all(&temp).with_context(|| format!("create {}", temp.display()))?;
    fs::create_dir_all(&incoming).with_context(|| format!("create {}", incoming.display()))?;
    match holding {
        SeedHolding::Complete => stage_complete_seed(&incoming, stream)?,
        SeedHolding::Partial(_) => {
            stage_partial_seed(&temp, stream, &holding.parts(part_count(options.file_size)))?;
        }
    }
    let name = format!("rmule-interop-amule-seed-{role}-{suffix}");
    let container = bench
        .amule_container(options.amule_image, &name)
        .env(
            "AMULE_SCENARIO_MODE",
            if options.rmule_on_ed2ksrv.is_some() {
                "ed2k-server"
            } else {
                "direct-peer"
            },
        )
        // On ed2k-server the seeds hold a High ID there, which the downloaders'
        // Lugdunum never hears of.
        .env("ED2K_SERVER_HOST", ED2KSRV_IP)
        .env("AMULE_TEMP_DIR", SEED_TEMP_MOUNT)
        .volume(&temp, SEED_TEMP_MOUNT)
        .env("AMULE_SHARED_DIR", SEED_INCOMING_MOUNT)
        .volume(&incoming, SEED_INCOMING_MOUNT)
        .env("AMULE_MAX_UPLOAD", cap.to_string())
        .env_assignments(options.amule_env);
    bench.start_extra(&name, container, "run a seed aMule")?;
    wait_for_amule_ready(
        &bench.docker,
        options.layout,
        &name,
        Duration::from_secs(options.timeout_secs),
        if options.rmule_on_ed2ksrv.is_some() {
            DOWNLOADER_READY
        } else {
            SEED_READY
        },
    )?;
    wait_for_share(
        &bench.docker,
        &name,
        Duration::from_secs(options.timeout_secs),
    )?;
    let ip = run_checked(bench.docker.container_ip(name.clone()), "inspect seed ip")?;
    Ok(Body {
        role: format!("seed-{role}"),
        ip: ip.trim().parse().context("seed address")?,
        container: name,
        detail: format!("{} at {cap} KiB/s", holding.spec()),
    })
}

/// Start the downloader playing `role` on the eserver, with no link yet.
pub(super) fn start_downloader(
    bench: &mut Bench,
    options: &PartialShareOptions<'_>,
    role: &str,
    suffix: &str,
) -> Result<Body> {
    let name = format!("rmule-interop-amule-{role}-{suffix}");
    let cap = if role == DOWNLOADER {
        options.downloader_max_download_kib
    } else {
        0
    };
    let mut container = bench
        .amule_container(options.downloader_image, &name)
        .env("AMULE_SCENARIO_MODE", "ed2k-server")
        .env_assignments(options.amule_env);
    if cap > 0 {
        container = container.env("AMULE_MAX_DOWNLOAD", cap.to_string());
    }
    bench.start_extra(&name, container, &format!("run the {role} aMule"))?;
    wait_for_amule_ready(
        &bench.docker,
        options.layout,
        &name,
        Duration::from_secs(options.timeout_secs),
        DOWNLOADER_READY,
    )?;
    let ip = run_checked(
        bench.docker.container_ip(name.clone()),
        "inspect downloader ip",
    )?;
    Ok(Body {
        role: role.to_owned(),
        ip: ip.trim().parse().context("downloader address")?,
        container: name,
        detail: if cap > 0 {
            format!("download capped at {cap} KiB/s")
        } else {
            "uncapped".to_owned()
        },
    })
}

/// Hold until the seed's `Show shared` lists the stream file.
fn wait_for_share(docker: &Docker, container: &str, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let shared = docker
            .exec(container.to_owned(), amulecmd_command("Show shared"))
            .to_command()
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
            .unwrap_or_default();
        if shared.contains(STREAM_FILE_NAME) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("seed {container} never listed {STREAM_FILE_NAME} as shared");
        }
        thread::sleep(Duration::from_secs(2));
    }
}

/// Logs off every body into the run dir: rmule's trail, each aMule's
/// stdout, logfile and download list, each stimulus's stdout.
pub(super) fn collect(
    docker: &Docker,
    layout: &RunLayout,
    root: &Path,
    topology: &TopologyFile,
) -> Result<()> {
    collect_rmule_logs(docker, layout, &topology.rmule_container)?;
    for body in topology.seeds.iter().chain(&topology.downloaders) {
        let dir = root.join("bodies").join(&body.role);
        fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        let logs = docker.logs(body.container.clone()).to_command().output()?;
        fs::write(dir.join("stdout.log"), &logs.stdout)?;
        let logfile = docker
            .exec(
                body.container.clone(),
                [
                    "sh".into(),
                    "-c".into(),
                    "cat /root/.aMule/logfile 2>/dev/null || true".into(),
                ],
            )
            .to_command()
            .output()?;
        fs::write(dir.join("amule-logfile.log"), &logfile.stdout)?;
        let downloads = docker
            .exec(body.container.clone(), amulecmd_command("Show dl"))
            .to_command()
            .output()?;
        fs::write(dir.join("show-dl.txt"), &downloads.stdout)?;
    }
    for stimulus in &topology.stimuli {
        let dir = root.join("stimulus").join(&stimulus.purpose);
        fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        let logs = docker
            .logs(stimulus.container.clone())
            .to_command()
            .output()?;
        fs::write(dir.join("stdout.log"), &logs.stdout)?;
    }
    Ok(())
}
