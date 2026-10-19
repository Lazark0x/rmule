//! The **reciprocity** flow (ADR-0116): a queued stock aMule uploader that
//! honours credits, in two legs.
//!
//! **Credit** — the upload preference and what it buys. Topology, on the
//! eserver's bridge: the **sharer** S, a stock aMule sharing rmule's file,
//! held to two slots by two **holders** and with two **waiters** queued ahead
//! of rmule; **rmule**, High ID, downloading S's file and sharing a gift file
//! with one upload slot; **X**, a stock aMule holding that slot; **W**, a stock
//! aMule queued at rmule first. Then S asks rmule for the gift too, and X
//! stops: rmule's freed slot goes to S, whose queue it stands in, ahead of W,
//! which waited longer — inside the Reciprocity Factor of 18/7. Once S holds
//! the gift, its credit for rmule is aMule's `sqrt(MB + 2)`
//! (`ClientCredits.cpp:139-161`); a holder stops, and S promotes rmule ahead of
//! the two waiters that queued before it. Taps in rmule's and S's namespaces.
//!
//! **Low ID** — the 15-minute reask. Inbound connections to rmule's listener
//! are dropped, so the eserver gives it a Low ID; it asks S, is ranked and
//! hangs up. A holder
//! stops: S marks rmule for its next connection (`UploadQueue.cpp:136-138`),
//! which comes with rmule's TCP full ask, 900 s after its rank where the build
//! before it waited 1300 s. A tap in rmule's namespace.

use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::artifacts::{Ed2kHashCommand, RunLayout, write_ed2k_link, write_incompressible_file};
use crate::docker::RunContainer;
use crate::flow::bench::{
    AMULE_PEER_TCP_PORT, Bench, CaptureSidecar, DEFAULT_TAP_INTERFACE, Eserver, amulecmd_command,
    run_checked,
};
use crate::flow::gate::{wait_for_amule_ready, wait_for_container_log};
use crate::flow::identity::ed2k_link_with_source;
use crate::flow::logs::{collect_amule_role_logs, collect_rmule_logs, collect_server_logs};
use crate::rmule::{
    CONTAINER_RUN_ROOT, RMULE_SERVE_TCP_PORT, RmuleClientContainer, release_held_download,
};

pub(crate) mod verdict;

pub use self::verdict::score_run_dir;

/// The holders' file, which only S shares.
const HOLDER_FILE: &str = "holder.bin";
/// Its link.
const HOLDER_LINK: &str = "holder.ed2k.txt";
/// The gift rmule shares, which X, W and S download from it.
const GIFT_FILE: &str = "gift.bin";
/// Its link.
const GIFT_LINK: &str = "gift.ed2k.txt";
/// How long a stopped body gets to close its links.
const STOP_GRACE_SECS: u64 = 10;

/// Which leg the run drives.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ReciprocityLeg {
    /// The upload preference, then S's credit for rmule.
    Credit,
    /// The Low-ID reask cadence.
    LowId,
}

/// The run's timings and caps.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReciprocityShape {
    /// The leg.
    pub leg: ReciprocityLeg,
    /// S's upload slot, KiB/s; S keeps two. aMule kicks a slot past 10 MB
    /// while someone waits (`UploadQueue.cpp:580-581`), so a slot this slow
    /// keeps both holders through the run.
    pub slot_kib: u32,
    /// Each of S's holders' download cap, KiB/s; unset, S's slot paces them.
    /// A holder capped below its slot keeps S's socket unwritable past
    /// aMule's 40 s timeout and loses the slot (`ClientTCPSocket.cpp:201-229`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_kib: Option<u32>,
    /// X's download cap, KiB/s: slow enough that X still holds rmule's one
    /// slot when the flow stops it. aMule's cap follows a 10 s average of the
    /// rate (`DownloadClient.cpp:1162-1177`), so X takes a burst at link speed
    /// first and the gift must outlast it.
    pub x_kib: u32,
    /// Seconds each body that joins a queue is given before the next joins,
    /// and before a stop: the waits the scores compare.
    pub step_secs: u64,
    /// Seconds the flow waits for the outcome it reads.
    pub run_window_secs: u64,
}

/// Stage rmule's `shared.bin`, S's holder file and rmule's gift, none of them
/// a compressor shrinks, with their ed2k links hashed by `command`.
///
/// # Errors
/// If a file cannot be written or hashed.
pub fn stage_reciprocity_files(
    layout: &RunLayout,
    rmule_size: u64,
    holder_size: u64,
    gift_size: u64,
    command: &Ed2kHashCommand,
) -> Result<()> {
    let dir = layout.synthetic_dir();
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    write_incompressible_file(&layout.synthetic_shared_file(), rmule_size, 0x5EED_0E01)?;
    write_ed2k_link(
        command,
        &layout.synthetic_shared_file(),
        &layout.synthetic_ed2k_file(),
    )?;
    for (name, link, size, seed) in [
        (HOLDER_FILE, HOLDER_LINK, holder_size, 0x5EED_0E02),
        (GIFT_FILE, GIFT_LINK, gift_size, 0x5EED_0E03),
    ] {
        write_incompressible_file(&dir.join(name), size, seed)?;
        write_ed2k_link(command, &dir.join(name), &dir.join(link))?;
    }
    Ok(())
}

/// Options for [`run_peer_reciprocity`].
pub struct PeerReciprocityOptions<'a> {
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
    /// The leg, its timings and caps.
    pub shape: ReciprocityShape,
}

/// The run's container names, by role.
struct Names {
    suffix: String,
}

impl Names {
    fn of(layout: &RunLayout) -> Self {
        Self {
            suffix: layout
                .root()
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
                .to_owned(),
        }
    }

    fn role(&self, role: &str) -> String {
        format!("rmule-interop-reciprocity-{role}-{}", self.suffix)
    }
}

/// A stock aMule downloading `link`, capped at `download_kib` when set,
/// idling once its sources are in.
fn start_downloader(
    bench: &mut Bench,
    options: &PeerReciprocityOptions<'_>,
    name: &str,
    link: &str,
    file_name: &str,
    download_kib: Option<u32>,
) -> Result<()> {
    let mut container = bench
        .amule_container(options.amule_image, name)
        .env("AMULE_DOWNLOAD_LINK", link)
        .env("AMULE_EXPECTED_FILE_NAME", file_name)
        .env("AMULE_DOWNLOAD_NO_WAIT", "1");
    if let Some(kib) = download_kib {
        container = container.env("AMULE_MAX_DOWNLOAD", kib.to_string());
    }
    bench.start_extra(
        name,
        container.env_assignments(options.amule_env),
        "run aMule",
    )?;
    wait_for_amule_ready(
        &bench.docker,
        options.layout,
        name,
        Duration::from_secs(options.timeout_secs),
        "rmule-amule-download-sources-ready",
    )
}

/// A one-shot container in `target`'s network namespace, from the aMule
/// image (which carries `iptables`), that drops every inbound connection to
/// rmule's listener.
fn low_id_firewall(image: &str, target: &str) -> RunContainer {
    [
        "-A",
        "INPUT",
        "-p",
        "tcp",
        "--dport",
        &RMULE_SERVE_TCP_PORT.to_string(),
        "--syn",
        "-j",
        "DROP",
    ]
    .into_iter()
    .fold(
        RunContainer::new(image.to_owned())
            .remove_after_exit()
            .network(format!("container:{target}"))
            .cap_add("NET_ADMIN")
            .entrypoint("iptables"),
        |container, arg| container.arg(arg),
    )
}

/// Wait until `path` holds `size` bytes, or `budget` passes.
fn wait_for_file(path: &Path, size: u64, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if fs::metadata(path).is_ok_and(|meta| meta.len() == size) {
            return true;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    false
}

/// The flags rmule's `download start` runs under in `shape`'s leg, each
/// readiness wait bounded by `timeout_secs`. In the credit leg rmule shares
/// the gift from one upload slot and serves on once its own download has
/// completed, which can come before S holds the whole gift: the run ends at
/// a deadline past every wait the flow makes after starting rmule (X's and
/// W's readiness, two steps, the gift's window and the copy's window).
fn rmule_flags(shape: &ReciprocityShape, timeout_secs: u64) -> Vec<String> {
    let mut flags = vec![
        "--report-parts-every-ms".to_owned(),
        "1000".to_owned(),
        "--stamp-events".to_owned(),
    ];
    if shape.leg == ReciprocityLeg::Credit {
        let deadline = 3 * timeout_secs + 2 * shape.step_secs + 2 * shape.run_window_secs;
        flags.extend([
            "--share".to_owned(),
            format!("{CONTAINER_RUN_ROOT}/synthetic/{GIFT_FILE}"),
            "--upload-slots".to_owned(),
            "1".to_owned(),
            "--linger".to_owned(),
            "--max-seconds".to_owned(),
            deadline.to_string(),
        ]);
    }
    flags
}

/// Run the flow's leg and score it.
///
/// # Errors
/// If a container fails to start, a readiness wait outlasts its budget, or
/// the verdict cannot be written. An outcome that does not come inside the
/// run window is scored, not an error.
pub fn run_peer_reciprocity(options: PeerReciprocityOptions<'_>) -> Result<()> {
    let shape = options.shape;
    let mut bench = Bench::new(
        options.container_runtime,
        options.layout,
        options.keep_containers,
    )?;
    let names = Names::of(options.layout);
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
    let step = Duration::from_secs(shape.step_secs);
    let root = options.layout.root().join(verdict::ROOT_DIR);
    fs::create_dir_all(&root).with_context(|| format!("create {}", root.display()))?;
    let sharer = names.role("sharer");
    let holders = [names.role("holder-a"), names.role("holder-b")];
    let waiters = [names.role("waiter-a"), names.role("waiter-b")];
    let (slot_holder, rival) = (names.role("x"), names.role("w"));
    let captures = [names.role("rmule-capture"), names.role("sharer-capture")];

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

        // S: rmule's file and the holders' file, two slots.
        let share_dir: PathBuf = root.join("share");
        fs::create_dir_all(&share_dir)
            .with_context(|| format!("create {}", share_dir.display()))?;
        fs::copy(
            options.layout.synthetic_shared_file(),
            share_dir.join("shared.bin"),
        )
        .context("stage rmule's file for the sharer")?;
        fs::copy(synthetic.join(HOLDER_FILE), share_dir.join(HOLDER_FILE))
            .context("stage the holders' file")?;
        let container = bench
            .amule_container(options.amule_image, &sharer)
            .volume(&share_dir, "/incoming")
            .env("AMULE_SHARED_DIR", "/incoming")
            .env("AMULE_MAX_UPLOAD", (2 * shape.slot_kib).to_string())
            .env("AMULE_SLOT_ALLOCATION", shape.slot_kib.to_string())
            .env_assignments(options.amule_env);
        bench.start_extra(&sharer, container, "run sharer aMule")?;
        wait_for_amule_ready(
            &bench.docker,
            options.layout,
            &sharer,
            timeout,
            "rmule-amule-ready",
        )?;
        let sharer_ip: Ipv4Addr = run_checked(
            bench.docker.container_ip(sharer.clone()),
            "inspect sharer ip",
        )?
        .trim()
        .parse()
        .context("sharer address")?;
        let at_sharer =
            |link: &str| ed2k_link_with_source(link, &sharer_ip.to_string(), AMULE_PEER_TCP_PORT);

        let holder_link = at_sharer(&read_link(HOLDER_LINK)?);
        for holder in &holders {
            start_downloader(
                &mut bench,
                &options,
                holder,
                &holder_link,
                HOLDER_FILE,
                shape.holder_kib,
            )?;
        }
        if shape.leg == ReciprocityLeg::Credit {
            for waiter in &waiters {
                start_downloader(
                    &mut bench,
                    &options,
                    waiter,
                    &at_sharer(&rmule_link),
                    "shared.bin",
                    None,
                )?;
            }
            std::thread::sleep(step);
        }

        let rmule_name = bench.names.rmule_container_name.clone();
        run_checked(
            options
                .rmule_client_container
                .prebuild_command(&bench.docker)?,
            "prebuild rmule-tools for the download container",
        )?;
        let flags = rmule_flags(&shape, options.timeout_secs);
        // Low ID: rmule does not serve; the firewall below keeps the
        // eserver's port test from its listener.
        let serve = shape.leg == ReciprocityLeg::Credit;
        let download = options
            .rmule_client_container
            .download_start_detached_with_args(
                bench.staging(options.layout),
                &rmule_name,
                &bench.names.server_endpoint(),
                &[rmule_link.as_str()],
                serve,
                &flags,
            )?;
        bench.start_rmule_container(download, "run rmule download container")?;
        let bpf = format!("tcp port {AMULE_PEER_TCP_PORT} or tcp port {RMULE_SERVE_TCP_PORT}");
        for (capture, target, pcap) in [
            (&captures[0], &rmule_name, verdict::RMULE_PCAP),
            (&captures[1], &sharer, verdict::SHARER_PCAP),
        ] {
            let tap = CaptureSidecar {
                image: options.capture_image,
                name: capture,
                target_container: target,
                interface: DEFAULT_TAP_INTERFACE,
                host_dir: root.clone(),
                pcap_file: pcap,
                bpf: &bpf,
            };
            bench.start_extra(capture, tap.container(), "run reciprocity tcpdump sidecar")?;
            wait_for_container_log(&bench.docker, capture, "listening on", timeout)?;
        }
        if shape.leg == ReciprocityLeg::LowId {
            // rmule's login binds its listener whether or not it serves
            // (ADR-0095), so a Low ID is a network condition: the eserver's
            // port test must not reach that listener.
            run_checked(
                bench
                    .docker
                    .run_container(low_id_firewall(options.amule_image, &rmule_name)),
                "drop inbound connections to rmule's listener",
            )?;
        }
        release_held_download(options.layout)?;
        let rmule_ip: Ipv4Addr = run_checked(
            bench.docker.container_ip(rmule_name.clone()),
            "inspect rmule ip",
        )?
        .trim()
        .parse()
        .context("rmule address")?;
        wait_for_container_log(&bench.docker, &rmule_name, "download.peer_queued", timeout)?;
        let mut marks = verdict::Marks::default();

        if shape.leg == ReciprocityLeg::Credit {
            // X holds rmule's one slot; W queues at rmule; after a step S
            // queues there too; after another X stops and rmule chooses.
            let gift_at_rmule = ed2k_link_with_source(
                &read_link(GIFT_LINK)?,
                &rmule_ip.to_string(),
                RMULE_SERVE_TCP_PORT,
            );
            start_downloader(
                &mut bench,
                &options,
                &slot_holder,
                &gift_at_rmule,
                GIFT_FILE,
                Some(shape.x_kib),
            )?;
            start_downloader(
                &mut bench,
                &options,
                &rival,
                &gift_at_rmule,
                GIFT_FILE,
                None,
            )?;
            let rival_ip: Ipv4Addr =
                run_checked(bench.docker.container_ip(rival.clone()), "inspect rival ip")?
                    .trim()
                    .parse()
                    .context("rival address")?;
            marks.rival = Some(rival_ip);
            std::thread::sleep(step);
            run_checked(
                bench.docker.exec(
                    sharer.clone(),
                    amulecmd_command(&format!("Add {gift_at_rmule}")),
                ),
                "the sharer asks rmule for the gift",
            )?;
            std::thread::sleep(step);
            marks.slot_freed_at = Some(verdict::unix_now());
            run_checked(
                bench
                    .docker
                    .stop_container(slot_holder.clone(), STOP_GRACE_SECS),
                "stop the body holding rmule's slot",
            )?;
            let gift_size = fs::metadata(synthetic.join(GIFT_FILE)).map_or(0, |meta| meta.len());
            marks.gift_complete = wait_for_file(
                &share_dir.join(GIFT_FILE),
                gift_size,
                Duration::from_secs(shape.run_window_secs),
            );
        }

        // A holder stops: S promotes its best waiter.
        marks.holder_stopped_at = Some(verdict::unix_now());
        run_checked(
            bench
                .docker
                .stop_container(holders[0].clone(), STOP_GRACE_SECS),
            "stop a holder",
        )?;
        let completed = wait_for_container_log(
            &bench.docker,
            &rmule_name,
            "download.completed id=1",
            Duration::from_secs(shape.run_window_secs),
        )
        .is_ok();
        println!("peer_reciprocity completed_in_window={completed}");
        verdict::Topology {
            rmule: rmule_ip,
            sharer: sharer_ip,
            shape,
            marks,
        }
        .write(&root)?;
        collect_rmule_logs(&bench.docker, options.layout, &rmule_name)?;
        collect_amule_role_logs(&bench.docker, options.layout, "sharer", &sharer)?;
        collect_server_logs(
            &bench.docker,
            options.layout,
            &bench.names.server_container_name,
        )?;
        Ok(())
    })();

    if result.is_err() {
        bench.collect_failure_logs(options.layout);
        if let Err(error) =
            collect_amule_role_logs(&bench.docker, options.layout, "sharer", &sharer)
        {
            eprintln!("warning: failed to collect the sharer's logs: {error:#}");
        }
    }
    if options.keep_containers {
        println!("kept_capture_dir={}", root.display());
    }
    bench.cleanup_best_effort();
    result?;
    let verdict = score_run_dir(options.layout.root())?;
    println!("peer_reciprocity verdict={verdict}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credit_shape() -> ReciprocityShape {
        ReciprocityShape {
            leg: ReciprocityLeg::Credit,
            slot_kib: 10,
            holder_kib: None,
            x_kib: 2,
            step_secs: 60,
            run_window_secs: 1200,
        }
    }

    /// rmule's own download from S can complete before S has fetched the
    /// whole gift from rmule, so the credit leg's rmule serves on past its
    /// completion until every wait the flow makes after starting it has run
    /// out: X's and W's readiness, two steps, the gift's window and the
    /// copy's window.
    #[test]
    fn the_credit_legs_rmule_serves_on_until_the_flows_last_wait() {
        let shape = credit_shape();
        let flags = rmule_flags(&shape, 600);
        assert!(flags.iter().any(|flag| flag == "--linger"), "{flags:?}");
        let deadline: u64 = flags
            .iter()
            .position(|flag| flag == "--max-seconds")
            .and_then(|at| flags.get(at + 1))
            .and_then(|secs| secs.parse().ok())
            .expect("a deadline the lingering run ends at");
        assert!(
            deadline >= 2 * 600 + 2 * shape.step_secs + 2 * shape.run_window_secs,
            "{deadline}"
        );
    }
}
