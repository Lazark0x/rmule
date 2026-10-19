//! The **crossing** flow: a stock aMule's own link to rmule lands while
//! rmule's dial to the same aMule is in flight, in both orderings, on the
//! serve side and on the download side (ADR-0107's Peer Links rules), plus a
//! Low-ID waiter coming back to a free slot.
//!
//! aMule keeps the socket it reads a peer's hello on and deletes its own
//! (`ClientList.cpp:400-403`), so which link survives a crossing is decided by
//! whose hello each end read first. The flow stages the race with `iptables`
//! holds in the two namespaces instead of hoping for it: a dial whose SYN is
//! held is in flight with nothing said (called off before its hello); a dial
//! whose data is held has connected and written its hello, which the far end
//! has not read (crossed after its hello); a held SYN of the aMule's own
//! connect lets the flow choose when its link lands.
//!
//! What makes a stock aMule open its own link at a chosen moment is a
//! download it adds: a source named in an added link is asked at once. On
//! the serve side the waiter cancels its queued download and adds it again,
//! so it comes back under the same User Hash; on the download side rmule's
//! seed adds a download of a file rmule shares.
//!
//! - `serve-called-off`: X holds rmule's one upload slot, W queues and its
//!   idle link closes. rmule's dial-back SYN to W is held; X stops; W comes
//!   back. Claims: the slot lands on W's own link, the transfer runs on it,
//!   and no second link stays up.
//! - `serve-crossed`: the same, but rmule's dial-back connects and its hello
//!   is held, and W's own connect is held until the dial's hello is out.
//!   Claims: `serve.crossed_link_let_go`, the slot lands on the dial, the
//!   transfer runs on it, and no second link stays up.
//! - `low-id-return`: W is Low ID, so rmule cannot dial it back; X stops,
//!   the slot sits free, W comes back. Claim: `OP_ACCEPTUPLOADREQ` on its
//!   returning link within a second of its hello.
//! - `download-yield`: rmule's download dial to its seed S is held at the
//!   SYN while S's own link lands. Claims: the download rides S's link and
//!   completes, and no second link stays up.
//! - `download-crossed`: rmule's dial connects with its hello held, S's own
//!   connect is held until then. Claims: the download carries on over the
//!   dial and completes, and no second link stays up.

use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::artifacts::RunLayout;
use crate::docker::RunContainer;
use crate::flow::bench::{
    AMULE_PEER_TCP_PORT, Bench, CaptureSidecar, DEFAULT_TAP_INTERFACE, Eserver, amulecmd_command,
    run_checked,
};
use crate::flow::gate::{wait_for_amule_ready, wait_for_container_log};
use crate::flow::identity::{ed2k_link_with_source, parse_ed2k_file_hash};
use crate::flow::logs::{collect_amule_role_logs, collect_rmule_logs, collect_server_logs};
use crate::rmule::{
    CONTAINER_RUN_ROOT, RMULE_SERVE_TCP_PORT, RmuleClientContainer, release_held_download,
};

pub(crate) mod verdict;

pub use self::verdict::score_run_dir;

/// The file X holds rmule's slot on, and the file W waits for (both shared
/// by rmule), as `stage_reciprocity_files` writes them.
const SLOT_FILE: &str = "slot.bin";
const SLOT_LINK: &str = "slot.ed2k.txt";
const WAIT_FILE: &str = "gift.bin";
const WAIT_LINK: &str = "gift.ed2k.txt";
/// X's download cap, KiB/s: slow enough to hold rmule's slot.
const X_KIB: u32 = 2;
/// S's upload cap, KiB/s: rmule's 1 MiB download takes about 16 s.
const SEED_MAX_UPLOAD_KIB: &str = "64";
const STOP_GRACE_SECS: u64 = 10;
/// The smallest IP packet that carries eD2k bytes rather than a bare ACK
/// (20-byte IP and 32-byte TCP headers with timestamps): a data hold drops
/// it and lets the handshake and the ACKs through.
const DATA_HOLD_MIN_LEN: &str = "60:65535";

/// Which race the flow stages.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CrossingLeg {
    /// rmule's dial-back is held at its SYN while the waiter comes back.
    ServeCalledOff,
    /// rmule's dial-back has written its hello when the waiter's link lands.
    ServeCrossed,
    /// A Low-ID waiter comes back while rmule's slot sits free.
    LowIdReturn,
    /// rmule's download dial is held at its SYN while its seed's link lands.
    DownloadYield,
    /// rmule's download dial has written its hello when its seed's link lands.
    DownloadCrossed,
}

impl CrossingLeg {
    /// Whether the leg races rmule's serve side (X, W) rather than its
    /// download from S.
    fn serves(self) -> bool {
        matches!(
            self,
            Self::ServeCalledOff | Self::ServeCrossed | Self::LowIdReturn
        )
    }
}

/// The timings a leg runs under.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrossingShape {
    /// The race.
    pub leg: CrossingLeg,
    /// Seconds W stays queued before X stops: past aMule's 40 s idle close.
    pub idle_secs: u64,
    /// Seconds each hold stands once the race is set before it is lifted.
    pub hold_secs: u64,
    /// Seconds the flow watches after the last hold is lifted.
    pub watch_secs: u64,
}

/// Options for [`run_peer_crossing`].
pub struct PeerCrossingOptions<'a> {
    /// The run dir every artifact is written under.
    pub layout: &'a RunLayout,
    /// The Docker-compatible CLI to invoke.
    pub container_runtime: &'a str,
    /// Build the project-owned images before starting anything.
    pub build_images: bool,
    /// The eserver image.
    pub server_image: &'a str,
    /// The aMule image (it carries `iptables` for the holds).
    pub amule_image: &'a str,
    /// The tcpdump capture-sidecar image.
    pub capture_image: &'a str,
    /// Build context for the eserver image.
    pub server_build_context: &'a Path,
    /// Build context for the aMule image.
    pub amule_build_context: &'a Path,
    /// Build context for the capture image.
    pub capture_build_context: &'a Path,
    /// Keep the containers after the run.
    pub keep_containers: bool,
    /// Per-step readiness budget, seconds.
    pub timeout_secs: u64,
    /// Host TCP port the eserver's port is published on.
    pub server_host_port: u16,
    /// The rmule download container.
    pub rmule_client_container: &'a RmuleClientContainer,
    /// Extra env for every aMule.
    pub amule_env: &'a [String],
    /// The race and its timings.
    pub shape: CrossingShape,
}

/// An `iptables` rule set in `target`'s namespace by a one-shot container
/// from `image`; `action` is `-A` to set it and `-D` to lift it.
fn iptables(image: &str, target: &str, action: &str, rule: &[String]) -> RunContainer {
    rule.iter().fold(
        RunContainer::new(image.to_owned())
            .remove_after_exit()
            .network(format!("container:{target}"))
            .cap_add("NET_ADMIN")
            .entrypoint("iptables")
            .arg(action)
            .arg("OUTPUT"),
        |container, arg| container.arg(arg),
    )
}

/// A hold on the TCP segments `target`'s namespace sends to `to:port`: the
/// SYN alone, or every segment carrying data.
fn hold(to: Ipv4Addr, port: u16, syn: bool) -> Vec<String> {
    let mut rule = vec![
        "-p".to_owned(),
        "tcp".to_owned(),
        "-d".to_owned(),
        to.to_string(),
        "--dport".to_owned(),
        port.to_string(),
    ];
    if syn {
        rule.push("--syn".to_owned());
    } else {
        rule.extend(["-m", "length", "--length", DATA_HOLD_MIN_LEN].map(str::to_owned));
    }
    rule.extend(["-j", "DROP"].map(str::to_owned));
    rule
}

/// The holds a leg stands up, each as (namespace's container, rule).
struct Holds<'a> {
    image: &'a str,
    set: Vec<(String, Vec<String>)>,
}

impl Holds<'_> {
    fn add(&mut self, bench: &Bench, target: &str, rule: Vec<String>) -> Result<()> {
        run_checked(
            bench
                .docker
                .run_container(iptables(self.image, target, "-A", &rule)),
            "set a hold",
        )?;
        println!(
            "peer_crossing hold_set target={target} rule={}",
            rule.join(" ")
        );
        self.set.push((target.to_owned(), rule));
        Ok(())
    }

    /// Lift the hold set `index`-th, marking the moment.
    fn lift(&self, bench: &Bench, index: usize) -> Result<f64> {
        let (target, rule) = &self.set[index];
        run_checked(
            bench
                .docker
                .run_container(iptables(self.image, target, "-D", rule)),
            "lift a hold",
        )?;
        let at = verdict::unix_now();
        println!("peer_crossing hold_lifted target={target} at={at:.3}");
        Ok(at)
    }
}

/// Start a stock aMule downloading `link` (`AMULE_DOWNLOAD_LINK`), and wait
/// until its download has its sources.
fn start_downloader(
    bench: &mut Bench,
    options: &PeerCrossingOptions<'_>,
    name: &str,
    link: &str,
    file_name: &str,
    shape: (Option<u32>, bool),
) -> Result<()> {
    let (download_kib, low_id) = shape;
    let mut container = bench
        .amule_container(options.amule_image, name)
        .env("AMULE_DOWNLOAD_LINK", link)
        .env("AMULE_EXPECTED_FILE_NAME", file_name)
        .env("AMULE_DOWNLOAD_NO_WAIT", "1");
    if let Some(kib) = download_kib {
        container = container.env("AMULE_MAX_DOWNLOAD", kib.to_string());
    }
    if low_id {
        container = container
            .env("AMULE_FORCE_LOW_ID", "1")
            .cap_add("NET_ADMIN");
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

/// `amulecmd` in `container`.
fn amulecmd(bench: &Bench, container: &str, command: &str, phase: &str) -> Result<()> {
    run_checked(
        bench
            .docker
            .exec(container.to_owned(), amulecmd_command(command)),
        phase,
    )
    .map(|_| ())
}

fn container_ip(bench: &Bench, name: &str) -> Result<Ipv4Addr> {
    run_checked(
        bench.docker.container_ip(name.to_owned()),
        "inspect an address",
    )?
    .trim()
    .parse()
    .with_context(|| format!("{name}'s address"))
}

/// Run the leg and score it.
///
/// # Errors
/// If a container fails to start, a readiness wait outlasts its budget, a
/// hold cannot be set or lifted, or the verdict cannot be written.
pub fn run_peer_crossing(options: PeerCrossingOptions<'_>) -> Result<()> {
    let shape = options.shape;
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
    let role = |role: &str| format!("rmule-interop-crossing-{role}-{suffix}");
    let (seed, holder, waiter, capture) =
        (role("seed"), role("x"), role("w"), role("rmule-capture"));
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
    let mut holds = Holds {
        image: options.amule_image,
        set: Vec::new(),
    };

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

        // S: the seed of rmule's own download.
        let share_dir: PathBuf = root.join("share");
        fs::create_dir_all(&share_dir)
            .with_context(|| format!("create {}", share_dir.display()))?;
        fs::copy(
            options.layout.synthetic_shared_file(),
            share_dir.join("shared.bin"),
        )
        .context("stage rmule's file for the seed")?;
        let container = bench
            .amule_container(options.amule_image, &seed)
            .volume(&share_dir, "/incoming")
            .env("AMULE_SHARED_DIR", "/incoming")
            .env("AMULE_MAX_UPLOAD", SEED_MAX_UPLOAD_KIB)
            .env_assignments(options.amule_env);
        bench.start_extra(&seed, container, "run the seed aMule")?;
        wait_for_amule_ready(
            &bench.docker,
            options.layout,
            &seed,
            timeout,
            "rmule-amule-ready",
        )?;
        let seed_ip = container_ip(&bench, &seed)?;

        let rmule_name = bench.names.rmule_container_name.clone();
        run_checked(
            options
                .rmule_client_container
                .prebuild_command(&bench.docker)?,
            "prebuild rmule-tools for the download container",
        )?;
        let deadline = 4 * options.timeout_secs + shape.idle_secs + 4 * shape.hold_secs;
        let flags: Vec<String> = [
            "--stamp-events",
            "--share",
            &format!("{CONTAINER_RUN_ROOT}/synthetic/{SLOT_FILE}"),
            "--share",
            &format!("{CONTAINER_RUN_ROOT}/synthetic/{WAIT_FILE}"),
            "--upload-slots",
            "1",
            "--linger",
            "--max-seconds",
            &(deadline + shape.watch_secs).to_string(),
        ]
        .map(str::to_owned)
        .to_vec();
        let download = options
            .rmule_client_container
            .download_start_detached_with_args(
                bench.staging(options.layout),
                &rmule_name,
                &bench.names.server_endpoint(),
                &[read_link("shared.ed2k.txt")?.as_str()],
                true,
                &flags,
            )?;
        bench.start_rmule_container(download, "run rmule download container")?;
        let tap = CaptureSidecar {
            image: options.capture_image,
            name: &capture,
            target_container: &rmule_name,
            interface: DEFAULT_TAP_INTERFACE,
            host_dir: root.clone(),
            pcap_file: verdict::RMULE_PCAP,
            bpf: &format!("tcp port {AMULE_PEER_TCP_PORT} or tcp port {RMULE_SERVE_TCP_PORT}"),
        };
        bench.start_extra(&capture, tap.container(), "run crossing tcpdump sidecar")?;
        wait_for_container_log(&bench.docker, &capture, "listening on", timeout)?;
        let rmule_ip = container_ip(&bench, &rmule_name)?;
        let wait_link = read_link(WAIT_LINK)?;
        let wait_at_rmule =
            ed2k_link_with_source(&wait_link, &rmule_ip.to_string(), RMULE_SERVE_TCP_PORT);
        let mut marks = verdict::Marks::default();

        let peer_ip = if shape.leg.serves() {
            release_held_download(options.layout)?;
            wait_for_container_log(&bench.docker, &rmule_name, "serve.files_announced", timeout)?;
            let slot_at_rmule = ed2k_link_with_source(
                &read_link(SLOT_LINK)?,
                &rmule_ip.to_string(),
                RMULE_SERVE_TCP_PORT,
            );
            start_downloader(
                &mut bench,
                &options,
                &holder,
                &slot_at_rmule,
                SLOT_FILE,
                (Some(X_KIB), false),
            )?;
            wait_for_container_log(
                &bench.docker,
                &rmule_name,
                "serve.upload_slot_granted",
                timeout,
            )?;
            let low_id = shape.leg == CrossingLeg::LowIdReturn;
            start_downloader(
                &mut bench,
                &options,
                &waiter,
                &wait_at_rmule,
                WAIT_FILE,
                (None, low_id),
            )?;
            wait_for_container_log(&bench.docker, &rmule_name, "serve.peer_queued", timeout)?;
            let waiter_ip = container_ip(&bench, &waiter)?;
            // Past aMule's idle close, so the waiter has no link when X stops.
            std::thread::sleep(Duration::from_secs(shape.idle_secs));
            match shape.leg {
                CrossingLeg::ServeCalledOff => {
                    holds.add(
                        &bench,
                        &rmule_name,
                        hold(waiter_ip, AMULE_PEER_TCP_PORT, true),
                    )?;
                }
                CrossingLeg::ServeCrossed => {
                    holds.add(
                        &bench,
                        &rmule_name,
                        hold(waiter_ip, AMULE_PEER_TCP_PORT, false),
                    )?;
                    holds.add(&bench, &waiter, hold(rmule_ip, RMULE_SERVE_TCP_PORT, true))?;
                }
                _ => {}
            }
            marks.holder_stopped_at = Some(verdict::unix_now());
            run_checked(
                bench.docker.stop_container(holder.clone(), STOP_GRACE_SECS),
                "stop the body holding rmule's slot",
            )?;
            let freed = if low_id {
                "serve.upload_slot_released"
            } else {
                "serve.upload_dial_back"
            };
            let dialed = wait_for_container_log(&bench.docker, &rmule_name, freed, timeout).is_ok();
            println!("peer_crossing slot_freed {freed} logged={dialed}");
            if shape.leg == CrossingLeg::ServeCrossed {
                // The dial connects through the SYN; its hello is written and held.
                std::thread::sleep(Duration::from_secs(2));
            }
            if low_id {
                // The slot sits free for a while before the waiter comes back.
                std::thread::sleep(Duration::from_secs(shape.hold_secs));
            }
            let hash: String = parse_ed2k_file_hash(&wait_link)?
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect();
            amulecmd(
                &bench,
                &waiter,
                &format!("Cancel {hash}"),
                "the waiter cancels its download",
            )?;
            marks.returned_at = Some(verdict::unix_now());
            amulecmd(
                &bench,
                &waiter,
                &format!("Add {wait_at_rmule}"),
                "the waiter adds it again",
            )?;
            for index in (0..holds.set.len()).rev() {
                std::thread::sleep(Duration::from_secs(shape.hold_secs));
                marks.lifted_at.push(holds.lift(&bench, index)?);
            }
            std::thread::sleep(Duration::from_secs(shape.watch_secs));
            waiter_ip
        } else {
            if shape.leg == CrossingLeg::DownloadYield {
                holds.add(
                    &bench,
                    &rmule_name,
                    hold(seed_ip, AMULE_PEER_TCP_PORT, true),
                )?;
            } else {
                holds.add(
                    &bench,
                    &rmule_name,
                    hold(seed_ip, AMULE_PEER_TCP_PORT, false),
                )?;
                holds.add(&bench, &seed, hold(rmule_ip, RMULE_SERVE_TCP_PORT, true))?;
            }
            release_held_download(options.layout)?;
            wait_for_container_log(
                &bench.docker,
                &rmule_name,
                "download.sources_found",
                timeout,
            )?;
            // rmule's dial is out (held at its SYN, or connected with its
            // hello held) before S opens its own link.
            std::thread::sleep(Duration::from_secs(2));
            marks.returned_at = Some(verdict::unix_now());
            amulecmd(
                &bench,
                &seed,
                &format!("Add {wait_at_rmule}"),
                "the seed adds a download from rmule",
            )?;
            for index in (0..holds.set.len()).rev() {
                std::thread::sleep(Duration::from_secs(shape.hold_secs));
                marks.lifted_at.push(holds.lift(&bench, index)?);
            }
            let completed = wait_for_container_log(
                &bench.docker,
                &rmule_name,
                "download.completed id=1",
                timeout,
            )
            .is_ok();
            println!("peer_crossing download_completed={completed}");
            std::thread::sleep(Duration::from_secs(shape.watch_secs));
            seed_ip
        };
        verdict::Topology {
            rmule: rmule_ip,
            peer: peer_ip,
            shape,
            marks,
        }
        .write(&root)?;
        collect_rmule_logs(&bench.docker, options.layout, &rmule_name)?;
        collect_amule_role_logs(&bench.docker, options.layout, "seed", &seed)?;
        if shape.leg.serves() {
            collect_amule_role_logs(&bench.docker, options.layout, "w", &waiter)?;
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
    }
    if options.keep_containers {
        println!("kept_capture_dir={}", root.display());
    }
    bench.cleanup_best_effort();
    result?;
    let verdict = score_run_dir(options.layout.root())?;
    println!("peer_crossing verdict={verdict}");
    Ok(())
}
