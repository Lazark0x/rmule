//! The Low-ID callback re-ask flow: a queued rmule re-asks a **Low-ID** stock
//! aMule it reached by callback with a UDP ping, and the answer keeps its
//! standing fresh.
//!
//! rmule reaches a Low-ID source only by asking the server it shares with the
//! source to relay a callback (`OP_CALLBACKREQUEST`, ADR-0039); the source
//! dials in and is adopted. Queued there, the source's record holds its queue
//! standing past the connection (ADR-0057, ADR-0090). aMule pings any queued
//! source that advertised a client-UDP port at the address it connected from,
//! Low ID or not (stock 2.3.3 `DownloadClient.cpp:1269-1296`), so
//! `FILEREASKTIME` less 20 s after the last rank rmule sends the sharer an
//! `OP_REASKFILEPING`; its `OP_REASKACK` refreshes the reask clock, and the
//! TCP full ask at `FILEREASKTIME` — a second `OP_CALLBACKREQUEST`, never a
//! dial at the endpoint the source came in from (aMule's `TryToConnect` on a
//! Low-ID client, `BaseClient.cpp:1521-1539`) — never falls due.
//!
//! Topology, on `ed2ksrv`'s fake-public `/24` (aMule accepts it and the
//! server's config pins its address there):
//! 1. `ed2ksrv`, with a tap in its namespace on its TCP port.
//! 2. The **sharer**: a stock aMule sharing a file no compressor shrinks,
//!    capped at 3 KB/s (aMule then keeps its floor of two upload slots,
//!    `UploadQueue.cpp:303-313`), and forced **Low-ID**: its entrypoint drops
//!    inbound TCP to its port (`AMULE_FORCE_LOW_ID`, a network condition), so
//!    the server's High-ID probe fails and every peer reaches it by callback.
//! 3. Two **slot-holders**: stock aMules that download the file, learn the
//!    sharer from the server and call it back, and hold both slots for the
//!    window, finishing no part at about 1.5 KB/s each. They start only once
//!    the server tap shows the sharer's `OP_OFFERFILES`: the sharer offers
//!    after hashing its share, about a minute after login, and a holder
//!    whose first `OP_GETSOURCES` comes back empty asks the server again only
//!    after aMule's 15-minute `SERVERREASKTIME`.
//! 4. A **stimulus**: `rmule-tools ipv6 hold-slot --extended-requests 0`,
//!    queued at the sharer and stating no part status. aMule pings a queued
//!    source only once its source ask is closed (`IsSourceRequestAllowed`,
//!    `DownloadClient.cpp:1271-1273`); for a complete source that takes an
//!    answer to a source ask, and the sharer answers only with a source to
//!    give — the holders hold no part, so none of them is one. A requester of
//!    unknown status is ("send it and hope", `KnownFile.cpp:978-984`). It
//!    dials the sharer directly: the sharer's inbound DROP gains one ACCEPT
//!    for the stimulus's address alone, so the server's High-ID probe still
//!    fails and the sharer stays Low-ID. Stimulus throughout (ADR-0045).
//! 5. **rmule**: `ed2k download start --serve` from the `rmule-tools` image —
//!    High ID, so it may ask for callbacks — with a tap in its namespace. It
//!    learns the sharer from the server, asks for the callback, is dialed,
//!    and is queued behind the holders.
//!
//! The window is anchored at rmule's `download.peer_queued` naming the sharer
//! and sits past `FILEREASKTIME`. No knob shortens rmule's reask period, so
//! the run is CLI-only (about 30 minutes); a retained run is re-scored by
//! [`score_run_dir`](self::verdict::score_run_dir).

mod stimulus;
pub(crate) mod verdict;

use std::fs;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use self::stimulus::{STIMULUS_DIR, queue_the_stimulus};
use self::verdict::{ADDRESSES, Addresses, RMULE_PCAP, ROOT_DIR, SERVER_PCAP};
use crate::artifacts::RunLayout;
use crate::docker::RunContainer;
use crate::flow::bench::{
    Bench, CaptureSidecar, DEFAULT_TAP_INTERFACE, ED2K_SERVER_PORT, amulecmd_command, run_checked,
};
use crate::flow::ed2k_server::search_wire::{ED2KSRV_IP, SUBNET, start_ed2ksrv, wait_for_offers};
use crate::flow::gate::{sit_tap_window, wait_for_container_log};
use crate::flow::logs::{collect_amule_role_logs, collect_rmule_logs, collect_server_logs};
use crate::rmule::{RMULE_SERVE_TCP_PORT, hold_image_until_released, release_held_download};

/// The sharer's upload cap (KiB/s): under 10 KB/s aMule keeps two slots.
const SHARER_MAX_UPLOAD_KIB: &str = "3";
/// The sharer's static address.
const SHARER_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 31);
/// One slot-holder per upload slot the sharer keeps, each at its own address.
const HOLDERS: [(&str, &str); 2] = [("holder-a", "203.0.113.32"), ("holder-b", "203.0.113.33")];
/// rmule's static address.
const RMULE_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 70);
/// What the sharer's own `amulecmd Status` says once the server gave it a
/// Low ID.
const LOW_ID_STATUS: &str = "with LowID";
/// The shared file's name, as `amulecmd Show ul` lists an upload of it.
const SHARED_FILE: &str = "shared.bin";
/// The interval between two reads of the sharer's upload list.
const UPLOAD_POLL: Duration = Duration::from_secs(2);
/// How long rmule's download runs past the readiness budget and the window:
/// enough for the ping, its answer and the instant the TCP full ask would
/// have fallen at to be harvested.
const RMULE_MARGIN_SECS: u64 = 300;

/// Options for [`run_peer_lowid_callback_reask`].
pub struct PeerLowIdCallbackReaskOptions<'a> {
    /// The run dir every artifact is written under; its synthetic dir holds
    /// the file [`stage_reask_emit_files`](super::stage_reask_emit_files)
    /// staged.
    pub layout: &'a RunLayout,
    /// The Docker-compatible CLI to invoke.
    pub container_runtime: &'a str,
    /// Build the counterparty images before starting anything.
    pub build_images: bool,
    /// Reuse the `rmule-tools` image as it is instead of rebuilding it from
    /// the workspace.
    pub skip_build: bool,
    /// Leave the containers and network running after the run.
    pub keep_containers: bool,
    /// Per-step readiness budget, in seconds.
    pub timeout_secs: u64,
    /// Seconds to sit past rmule's queueing: `FILEREASKTIME` plus margin.
    pub reask_window_secs: u64,
    /// The aMule image the sharer and the holders run.
    pub amule_image: &'a str,
    /// Build context for the aMule image.
    pub amule_build_context: &'a Path,
    /// Extra environment for every aMule container (`KEY=VALUE`).
    pub amule_env: &'a [String],
    /// The `ed2ksrv` image, refused unless its commit label matches the pin.
    pub ed2ksrv_image: &'a str,
    /// The `ed2ksrv` recipe directory.
    pub ed2ksrv_build_context: &'a Path,
    /// The `ed2ksrv` bench config; its `this_ip` is rendered per run.
    pub ed2ksrv_config: &'a Path,
    /// The tcpdump capture-sidecar image.
    pub capture_image: &'a str,
    /// Build context for the capture-sidecar image.
    pub capture_build_context: &'a Path,
    /// The `rmule-tools` image rmule downloads from.
    pub rmule_tools_image: &'a str,
    /// Dockerfile for the `rmule-tools` image.
    pub rmule_tools_dockerfile: &'a Path,
    /// Build context for the `rmule-tools` image (the repo root).
    pub rmule_tools_build_context: &'a Path,
}

/// Drive the Low-ID callback re-ask flow and write its verdict.
///
/// # Errors
/// If a body cannot be started or never reaches the state the flow needs —
/// the sharer earning a High ID, the holders never taking both slots, rmule
/// never queued — or the run cannot be scored.
pub fn run_peer_lowid_callback_reask(options: PeerLowIdCallbackReaskOptions<'_>) -> Result<()> {
    let mut bench = Bench::new(
        options.container_runtime,
        options.layout,
        options.keep_containers,
    )?;
    if options.build_images {
        bench.build_image("aMule", options.amule_image, options.amule_build_context)?;
        bench.build_image(
            "capture",
            options.capture_image,
            options.capture_build_context,
        )?;
        crate::flow::ed2ksrv::build(
            options.ed2ksrv_image,
            options.ed2ksrv_build_context,
            options.layout.root(),
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
    let timeout = Duration::from_secs(options.timeout_secs);
    let suffix = options
        .layout
        .root()
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_owned();
    let sharer = format!("rmule-interop-amule-lowid-sharer-{suffix}");
    let server_tap = format!("rmule-interop-lowid-server-tap-{suffix}");
    let rmule_tap = format!("rmule-interop-lowid-rmule-tap-{suffix}");
    let stimulus = format!("rmule-interop-lowid-stimulus-{suffix}");
    let rmule = bench.names.rmule_container_name.clone();
    let holders: Vec<(String, &str, &str)> = HOLDERS
        .iter()
        .map(|&(role, ip)| (format!("rmule-interop-amule-{role}-{suffix}"), role, ip))
        .collect();

    let mut ed2ksrv_started: Option<String> = None;
    let result = (|| -> Result<()> {
        bench.create_network(options.layout, Some(SUBNET))?;
        let ed2ksrv = start_ed2ksrv(
            &mut bench,
            options.ed2ksrv_image,
            options.ed2ksrv_config,
            &root,
            timeout,
        )?;
        ed2ksrv_started = Some(ed2ksrv.clone());
        let server = SocketAddrV4::new(
            ED2KSRV_IP.parse().context("ed2ksrv address")?,
            ED2K_SERVER_PORT,
        );
        // Before the sharer logs in, so its OP_IDCHANGE is on the tap.
        let tap = CaptureSidecar {
            image: options.capture_image,
            name: &server_tap,
            target_container: &ed2ksrv,
            interface: DEFAULT_TAP_INTERFACE,
            host_dir: root.clone(),
            pcap_file: SERVER_PCAP,
            bpf: "tcp port 4661",
        };
        bench.start_extra(&server_tap, tap.container(), "run the server tap")?;

        let link = fs::read_to_string(options.layout.synthetic_ed2k_file())
            .with_context(|| format!("read {}", options.layout.synthetic_ed2k_file().display()))?;
        let link = link.trim();
        let sharer_ip = SHARER_IP.to_string();
        bench.start_extra(
            &sharer,
            amule_on_ed2ksrv(&bench, options.amule_image, &sharer, &sharer_ip)
                .volume(options.layout.synthetic_dir(), "/incoming")
                .env("AMULE_SHARED_DIR", "/incoming")
                .env("AMULE_MAX_UPLOAD", SHARER_MAX_UPLOAD_KIB)
                .env("AMULE_FORCE_LOW_ID", "1")
                .cap_add("NET_ADMIN")
                .env_assignments(options.amule_env),
            "run the Low-ID sharer",
        )?;
        let status = wait_for_container_log(&bench.docker, &sharer, "rmule-amule-ready", timeout)?;
        if !status.contains(LOW_ID_STATUS) {
            bail!("the sharer did not log in with a Low ID; its Status:\n{status}");
        }
        wait_for_offers(
            "peer_lowid_callback_reask",
            &root.join(SERVER_PCAP),
            SHARER_IP,
            &options.layout.synthetic_dir(),
            timeout,
        )?;

        for (holder, _, ip) in &holders {
            bench.start_extra(
                holder,
                amule_on_ed2ksrv(&bench, options.amule_image, holder, ip)
                    .env("AMULE_DOWNLOAD_LINK", link)
                    .env("AMULE_DOWNLOAD_NO_WAIT", "1")
                    .env_assignments(options.amule_env),
                "run a slot-holder",
            )?;
            wait_for_container_log(
                &bench.docker,
                holder,
                "rmule-amule-download-sources-ready",
                timeout,
            )?;
        }
        let uploads = wait_for_uploads(&bench, &sharer, HOLDERS.len(), timeout)?;
        println!("peer_lowid_callback_reask holders_uploading\n{uploads}");
        queue_the_stimulus(
            &mut bench,
            options.rmule_tools_image,
            &sharer,
            &stimulus,
            &root,
            link,
            options.timeout_secs,
        )?;
        println!("peer_lowid_callback_reask stimulus_queued_by_the_sharer=true");

        let deadline = options.timeout_secs + options.reask_window_secs + RMULE_MARGIN_SECS;
        let download = rmule_download(
            &bench,
            options.rmule_tools_image,
            &rmule,
            options.layout.root(),
            &server,
            link,
            deadline,
        );
        let command = bench.docker.run_container(download);
        bench.start_rmule_container(command, "run the rmule download")?;
        let tap = CaptureSidecar {
            image: options.capture_image,
            name: &rmule_tap,
            target_container: &rmule,
            interface: DEFAULT_TAP_INTERFACE,
            host_dir: root.clone(),
            pcap_file: RMULE_PCAP,
            bpf: "tcp or udp",
        };
        bench.start_extra(&rmule_tap, tap.container(), "run the rmule tap")?;
        // rmule logs in, asks for the callback and is dialed back within a
        // second of starting; the verdict anchors on that first dial-back, so
        // rmule waits for the tap.
        wait_for_container_log(&bench.docker, &rmule_tap, "listening on", timeout)?;
        release_held_download(options.layout)?;

        // The sharer's rank, not a holder's: holders share the partial file
        // too, and rmule asks them as well.
        let queued = format!("download.peer_queued id=1 peer={SHARER_IP}:");
        wait_for_container_log(&bench.docker, &rmule, &queued, timeout)?;
        println!("peer_lowid_callback_reask rmule_queued_by_the_low_id_sharer=true");
        sit_tap_window(
            "peer_lowid_callback_reask",
            Duration::from_secs(options.reask_window_secs),
        );

        collect_rmule_logs(&bench.docker, options.layout, &rmule)?;
        collect_amule_role_logs(&bench.docker, options.layout, "sharer", &sharer)?;
        for (holder, role, _) in &holders {
            collect_amule_role_logs(&bench.docker, options.layout, role, holder)?;
        }
        collect_server_logs(&bench.docker, options.layout, &ed2ksrv)?;
        save_logs(
            &bench,
            &stimulus,
            &root.join(STIMULUS_DIR).join("stdout.log"),
        )?;
        let pin = fs::read_to_string(root.join("ed2ksrv-pin.txt")).unwrap_or_default();
        let addresses = Addresses {
            rmule: RMULE_IP,
            rmule_port: RMULE_SERVE_TCP_PORT,
            sharer: SHARER_IP,
            server,
            ed2ksrv_pin: pin.trim().to_owned(),
        };
        let path = root.join(ADDRESSES);
        fs::write(
            &path,
            toml::to_string_pretty(&addresses).context("serialize the addresses")?,
        )
        .with_context(|| format!("write {}", path.display()))?;
        let verdict = verdict::score_run_dir(options.layout.root())?;
        println!("peer_lowid_callback_reask verdict={verdict}");
        Ok(())
    })();

    if result.is_err() {
        bench.collect_failure_logs(options.layout);
        // The sharer, the holders and the server are extras the bench's own
        // failure sweep does not reach; their logs are what tells a stalled
        // callback road apart.
        let stimulus_log = root.join(STIMULUS_DIR).join("stdout.log");
        if let Err(error) = save_logs(&bench, &stimulus, &stimulus_log) {
            eprintln!("warning: failed to collect the stimulus logs: {error:#}");
        }
        let mut roles = vec![("sharer", sharer.as_str())];
        roles.extend(holders.iter().map(|(name, role, _)| (*role, name.as_str())));
        for (role, name) in roles {
            if let Err(error) = collect_amule_role_logs(&bench.docker, options.layout, role, name) {
                eprintln!("warning: failed to collect the {role} logs: {error:#}");
            }
        }
        if let Some(ed2ksrv) = &ed2ksrv_started
            && let Err(error) = collect_server_logs(&bench.docker, options.layout, ed2ksrv)
        {
            eprintln!("warning: failed to collect the ed2ksrv logs: {error:#}");
        }
    }
    bench.cleanup_best_effort();
    result
}

/// Write `container`'s stdout and stderr to `path`.
fn save_logs(bench: &Bench, container: &str, path: &Path) -> Result<()> {
    let output = bench
        .docker
        .logs(container.to_owned())
        .to_command()
        .output()
        .with_context(|| format!("docker logs {container}"))?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    fs::write(path, text).with_context(|| format!("write {}", path.display()))
}

/// A stock aMule on the bench at `ip`, logged in to `ed2ksrv` with plain
/// frames, so the server tap reads every one.
fn amule_on_ed2ksrv(bench: &Bench, image: &str, name: &str, ip: &str) -> RunContainer {
    RunContainer::new(image.to_owned())
        .detach()
        .name(name)
        .network(bench.names.network_name.clone())
        .ip(ip)
        .env("ED2K_SERVER_HOST", ED2KSRV_IP)
        .env("ED2K_SERVER_PORT", ED2K_SERVER_PORT.to_string())
        .env("AMULE_CRYPT_SUPPORTED", "0")
        .env("AMULE_CRYPT_REQUESTED", "0")
}

/// rmule's download from the `rmule-tools` image: High ID through its bound
/// listener, bounded by `max_seconds`, its data under the run dir.
fn rmule_download(
    bench: &Bench,
    image: &str,
    name: &str,
    run_root: &Path,
    server: &SocketAddrV4,
    link: &str,
    max_seconds: u64,
) -> RunContainer {
    [
        "ed2k",
        "download",
        "start",
        "--data-dir",
        "/w/rmule",
        "--server",
        &server.to_string(),
        "--file",
        link,
        "--out",
        "/w/rmule/output.bin",
        "--tcp-port",
        &RMULE_SERVE_TCP_PORT.to_string(),
        "--serve",
        "--max-seconds",
        &max_seconds.to_string(),
    ]
    .iter()
    .fold(
        hold_image_until_released(
            RunContainer::new(image.to_owned())
                .detach()
                .name(name)
                .network(bench.names.network_name.clone())
                .ip(RMULE_IP.to_string())
                .env("RMULE_LOG", "info")
                .volume(run_root, "/w"),
            "/w",
        ),
        |container, arg| container.arg(*arg),
    )
}

/// Hold until the sharer's own upload list names `want` uploads of the shared
/// file, and return that list: the holders have both slots, so rmule will be
/// queued rather than served.
fn wait_for_uploads(bench: &Bench, sharer: &str, want: usize, timeout: Duration) -> Result<String> {
    let started = Instant::now();
    loop {
        let listing = run_checked(
            bench
                .docker
                .exec(sharer.to_owned(), amulecmd_command("Show ul")),
            "read the sharer's upload list",
        )?;
        if listing
            .lines()
            .filter(|line| line.contains(SHARED_FILE))
            .count()
            >= want
        {
            return Ok(listing);
        }
        if started.elapsed() >= timeout {
            bail!("the sharer never listed {want} uploads of {SHARED_FILE}:\n{listing}");
        }
        thread::sleep(UPLOAD_POLL);
    }
}
