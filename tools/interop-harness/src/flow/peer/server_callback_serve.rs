//! The server-callback-serve flow: a High-ID stock aMule downloads from a
//! **Low-ID** rmule through the server's callback relay (ADR-0061).
//!
//! The downloader learns rmule from the server as a Low-ID source, so it
//! cannot dial it: it asks the server to invite rmule (`OP_CALLBACKREQUEST`,
//! `0x1C`), the server relays `OP_CALLBACKREQUESTED` (`0x35`) naming the
//! downloader's listener, and rmule dials that listener and serves the file
//! over the link, as aMule's own `OP_CALLBACKREQUESTED` arm does
//! (`ServerSocket.cpp:554-591`).
//!
//! Topology, on `ed2ksrv`'s fake-public `/24`:
//! 1. `ed2ksrv`, with a tap in its namespace on its TCP port. Lugdunum cannot
//!    stand in: it never surfaces a Low-ID source (ADR-0040).
//! 2. **rmule**: `ed2k serve start` from the `rmule-tools` image sharing the
//!    synthetic file, forced **Low-ID** by its entrypoint dropping inbound
//!    TCP to its listener (`RMULE_FORCE_LOW_ID_TCP_PORT`, the network
//!    condition `AMULE_FORCE_LOW_ID` is for aMule), so the server's High-ID
//!    probe fails and no peer can dial it. A tap in its namespace; rmule is
//!    held until the tap listens, so its login and every dial are on it.
//! 3. The **downloader**: a stock aMule on the same server, High ID, handed
//!    the plain link once the server tap shows rmule's `OP_OFFERFILES`.
//!
//! The verdict ([`score_run_dir`](self::verdict::score_run_dir)) reads both
//! taps and the downloader's copy; a retained run is re-scored the same way.

pub(crate) mod verdict;

use std::fs;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};

use self::verdict::{ADDRESSES, Addresses, RMULE_PCAP, ROOT_DIR, SERVER_PCAP};
use super::lowid_callback_reask::amule_on_ed2ksrv;
use crate::artifacts::RunLayout;
use crate::docker::RunContainer;
use crate::flow::bench::{Bench, CaptureSidecar, DEFAULT_TAP_INTERFACE, ED2K_SERVER_PORT};
use crate::flow::ed2k_server::search_wire::{ED2KSRV_IP, SUBNET, start_ed2ksrv, wait_for_offers};
use crate::flow::gate::wait_for_container_log;
use crate::flow::logs::{collect_amule_role_logs, collect_rmule_logs, collect_server_logs};
use crate::rmule::{RMULE_SERVE_TCP_PORT, hold_image_until_released, release_held_download};

/// rmule's static address.
const RMULE_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 70);
/// The downloader's static address.
const DOWNLOADER_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 31);
/// The shared file's name, as the downloader writes its copy.
const SHARED_FILE: &str = "shared.bin";
/// How long rmule serves past the readiness budget: the downloader's whole
/// transfer rides inside it.
const RMULE_MARGIN_SECS: u64 = 600;

/// Options for [`run_server_callback_serve`].
pub struct ServerCallbackServeOptions<'a> {
    /// The run dir every artifact is written under; its synthetic dir holds
    /// the shared file and its link.
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
    /// The aMule image the downloader runs.
    pub amule_image: &'a str,
    /// Build context for the aMule image.
    pub amule_build_context: &'a Path,
    /// Extra environment for the aMule container (`KEY=VALUE`).
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
    /// The `rmule-tools` image rmule serves from.
    pub rmule_tools_image: &'a str,
    /// Dockerfile for the `rmule-tools` image.
    pub rmule_tools_dockerfile: &'a Path,
    /// Build context for the `rmule-tools` image (the repo root).
    pub rmule_tools_build_context: &'a Path,
}

/// Drive the server-callback-serve flow and write its verdict.
///
/// # Errors
/// If a body cannot be started or never reaches the state the flow needs —
/// rmule never offering its file, the downloader never completing — or the
/// run cannot be scored.
pub fn run_server_callback_serve(options: ServerCallbackServeOptions<'_>) -> Result<()> {
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
    let downloader = format!("rmule-interop-amule-callback-downloader-{suffix}");
    let server_tap = format!("rmule-interop-callback-serve-server-tap-{suffix}");
    let rmule_tap = format!("rmule-interop-callback-serve-rmule-tap-{suffix}");
    let rmule = bench.names.rmule_container_name.clone();

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
        // Before rmule logs in, so its OP_IDCHANGE is on the tap.
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

        let serve = rmule_serve(
            &bench,
            options.rmule_tools_image,
            &rmule,
            options.layout.root(),
            &server,
            options.timeout_secs * 2 + RMULE_MARGIN_SECS,
        );
        let command = bench.docker.run_container(serve);
        bench.start_rmule_container(command, "run the Low-ID rmule sharer")?;
        let tap = CaptureSidecar {
            image: options.capture_image,
            name: &rmule_tap,
            target_container: &rmule,
            interface: DEFAULT_TAP_INTERFACE,
            host_dir: root.clone(),
            pcap_file: RMULE_PCAP,
            bpf: "tcp",
        };
        bench.start_extra(&rmule_tap, tap.container(), "run the rmule tap")?;
        wait_for_container_log(&bench.docker, &rmule_tap, "listening on", timeout)?;
        release_held_download(options.layout)?;
        wait_for_container_log(
            &bench.docker,
            &rmule,
            "rmule-tools-low-id-firewall-installed",
            timeout,
        )?;
        wait_for_offers(
            verdict::FLOW,
            &root.join(SERVER_PCAP),
            RMULE_IP,
            &options.layout.synthetic_shared_file(),
            timeout,
        )?;

        let link = fs::read_to_string(options.layout.synthetic_ed2k_file())
            .with_context(|| format!("read {}", options.layout.synthetic_ed2k_file().display()))?;
        let size = fs::metadata(options.layout.synthetic_shared_file())
            .with_context(|| format!("stat {}", options.layout.synthetic_shared_file().display()))?
            .len();
        bench.start_extra(
            &downloader,
            amule_on_ed2ksrv(
                &bench,
                options.amule_image,
                &downloader,
                &DOWNLOADER_IP.to_string(),
            )
            .volume(options.layout.amule_dir(), "/incoming")
            .env("AMULE_SHARED_DIR", "/incoming")
            .env("AMULE_DOWNLOAD_LINK", link.trim())
            .env("AMULE_EXPECTED_FILE_NAME", SHARED_FILE)
            .env("AMULE_EXPECTED_SIZE", size.to_string())
            .env_assignments(options.amule_env),
            "run the High-ID downloader",
        )?;
        let finished = wait_for_container_log(
            &bench.docker,
            &downloader,
            "rmule-amule-download-complete",
            timeout,
        );
        collect_rmule_logs(&bench.docker, options.layout, &rmule)?;
        collect_amule_role_logs(&bench.docker, options.layout, "downloader", &downloader)?;
        collect_server_logs(&bench.docker, options.layout, &ed2ksrv)?;
        let pin = fs::read_to_string(root.join("ed2ksrv-pin.txt")).unwrap_or_default();
        let addresses = Addresses {
            rmule: RMULE_IP,
            rmule_port: RMULE_SERVE_TCP_PORT,
            downloader: DOWNLOADER_IP,
            server,
            ed2ksrv_pin: pin.trim().to_owned(),
        };
        let path = root.join(ADDRESSES);
        fs::write(
            &path,
            toml::to_string_pretty(&addresses).context("serialize the addresses")?,
        )
        .with_context(|| format!("write {}", path.display()))?;
        // A downloader that never finished is scored, not hidden: the verdict
        // names where the road stopped.
        let verdict = verdict::score_run_dir(options.layout.root())?;
        println!("{} verdict={verdict}", verdict::FLOW);
        finished.map(|_| ())
    })();

    if result.is_err() {
        bench.collect_failure_logs(options.layout);
        if let Err(error) =
            collect_amule_role_logs(&bench.docker, options.layout, "downloader", &downloader)
        {
            eprintln!("warning: failed to collect the downloader logs: {error:#}");
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

/// rmule serving the synthetic file from the `rmule-tools` image toward
/// `server`, its listener's inbound TCP dropped so the server assigns a Low
/// ID, bounded by `max_seconds`, held until the flow releases it.
fn rmule_serve(
    bench: &Bench,
    image: &str,
    name: &str,
    run_root: &Path,
    server: &SocketAddrV4,
    max_seconds: u64,
) -> RunContainer {
    [
        "ed2k",
        "serve",
        "start",
        "--file",
        "/w/synthetic/shared.bin",
        "--server",
        &server.to_string(),
        "--listen",
        &format!("0.0.0.0:{RMULE_SERVE_TCP_PORT}"),
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
                .env(
                    "RMULE_FORCE_LOW_ID_TCP_PORT",
                    RMULE_SERVE_TCP_PORT.to_string(),
                )
                .cap_add("NET_ADMIN")
                .volume(run_root, "/w"),
            "/w",
        ),
        |container, arg| container.arg(*arg),
    )
}
