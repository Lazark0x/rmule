//! The peer-UDP reask **consume** flow (flow L, ADR-0057).
//!
//! A stock aMule, queued on rmule and disconnected, is the consume
//! counterparty: its own ~21.4-min `FILEREASKTIME` timer should emit
//! `OP_REASKFILEPING` (`0x90`) toward rmule's client-UDP endpoint. rmule serves
//! with a single upload slot, a throttled slot-holder aMule occupies it, and a
//! second aMule is therefore held queued, hangs up, and enters rmule's
//! disconnected standing. The shared file is one no compressor shrinks, as the
//! emit leg's is: rmule sends compressed parts, and a compressible file would
//! reach the throttled holder whole within minutes and free the slot. A passive tcpdump on rmule's own network namespace
//! records every datagram the reasker sends across the window; the datagram
//! count toward rmule is the captured fact either way (ADR-0045).

pub(crate) mod tap;
mod verdict;

pub use self::verdict::score_run_dir;

use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::artifacts::RunLayout;
use crate::flow::bench::{Bench, CaptureSidecar, DEFAULT_TAP_INTERFACE, Eserver, run_checked};
use crate::flow::gate::{sit_tap_window, wait_for_amule_ready};
use crate::flow::identity::{ed2k_link_with_source, parse_ed2k_file_hash};
use crate::flow::logs::{collect_amule_role_logs, collect_rmule_logs, collect_server_logs};
use crate::rmule::{RMULE_SERVE_TCP_PORT, RmuleServeContainer, ServeKnobs};

/// aMule `FILEREASKTIME` (`Constants.h`, 1,300,000 ms). The UDP source-reask
/// fires at `FILEREASKTIME − 20 s` (~21.4 min), the TCP full ask at
/// `FILEREASKTIME` (~21.7 min). The default reask window sits past both so a
/// genuine counterparty reask, if one is emitted, lands inside the capture.
pub const DEFAULT_REASK_WINDOW_SECS: u64 = 1_500;
/// The slot-holder's download throttle (KiB/s). Low enough that its download of
/// a large shared file cannot complete inside the reask window, so it keeps
/// rmule's single upload slot occupied and the reasker stays queued.
const REASK_HOLDER_THROTTLE_KIB: &str = "2";

/// The bench subnet for a reask run: the first fake-public `/24` when any
/// part of it arms rmule's peer obfuscation, else the default. rmule's send
/// gate keys on its own public address and takes no RFC 1918 address as one
/// (ADR-0084), so on a private net its datagrams could only leave plain.
///
/// # Errors
/// If the fake-public plan cannot be read.
pub(super) fn crypt_subnet(peer_crypt: Option<&str>, flips: &[String]) -> Result<Option<String>> {
    let crypt_at_all = peer_crypt.is_some() || flips.iter().any(|flip| !flip.ends_with(":off"));
    Ok(crypt_at_all
        .then(|| crate::fake_public::fake_public_address(0))
        .transpose()?
        .map(|address| address.subnet))
}

/// Options for [`run_peer_udp_reask`] (flow L).
pub struct PeerUdpReaskOptions<'a> {
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
    /// The rust image + workspace rmule serves from.
    pub rmule_serve_container: &'a RmuleServeContainer,
    /// Seconds to sit past the queue before harvesting the tap — cover
    /// `FILEREASKTIME` (~1300 s) plus margin.
    pub reask_window_secs: u64,
    /// `--peer-crypt <policy>` for the serving rmule. Set together with the
    /// counterparty's `AMULE_CRYPT_SUPPORTED`/`_REQUESTED` (below) this is the
    /// peer-UDP **crypt** capture: aMule obfuscates its own `0x90`
    /// only toward a peer whose hello claimed `SupportsCryptLayer`.
    pub peer_crypt: Option<&'a str>,
    /// `--peer-crypt-flip <secs>:<policy>` for the serving rmule, one per
    /// entry: its obfuscation policy changes mid-run, live (ADR-0046), so a
    /// reask before a flip and the one after meet different policies. The
    /// result line lists each change rmule marked.
    pub peer_crypt_flip: &'a [String],
    /// Extra environment for both aMule containers (`KEY=VALUE`).
    pub amule_env: &'a [String],
}

/// The peer-UDP **reask consume** flow (flow L, ADR-0057).
///
/// A stock aMule, queued on rmule and disconnected, is the ADR-0057 consume
/// counterparty: its own ~21.4-min timer should emit `OP_REASKFILEPING`
/// (`0x90`) toward rmule's client-UDP endpoint. rmule serves with a **single**
/// upload slot (`--upload-slots 1`), a throttled slot-holder aMule occupies it,
/// and a second aMule is therefore held **queued** — it receives an
/// `OP_QUEUERANKING`, hangs up (aMule's "ask, learn rank, hang up" lifecycle),
/// and enters rmule's disconnected standing. A passive tcpdump on rmule's own
/// network namespace records every datagram the reasker sends across the
/// `FILEREASKTIME` window.
///
/// This is the **capture-bearing** live attempt. It is **CLI/sweep-only**
/// (the ~25-min wall-clock wait keeps it out of the `RMULE_BENCH` fast suite).
/// The captured fact is a counterparty observation either way: rmule's own hello
/// advertises **no** `CT_EMULE_UDPPORTS` client-UDP port (Honest Capability
/// Advertisement — it binds no live client-UDP socket; the ADR-0057 socket
/// unification is deferred), so the reasker learns no UDP port for rmule and its
/// `UDPReaskForDownload` gate never opens — no `0x90` is emitted. The flow
/// records the reasker's UDP datagram count toward rmule (the ADR-0045 evidence),
/// which the sweep reports as the observed behavior.
pub fn run_peer_udp_reask(options: PeerUdpReaskOptions<'_>) -> Result<()> {
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
    let holder = format!("rmule-interop-amule-holder-{suffix}");
    let reasker = format!("rmule-interop-amule-reasker-{suffix}");
    let capture = format!("rmule-interop-reask-capture-{suffix}");

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
    let capture_dir = options.layout.root().join("reask-capture");
    fs::create_dir_all(&capture_dir)
        .with_context(|| format!("create {}", capture_dir.display()))?;

    let result = (|| -> Result<()> {
        let subnet = crypt_subnet(options.peer_crypt, options.peer_crypt_flip)?;
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

        // rmule serve with a single upload slot so a second requester queues.
        let rmule_name = bench.names.rmule_container_name.clone();
        bench.start_rmule_serve(
            options.layout,
            options.rmule_serve_container,
            ServeKnobs {
                upload_slots: Some(1),
                peer_crypt: options.peer_crypt,
                peer_crypt_flip: options.peer_crypt_flip,
                identity_dir: None,
            },
            timeout,
        )?;

        let rmule_ip = run_checked(
            bench.docker.container_ip(rmule_name.clone()),
            "inspect rmule ip",
        )?;
        let ed2k_link = fs::read_to_string(options.layout.synthetic_ed2k_file())
            .with_context(|| format!("read {}", options.layout.synthetic_ed2k_file().display()))?;
        let sourced =
            ed2k_link_with_source(ed2k_link.trim(), rmule_ip.trim(), RMULE_SERVE_TCP_PORT);

        // Passive tap on rmule's own netns. Everything on the isolated net: the
        // serve-TCP exchange, any UDP, AND the eserver leg (port 4661) — aMule's
        // reask cycle is `theApp->IsConnected()`-gated (PartFile.cpp:1461/1476),
        // so the reasker's server-connection state at due-time is itself evidence.
        let tap = CaptureSidecar {
            image: options.capture_image,
            name: &capture,
            target_container: &rmule_name,
            interface: DEFAULT_TAP_INTERFACE,
            host_dir: capture_dir.clone(),
            pcap_file: "reask.pcap",
            bpf: "tcp or udp",
        };
        bench.start_extra(&capture, tap.container(), "run reask tcpdump sidecar")?;

        // Slot-holder: throttled so its download of the large shared file never
        // completes, keeping rmule's single slot occupied for the whole window.
        let holder_container = bench
            .amule_container(options.amule_image, &holder)
            .env("AMULE_DOWNLOAD_LINK", sourced.as_str())
            .env("AMULE_DOWNLOAD_NO_WAIT", "1")
            .env("AMULE_MAX_DOWNLOAD", REASK_HOLDER_THROTTLE_KIB)
            .env_assignments(options.amule_env);
        bench.start_extra(&holder, holder_container, "run slot-holder aMule")?;
        wait_for_amule_ready(
            &bench.docker,
            options.layout,
            &holder,
            timeout,
            "rmule-amule-download-sources-ready",
        )?;

        // Reasker: with the slot held, its request is queued (not granted).
        let reasker_container = bench
            .amule_container(options.amule_image, &reasker)
            .env("AMULE_DOWNLOAD_LINK", sourced.as_str())
            .env("AMULE_DOWNLOAD_NO_WAIT", "1")
            .env_assignments(options.amule_env);
        bench.start_extra(&reasker, reasker_container, "run reasker aMule")?;
        wait_for_amule_ready(
            &bench.docker,
            options.layout,
            &reasker,
            timeout,
            "rmule-amule-download-sources-ready",
        )?;
        let reasker_ip = run_checked(
            bench.docker.container_ip(reasker.clone()),
            "inspect reasker ip",
        )?;

        // Confirm rmule queued the reasker (the OP_QUEUERANKING wire). The
        // log is collected again once the window has ended, so the retained
        // copy covers the whole run.
        let rmule_log = collect_rmule_logs(
            &bench.docker,
            options.layout,
            &bench.names.rmule_container_name,
        )?;
        let queued = rmule_log.contains("serve.peer_queued");
        println!(
            "peer_udp_reask queued_by_rmule={queued} reasker_ip={}",
            reasker_ip.trim()
        );

        // Sit the FILEREASKTIME window. The tap records whatever the reasker
        // emits toward rmule; the operator lets the CLI run.
        sit_tap_window(
            "peer_udp_reask",
            Duration::from_secs(options.reask_window_secs),
        );

        // Harvest: count the reasker's UDP datagrams toward rmule (the 0x90
        // reask evidence). Zero ⇒ no peer-UDP reask reached rmule.
        let reask_udp = run_checked(
            bench.docker.exec(
                capture.clone(),
                [
                    OsString::from("sh"),
                    OsString::from("-c"),
                    OsString::from(format!(
                        "tcpdump -nr {} 'udp and src host {}' 2>/dev/null | wc -l",
                        tap.pcap_path(),
                        reasker_ip.trim()
                    )),
                ],
            ),
            "count reasker udp",
        )?;
        println!(
            "peer_udp_reask result queued={queued} reask_udp_datagrams={} (0 ⇒ no OP_REASKFILEPING reached rmule)",
            reask_udp.trim()
        );
        if !options.peer_crypt_flip.is_empty() {
            let rmule_log = collect_rmule_logs(
                &bench.docker,
                options.layout,
                &bench.names.rmule_container_name,
            )?;
            println!(
                "peer_udp_reask obfuscation_flips={}",
                crate::flow::evidence::toml_strings(&crate::flow::evidence::obfuscation_flips(
                    &rmule_log
                ))
            );
        }

        // Persist every log after the window, so each covers the whole run:
        // the reasker's server-connection lifecycle ("Connection lost"/re-login
        // attempts) is the IsConnected()-gate evidence the pcap alone can't
        // show. The two aMules write to their own role paths.
        collect_rmule_logs(
            &bench.docker,
            options.layout,
            &bench.names.rmule_container_name,
        )?;
        collect_amule_role_logs(&bench.docker, options.layout, "holder", &holder)?;
        collect_amule_role_logs(&bench.docker, options.layout, "reasker", &reasker)?;
        collect_server_logs(
            &bench.docker,
            options.layout,
            &bench.names.server_container_name,
        )?;

        // Score the retained tap: the verdict file is what a re-score reads.
        verdict::write(
            options.layout.root(),
            &verdict::ReaskRun {
                pcap: &capture_dir.join("reask.pcap"),
                rmule: rmule_ip.trim().parse().context("rmule address")?,
                reasker: reasker_ip.trim().parse().context("reasker address")?,
                file_hash: parse_ed2k_file_hash(ed2k_link.trim())?,
                file_size: fs::metadata(options.layout.synthetic_shared_file())
                    .context("stat the shared file")?
                    .len(),
                crypt: options.peer_crypt.is_some(),
                flips: tap::Flip::read_run_dir(options.layout.root()),
            },
        )?;
        Ok(())
    })();

    if options.keep_containers {
        println!("kept_capture_dir={}", capture_dir.display());
    }
    bench.cleanup_best_effort();
    result
}
