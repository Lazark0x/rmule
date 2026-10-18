//! The holepunch-fail leg: `ed2ksrv`'s `OP_LOWID_HOLEPUNCH_FAIL` (`0x62`),
//! the server's refusal of an introduction (ADR-0091).
//!
//! The punch flows only ever drew the `0x61` introduction, so rmule's `0x62`
//! decoder rests on hand-written vectors. Here one `ed2k server probe` logs in
//! to `ed2ksrv` riding `CT_EMULE_UDPPORTS`, and asks for a punch toward a Low
//! ID nobody holds; a punch-capable server refuses it with `0x62`, naming the
//! target and why. A tap in the server's namespace records both frames, and
//! the refusal is cut from it whole into `holepunch_fail_0x62.bin` for fixture
//! promotion — the server's bytes, never re-encoded.

use std::fs;
use std::net::{SocketAddr, SocketAddrV4};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::artifacts::RunLayout;
use crate::flow::bench::{Bench, CaptureSidecar, DEFAULT_TAP_INTERFACE, ED2K_SERVER_PORT};
use crate::flow::ed2k_server::search_wire::{ED2KSRV_IP, SUBNET, start_ed2ksrv};
use crate::flow::gate::wait_for_container_log;
use crate::flow::logs::collect_server_logs;
use crate::flow::nat::claims::{Claim, Evidence, label};
use crate::flow::pcap::{Ed2kFrame, TcpStream, records, tcp_capture};
use crate::flow::wire_filter::OP_EDONKEYPROT;
use crate::rmule::{ProbeAsks, RmuleClientContainer};

/// The flow's name and its verdict file's stem.
pub(crate) const FLOW: &str = "ed2ksrv-holepunch-fail";
/// Where the flow's own artifacts sit under the run dir.
pub(crate) const ROOT_DIR: &str = "holepunch-fail";
/// The tap in `ed2ksrv`'s namespace.
pub(crate) const SERVER_PCAP: &str = "server.pcap";
/// The refusal, cut whole from the tap.
pub(crate) const REFUSAL_FRAME: &str = "holepunch_fail_0x62.bin";
/// A Low ID no client holds: the server has nobody to introduce. Its four
/// bytes differ, so the refusal's byte order is read, not assumed.
pub(crate) const GHOST_LOW_ID: u32 = 0x00FE_DCBA;
/// The client-UDP port the probe's `0xF9` names.
const PROBE_UDP_PORT: u16 = 4672;

/// `OP_LOWID_HOLEPUNCH_REQUEST`.
const OP_HOLEPUNCH_REQUEST: u8 = 0x60;
/// `OP_LOWID_HOLEPUNCH_FAIL`.
const OP_HOLEPUNCH_FAIL: u8 = 0x62;
/// The refusal reason for a target no connected client holds
/// (`src/server/holepunch.rs:74-77`).
const REASON_TARGET_NOT_CONNECTED: u8 = 1;

/// Options for [`run_holepunch_fail`].
pub struct HolepunchFailOptions<'a> {
    /// The run dir every artifact is written under.
    pub layout: &'a RunLayout,
    /// The Docker-compatible CLI to invoke.
    pub container_runtime: &'a str,
    /// Build the counterparty images before starting anything.
    pub build_images: bool,
    /// Leave the containers and network running after the run.
    pub keep_containers: bool,
    /// Per-step readiness budget, in seconds.
    pub timeout_secs: u64,
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
    /// The rust image + workspace the probe runs in.
    pub rmule_client_container: &'a RmuleClientContainer,
}

/// Drive the leg and write its verdict.
///
/// # Errors
/// If `ed2ksrv` or the probe cannot be started, or the run cannot be scored.
pub fn run_holepunch_fail(options: HolepunchFailOptions<'_>) -> Result<()> {
    let mut bench = Bench::new(
        options.container_runtime,
        options.layout,
        options.keep_containers,
    )?;
    if options.build_images {
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
    let root = options.layout.root().join(ROOT_DIR);
    fs::create_dir_all(&root).with_context(|| format!("create {}", root.display()))?;
    let timeout = Duration::from_secs(options.timeout_secs);

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
        let tap = format!("{ed2ksrv}-tap");
        let sidecar = CaptureSidecar {
            image: options.capture_image,
            name: &tap,
            target_container: &ed2ksrv,
            interface: DEFAULT_TAP_INTERFACE,
            host_dir: root.clone(),
            pcap_file: SERVER_PCAP,
            bpf: "tcp port 4661",
        };
        bench.start_extra(&tap, sidecar.container(), "run the server tap")?;
        wait_for_container_log(&bench.docker, &tap, "listening on", timeout)?;

        let server = format!("{ED2KSRV_IP}:{ED2K_SERVER_PORT}");
        let probe = options.rmule_client_container.probe_command(
            bench.staging(options.layout),
            &server,
            ProbeAsks {
                udp_ports_advert: Some(PROBE_UDP_PORT),
                advertise_ipv6: None,
                holepunch_target: Some(GHOST_LOW_ID),
            },
        );
        let output = probe
            .to_command()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("run the holepunch probe")?;
        let mut log = String::from_utf8_lossy(&output.stdout).into_owned();
        log.push_str(&String::from_utf8_lossy(&output.stderr));
        fs::write(root.join("probe.log"), &log).context("write the probe log")?;
        collect_server_logs(&bench.docker, options.layout, &ed2ksrv)?;
        let verdict = score_run_dir(options.layout.root())?;
        println!("{FLOW} verdict={verdict}");
        Ok(())
    })();

    if result.is_err() {
        bench.collect_failure_logs(options.layout);
        if let Some(ed2ksrv) = &ed2ksrv_started
            && let Err(error) = collect_server_logs(&bench.docker, options.layout, ed2ksrv)
        {
            eprintln!("warning: failed to collect the ed2ksrv logs: {error:#}");
        }
    }
    bench.cleanup_best_effort();
    result
}

/// The counts a verdict reports beside its claims.
#[derive(Debug, Default, Serialize, PartialEq)]
pub(crate) struct Rows {
    /// `0x60`s that reached the server naming the ghost id.
    pub(crate) requests_server_tap: usize,
    /// `0x62`s the server sent the asker.
    pub(crate) refusals_server_tap: usize,
    /// The first refusal's reason byte, `-1` when none came.
    pub(crate) reason: i64,
    /// The first refusal's whole length, header included.
    pub(crate) refusal_frame_bytes: usize,
}

/// The verdict file.
#[derive(Debug, Serialize)]
struct Verdict<'a> {
    #[serde(rename = "scenario")]
    flow: &'static str,
    verdict: &'static str,
    detail: String,
    ed2ksrv_pin: &'a str,
    rows: &'a Rows,
    claim: &'a [Claim],
}

/// Score the retained run at `run_dir`: cut the refusal into its own file,
/// write the verdict, print it, and return the label.
///
/// # Errors
/// If the tap is missing or unreadable — a broken run, never a zero.
pub fn score_run_dir(run_dir: &Path) -> Result<&'static str> {
    let root = run_dir.join(ROOT_DIR);
    let capture = tcp_capture(&records(&root.join(SERVER_PCAP))?)?;
    let frames: Vec<Ed2kFrame> = capture
        .streams
        .iter()
        .flat_map(TcpStream::ed2k_frames)
        .collect();
    let server = SocketAddr::V4(SocketAddrV4::new(
        ED2KSRV_IP.parse().context("ed2ksrv address")?,
        ED2K_SERVER_PORT,
    ));
    let (claims, rows, refusal) = claims(server, &frames);
    if let Some(refusal) = refusal {
        let path = root.join(REFUSAL_FRAME);
        fs::write(&path, &refusal.bytes).with_context(|| format!("write {}", path.display()))?;
    }
    let pin = fs::read_to_string(root.join("ed2ksrv-pin.txt")).unwrap_or_default();
    let (verdict, detail) = label(&claims);
    let text = toml::to_string_pretty(&Verdict {
        flow: FLOW,
        verdict,
        detail,
        ed2ksrv_pin: pin.trim(),
        rows: &rows,
        claim: &claims,
    })
    .context("serialize the verdict")?;
    let path = run_dir.join(format!("{FLOW}-verdict.toml"));
    fs::write(&path, &text).with_context(|| format!("write {}", path.display()))?;
    println!("{text}");
    Ok(verdict)
}

/// The leg's claims and rows over the server tap's frames, and the refusal
/// frame to cut out.
pub(crate) fn claims(
    server: SocketAddr,
    frames: &[Ed2kFrame],
) -> (Vec<Claim>, Rows, Option<&Ed2kFrame>) {
    let names_ghost = |f: &Ed2kFrame| {
        f.payload()
            .get(..4)
            .is_some_and(|id| id == GHOST_LOW_ID.to_le_bytes())
    };
    let requests: Vec<&Ed2kFrame> = frames
        .iter()
        .filter(|f| {
            f.destination == server
                && (f.protocol, f.opcode) == (OP_EDONKEYPROT, OP_HOLEPUNCH_REQUEST)
                && names_ghost(f)
        })
        .collect();
    let request = requests.first().copied();
    let refusals: Vec<&Ed2kFrame> = frames
        .iter()
        .filter(|f| {
            f.source == server
                && request.is_some_and(|r| f.destination == r.source && f.at >= r.at)
                && (f.protocol, f.opcode) == (OP_EDONKEYPROT, OP_HOLEPUNCH_FAIL)
        })
        .collect();
    let refusal = refusals.first().copied();
    let reason = refusal.and_then(|f| f.payload().get(4).copied());
    let claims = vec![
        Claim::about(
            "the-probe-asked-a-punch-toward-a-low-id-nobody-holds",
            request.is_some(),
            Evidence::RmuleOnly,
            request.map_or_else(
                || format!("no 0x60 naming {GHOST_LOW_ID:#x} reached the server"),
                |r| format!("0x60 from {} at {:.3}", r.source, r.at),
            ),
        ),
        Claim::about(
            "the-server-refused-it-with-0x62-naming-the-target",
            refusal.is_some_and(names_ghost),
            Evidence::Captured,
            refusal.map_or_else(
                || "no 0x62 came back to the asker".to_owned(),
                |f| {
                    format!(
                        "0x62 at {:.3}, {}-byte body, cut into {REFUSAL_FRAME}",
                        f.at,
                        f.payload().len()
                    )
                },
            ),
        ),
        Claim::about(
            "the-refusal-reads-target-not-connected",
            reason == Some(REASON_TARGET_NOT_CONNECTED),
            Evidence::Captured,
            reason.map_or_else(
                || "no reason byte was read".to_owned(),
                |byte| format!("reason byte {byte}"),
            ),
        ),
    ];
    let rows = Rows {
        requests_server_tap: requests.len(),
        refusals_server_tap: refusals.len(),
        reason: reason.map_or(-1, i64::from),
        refusal_frame_bytes: refusal.map_or(0, |f| f.bytes.len()),
    };
    (claims, rows, refusal)
}

#[cfg(test)]
mod tests;
