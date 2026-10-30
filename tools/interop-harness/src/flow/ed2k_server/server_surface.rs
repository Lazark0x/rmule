//! The `ed2ksrv-server-surface` leg: what the pinned server draws of the rows
//! that had no other counterparty.
//!
//! - **A crypt-pong under a key learned from a plain advert.** `ed2k server
//!   crypt-pong` takes the server's UDP key and obfuscation port off its plain
//!   `0x97`, seals a `0x96` under that key, and keeps both answers
//!   (`crypt-pong/`). The crypt ping's answer is keyed on rmule's own
//!   challenge; this one is the keying every later server datagram rides.
//! - **A Sentinel Source, to a Low-ID requester only.** On `config-ipv6.toml`
//!   one Low-ID client offers a file and names an IPv6 in its login; a second
//!   Low-ID client naming an IPv6 asks for it and must read a sentinel; a third
//!   naming none must read the classic record for the same source.
//!   ed2k-server's rule is `get_sources.rs:131-133`.
//! - **`0x26` and the `OP_SERVERLIST` v6 block.** The pin writes neither:
//!   `build_tcp_server_list` is IPv4 records and nothing after them, and
//!   `build_callbackrequested` has no IPv6 form because an IPv6 session is
//!   never High ID. The leg measures that on the server's tap and records a
//!   **Documented Absence** (ADR-0045), so a later pin that starts writing them
//!   fails this row instead of passing unnoticed.

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use rmule_primitives::{ServerCryptDirection, decrypt_datagram_server};
use serde::Serialize;

use crate::artifacts::RunLayout;
use crate::docker::RunContainer;
use crate::flow::bench::{
    Bench, CaptureSidecar, DEFAULT_TAP_INTERFACE, ED2K_SERVER_PORT, run_checked,
};
use crate::flow::ed2k_server::rmule_tools::run_to_exit;
use crate::flow::ed2k_server::search_wire::{ED2KSRV_IP, SUBNET, start_ed2ksrv};
use crate::flow::gate::wait_for_container_log;
use crate::flow::logs::collect_server_logs;
use crate::flow::nat::claims::{Claim, DriverRow, Evidence, label};
use crate::flow::pcap::{Ed2kFrame, TcpStream, records, tcp_capture};
use crate::flow::wire_filter::OP_EDONKEYPROT;

/// The flow's name and its verdict file's stem.
pub(crate) const FLOW: &str = "ed2ksrv-server-surface";
/// Where the flow's artifacts sit under the run dir.
pub(crate) const ROOT_DIR: &str = "server-surface";
/// The tap in `ed2ksrv`'s namespace.
pub(crate) const SERVER_PCAP: &str = "server.pcap";
/// The crypt-pong leg's output directory.
const CRYPT_DIR: &str = "crypt-pong";
/// The plain advert and the sealed answer, as `ed2k server crypt-pong` names them.
const PLAIN_REPLY: &str = "status_res_0x97_plain.bin";
const SEALED_REPLY: &str = "status_res_0x97_crypt.bin";
/// The file the source offers.
const FILE_HASH: &str = "A1B2C3D4E5F60718293A4B5C6D7E8F90";
/// How long the source stays logged in; the two asks run inside it.
const SOURCE_WINDOW_SECS: u64 = 45;
/// How long each asker reads.
const ASK_WINDOW_SECS: u64 = 8;

const CRYPT_IP: &str = "203.0.113.50";
const SOURCE_IP: &str = "203.0.113.51";
const CAPABLE_IP: &str = "203.0.113.52";
const LEGACY_IP: &str = "203.0.113.53";
/// RFC 9637 addresses: `is_publishable_ipv6` publishes them, no route needed.
const SOURCE_V6: &str = "3fff:ed2:1::51";
const CAPABLE_V6: &str = "3fff:ed2:1::52";

/// `OP_SERVERLIST`.
const OP_SERVERLIST: u8 = 0x32;
/// `OP_CALLBACKREQUESTED_IPV6`.
const OP_CALLBACKREQUESTED_IPV6: u8 = 0x26;

/// Options for [`run_server_surface`].
pub struct ServerSurfaceOptions<'a> {
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
    /// The `ed2ksrv` IPv6 bench config; its `this_ip` is rendered per run.
    pub ed2ksrv_config: &'a Path,
    /// The tcpdump capture-sidecar image.
    pub capture_image: &'a str,
    /// Build context for the capture-sidecar image.
    pub capture_build_context: &'a Path,
    /// The `rmule-tools` image, built from the tip under test.
    pub rmule_tools_image: &'a str,
}

/// Drive the leg and write its verdict.
///
/// # Errors
/// If `ed2ksrv` or a driver cannot be started, or the run cannot be scored.
pub fn run_server_surface(options: ServerSurfaceOptions<'_>) -> Result<()> {
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

    let mut started: Option<String> = None;
    let result = (|| -> Result<()> {
        bench.create_network(options.layout, Some(SUBNET))?;
        let ed2ksrv = start_ed2ksrv(
            &mut bench,
            options.ed2ksrv_image,
            options.ed2ksrv_config,
            &root,
            timeout,
        )?;
        started = Some(ed2ksrv.clone());
        let tap = format!("{ed2ksrv}-tap");
        let sidecar = CaptureSidecar {
            image: options.capture_image,
            name: &tap,
            target_container: &ed2ksrv,
            interface: DEFAULT_TAP_INTERFACE,
            host_dir: root.clone(),
            pcap_file: SERVER_PCAP,
            bpf: "tcp port 4661 or udp portrange 4661-4680",
        };
        bench.start_extra(&tap, sidecar.container(), "run the server tap")?;
        wait_for_container_log(&bench.docker, &tap, "listening on", timeout)?;
        drive(&mut bench, &options, &root, &ed2ksrv, timeout)?;
        bench.stop_extra(&tap);
        collect_server_logs(&bench.docker, options.layout, &ed2ksrv)?;
        let verdict = score_run_dir(options.layout.root())?;
        println!("{FLOW} verdict={verdict}");
        Ok(())
    })();

    if result.is_err() {
        bench.collect_failure_logs(options.layout);
        if let Some(ed2ksrv) = &started
            && let Err(error) = collect_server_logs(&bench.docker, options.layout, ed2ksrv)
        {
            eprintln!("warning: failed to collect the ed2ksrv logs: {error:#}");
        }
    }
    bench.cleanup_best_effort();
    result
}

/// The server probe's argv for one session.
fn probe_args<'a>(
    server: &'a str,
    advertise: Option<&'a str>,
    user_hash: &'a str,
    capture: &'a str,
    out: &'a str,
    window: &'a str,
) -> Vec<&'a str> {
    let mut args = vec![
        "ipv6",
        "server-probe",
        "--server",
        server,
        "--user-hash",
        user_hash,
        "--capture",
        capture,
        "--out",
        out,
        "--window-secs",
        window,
    ];
    if let Some(address) = advertise {
        args.extend(["--advertise-ipv6", address]);
    }
    args
}

fn drive(
    bench: &mut Bench,
    options: &ServerSurfaceOptions<'_>,
    root: &Path,
    ed2ksrv: &str,
    timeout: Duration,
) -> Result<()> {
    let image = options.rmule_tools_image;
    let server = format!("{ED2KSRV_IP}:{ED2K_SERVER_PORT}");
    let crypt = format!("{ed2ksrv}-crypt");
    run_to_exit(
        bench,
        image,
        &crypt,
        CRYPT_IP,
        root,
        &[
            "ed2k",
            "server",
            "crypt-pong",
            &server,
            "--out",
            &format!("/w/{CRYPT_DIR}"),
        ],
    )?;

    let source = format!("{ed2ksrv}-source");
    let source_window = SOURCE_WINDOW_SECS.to_string();
    let mut args = probe_args(
        &server,
        Some(SOURCE_V6),
        "51515151515151515151515151515151",
        "/w/source-capture",
        "/w/source.toml",
        &source_window,
    );
    args.extend(["--offer-file", FILE_HASH]);
    let container = args.into_iter().fold(
        RunContainer::new(image.to_owned())
            .detach()
            .name(&source)
            .network(bench.names.network_name.clone())
            .ip(SOURCE_IP)
            .env("RMULE_LOG", "info")
            .volume(root, "/w"),
        RunContainer::arg,
    );
    bench.start_extra(&source, container, "run the offering client")?;
    wait_for_container_log(&bench.docker, &source, "ipv6-server-probe offered", timeout)?;

    let ask_window = ASK_WINDOW_SECS.to_string();
    for (name, ip, advertise, user_hash, leg) in [
        (
            "capable",
            CAPABLE_IP,
            Some(CAPABLE_V6),
            "52525252525252525252525252525252",
            "capable",
        ),
        (
            "legacy",
            LEGACY_IP,
            None,
            "53535353535353535353535353535353",
            "legacy",
        ),
    ] {
        let capture = format!("/w/{leg}-capture");
        let out = format!("/w/{leg}.toml");
        let mut args = probe_args(&server, advertise, user_hash, &capture, &out, &ask_window);
        args.extend(["--file-hash", FILE_HASH]);
        run_to_exit(bench, image, &format!("{ed2ksrv}-{name}"), ip, root, &args)?;
    }
    run_checked(
        bench.docker.wait(source.clone()),
        "wait for the offering client",
    )?;
    Ok(())
}

/// The crypt-pong leg as read off the two replies.
#[derive(Debug, Default, PartialEq, Serialize)]
pub(crate) struct CryptPong {
    /// The UDP key the plain advert named, `0` when none.
    pub(crate) learned_key: u32,
    /// The obfuscation UDP port the plain advert named, `0` when none.
    pub(crate) sealed_port: u16,
    /// The sealed answer's first byte was no plain eD2k marker.
    pub(crate) reply_sealed: bool,
    /// It opened under the learned key to a `0x97`.
    pub(crate) opened: bool,
}

/// Where a `0x97` body keeps the obfuscation UDP port, then the TCP one, then
/// the key: after eight 32-bit fields (challenge … low-ID users).
const CRYPT_FACTS_AT: usize = 2 + 32;

/// The obfuscation UDP port and the key a `0x97` names.
fn crypt_facts(status: &[u8]) -> Option<(u16, u32)> {
    if status.get(..2)? != [0xE3, 0x97] {
        return None;
    }
    let facts = status.get(CRYPT_FACTS_AT..CRYPT_FACTS_AT + 8)?;
    Some((
        u16::from_le_bytes([facts[0], facts[1]]),
        u32::from_le_bytes([facts[4], facts[5], facts[6], facts[7]]),
    ))
}

/// Read the two replies.
pub(crate) fn read_crypt_pong(plain: Option<&[u8]>, sealed: Option<&[u8]>) -> CryptPong {
    let (sealed_port, learned_key) = plain.and_then(crypt_facts).unwrap_or_default();
    let opened = sealed.is_some_and(|bytes| {
        decrypt_datagram_server(bytes, learned_key, ServerCryptDirection::FromServer)
            .is_some_and(|opened| opened.get(..2) == Some(&[0xE3, 0x97]))
    });
    CryptPong {
        learned_key,
        sealed_port,
        reply_sealed: sealed.is_some_and(|bytes| bytes.first().is_some_and(|byte| *byte != 0xE3)),
        opened,
    }
}

/// The counts a verdict reports beside its claims.
#[derive(Debug, Default, Serialize, PartialEq)]
pub(crate) struct Rows {
    /// The crypt-pong leg.
    pub(crate) crypt_pong: CryptPong,
    /// `OP_IDCHANGE` flags the capable session read.
    pub(crate) capable_tcp_flags: i64,
    /// Sentinels the capable requester read.
    pub(crate) capable_sentinels: i64,
    /// Sentinels and sources the requester with no tag read.
    pub(crate) legacy_sentinels: i64,
    /// Sources the requester with no tag read.
    pub(crate) legacy_sources: i64,
    /// `0x26` frames on the server's tap.
    pub(crate) callback_v6_frames: usize,
    /// `OP_SERVERLIST` frames on the server's tap.
    pub(crate) server_list_frames: usize,
    /// Of those, frames with bytes past their IPv4 records.
    pub(crate) server_list_v6_tails: usize,
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

/// Whether an `OP_SERVERLIST` body runs past its `count` IPv4 records.
fn has_v6_tail(body: &[u8]) -> bool {
    body.first()
        .is_some_and(|count| body.len() > 1 + usize::from(*count) * 6)
}

/// Score the retained run at `run_dir`, write the verdict, print it, and return
/// the label.
///
/// # Errors
/// If the tap or a driver row is missing or unreadable: a broken run, never a
/// zero.
pub fn score_run_dir(run_dir: &Path) -> Result<&'static str> {
    let root = run_dir.join(ROOT_DIR);
    let capture = tcp_capture(&records(&root.join(SERVER_PCAP))?)?;
    let frames: Vec<Ed2kFrame> = capture
        .streams
        .iter()
        .flat_map(TcpStream::ed2k_frames)
        .collect();
    let plain = fs::read(root.join(CRYPT_DIR).join(PLAIN_REPLY)).ok();
    let sealed = fs::read(root.join(CRYPT_DIR).join(SEALED_REPLY)).ok();
    let crypt_pong = read_crypt_pong(plain.as_deref(), sealed.as_deref());
    let capable = DriverRow::read(&root.join("capable.toml"))?;
    let legacy = DriverRow::read(&root.join("legacy.toml"))?;

    let frames_of = |opcode: u8| {
        frames
            .iter()
            .filter(move |frame| (frame.protocol, frame.opcode) == (OP_EDONKEYPROT, opcode))
    };
    let rows = Rows {
        crypt_pong,
        capable_tcp_flags: capable.int("tcp_flags_bits"),
        capable_sentinels: capable.int("sentinel_count"),
        legacy_sentinels: legacy.int("sentinel_count"),
        legacy_sources: legacy.int("source_count"),
        callback_v6_frames: frames_of(OP_CALLBACKREQUESTED_IPV6).count(),
        server_list_frames: frames_of(OP_SERVERLIST).count(),
        server_list_v6_tails: frames_of(OP_SERVERLIST)
            .filter(|frame| has_v6_tail(frame.payload()))
            .count(),
    };
    let sources_named = capable
        .list("ipv6_sources")
        .iter()
        .any(|source| source.contains(SOURCE_V6));
    let claims = claims(&rows, sources_named);
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

/// The leg's claims over its rows. `sources_named` says the capable requester's
/// sources named the offering client's IPv6.
pub(crate) fn claims(rows: &Rows, sources_named: bool) -> Vec<Claim> {
    let pong = &rows.crypt_pong;
    let flags = u32::try_from(rows.capable_tcp_flags).unwrap_or(0);
    vec![
        Claim::about(
            "the-plain-advert-named-a-key-and-an-obfuscation-port",
            pong.learned_key != 0 && pong.sealed_port != 0,
            Evidence::Captured,
            format!(
                "key {:#010x}, UDP port {}",
                pong.learned_key, pong.sealed_port
            ),
        ),
        Claim::about(
            "the-server-answered-sealed-under-that-key",
            pong.reply_sealed && pong.opened,
            Evidence::Captured,
            format!("sealed={} opened={}", pong.reply_sealed, pong.opened),
        ),
        Claim::about(
            "the-server-announced-the-extension-and-the-update",
            flags & 0xC000 == 0xC000,
            Evidence::Captured,
            format!("OP_IDCHANGE flags {flags:#010x}"),
        ),
        Claim::about(
            "a-low-id-requester-with-the-tag-read-a-sentinel-naming-the-source",
            rows.capable_sentinels > 0 && sources_named,
            Evidence::Captured,
            format!(
                "{} sentinels, source named: {sources_named}",
                rows.capable_sentinels
            ),
        ),
        Claim::about(
            "a-requester-without-the-tag-read-the-classic-record",
            rows.legacy_sentinels == 0 && rows.legacy_sources > 0,
            Evidence::Captured,
            format!(
                "{} sentinels, {} sources",
                rows.legacy_sentinels, rows.legacy_sources
            ),
        ),
        Claim::absence(
            "the-pin-writes-no-0x26",
            i64::try_from(rows.callback_v6_frames).unwrap_or(-1),
            "ed2k-server has no IPv6 form of OP_CALLBACKREQUESTED: an IPv6 session is never \
             High ID, so no callback can name an IPv6 requester (`callback.rs:124-129`).",
        ),
        Claim::absence(
            "the-pin-writes-no-serverlist-v6-block",
            i64::try_from(rows.server_list_v6_tails).unwrap_or(-1),
            format!(
                "{} OP_SERVERLIST frames on the tap; `build_tcp_server_list` writes IPv4 \
                 records and stops (`gossip.rs:822`).",
                rows.server_list_frames
            ),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trailing byte is a block even when it says zero entries: the rule is
    /// what the frame holds past its records, which is what a pin that starts
    /// writing the block would change.
    #[test]
    fn a_server_list_with_bytes_past_its_records_has_a_tail() {
        assert!(!has_v6_tail(&[0]));
        assert!(!has_v6_tail(&[1, 1, 2, 3, 4, 0x35, 0x12]));
        assert!(has_v6_tail(&[0, 0]));
    }

    /// The answer counts only if it opens under the key the *advert* named: a
    /// reply sealed under another key, or a plain one, fails the row.
    #[test]
    fn a_crypt_pong_counts_only_under_the_advertised_key() {
        use rmule_primitives::{DatagramNonce, encrypt_datagram_server};

        let key = 0x1234_5678_u32;
        let mut advert = vec![0xE3, 0x97];
        advert.extend_from_slice(&0x55AA_0042_u32.to_le_bytes());
        advert.extend_from_slice(&[0; 28]);
        advert.extend_from_slice(&4675_u16.to_le_bytes());
        advert.extend_from_slice(&4673_u16.to_le_bytes());
        advert.extend_from_slice(&key.to_le_bytes());
        let nonce = DatagramNonce {
            marker_byte: 0x5A,
            random_key: 0xD756,
            padding: Vec::new(),
        };
        let under =
            |key| encrypt_datagram_server(&advert, key, ServerCryptDirection::FromServer, &nonce);

        let good = read_crypt_pong(Some(&advert), Some(&under(key)));
        assert_eq!(good.learned_key, key);
        assert_eq!(good.sealed_port, 4675);
        assert!(good.reply_sealed && good.opened);

        let wrong = read_crypt_pong(Some(&advert), Some(&under(key ^ 1)));
        assert!(wrong.reply_sealed && !wrong.opened);

        let plain = read_crypt_pong(Some(&advert), Some(&advert));
        assert!(!plain.reply_sealed && !plain.opened);
    }
}
