//! The last leg of `peer-hello-surface`: kno's aMule, its IPv6 verified by the
//! leg before, **dials rmule**.
//!
//! Once kno has verified its own IPv6 address its hellos count
//! `CT_MOD_IP_V6` and never write it — the over-counted answer the leg before
//! reads. Its `OP_HELLO` is built by the same writer, so a serving rmule that
//! kno dials should see the short hello on the inbound road and refuse it
//! (`adapters/inbound_triage.rs`). A fresh serving rmule offers file `E`,
//! kno is told to download it and learns rmule from the server; kno's
//! `OP_HELLO` to rmule is cut from kno's own tap and read with rmule's hello
//! reader, and the serving rmule's `peer_hello_refused` line is its own half.

use std::time::Duration;

use anyhow::{Context, Result};

use super::after_meeting::{refusal_of, tap_of};
use super::transfer::add_download;
use super::{CLIENTS, Client, Kind, keep_log};
use crate::flow::bench::Bench;
use crate::flow::bench::CAPTURE_MOUNT;
use crate::flow::evidence::write_pcap_all_matches;
use crate::flow::gate::wait_for_container_log;
use crate::flow::nat::dialect::bench::{
    HOST_AMULE_KNO, HOST_ED2KSRV, Ipv6DialectOptions, Stage, start_detached_driver,
};
use crate::flow::nat::dialect::verdict::{Claim, Evidence};
use crate::flow::nat::dialect::{BODY_PEER_TCP_PORT, ED2KSRV_TCP_PORT};
use crate::flow::nat::synthetic::write_hashed;
use crate::flow::pcap::tcp_streams;
use rmule_peer::HelloRefusalCode;

/// `E`'s size: one part.
const SERVED_E_BYTES: u64 = (2 << 20) + 3_331;
/// The serving rmule's host slot: the transfer leg's downloader from kno held
/// it and has exited. kno met that address under another user hash, which
/// does not shape the hello it writes.
const SERVE_E_HOST: usize = 7;
const SERVE_E_ROLE: &str = "hsknodial";
/// A user hash of its own, so kno meets a stranger rather than the rmule it
/// already knows.
const SERVE_E_HASH: &str = "C47E0B2D91A35F6883E1D7A0B52C9F46";
const SERVE_E_SECS: u64 = 240;
/// How long kno has to find rmule through the server and dial it.
const KNO_DIAL_WAIT_SECS: u64 = 120;
const OFFER_SETTLE_SECS: u64 = 20;
const OP_HELLO: (u8, u8) = (0xE3, 0x01);

/// Run the leg and return its claims.
///
/// # Errors
/// If the serving rmule cannot start or kno cannot be told to download.
pub(super) fn kno_dials_rmule(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
) -> Result<Vec<Claim>> {
    let e_dir = stage.leg_dir.join("serve-e");
    std::fs::create_dir_all(&e_dir).with_context(|| format!("create {}", e_dir.display()))?;
    let shared_e = write_hashed(&e_dir, SERVED_E_BYTES)?;
    let server = format!("{}:{ED2KSRV_TCP_PORT}", stage.v4(HOST_ED2KSRV));
    let serve_v4 = stage.v4(SERVE_E_HOST).to_owned();
    let args = [
        "ed2k",
        "serve",
        "start",
        "--file",
        "/out/serve-e/shared.bin",
        "--server",
        &server,
        "--listen",
        &format!("0.0.0.0:{BODY_PEER_TCP_PORT}"),
        "--own-ip",
        &serve_v4,
        "--user-hash",
        SERVE_E_HASH,
        "--max-seconds",
        &SERVE_E_SECS.to_string(),
    ]
    .map(str::to_owned);
    let (serve, announced) = start_detached_driver(
        bench,
        options,
        stage,
        SERVE_E_ROLE,
        SERVE_E_HOST,
        &args,
        "serve files_announced",
    )?;
    if !announced {
        let log = keep_log(bench, stage, &serve, "rmule-serve-e");
        anyhow::bail!(
            "the rmule kno should dial never announced its file: {}",
            log.lines().last().unwrap_or_default()
        );
    }
    std::thread::sleep(Duration::from_secs(OFFER_SETTLE_SECS));
    let kno = kno_amule()?;
    add_download(bench, options, stage, kno, &shared_e.link)?;
    let refused = wait_for_container_log(
        &bench.docker,
        &serve,
        "peer_hello_refused",
        Duration::from_secs(KNO_DIAL_WAIT_SECS),
    )
    .is_ok();
    let serve_log = keep_log(bench, stage, &serve, "rmule-serve-e");

    let kno_v4 = stage.v4(HOST_AMULE_KNO).to_owned();
    let out = "amule-kno-dials-rmule.pcap";
    write_pcap_all_matches(
        &bench.docker,
        &tap_of(options, kno)?,
        &format!("{CAPTURE_MOUNT}/tap-{}.pcap", kno.name),
        &format!("tcp and host {kno_v4} and host {serve_v4}"),
        out,
    )?;
    let streams = tcp_streams(&stage.leg_dir.join(out))?;
    let kno_ip: std::net::IpAddr = kno_v4.parse().context("kno address")?;
    let hellos: Vec<_> = streams
        .iter()
        .filter(|stream| stream.source.ip() == kno_ip)
        .flat_map(|stream| stream.ed2k_frames())
        .filter(|frame| (frame.protocol, frame.opcode) == OP_HELLO)
        .collect();
    if let Some(first) = hellos.first() {
        std::fs::write(
            stage.leg_dir.join("op-hello-amule-kno-verified.bin"),
            &first.bytes,
        )
        .context("write kno's verified OP_HELLO")?;
    }
    let short = hellos
        .iter()
        .filter(|frame| {
            matches!(
                refusal_of(&frame.bytes),
                Some(HelloRefusalCode::TagCountShort { .. })
            )
        })
        .count();
    let named = serve_log
        .lines()
        .find(|line| line.contains("peer_hello_refused"))
        .map(str::trim)
        .unwrap_or_default()
        .to_owned();
    Ok(vec![
        Claim::about(
            "amule-kno-dials-rmule-with-an-over-counted-hello",
            short > 0,
            Evidence::Captured,
            format!(
                "kno, its IPv6 verified, told to fetch E from a serving rmule it had not met: \
                 {} OP_HELLO(s) from kno on its own tap toward rmule, {short} of them counting \
                 a tag they never carry (read with rmule's hello reader); the first is \
                 `op-hello-amule-kno-verified.bin`",
                hellos.len(),
            ),
        ),
        Claim::about(
            "rmule-refuses-knos-over-counted-hello-inbound",
            refused && !named.is_empty(),
            Evidence::RmuleOnly,
            format!("the serving rmule's line for kno's hello: {named:?}"),
        ),
    ])
}

pub(super) fn kno_amule() -> Result<&'static Client> {
    CLIENTS
        .iter()
        .find(|c| c.kind == Kind::AmuleKno)
        .context("kno's aMule body")
}
