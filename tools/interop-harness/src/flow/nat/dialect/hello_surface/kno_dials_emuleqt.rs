//! The last leg of `peer-hello-surface`: kno's aMule, its IPv6 verified,
//! **dials emule-qt**, the bench's one eMule body, built from the eMule
//! source tree.
//!
//! The emule-qt the flow started is no stranger to kno by now: kno pulled
//! file `A` from it in the transfer leg, before its IPv6 was verified (a
//! nine-tag hello that counts what it writes, run `1790850030`), and a known
//! client is asked again only on aMule's reask clock. So the leg starts a
//! **fresh** emule-qt — its own address and user hash, its own file — and
//! tells kno to download that file: kno learns it from the server and dials
//! at once, with the hello it now writes to everyone, the over-counted one
//! the serving rmule refuses. What emule-qt does with it — `OP_HELLOANSWER`
//! or a hang-up — is read off kno's tap, which carries both directions, and
//! emule-qt's own log.

use std::time::Duration;

use anyhow::{Context, Result};

use super::after_meeting::{refusal_of, tap_of};
use super::kno_dials::kno_amule;
use super::transfer::add_download;
use super::{EMULEQT_HASHED, EMULEQT_READY};
use crate::flow::bench::{Bench, CAPTURE_MOUNT};
use crate::flow::evidence::write_pcap_all_matches;
use crate::flow::gate::wait_for_container_log;
use crate::flow::nat::dialect::bench::{
    HOST_AMULE_KNO, HOST_ED2KSRV, Ipv6DialectOptions, Stage, body_log, container_name,
};
use crate::flow::nat::dialect::verdict::{Claim, Evidence};
use crate::flow::nat::dialect::{BODY_PEER_TCP_PORT, ED2KSRV_TCP_PORT};
use crate::flow::nat::synthetic::write_hashed;
use crate::flow::pcap;
use crate::flow::pinned_image::EMULEQT;
use rmule_peer::HelloRefusalCode;

/// The fresh emule-qt's host slot, on the one /24 this flow's network holds:
/// the transfer leg's downloader from stock aMule had it and has exited. kno
/// never dialled that downloader (it served kno nothing and listened on no
/// port), so the address is a stranger's to kno.
const FRESH_QT_HOST: usize = 5;
const FRESH_QT_ROLE: &str = "hsqtfresh";
/// Its one file: one part, a size no other body shares.
const FRESH_QT_BYTES: u64 = (2 << 20) + 7_919;
/// How long the server gets to take the fresh emule-qt's offer.
const OFFER_SETTLE: Duration = Duration::from_secs(20);
/// How long kno has to find the fresh emule-qt through the server and dial it.
/// aMule sends its next server source request no sooner than 300 s after the
/// last (`DownloadQueue.cpp:1127`, 15 files × 20 s), and the leg before this
/// one sent one when kno added file `E`; run `1790853120` waited 120 s and kno
/// never asked.
const KNO_DIAL_WAIT: Duration = Duration::from_secs(420);
/// How often the leg re-reads kno's tap while it waits for kno's dial.
const TAP_POLL: Duration = Duration::from_secs(10);
const OP_HELLO: (u8, u8) = (0xE3, 0x01);
const OP_HELLOANSWER: (u8, u8) = (0xE3, 0x4C);

/// Run the leg and return its claims: whether kno's hello to the fresh
/// emule-qt was over-counted, and whether emule-qt refused it.
///
/// # Errors
/// If the fresh emule-qt cannot start, kno cannot be told to download, or a
/// tap cannot be lifted.
pub(super) fn kno_dials_emuleqt(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
) -> Result<Vec<Claim>> {
    let kno = kno_amule()?;
    let dir = stage.leg_dir.join("emuleqt-fresh-incoming");
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let file = write_hashed(&dir, FRESH_QT_BYTES)?;
    let qt = container_name(options.layout, FRESH_QT_ROLE)?;
    let qt_v4 = stage.v4(FRESH_QT_HOST).to_owned();
    let pinned = EMULEQT.check(&bench.docker, options.emuleqt_image)?;
    bench.start_extra(
        &qt,
        pinned
            .container()
            .detach()
            .name(&qt)
            .network(&stage.network)
            .ip(&qt_v4)
            .ip6(stage.v6(FRESH_QT_HOST))
            .cap_add("NET_ADMIN")
            .volume(&dir, "/incoming")
            .env("EMULEQT_SCENARIO_MODE", "ed2k-server")
            .env("ED2K_SERVER_HOST", stage.v4(HOST_ED2KSRV))
            .env("ED2K_SERVER_PORT", ED2KSRV_TCP_PORT.to_string()),
        "run a fresh emule-qt for kno to dial",
    )?;
    let timeout = Duration::from_secs(options.timeout_secs);
    wait_for_container_log(&bench.docker, &qt, EMULEQT_READY, timeout)?;
    wait_for_container_log(&bench.docker, &qt, EMULEQT_HASHED, timeout)?;
    std::thread::sleep(OFFER_SETTLE);

    let kno_v4 = stage.v4(HOST_AMULE_KNO).to_owned();
    let kno_ip: std::net::IpAddr = kno_v4.parse().context("kno address")?;
    let out = "amule-kno-dials-emuleqt.pcap";
    let lift = || -> Result<pcap::TcpCapture> {
        write_pcap_all_matches(
            &bench.docker,
            &tap_of(options, kno)?,
            &format!("{CAPTURE_MOUNT}/tap-{}.pcap", kno.name),
            &format!("tcp and host {kno_v4} and host {qt_v4} and port {BODY_PEER_TCP_PORT}"),
            out,
        )?;
        pcap::tcp_capture(&pcap::records(&stage.leg_dir.join(out))?)
    };
    let kno_dials = |stream: &pcap::TcpStream| {
        stream.source.ip() == kno_ip && stream.destination.port() == BODY_PEER_TCP_PORT
    };
    add_download(bench, options, stage, kno, &file.link)?;
    let deadline = std::time::Instant::now() + KNO_DIAL_WAIT;
    let mut capture = lift()?;
    while !capture.streams.iter().any(kno_dials) && std::time::Instant::now() < deadline {
        std::thread::sleep(TAP_POLL);
        capture = lift()?;
    }
    // Let a refusal or an answer land on the connection.
    std::thread::sleep(TAP_POLL);
    let capture = lift()?;
    let qt_log = body_log(bench, stage, &qt, "emuleqt-fresh").unwrap_or_default();

    let mut hellos = 0;
    let mut short = 0;
    let mut answered_short = 0;
    let mut rows = Vec::new();
    for stream in capture.streams.iter().filter(|stream| kno_dials(stream)) {
        let Some(hello) = stream
            .ed2k_frames()
            .into_iter()
            .find(|frame| (frame.protocol, frame.opcode) == OP_HELLO)
        else {
            continue;
        };
        hellos += 1;
        let is_short = matches!(
            refusal_of(&hello.bytes),
            Some(HelloRefusalCode::TagCountShort { .. })
        );
        if is_short && short == 0 {
            std::fs::write(
                stage.leg_dir.join("op-hello-amule-kno-to-emuleqt.bin"),
                &hello.bytes,
            )
            .context("write kno's OP_HELLO to emule-qt")?;
        }
        short += usize::from(is_short);
        let answer = capture
            .streams
            .iter()
            .filter(|back| back.source == stream.destination && back.destination == stream.source)
            .flat_map(pcap::TcpStream::ed2k_frames)
            .find(|frame| (frame.protocol, frame.opcode) == OP_HELLOANSWER && frame.at >= hello.at);
        answered_short += usize::from(is_short && answer.is_some());
        let closed = capture
            .closes
            .iter()
            .find(|close| {
                close.at >= stream.opened_at()
                    && ((close.source == stream.source && close.destination == stream.destination)
                        || (close.source == stream.destination
                            && close.destination == stream.source))
            })
            .map_or("open at the leg's end", |close| {
                if close.source == stream.source {
                    "kno closed first"
                } else {
                    "emule-qt closed first"
                }
            });
        let after_hello: Vec<String> = capture
            .streams
            .iter()
            .filter(|back| back.source == stream.destination && back.destination == stream.source)
            .flat_map(pcap::TcpStream::ed2k_frames)
            .map(|frame| format!("{:#04x}/{:#04x}", frame.protocol, frame.opcode))
            .collect();
        rows.push(format!(
            "{} hello {} bytes{} at {:.3}: {}, {closed}; emule-qt sent [{}]",
            stream.source,
            hello.bytes.len(),
            if is_short { " (over-counted)" } else { "" },
            hello.at,
            answer.map_or("no OP_HELLOANSWER".to_owned(), |frame| format!(
                "OP_HELLOANSWER at {:.3}",
                frame.at
            )),
            after_hello.join(" "),
        ));
    }
    let qt_lines: Vec<&str> = qt_log
        .lines()
        .filter(|line| line.contains(&kno_v4))
        .map(str::trim)
        .take(6)
        .collect();
    Ok(vec![
        Claim::about(
            "amule-kno-dials-emuleqt-with-an-over-counted-hello",
            short > 0,
            Evidence::Captured,
            format!(
                "kno, its IPv6 verified, told to fetch a fresh emule-qt's file: {hellos} \
                 connection(s) from kno to it carried an OP_HELLO, {short} of them counting a \
                 tag they never carry (read with rmule's hello reader); the first is \
                 `op-hello-amule-kno-to-emuleqt.bin`"
            ),
        ),
        Claim::about(
            "emuleqt-refuses-knos-over-counted-hello",
            short > 0 && answered_short == 0,
            Evidence::Captured,
            format!(
                "per connection, off kno's tap: [{}]; emule-qt's log lines naming kno: \
                 {qt_lines:?}",
                rows.join("; ")
            ),
        ),
    ])
}
