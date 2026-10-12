//! The legs of `peer-hello-surface` that run after rmule has already met each
//! client, in the order the first run hit (`1790611214`):
//!
//! 1. **Dial-back**: rmule's hello legs dialled each client and closed. A
//!    serving rmule under the same user hash, at the same address and port,
//!    now offers a fresh file `C`, and each client is told to download it, so
//!    each learns rmule as a source from the server. What a client does with a
//!    source it has met before is read off its own tap: a new connection to
//!    rmule's port, or its ask written on the link the hello leg opened.
//! 2. **kno's over-counted answer**: rmule dials kno over native IPv6, which
//!    verifies kno's IPv6 address. From then on kno's hello answer counts
//!    `CT_MOD_IP_V6` and never writes it. Stock aMule and a downloading rmule
//!    are each sent after kno's file, and each one's reaction to that answer
//!    is read: aMule's off its tap and debug log, rmule's off its own event
//!    line.

use std::time::Duration;

use anyhow::{Context, Result};
use rmule_peer::{HelloRefusal, HelloRefusalCode, PeerPacket, PeerPacketDecodeError};
use rmule_primitives::Packet;

use super::transfer::add_download;
use super::{CLIENTS, Client, Kind, keep_log, tap_prefix};
use crate::flow::bench::{Bench, CAPTURE_MOUNT, run_checked};
use crate::flow::evidence::write_pcap_all_matches;
use crate::flow::nat::dialect::bench::{
    HOST_AMULE_KNO, HOST_DRIVER, HOST_ED2KSRV, HOST_LEGACY_AMULE, Ipv6DialectOptions, Stage,
    container_name, start_detached_driver, wait_for_exit,
};
use crate::flow::nat::dialect::legs::{RMULE_USER_HASH, hello_leg};
use crate::flow::nat::dialect::verdict::{Claim, Evidence};
use crate::flow::nat::dialect::{BODY_PEER_TCP_PORT, ED2KSRV_TCP_PORT};
use crate::flow::nat::synthetic::write_hashed;
use crate::flow::pcap::{Ed2kFrame, tcp_streams};

/// File `C`: one part, and a size no other file of this flow has, so its hash
/// is its own.
const SERVED_C_BYTES: u64 = (3 << 20) + 7_777;
/// How long the serving rmule offers `C`, and the kno downloader runs.
const DIAL_BACK_SECS: u64 = 420;
const KNO_DOWNLOAD_SECS: u64 = 90;
const OFFER_SETTLE_SECS: u64 = 20;
const SERVE_ROLE: &str = "hsback";
const KNO_DOWNLOADER_ROLE: &str = "hskno6dl";
/// A downloader's host from the transfer legs, free once they exited.
const KNO_DOWNLOADER_HOST: usize = 5;
const KNO_DOWNLOADER_HASH: &str = "5A0F3C7E91D2468BA1B3C5D7E9F20486";

/// `OP_GETSOURCES` and its obfuscation-capable twin `OP_GETSOURCES_OBFU`.
const OP_GETSOURCES: [(u8, u8); 2] = [(0xE3, 0x19), (0xE3, 0x23)];
/// Stock aMule's gap between two TCP source-request frames: fifteen files
/// times twenty seconds (`DownloadQueue.cpp:1044`, `:1127`).
const TCP_SOURCE_GATE_SECS: f64 = 300.0;
/// How long before that gate rmule re-dials: the hello tool holds its link
/// four seconds, then closes it.
const DIAL_LEAD_SECS: f64 = 8.0;
/// How long past its gate stock aMule gets to ask for kno's sources and dial.
const KNO_DIAL_SETTLE_SECS: f64 = 30.0;
const OP_HELLOANSWER: (u8, u8) = (0xE3, 0x4C);
const PART_FRAMES: [(u8, u8); 3] = [(0xE3, 0x46), (0xC5, 0x40), (0xC5, 0xA2)];

/// Run both legs and return their claims.
///
/// # Errors
/// If a driver cannot start or a body cannot be told to download.
pub(super) fn drive(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
) -> Result<Vec<Claim>> {
    let mut claims = dial_back(bench, options, stage)?;
    claims.extend(kno_over_counted_answer(bench, options, stage)?);
    claims.extend(super::kno_dials::kno_dials_rmule(bench, options, stage)?);
    claims.extend(super::kno_dials_emuleqt::kno_dials_emuleqt(
        bench, options, stage,
    )?);
    Ok(claims)
}

fn dial_back(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
) -> Result<Vec<Claim>> {
    let c_dir = stage.leg_dir.join("serve-c");
    std::fs::create_dir_all(&c_dir).with_context(|| format!("create {}", c_dir.display()))?;
    let shared_c = write_hashed(&c_dir, SERVED_C_BYTES)?;
    let server = format!("{}:{ED2KSRV_TCP_PORT}", stage.v4(HOST_ED2KSRV));
    let serve_v4 = stage.v4(HOST_DRIVER).to_owned();
    let args = [
        "ed2k",
        "serve",
        "start",
        "--file",
        "/out/serve-c/shared.bin",
        "--server",
        &server,
        "--listen",
        &format!("0.0.0.0:{BODY_PEER_TCP_PORT}"),
        "--own-ip",
        &serve_v4,
        "--user-hash",
        RMULE_USER_HASH,
        "--max-seconds",
        &DIAL_BACK_SECS.to_string(),
    ]
    .map(str::to_owned);
    let (serve, announced) = start_detached_driver(
        bench,
        options,
        stage,
        SERVE_ROLE,
        HOST_DRIVER,
        &args,
        "serve.files_announced",
    )?;
    if !announced {
        let log = keep_log(bench, stage, &serve, "rmule-serve-c");
        anyhow::bail!(
            "the dial-back rmule never announced its file: {}",
            log.lines().last().unwrap_or_default()
        );
    }
    std::thread::sleep(Duration::from_secs(OFFER_SETTLE_SECS));
    for client in &CLIENTS {
        add_download(bench, options, stage, client, &shared_c.link)?;
    }
    // The race the first run lost: stock aMule sends one TCP source request
    // frame per 300 s (`DownloadQueue.cpp:1127`), so `C`'s source reaches it
    // when that gate next opens. rmule dials it again just before, from the
    // serving rmule's own address and under its hash, so the answer lands
    // while aMule still holds the link the dial closed.
    let legacy = legacy_amule()?;
    sleep_until_source_gate(bench, options, stage, legacy, -DIAL_LEAD_SECS)?;
    let hello = redial(bench, stage, &serve, legacy);
    wait_for_exit(bench, &serve)?;
    let serve_log = keep_log(bench, stage, &serve, "rmule-serve-c");
    let amule_log = amule_logfile(bench, options, stage, legacy, "dial-back");

    let mut claims = Vec::new();
    for client in &CLIENTS {
        let seen = seen_after_ask(
            bench,
            options,
            stage,
            client,
            &serve_v4,
            &shared_c.file_hash,
        )?;
        claims.push(dial_back_claim(
            client,
            &seen,
            &serve_log,
            stage.v4(client.host),
            &serve_v4,
        ));
    }
    let named = lines_naming(&amule_log, &serve_v4, 12);
    claims.push(Claim::about(
        "amule-233-log-shows-the-met-earlier-source",
        !named.is_empty(),
        Evidence::Captured,
        format!(
            "rmule's re-dial of stock aMule from the serving address: {hello}; stock aMule's own \
             debug lines naming that address: {named:?}"
        ),
    ));
    Ok(claims)
}

/// What one client's tap shows between it and the serving address, from the
/// moment it asked the server for `C`'s sources.
struct SeenAfterAsk {
    /// When the client asked, on its tap's clock; `None` if it never did.
    asked_at: Option<f64>,
    /// New connections the client opened to rmule's peer port.
    dials: usize,
    /// Frames the client wrote on a link it did not open to rmule's peer port
    /// — the link an earlier rmule dial left behind.
    on_old_link: Vec<String>,
    /// Part frames rmule sent it.
    parts: usize,
}

fn seen_after_ask(
    bench: &Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
    client: &Client,
    serve_v4: &str,
    file_hash: &str,
) -> Result<SeenAfterAsk> {
    let client_v4 = stage.v4(client.host).to_owned();
    let server_v4 = stage.v4(HOST_ED2KSRV).to_owned();
    let out = format!("{}-dial-back.pcap", client.name);
    write_pcap_all_matches(
        &bench.docker,
        &tap_of(options, client)?,
        &format!("{CAPTURE_MOUNT}/tap-{}.pcap", client.name),
        &format!("tcp and host {client_v4} and (host {serve_v4} or host {server_v4})"),
        &out,
    )?;
    let streams = tcp_streams(&stage.leg_dir.join(&out))?;
    let hash = hex_bytes(file_hash);
    let asked_at = streams
        .iter()
        .flat_map(crate::flow::pcap::TcpStream::ed2k_frames)
        .filter(|f| OP_GETSOURCES.contains(&(f.protocol, f.opcode)))
        .filter(|f| f.payload().windows(16).any(|w| w == hash.as_slice()))
        .map(|f| f.at)
        .reduce(f64::min);
    let Some(t0) = asked_at else {
        return Ok(SeenAfterAsk {
            asked_at,
            dials: 0,
            on_old_link: Vec::new(),
            parts: 0,
        });
    };
    let serve_ip: std::net::IpAddr = serve_v4.parse().context("serve address")?;
    let mut dials = 0;
    let mut on_old_link = Vec::new();
    let mut parts = 0;
    for stream in &streams {
        let frames: Vec<Ed2kFrame> = stream
            .ed2k_frames()
            .into_iter()
            .filter(|f| f.at >= t0)
            .collect();
        let to_rmule = stream.destination.ip() == serve_ip;
        let from_rmule = stream.source.ip() == serve_ip;
        if to_rmule && stream.destination.port() == BODY_PEER_TCP_PORT && !frames.is_empty() {
            dials += 1;
        }
        if to_rmule && stream.destination.port() != BODY_PEER_TCP_PORT {
            on_old_link.extend(frames.iter().map(|f| {
                format!(
                    "{:#04x}/{:#04x} {} bytes to {}",
                    f.protocol,
                    f.opcode,
                    f.bytes.len(),
                    stream.destination
                )
            }));
        }
        if from_rmule {
            parts += frames
                .iter()
                .filter(|f| PART_FRAMES.contains(&(f.protocol, f.opcode)))
                .count();
        }
    }
    Ok(SeenAfterAsk {
        asked_at,
        dials,
        on_old_link,
        parts,
    })
}

/// The dial-back claim for one client.
///
/// Stock aMule 2.3.3 keeps a client it has met, socket included,
/// and does not notice the peer's FIN on an idle link. A server source that
/// matches that client by IP and port is attached to it
/// (`CClientList::AttachToAlreadyKnown`, `DownloadQueue.cpp:672`), the file
/// ask goes out on the stale socket, rmule's host answers RST, and the
/// client — `DS_CONNECTED` with no answer — goes on the dead-source list
/// (`BaseClient.cpp:1289-1292`) for 30 to 45 minutes (`DeadSourceList.cpp:34-35`).
/// That is aMule's own rule, and the claim holds while stock aMule writes
/// its ask on the old link and fetches nothing. kno's fork and emule-qt close
/// their side the moment rmule's FIN arrives (measured, run `1790782321`), so
/// a later source is dialled anew; their claim is the fetch.
fn dial_back_claim(
    client: &Client,
    seen: &SeenAfterAsk,
    serve_log: &str,
    client_v4: &str,
    serve_v4: &str,
) -> Claim {
    let name = client.name;
    let served = serve_log
        .lines()
        .find(|l| {
            (l.contains("upload_slot_granted") || l.contains("peer_queued"))
                && l.contains(&format!("peer={client_v4}:"))
        })
        .unwrap_or_default()
        .trim()
        .to_owned();
    let facts = format!(
        "{name} asked the server for C at tap time {:?}; after that: {} new connection(s) to \
         {serve_v4}:{BODY_PEER_TCP_PORT}, {} frame(s) on the earlier dial's link {:?}, {} part \
         frame(s) from rmule; the serving rmule's first grant or queue line: {served:?}",
        seen.asked_at,
        seen.dials,
        seen.on_old_link.len(),
        seen.on_old_link,
        seen.parts,
    );
    match client.kind {
        Kind::Amule => Claim::about(
            format!("{name}-asks-rmule-met-earlier-on-the-stale-link-and-drops-it"),
            seen.asked_at.is_some() && !seen.on_old_link.is_empty() && seen.parts == 0,
            Evidence::Captured,
            facts,
        ),
        Kind::AmuleKno | Kind::EmuleQt => Claim::about(
            format!("{name}-fetches-from-rmule-met-earlier"),
            seen.parts > 0,
            Evidence::Captured,
            facts,
        ),
    }
}

fn kno_over_counted_answer(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
) -> Result<Vec<Claim>> {
    let kno_v6 = format!("[{}]:{BODY_PEER_TCP_PORT}", stage.v6(HOST_AMULE_KNO));
    // kno verifies its IPv6 on its first inbound native-IPv6 connection.
    let row = hello_leg(bench, options, stage, "kno-ipv6-verify", &kno_v6, None)?;
    let kno_link = std::fs::read_to_string(stage.leg_dir.join("amule-kno-b.link"))
        .context("read kno's file link")?;
    let kno_link = kno_link.trim();
    let legacy = legacy_amule()?;
    add_download(bench, options, stage, legacy, kno_link)?;
    let server = format!("{}:{ED2KSRV_TCP_PORT}", stage.v4(HOST_ED2KSRV));
    let args = [
        "ed2k",
        "download",
        "start",
        "--data-dir",
        "/out/hs-kno6-data",
        "--server",
        &server,
        "--file",
        kno_link,
        "--out",
        "/out/dl/hs-kno6.bin",
        "--user-hash",
        KNO_DOWNLOADER_HASH,
        "--max-seconds",
        &KNO_DOWNLOAD_SECS.to_string(),
    ]
    .map(str::to_owned);
    let (downloader, _) = start_detached_driver(
        bench,
        options,
        stage,
        KNO_DOWNLOADER_ROLE,
        KNO_DOWNLOADER_HOST,
        &args,
        "download",
    )?;
    wait_for_exit(bench, &downloader)?;
    // Stock aMule asks for kno's sources only when its source-request gate
    // opens again; give its dial a moment past that.
    sleep_until_source_gate(bench, options, stage, legacy, KNO_DIAL_SETTLE_SECS)?;
    let downloader_log = keep_log(bench, stage, &downloader, "rmule-kno6-downloader");
    let amule_log = amule_logfile(bench, options, stage, legacy, "kno-answer");

    let legacy_v4 = stage.v4(HOST_LEGACY_AMULE).to_owned();
    let kno_v4 = stage.v4(HOST_AMULE_KNO).to_owned();
    let out = "amule-233-with-kno.pcap";
    write_pcap_all_matches(
        &bench.docker,
        &tap_of(options, legacy)?,
        &format!("{CAPTURE_MOUNT}/tap-{}.pcap", legacy.name),
        &format!("tcp and host {legacy_v4} and host {kno_v4}"),
        out,
    )?;
    let streams = tcp_streams(&stage.leg_dir.join(out))?;
    let kno_ip: std::net::IpAddr = kno_v4.parse().context("kno address")?;
    let mut answers = Vec::new();
    let mut after_answer = Vec::new();
    for stream in &streams {
        if stream.source.ip() == kno_ip {
            for frame in stream.ed2k_frames() {
                if (frame.protocol, frame.opcode) == OP_HELLOANSWER {
                    answers.push((frame.at, refusal_of(&frame.bytes)));
                }
            }
        }
    }
    let first_answer = answers.first().map(|(at, _)| *at);
    for stream in &streams {
        if stream.destination.ip() == kno_ip {
            after_answer.extend(
                stream
                    .ed2k_frames()
                    .into_iter()
                    .filter(|f| first_answer.is_some_and(|t| f.at > t))
                    .map(|f| format!("{:#04x}/{:#04x}", f.protocol, f.opcode)),
            );
        }
    }
    let short = answers
        .iter()
        .filter(|(_, r)| matches!(r, Some(HelloRefusalCode::TagCountShort { .. })))
        .count();
    let aborted = amule_log
        .lines()
        .filter(|l| l.contains("Caught") || l.contains("caused an error"))
        .map(str::trim)
        .take(3)
        .collect::<Vec<_>>();
    let named = downloader_log
        .lines()
        .find(|l| l.contains("peer.hello_refused code=tag_count_short"))
        .map(str::trim)
        .unwrap_or_default()
        .to_owned();
    Ok(vec![
        Claim::about(
            "amule-233-refuses-knos-over-counted-answer",
            short > 0 && after_answer.is_empty(),
            Evidence::Captured,
            format!(
                "after rmule's IPv6 hello verified kno's address (row identified={}), stock aMule \
                 was sent after kno's file: {} OP_HELLOANSWER(s) from kno on aMule's tap, {short} \
                 of them counting a tag they never carry (read with rmule's hello reader); frames \
                 aMule sent kno after the first answer: {after_answer:?}; aMule's own lines: \
                 {aborted:?}",
                row.flag("identified"),
                answers.len(),
            ),
        ),
        Claim::about(
            "rmule-names-knos-over-counted-answer",
            !named.is_empty(),
            Evidence::RmuleOnly,
            format!("the downloading rmule's line for kno's answer: {named:?}"),
        ),
    ])
}

/// The refusal code rmule's own hello reader names `frame` with, if any.
pub(super) fn refusal_of(frame: &[u8]) -> Option<HelloRefusalCode> {
    let packet = Packet::decode_exact(frame).ok()?;
    match PeerPacket::decode(&packet) {
        Err(
            PeerPacketDecodeError::Hello { source } | PeerPacketDecodeError::HelloAnswer { source },
        ) => HelloRefusal::from_decode_error(&source).map(|r| r.code),
        _ => None,
    }
}

/// A body's aMule logfile, kept beside the leg; empty when it cannot be read.
fn amule_logfile(
    bench: &Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
    client: &Client,
    leg: &str,
) -> String {
    let Ok(container) = container_name(options.layout, client.role) else {
        return String::new();
    };
    let text = run_checked(
        bench.docker.exec(
            container,
            ["sh", "-c", "cat /root/.aMule/logfile 2>/dev/null || true"]
                .map(std::ffi::OsString::from)
                .to_vec(),
        ),
        "read the aMule logfile",
    )
    .unwrap_or_default();
    let _ = std::fs::write(
        stage
            .leg_dir
            .join(format!("{}-logfile-{leg}.log", client.name)),
        &text,
    );
    text
}

pub(super) fn tap_of(options: &Ipv6DialectOptions<'_>, client: &Client) -> Result<String> {
    let suffix = options
        .layout
        .root()
        .file_name()
        .and_then(|n| n.to_str())
        .context("run dir name")?
        .to_owned();
    Ok(format!("{}-{}", tap_prefix(&suffix), client.name))
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2)
        .filter_map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok())
        .collect()
}

fn legacy_amule() -> Result<&'static Client> {
    CLIENTS
        .iter()
        .find(|c| c.kind == Kind::Amule)
        .context("the stock aMule body")
}

fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

/// When `client` last asked the server for sources, on its tap's clock.
fn last_source_ask(
    bench: &Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
    client: &Client,
) -> Result<Option<f64>> {
    let out = format!("{}-source-asks.pcap", client.name);
    write_pcap_all_matches(
        &bench.docker,
        &tap_of(options, client)?,
        &format!("{CAPTURE_MOUNT}/tap-{}.pcap", client.name),
        &format!(
            "tcp and host {} and host {}",
            stage.v4(client.host),
            stage.v4(HOST_ED2KSRV)
        ),
        &out,
    )?;
    Ok(tcp_streams(&stage.leg_dir.join(&out))?
        .iter()
        .flat_map(crate::flow::pcap::TcpStream::ed2k_frames)
        .filter(|f| OP_GETSOURCES.contains(&(f.protocol, f.opcode)))
        .map(|f| f.at)
        .reduce(f64::max))
}

/// rmule's hello tool, run inside the serving rmule's container: its address,
/// its hash and its advertised port, as the first run's hello leg had them.
fn redial(bench: &Bench, stage: &Stage, serve: &str, client: &Client) -> String {
    let peer = format!("{}:{BODY_PEER_TCP_PORT}", stage.v4(client.host));
    let argv = [
        "rmule-tools",
        "ipv6",
        "hello",
        "--peer",
        &peer,
        "--advertise-ipv6",
        stage.v6(HOST_DRIVER),
        "--user-hash",
        RMULE_USER_HASH,
        "--capture",
        "/out/dial-back-redial-capture",
        "--out",
        "/out/dial-back-redial.toml",
    ]
    .map(std::ffi::OsString::from)
    .to_vec();
    let at = unix_now();
    match run_checked(
        bench.docker.exec(serve.to_owned(), argv),
        "re-dial the stock aMule",
    ) {
        Ok(_) => format!("dialled {peer} at {at:.3}, row dial-back-redial.toml"),
        Err(error) => format!("the re-dial at {at:.3} failed: {error}"),
    }
}

/// Up to `limit` lines of `log` that name `address`.
fn lines_naming<'a>(log: &'a str, address: &str, limit: usize) -> Vec<&'a str> {
    log.lines()
        .filter(|l| l.contains(address))
        .map(str::trim)
        .take(limit)
        .collect()
}

/// Sleep until `offset` seconds past the moment `client`'s next TCP source
/// request may leave: its last one plus the gate. Returns at once when the
/// moment has passed or the client never asked.
fn sleep_until_source_gate(
    bench: &Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
    client: &Client,
    offset: f64,
) -> Result<()> {
    if let Some(asked) = last_source_ask(bench, options, stage, client)? {
        let wait = asked + TCP_SOURCE_GATE_SECS + offset - unix_now();
        if wait > 0.0 {
            std::thread::sleep(Duration::from_secs_f64(wait.min(TCP_SOURCE_GATE_SECS)));
        }
    }
    Ok(())
}
