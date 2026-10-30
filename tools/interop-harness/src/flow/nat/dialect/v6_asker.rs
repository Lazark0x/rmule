//! `ipv6-asker`: a dual-stack emule-qt asks rmule for a file over IPv6 while
//! rmule holds that same peer as a source of another file (ADR-0107).
//!
//! rmule runs one `Core`, sharing the asked file and downloading the file
//! emule-qt shares, whose link names emule-qt's `[v6]:4662`. The server names
//! emule-qt's IPv4 too, so rmule holds it as a source at both addresses. Its
//! dials at both are held at the SYN, so emule-qt's ask lands first; the holds
//! lift once rmule has answered it, so a dial rmule still wanted would reach the
//! tap. emule-qt is logged in over IPv4, so its hello claims an IPv4 High ID on
//! an IPv6 link.
//!
//! emule-qt also learns rmule's IPv4 from the server and dials it beside the
//! IPv6. That dial is dropped at rmule's listener, and only the server's probe
//! gets through: a dual-stack peer's second link is a separate row of this
//! ticket's, drawn in run `1793356626`, where rmule banned the peer's IPv4.
//!
//! What a claim reads is emule-qt's own tap: who opened each link, what rode
//! it, and the copy rmule ended with. emule-qt's own download of the asked file
//! does not finish on this link: the absence claim says why.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::docker::RunContainer;
use crate::flow::bench::{Bench, run_checked};
use crate::flow::gate::wait_for_container_log;
use crate::flow::identity::parse_ed2k_file_hash;
use crate::flow::nat::dialect::bench::{
    HOST_DRIVER, HOST_ED2KSRV, HOST_EMULEQT, Ipv6DialectOptions, Stage, body_log, container_name,
    out, start_detached_driver_with_env, wait_for_exit,
};
use crate::flow::nat::dialect::legs::RMULE_USER_HASH;
use crate::flow::nat::dialect::verdict::{Claim, Evidence};
use crate::flow::nat::dialect::{BODY_PEER_TCP_PORT, ED2KSRV_TCP_PORT};
use crate::flow::nat::synthetic::write_hashed;
use crate::flow::pcap::{Ed2kFrame, TcpCapture, records, tcp_capture};
use crate::flow::peer::one_link::verdict::{part_of, requested};

/// The file rmule shares and emule-qt asks for.
const ASKED_BYTES: u64 = 3 << 20;
/// rmule's bounded run.
const RMULE_SECS: u64 = 60;
/// How long the ride is waited for, inside rmule's bounded run.
const ANSWER_WAIT: Duration = Duration::from_secs(40);
/// rmule's container role.
const RMULE_ROLE: &str = "v6asked";
/// The line rmule prints when the core stands.
const RMULE_READY: &str = "download";
/// The line rmule prints when the download rides the link it found.
const ASK_ANSWERED: &str = "download.link_shared";

const OP_HELLO: u8 = 0x01;
const OP_STARTUPLOADREQ: u8 = 0x54;
const OP_ACCEPTUPLOADREQ: u8 = 0x55;

/// `link` naming `[v6]:port` as an IPv6 source (ADR-0089 §6.2).
fn with_v6_source(link: &str, v6: &str, port: u16) -> Result<String> {
    let prefix = link
        .strip_suffix("|/")
        .with_context(|| format!("{link} is no canonical file link"))?;
    Ok(format!("{prefix}|s6=[{v6}]:{port}|/"))
}

/// A hold's `iptables` rule on rmule's dial of `address`.
fn dial_hold(action: &str, address: &str) -> Vec<String> {
    [
        action,
        "OUTPUT",
        "-p",
        "tcp",
        "-d",
        address,
        "--dport",
        &BODY_PEER_TCP_PORT.to_string(),
        "--syn",
        "-j",
        "DROP",
    ]
    .map(str::to_owned)
    .to_vec()
}

/// Drive the flow and return its claims.
///
/// # Errors
/// If a body cannot start or the tap cannot be read.
pub(super) fn drive(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
) -> Result<(Vec<Claim>, String)> {
    let held_by_qt = stage.shared.as_ref().context("emule-qt shares a file")?;
    let qt_v6 = stage.v6(HOST_EMULEQT).to_owned();
    let qt_v4 = stage.v4(HOST_EMULEQT).to_owned();
    let rmule_v6 = stage.v6(HOST_DRIVER).to_owned();
    let dir = stage.leg_dir.join("asked");
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let asked = write_hashed(&dir, ASKED_BYTES)?;

    let args = [
        "ed2k",
        "download",
        "start",
        "--data-dir",
        &out("store"),
        "--server",
        &format!("{}:{ED2KSRV_TCP_PORT}", stage.v4(HOST_ED2KSRV)),
        "--file",
        &with_v6_source(&held_by_qt.link, &qt_v6, BODY_PEER_TCP_PORT)?,
        "--out",
        &out("dl/from-emuleqt.bin"),
        "--serve",
        "--share",
        &out("asked/shared.bin"),
        "--linger",
        "--stamp-events",
        "--max-seconds",
        &RMULE_SECS.to_string(),
        "--user-hash",
        RMULE_USER_HASH,
    ]
    .map(str::to_owned);
    let env = [
        ("RMULE_HOLD_DIAL6", format!("{qt_v6} {BODY_PEER_TCP_PORT}")),
        ("RMULE_HOLD_DIAL4", format!("{qt_v4} {BODY_PEER_TCP_PORT}")),
        (
            "RMULE_FORCE_LOW_ID_TCP_PORT",
            BODY_PEER_TCP_PORT.to_string(),
        ),
        ("RMULE_TCP_ACCEPT_FROM", stage.v4(HOST_ED2KSRV).to_owned()),
        (
            "RMULE_LOG",
            "info,rmule_core::serve=debug,rmule_core::adapters=debug".to_owned(),
        ),
    ];
    let (rmule, _) = start_detached_driver_with_env(
        bench,
        options,
        stage,
        RMULE_ROLE,
        HOST_DRIVER,
        &args,
        RMULE_READY,
        &env,
    )?;

    let qt = container_name(options.layout, "v6qt")?;
    let said = run_checked(
        bench.docker.exec(
            qt,
            [
                "emulecored",
                "--config",
                "/config",
                "--port",
                "4712",
                "--add-link",
                &with_v6_source(&asked.link, &rmule_v6, BODY_PEER_TCP_PORT)?,
            ]
            .map(std::ffi::OsString::from)
            .to_vec(),
        ),
        "add the asked file to emule-qt",
    )?;
    std::fs::write(stage.leg_dir.join("emuleqt-add.log"), said).context("keep the add answer")?;

    let ridden = wait_for_container_log(&bench.docker, &rmule, ASK_ANSWERED, ANSWER_WAIT).is_ok();
    for (table, target) in [("ip6tables", &qt_v6), ("iptables", &qt_v4)] {
        run_checked(
            bench.docker.run_container(
                dial_hold("-D", target).into_iter().fold(
                    RunContainer::new(options.rmule_tools_image)
                        .network(format!("container:{rmule}"))
                        .cap_add("NET_ADMIN")
                        .entrypoint(table)
                        .remove_after_exit(),
                    RunContainer::arg,
                ),
            ),
            "lift a hold on rmule's dial",
        )?;
    }
    wait_for_exit(bench, &rmule)?;
    let log = body_log(bench, stage, &rmule, "rmule")?;

    let capture = tcp_capture(&records(&stage.leg_dir.join("tap-wan.pcap"))?)?;
    let qt_address: std::net::IpAddr = qt_v6.parse().context("emule-qt's IPv6")?;
    let rmule_address: std::net::IpAddr = rmule_v6.parse().context("rmule's IPv6")?;
    let links = Links {
        capture: &capture,
        qt: SocketAddr::new(qt_address, BODY_PEER_TCP_PORT),
        rmule: SocketAddr::new(rmule_address, BODY_PEER_TCP_PORT),
    };
    let copy = std::fs::read(stage.leg_dir.join("dl/from-emuleqt.bin")).unwrap_or_default();
    let shared = std::fs::read(&held_by_qt.path).context("read emule-qt's file")?;
    let mut claims = links.claims(
        &parse_ed2k_file_hash(&asked.link)?,
        &parse_ed2k_file_hash(&held_by_qt.link)?,
        &qt_v4,
    );
    claims.push(Claim::about(
        "the-download-of-that-peer-completed-byte-equal",
        ridden && copy == shared,
        Evidence::Captured,
        format!(
            "{} bytes of {}; {}",
            copy.len(),
            shared.len(),
            first_line(&log, "download.link_shared")
        ),
    ));
    Ok((claims, String::new()))
}

/// The first line of `log` holding `marker`, or nothing.
fn first_line<'a>(log: &'a str, marker: &str) -> &'a str {
    log.lines()
        .find(|line| line.contains(marker))
        .unwrap_or_default()
}

/// The tap's view of the two peers.
struct Links<'a> {
    capture: &'a TcpCapture,
    qt: SocketAddr,
    rmule: SocketAddr,
}

impl Links<'_> {
    /// The source ports of the dials `source` made at `host`, retransmissions
    /// folded.
    fn dials(&self, source: std::net::IpAddr, host: std::net::IpAddr) -> Vec<u16> {
        let mut ports: Vec<u16> = self
            .capture
            .opens
            .iter()
            .filter(|open| open.source.ip() == source && open.destination.ip() == host)
            .map(|open| open.source.port())
            .collect();
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    fn claims(&self, asked: &[u8; 16], held: &[u8; 16], qt_v4: &str) -> Vec<Claim> {
        let qt_ip = self.qt.ip();
        let rmule_ip = self.rmule.ip();
        let qt_dials = self.dials(qt_ip, rmule_ip);
        let rmule_dials = self.dials(rmule_ip, qt_ip);

        let streams = || self.capture.streams.iter();
        let asker_stream = streams().find(|stream| {
            stream.source.ip() == qt_ip
                && stream.destination == self.rmule
                && stream
                    .ed2k_frames()
                    .first()
                    .is_some_and(|frame| frame.opcode == OP_HELLO)
        });
        let asker_port = asker_stream.map_or(0, |stream| stream.source.port());
        let on_link = |to_rmule: bool,
                       read: &dyn Fn(&Ed2kFrame) -> Option<[u8; 16]>,
                       hash: &[u8; 16]| {
            streams()
                .filter(|stream| {
                    let (qt_end, rmule_end) = if to_rmule {
                        (stream.source, stream.destination)
                    } else {
                        (stream.destination, stream.source)
                    };
                    qt_end.ip() == qt_ip && qt_end.port() == asker_port && rmule_end == self.rmule
                })
                .flat_map(|stream| stream.ed2k_frames())
                .filter(|frame| read(frame).is_some_and(|got| got == *hash))
                .count()
        };
        // `<hash size 1><hash 16><client id 4>` after the opcode.
        let claimed_id = asker_stream
            .and_then(|stream| stream.ed2k_frames().into_iter().next())
            .and_then(|hello| hello.bytes.get(23..27).map(<[u8]>::to_vec))
            .map_or_else(String::new, |id| {
                format!("{}.{}.{}.{}", id[0], id[1], id[2], id[3])
            });

        let ask_frames = on_link(true, &requested, asked);
        let our_asks = on_link(false, &requested, held);
        let their_parts = on_link(true, &part_of, held);
        let our_parts = on_link(false, &part_of, asked);
        let slot_ask = |frame: &Ed2kFrame| {
            (frame.opcode == OP_STARTUPLOADREQ)
                .then(|| frame.bytes.get(6..22)?.try_into().ok())
                .flatten()
        };
        let slot_asks = on_link(true, &slot_ask, asked);
        let other_asks = on_link(true, &slot_ask, held);
        let grants = streams()
            .filter(|stream| stream.source == self.rmule && stream.destination.port() == asker_port)
            .flat_map(|stream| stream.ed2k_frames())
            .filter(|frame| frame.opcode == OP_ACCEPTUPLOADREQ)
            .count();
        let at_v4_listener = |address: SocketAddr| {
            address.port() == BODY_PEER_TCP_PORT && address.ip().to_string() == qt_v4
        };
        let v4_links = self
            .capture
            .opens
            .iter()
            .filter(|open| at_v4_listener(open.destination))
            .map(|open| open.source)
            .collect::<std::collections::BTreeSet<_>>();
        let v4_file_frames = streams()
            .filter(|stream| at_v4_listener(stream.destination))
            .flat_map(|stream| stream.ed2k_frames())
            .filter(|frame| {
                [asked, held]
                    .iter()
                    .any(|hash| [requested(frame), part_of(frame)].contains(&Some(**hash)))
            })
            .count();
        vec![
            Claim::about(
                "emuleqt-asked-rmule-over-ipv6",
                !qt_dials.is_empty() && ask_frames > 0,
                Evidence::Captured,
                format!(
                    "emule-qt dialed [{rmule_ip}]:{} from ports {qt_dials:?}; {ask_frames} name \
                     asks for the shared file on the link from port {asker_port}",
                    self.rmule.port()
                ),
            ),
            Claim::about(
                "the-hello-claimed-a-high-id-the-link-does-not-carry",
                claimed_id == qt_v4,
                Evidence::Captured,
                format!("emule-qt's hello on the IPv6 link claims client id {claimed_id}"),
            ),
            Claim::about(
                "the-download-rode-the-askers-link",
                our_asks > 0 && their_parts > 0,
                Evidence::Captured,
                format!(
                    "on the link emule-qt opened: {our_asks} name asks from rmule for the held \
                     file, {their_parts} part frames of it from emule-qt, {our_parts} part \
                     frames of the shared file from rmule"
                ),
            ),
            Claim::absence(
                "emuleqts-slot-ask-on-the-shared-link-names-the-file-rmule-asked-for",
                slot_asks.try_into().unwrap_or(i64::MAX),
                format!(
                    "{slot_asks} slot asks for the shared file, {other_asks} for the held file, \
                     {grants} grants. `sendStartupLoadReq` writes `m_reqUpFileId`, the file this \
                     peer asked of emule-qt, not its own `m_reqFile` (`DownloadClient.cpp:319-320` \
                     at `73fff714`), so its ask for the shared file never reaches the wire on a \
                     link rmule also downloads on. rmule offers no file with no verified part \
                     and answers such an ask nothing, as aMule does \
                     (`ClientTCPSocket.cpp:606-618`)."
                ),
            ),
            Claim::about(
                "one-link-one-client",
                rmule_dials.is_empty() && qt_dials.len() == 1 && v4_file_frames == 0,
                Evidence::Captured,
                format!(
                    "over IPv6 rmule dialed from ports {rmule_dials:?}, emule-qt from \
                     {qt_dials:?}; rmule's held dials at emule-qt's IPv4 listener that landed \
                     after the lift: {v4_links:?}, with {v4_file_frames} file frames from rmule on them"
                ),
            ),
        ]
    }
}
