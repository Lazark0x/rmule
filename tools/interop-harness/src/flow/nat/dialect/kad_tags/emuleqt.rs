//! The emule-qt leg of `ipv6-kad-tags`: emule-qt `73fff714`, a
//! Kad node sharing a file of its own, publishes a source row carrying its
//! `ip6` to a rmule storer at that file's key, and a rmule `Core` downloads
//! the file off the row the storer re-serves. kno's row cannot carry the
//! transfer at its pin (its verified-IPv6 hello answer over-counts, `ipv6-hello-tags`), so
//! this is the flow's byte-equal transfer and a second, lower-case `ip6`
//! writer (`QByteArray::toHex`, `KadSearch.cpp:1386-1391`; ADR-0087's
//! amendment).
//!
//! emule-qt publishes a type-1 row only once its Kad reads open, and every
//! gate on the way is sequenced here (emule-qt `src/core`, `73fff714`):
//!
//! - **No row while firewalled.** A firewalled node with no buddy publishes
//!   nothing (`kademlia/KadSearch.cpp:225-233`, `files/KnownFile.cpp:716-724`,
//!   retried every tick). It reads open once two connect-back acks arrive
//!   (`kademlia/KadPrefs.cpp:158-166`): each is a peer that answered its
//!   `KADEMLIA_FIREWALLED2_REQ` by dialling its TCP port back and sending
//!   `OP_KAD_FWTCPCHECK_ACK` from an IP it asked within 180 s
//!   (`client/UpDownClient.cpp:3455-3475`, `client/ClientList.cpp:417-438`).
//! - **A check rides a hello.** emule-qt sends one on each hello exchange while
//!   fewer than four answers are in (`kademlia/KadUDPListener.cpp:838-845`,
//!   `:936-944`), and ten seconds after its first answered hello it restarts
//!   the round, zeroing the ack count (`kademlia/Kademlia.cpp:611-623`,
//!   `:221-248`, `KadPrefs.cpp:111-115`). Its own hellos come off the
//!   one-per-minute small timer, which greets the oldest expired contact and
//!   rotates past it on the first pass (`KadRoutingZone.cpp:79`, `:545-570`);
//!   an answered contact is not due again for an hour (`KadContact.cpp:110-117`).
//! - **Three hellos before any publish.** `SharedFileList::publish` waits on
//!   `isKadReady()` — three `HELLO_RES` received (`Kademlia.cpp:205-210`,
//!   `KadDefines.h:67`) — and on the first self-lookup, three minutes in
//!   (`Kademlia.cpp:110`, `files/SharedFileList.cpp:714-724`).
//! - **Two contacts per `/24`.** A routing bin admits two from one `/24`
//!   (`KadRoutingBin.cpp:59-64`), so three contacts need a second `/24`: the
//!   two dial-back Cores stand on it ([`HOST_KAD_QT_DIAL_BACK`],
//!   [`HOST_KAD_QT_DIAL_BACK_2`]).
//! - **One publish attempt.** The first store lookup goes out as soon as the
//!   node is ready and its self-lookup is done (`SharedFileList.cpp:714-724`),
//!   and `KnownFile::publishSrc` books the next one five hours out before the
//!   lookup runs (`KnownFile.cpp:738`). If the node still reads firewalled
//!   when the store phase builds its tags, it sends nothing and stops
//!   (`KadSearch.cpp:1448-1453`). So both acks must be in before that lookup.
//!
//! So `nodes.dat` names, in order, **dial-back Core A**, the **storer** and
//! **dial-back Core B**. The first pass rotates Core A to the back; the storer
//! is greeted at +60 s, the hello that connects emule-qt and whose check the
//! +70 s restart wipes (a `kad join-node` answers `0x58` but never dials back);
//! Core B at +120 s and Core A at +180 s each draw a check inside the new
//! round, and each dials back as rmule's ADR-0058 responder (`rmule-kad`
//! `node/firewall.rs:87-121`, enacted in `rmule-core`
//! `adapters/kad_runtime/node.rs`). The third hello answer, the second ack and
//! the self-lookup all land by +181 s, and the store lookup follows at once.
//!
//! **Measured** (run `1790249850`, from `Kad: Started with ID`): hellos at
//! +61 s (storer), +121 s (Core B, which dialled back at once) and +181 s
//! (Core A). The second ack was Core B's again, at +180 s: Core B greeted
//! emule-qt in turn, and emule-qt checks off the `HELLO_RES_ACK` too
//! (`KadUDPListener.cpp:838-845`). By
//! Core A's hello four answers were in, so it drew no check. Self-lookup at
//! +180 s, store lookup at +198 s, the `0x44` at +201 s; the storer indexed it
//! at once, and the download fetched the file over IPv6 within 3.1 s.
//!
//! **Why not kno as a dial-back.** The first design put kno where Core B is.
//! Run `1790248139` measured it: kno's `HELLO_RES` carries `KADMISCOPTIONS`
//! `0x03` (it reads itself UDP- and TCP-firewalled), and emule-qt drops a
//! UDP-firewalled contact before it sends the check
//! (`KadUDPListener.cpp:502-505`), so the check never went out. Only the +181 s
//! ack arrived before the store lookup at +197 s, and emule-qt published nothing.
//!
//! **Why not the download `Core` as the second dial-back.** Its Kad source
//! search runs once at start and then hourly (`kad_reask_interval`,
//! `rmule-core` `service/config.rs:245`), so a `Core` up in time to answer the
//! check has searched before there is a row. And a `Core` whose own self-check
//! is live — `ed2k download start` arms it (`rmule-tools` `download.rs:141`) —
//! refuses to dial back a node it is checking (`firewall.rs:149`),
//! which on a hello exchange it always is. The dial-back Core is `ed2k serve
//! start --kad --kad-assume-open`: the same responder with its own self-check
//! off, rmule's stimulus posture.

use std::fs;
use std::net::Ipv6Addr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rmule_primitives::{ClientDecryptKeys, decrypt_datagram_client};

use super::{
    DownloadLeg, DownloadSpec, JOIN_NODE_READY_MARKER, STORER_INDEXED_MARKER, download_leg,
    join_node_args, kad_filter, lift_datagram_from, published_source, search_rows, subdir,
};
use crate::docker::RunContainer;
use crate::flow::bench::{Bench, DEFAULT_TAP_INTERFACE};
use crate::flow::evidence::write_pcap_all_matches;
use crate::flow::gate::wait_for_container_log;
use crate::flow::identity::{hex_lower, parse_ed2k_file_hash, parse_ipv4_octets};
use crate::flow::mesh::KAD_CONTACT_VERSION;
use crate::flow::nat::dialect::bench::{
    HOST_KAD_EMULEQT, HOST_KAD_QT_DIAL_BACK, HOST_KAD_QT_DIAL_BACK_2, HOST_KAD_QT_DOWNLOADER,
    HOST_KAD_QT_STORER, Ipv6DialectOptions, Stage, TAP_FILTER, body_log, container_name,
    start_detached_driver, wait_for_exit,
};
use crate::flow::nat::dialect::verdict::{Body, Claim, Evidence};
use crate::flow::nat::dialect::{BODY_CLIENT_UDP_PORT, BODY_PEER_TCP_PORT};
use crate::flow::nat::synthetic::write_hashed;
use crate::flow::pcap::udp_payloads;
use crate::flow::taps::{Attachment, PerAttachmentTaps, TapRole};
use crate::kad_seed::{KadContact, build_routing_zone_nodes_dat, storer_kad_id_for_file_hash};

/// The file emule-qt shares: a third size, so a third key, so the download
/// finds exactly one row.
const EMULEQT_SHARED_BYTES: u64 = 3 << 19;

/// emule-qt's container role and leg-dir log name.
const EMULEQT_ROLE: &str = "v6qtkad";
const EMULEQT_LOG: &str = "emuleqt-kad";
/// The image's `kad-node` readiness marker: Kad started (`Kad: Started with ID`).
const EMULEQT_READY_MARKER: &str = "rmule-emuleqt-kad-node-ready";
/// emule-qt's line once it hashed a shared file (`SharedFileList.cpp:139`).
const EMULEQT_HASHED_MARKER: &str = "Hashed OK";
/// How long emule-qt is given to publish once up: hellos at +60/+120/+180 s,
/// the self-lookup from +180 s, then the store lookup (measured: the `0x44` at
/// +201 s).
const EMULEQT_PUBLISH_WINDOW_SECS: u64 = 480;

/// The storer at emule-qt's file's key.
const QT_STORER_ROLE: &str = "v6kad-qt-storer";
const QT_STORER_USER_HASH: &str = "51515151515151515151515151515151";
/// Its window: emule-qt's publish window, then the download's.
const QT_STORER_WINDOW_SECS: u64 = 900;
/// The tap on the storer's attachment, which sees emule-qt's `0x44` arrive.
const QT_STORER_TAP_ROLE: &str = "v6qtstorertap";
const QT_STORER_ATTACHMENT: &str = "qt-storer";

/// The two dial-back Cores.
struct DialBack {
    role: &'static str,
    host: usize,
    user_hash: &'static str,
    /// Far from every key on the bench, distinct per word.
    kad_id: [u8; 16],
}
const DIAL_BACK_A: DialBack = DialBack {
    role: "v6kad-qt-dialback",
    host: HOST_KAD_QT_DIAL_BACK,
    user_hash: "52525252525252525252525252525252",
    kad_id: [
        0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x87, 0x65, 0x43, 0x21, 0x0F, 0xED, 0xCB,
        0xA9,
    ],
};
const DIAL_BACK_B: DialBack = DialBack {
    role: "v6kad-qt-dialback-b",
    host: HOST_KAD_QT_DIAL_BACK_2,
    user_hash: "54545454545454545454545454545454",
    kad_id: [
        0xA9, 0xCB, 0xED, 0x0F, 0x21, 0x43, 0x65, 0x87, 0x78, 0x56, 0x34, 0x12, 0xF0, 0xDE, 0xBC,
        0x9A,
    ],
};
/// `ed2k serve start` needs a file to share; its row, if any, lands nowhere.
const DIAL_BACK_SHARED_BYTES: u64 = 1 << 16;
/// A closed local port: the serve activity treats the failed login as
/// non-fatal, and a local refusal fails at once.
const DIAL_BACK_CLOSED_SERVER: &str = "127.0.0.1:4661";
const DIAL_BACK_WINDOW_SECS: u64 = 900;
const DIAL_BACK_READY_MARKER: &str = "serve serving_started";

/// The rmule downloader of emule-qt's file.
const QT_DOWNLOADER_ROLE: &str = "v6kad-qt-downloader";
const QT_DOWNLOADER_USER_HASH: &str = "71717171717171717171717171717171";
const QT_DOWNLOADER_KAD_ID: [u8; 16] = [
    0x5E, 0x6F, 0x70, 0x81, 0x92, 0xA3, 0xB4, 0xC5, 0xD6, 0xE7, 0xF8, 0x09, 0x1A, 0x2B, 0x3C, 0x4D,
];

/// The datagrams lifted off the storer's tap, by file stem.
const EMULEQT_PUBLISH: &str = "emuleqt-publish-source-req-0x44";
const QT_STORER_SEARCH_RES: &str = "rmule-qt-storer-search-res-0x3b";

/// The `ip6` tag's header: string type, three-byte name, 32 characters.
const IP6_TAG_HEADER: [u8; 8] = [0x02, 0x03, 0x00, b'i', b'p', b'6', 0x20, 0x00];

/// emule-qt's entry in the verdict's body list.
pub(super) fn body(options: &Ipv6DialectOptions<'_>, stage: &Stage) -> Body {
    Body {
        name: "emuleqt".to_owned(),
        image: options.emuleqt_image.to_owned(),
        pin: "ModderMule/emule-qt 73fff714 (kad-node)".to_owned(),
        address_v4: stage.v4(HOST_KAD_EMULEQT).to_owned(),
        address_v6: stage.v6(HOST_KAD_EMULEQT).to_owned(),
    }
}

/// Stand the leg up, wait for emule-qt's row, download off it, and draw the
/// three claims.
///
/// # Errors
/// If a body cannot start or a lifted file cannot be written.
pub(super) fn drive(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
) -> Result<Vec<Claim>> {
    let timeout = Duration::from_secs(options.timeout_secs);
    let shared_dir = subdir(&stage.leg_dir, "emuleqt-shared")?;
    let file = write_hashed(&shared_dir, EMULEQT_SHARED_BYTES)?;
    let key = storer_kad_id_for_file_hash(parse_ed2k_file_hash(&file.link)?);

    subdir(&stage.leg_dir, QT_STORER_ROLE)?;
    let (storer, ready) = start_detached_driver(
        bench,
        options,
        stage,
        QT_STORER_ROLE,
        HOST_KAD_QT_STORER,
        &storer_args(options, stage, key),
        JOIN_NODE_READY_MARKER,
    )?;
    if !ready {
        bail!("the rmule storer {storer} never bound its socket");
    }
    let tap_prefix = container_name(options.layout, QT_STORER_TAP_ROLE)?;
    PerAttachmentTaps::start(
        bench,
        options.capture_image,
        &storer,
        &tap_prefix,
        &stage.leg_dir,
        &[Attachment {
            name: QT_STORER_ATTACHMENT,
            interface: DEFAULT_TAP_INTERFACE,
            role: TapRole::Evidence,
            bpf: TAP_FILTER,
        }],
        timeout,
    )?;

    let dial_backs = [
        start_dial_back(bench, options, stage, &DIAL_BACK_A)?,
        start_dial_back(bench, options, stage, &DIAL_BACK_B)?,
    ];
    let seed = subdir(&stage.leg_dir, "emuleqt-seed")?;
    fs::write(seed.join("nodes.dat"), nodes_dat(stage, key)?)
        .context("write emule-qt's nodes.dat")?;

    let emuleqt = container_name(options.layout, EMULEQT_ROLE)?;
    bench.start_extra(
        &emuleqt,
        RunContainer::new(options.emuleqt_image)
            .detach()
            .name(&emuleqt)
            .network(&stage.network)
            .ip(stage.v4(HOST_KAD_EMULEQT))
            .ip6(stage.v6(HOST_KAD_EMULEQT))
            .cap_add("NET_ADMIN")
            .volume(&shared_dir, "/incoming")
            .volume(&seed, "/seed")
            .env("EMULEQT_SCENARIO_MODE", "kad-node")
            .env("EMULEQT_KAD_NODES_DAT", "/seed/nodes.dat"),
        "run emule-qt as a seeded Kad node",
    )?;
    wait_for_container_log(&bench.docker, &emuleqt, EMULEQT_READY_MARKER, timeout)?;
    wait_for_container_log(&bench.docker, &emuleqt, EMULEQT_HASHED_MARKER, timeout)?;

    let indexed = wait_for_container_log(
        &bench.docker,
        &storer,
        STORER_INDEXED_MARKER,
        Duration::from_secs(EMULEQT_PUBLISH_WINDOW_SECS),
    )
    .is_ok();
    // The downloader takes the Kad publisher's address; that body's window
    // ended minutes ago, and its exit is what frees the address.
    wait_for_exit(
        bench,
        &container_name(options.layout, super::PUBLISHER_ROLE)?,
    )?;
    let download = download_leg(
        bench,
        options,
        stage,
        &DownloadSpec {
            role: QT_DOWNLOADER_ROLE,
            host: HOST_KAD_QT_DOWNLOADER,
            file: &file,
            storer_host: HOST_KAD_QT_STORER,
            kad_id: QT_DOWNLOADER_KAD_ID,
            user_hash: QT_DOWNLOADER_USER_HASH,
        },
        indexed,
    )?;

    let emuleqt_log = body_log(bench, stage, &emuleqt, EMULEQT_LOG)?;
    for (container, dial_back) in dial_backs.iter().zip([&DIAL_BACK_A, &DIAL_BACK_B]) {
        body_log(bench, stage, container, dial_back.role)?;
    }
    let storer_log = body_log(bench, stage, &storer, QT_STORER_ROLE)?;

    let tap = format!("{tap_prefix}-{QT_STORER_ATTACHMENT}");
    let pcap = format!("/capture/tap-{QT_STORER_ATTACHMENT}.pcap");
    let emuleqt_v4 = stage.v4(HOST_KAD_EMULEQT);
    let storer_v4 = stage.v4(HOST_KAD_QT_STORER);
    let publish = lift_publish(bench, stage, (&tap, &pcap), (emuleqt_v4, storer_v4), key)?;
    let answer = lift_datagram_from(
        bench,
        stage,
        (&tap, &pcap),
        QT_STORER_SEARCH_RES,
        &kad_filter(storer_v4, stage.v4(HOST_KAD_QT_DOWNLOADER), 0x3b),
    )?;

    let firewall_checks: Vec<&str> = emuleqt_log
        .lines()
        .filter(|line| line.contains("Sent FIREWALLED2_REQ"))
        .map(str::trim)
        .collect();
    println!("ipv6-kad-tags emule-qt firewall checks sent: {firewall_checks:?}");
    let served = storer_log
        .lines()
        .find(|line| {
            line.contains("SourceSearchServed") && line.contains(stage.v4(HOST_KAD_QT_DOWNLOADER))
        })
        .unwrap_or("")
        .trim();
    let emuleqt_v6: Ipv6Addr = stage
        .v6(HOST_KAD_EMULEQT)
        .parse()
        .context("emule-qt's IPv6")?;
    Ok(claims(
        &EmuleQtLeg {
            publish: publish.as_deref(),
            answer: answer.as_deref(),
            download: &download,
            file_hash: &file.file_hash,
            served,
        },
        emuleqt_v4,
        emuleqt_v6,
    ))
}

/// The storer's `kad join-node` operands; with `--rmule-kad-crypt` it arms
/// the ADR-0046 datagram crypt and verify keys bound to its own address, so
/// its `HELLO_RES_ACK` carries the receiver key emule-qt checks.
fn storer_args(options: &Ipv6DialectOptions<'_>, stage: &Stage, key: [u8; 16]) -> Vec<String> {
    let mut args = join_node_args(
        stage,
        QT_STORER_ROLE,
        key,
        QT_STORER_USER_HASH,
        QT_STORER_WINDOW_SECS,
    );
    if options.rmule_kad_crypt {
        args.extend([
            "--kad-crypt".to_owned(),
            "--public-ip".to_owned(),
            stage.v4(HOST_KAD_QT_STORER).to_owned(),
        ]);
    }
    args
}

/// Lift emule-qt's `0x44` to the storer off the storer's tap, and return its
/// plaintext. emule-qt obfuscates a Kad datagram to a contact whose Kad ID it
/// knows (the storer's is in its `nodes.dat`), keyed to that ID, so the frame
/// is found by decrypting each datagram it sent the storer with the storer's
/// ID — the storer's own receive path. `<stem>.bin` keeps the bytes as they
/// crossed the wire and `<stem>-plain.bin` the decrypted packet.
fn lift_publish(
    bench: &Bench,
    stage: &Stage,
    (tap, pcap): (&str, &str),
    (emuleqt_v4, storer_v4): (&str, &str),
    storer_kad_id: [u8; 16],
) -> Result<Option<Vec<u8>>> {
    let subset = format!("{EMULEQT_PUBLISH}-candidates.pcap");
    write_pcap_all_matches(
        &bench.docker,
        tap,
        pcap,
        &format!("udp and src host {emuleqt_v4} and dst host {storer_v4}"),
        &subset,
    )?;
    let keys = ClientDecryptKeys {
        kad_id: Some(&storer_kad_id),
        ..Default::default()
    };
    let found = udp_payloads(&stage.leg_dir.join(&subset))?
        .into_iter()
        .find_map(|wire| {
            let plain = if wire.first() == Some(&0xE4) {
                wire.clone()
            } else {
                decrypt_datagram_client(&wire, &keys)?.payload
            };
            plain.starts_with(&[0xE4, 0x44]).then_some((wire, plain))
        });
    if let Some((wire, plain)) = &found {
        for (suffix, bytes) in [("", wire), ("-plain", plain)] {
            let path = stage.leg_dir.join(format!("{EMULEQT_PUBLISH}{suffix}.bin"));
            fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))?;
        }
    }
    println!(
        "ipv6-kad-tags lifted {EMULEQT_PUBLISH}: {} bytes on the wire, {} plain",
        found.as_ref().map_or(0, |(wire, _)| wire.len()),
        found.as_ref().map_or(0, |(_, plain)| plain.len()),
    );
    Ok(found.map(|(_, plain)| plain))
}

/// Start a dial-back Core on the second `/24`, its Kad table empty: emule-qt
/// greets it, and it answers the check that greeting carries.
fn start_dial_back(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
    dial_back: &DialBack,
) -> Result<String> {
    let dir = subdir(&stage.leg_dir, dial_back.role)?;
    let shared = write_hashed(&dir, DIAL_BACK_SHARED_BYTES)?;
    let name = shared
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .context("the dial-back Core's file name")?;
    let args = [
        "ed2k",
        "serve",
        "start",
        "--file",
        &format!("/out/{}/{name}", dial_back.role),
        "--server",
        DIAL_BACK_CLOSED_SERVER,
        "--listen",
        &format!("0.0.0.0:{BODY_PEER_TCP_PORT}"),
        "--kad",
        "--kad-id-hex",
        &hex_lower(&dial_back.kad_id),
        "--udp-port",
        &BODY_CLIENT_UDP_PORT.to_string(),
        "--kad-assume-open",
        "--user-hash",
        dial_back.user_hash,
        "--max-seconds",
        &DIAL_BACK_WINDOW_SECS.to_string(),
    ]
    .map(str::to_owned)
    .into_iter()
    // `supported` arms the Core's Kad datagram crypt and its verify keys
    // (`CoreConfig::peer_crypt`) without initiating peer-TCP
    // obfuscation.
    .chain(
        options
            .rmule_kad_crypt
            .then(|| ["--peer-crypt".to_owned(), "supported".to_owned()])
            .into_iter()
            .flatten(),
    )
    .collect::<Vec<_>>();
    let (container, ready) = start_detached_driver(
        bench,
        options,
        stage,
        dial_back.role,
        dial_back.host,
        &args,
        DIAL_BACK_READY_MARKER,
    )?;
    if !ready {
        bail!("the dial-back Core {container} never started serving");
    }
    Ok(container)
}

/// emule-qt's routing-zone `nodes.dat`, in the order the module doc derives:
/// dial-back Core A, the storer, dial-back Core B.
fn nodes_dat(stage: &Stage, key: [u8; 16]) -> Result<Vec<u8>> {
    let contact = |kad_id, host| -> Result<KadContact> {
        Ok(KadContact {
            kad_id,
            ipv4: parse_ipv4_octets(stage.v4(host))?,
            udp_port: BODY_CLIENT_UDP_PORT,
            tcp_port: BODY_PEER_TCP_PORT,
            version: KAD_CONTACT_VERSION,
        })
    };
    Ok(build_routing_zone_nodes_dat(&[
        contact(DIAL_BACK_A.kad_id, DIAL_BACK_A.host)?,
        contact(key, HOST_KAD_QT_STORER)?,
        contact(DIAL_BACK_B.kad_id, DIAL_BACK_B.host)?,
    ]))
}

/// What the leg left behind for its claims.
struct EmuleQtLeg<'a> {
    /// emule-qt's `0x44` to the storer, off the storer's tap.
    publish: Option<&'a [u8]>,
    /// The storer's `0x3B` to the downloader, off the same tap.
    answer: Option<&'a [u8]>,
    download: &'a DownloadLeg,
    /// emule-qt's file, upper-case hex.
    file_hash: &'a str,
    /// The storer's `SourceSearchServed` line for the downloader.
    served: &'a str,
}

/// The leg's three claims.
fn claims(leg: &EmuleQtLeg<'_>, emuleqt_v4: &str, emuleqt_v6: Ipv6Addr) -> Vec<Claim> {
    let dial = "rmule-re-served-emule-qts-ip6-and-dialled-it";
    let transfer = "the-file-arrived-byte-equal-off-emule-qts-kad-row";
    let mut claims = vec![lower_case_ip6_claim(leg.publish, emuleqt_v6)];
    if !leg.download.ran {
        let note = "the storer never indexed emule-qt's row, so there was no source to download";
        claims.push(Claim::about(dial, false, Evidence::RmuleOnly, note));
        claims.push(Claim::about(transfer, false, Evidence::RmuleOnly, note));
        return claims;
    }

    let rows = leg.answer.map(search_rows).transpose();
    let re_served = rows.as_ref().ok().and_then(|rows| {
        rows.iter()
            .flatten()
            .find_map(|row| row.facts().and_then(|facts| facts.ipv6))
    });
    let v6_peer = format!("[{emuleqt_v6}]:{BODY_PEER_TCP_PORT}");
    let v4_peer = format!("{emuleqt_v4}:{BODY_PEER_TCP_PORT}");
    let selected: Vec<&str> = leg
        .download
        .log
        .lines()
        .filter(|line| line.contains("download peer_selected"))
        .map(str::trim)
        .collect();
    let dialled_v6 = selected
        .iter()
        .any(|line| line.ends_with(&format!("peer={v6_peer}")));
    let dialled_v4 = selected
        .iter()
        .any(|line| line.ends_with(&format!("peer={v4_peer}")));
    claims.push(Claim::about(
        dial,
        re_served.is_some_and(|endpoint| endpoint.ip == emuleqt_v6) && dialled_v6 && !dialled_v4,
        Evidence::RmuleOnly,
        format!(
            "The storer's 0x3B to the downloader ({} bytes) re-served ip6 {re_served:?} \
             (decode: {:?}); its line: {:?}. The download, handed emule-qt's link alone, \
             selected {selected:?}: emule-qt's IPv6 {v6_peer} {dialled_v6}, its IPv4 {v4_peer} \
             {dialled_v4}.",
            leg.answer.map_or(0, <[u8]>::len),
            rows.as_ref().err(),
            leg.served,
        ),
    ));

    let arrived = leg.download.output_hash.as_deref() == Some(leg.file_hash);
    claims.push(Claim::about(
        transfer,
        arrived,
        Evidence::RmuleOnly,
        format!(
            "The downloader's output hashed to ED2K {:?} against emule-qt's {}.",
            leg.download.output_hash, leg.file_hash
        ),
    ));
    claims
}

/// `emule-qt-published-a-lower-case-ip6`: emule-qt's `0x44` carries an `ip6`
/// whose 32 characters are its IPv6 in lower-case hex, byte for byte — the
/// spelling rmule's reader must take as readily as kno's upper-case one — and
/// rmule's publish decoder reads that value back as the address.
fn lower_case_ip6_claim(publish: Option<&[u8]>, emuleqt_v6: Ipv6Addr) -> Claim {
    let expected = hex_lower(&emuleqt_v6.octets());
    let raw = publish.and_then(ip6_tag);
    let decoded = publish.map(published_source).transpose();
    let source = decoded.as_ref().ok().and_then(Option::as_ref);
    let decoded_ip6 = source.and_then(|source| source.ipv6);
    let source_type = source.and_then(|source| source.source_type);
    Claim::about(
        "emule-qt-published-a-lower-case-ip6",
        raw == Some(expected.as_bytes()) && decoded_ip6 == Some(emuleqt_v6),
        Evidence::Captured,
        format!(
            "emule-qt's 0x44 to the storer ({} bytes, source type {source_type:?}) carried ip6 \
             {:?}, expected {expected:?}; rmule's decoder read {decoded_ip6:?} (error: {:?}).",
            publish.map_or(0, <[u8]>::len),
            raw.map(String::from_utf8_lossy),
            decoded.as_ref().err().map(|error| format!("{error:#}")),
        ),
    )
}

/// The 32 value characters of the first `ip6` tag in `frame`.
fn ip6_tag(frame: &[u8]) -> Option<&[u8]> {
    let at = frame
        .windows(IP6_TAG_HEADER.len())
        .position(|window| window == IP6_TAG_HEADER)?;
    frame.get(at + IP6_TAG_HEADER.len()..at + IP6_TAG_HEADER.len() + 32)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use rmule_kad::{Kad2Message, KadId, KadPublishedSource, KadSourceRow, encode_source_result};

    use super::{DownloadLeg, EmuleQtLeg, IP6_TAG_HEADER, claims};

    const QT_V4: &str = "45.55.200.10";
    const QT_V6: Ipv6Addr = Ipv6Addr::new(0x3fff, 0x0ed2, 1, 0, 0, 0, 0, 0xa);
    const FILE_HASH: &str = "0123456789ABCDEF0123456789ABCDEF";

    /// A type-1 `0x44` naming `ip6`, written by rmule's encoder — which spells
    /// the tag upper-case.
    fn publish(ip6: Ipv6Addr) -> Vec<u8> {
        Kad2Message::PublishSourceReq {
            file: KadId::from_bytes([0x33; 16]),
            source_id: [0x71; 16],
            source: KadPublishedSource {
                source_type: Some(1),
                tcp_port: Some(4662),
                ipv6: Some(ip6),
                ..KadPublishedSource::default()
            },
        }
        .encode()
        .encode()
    }

    /// The same frame with the tag's value lower-cased, as emule-qt's
    /// `QByteArray::toHex` writes it.
    fn lower_cased(mut frame: Vec<u8>) -> Vec<u8> {
        let at = frame
            .windows(IP6_TAG_HEADER.len())
            .position(|window| window == IP6_TAG_HEADER)
            .unwrap()
            + IP6_TAG_HEADER.len();
        frame[at..at + 32].make_ascii_lowercase();
        frame
    }

    /// The storer's one-row answer re-serving `ip6`.
    fn answer(ip6: Option<Ipv6Addr>) -> Vec<u8> {
        let row = KadSourceRow {
            source_id: [0x71; 16],
            source_type: 1,
            ip: Ipv4Addr::new(45, 55, 200, 10),
            tcp_port: 4662,
            udp_port: 4672,
            encryption: None,
            buddy: None,
            ipv6: ip6,
        };
        encode_source_result(
            KadId::from_bytes([0x22; 16]),
            KadId::from_bytes([0x33; 16]),
            &[row],
        )[0]
        .encode()
    }

    fn download(peers: &[&str]) -> DownloadLeg {
        DownloadLeg {
            ran: true,
            log: peers
                .iter()
                .map(|peer| format!("download peer_selected id=1 peer={peer}\n"))
                .collect(),
            output_hash: Some(FILE_HASH.to_owned()),
        }
    }

    fn outcomes(publish: &[u8], answer: &[u8], download: &DownloadLeg) -> Vec<&'static str> {
        let leg = EmuleQtLeg {
            publish: Some(publish),
            answer: Some(answer),
            download,
            file_hash: FILE_HASH,
            served: "",
        };
        claims(&leg, QT_V4, QT_V6)
            .iter()
            .map(|claim| claim.outcome)
            .collect()
    }

    /// The `ip6` claim is byte-level: the same address spelled upper-case, as
    /// rmule and kno write it, decodes identically and must not pass for
    /// emule-qt's lower-case bytes; nor may a lower-case tag naming another
    /// address.
    #[test]
    fn only_emule_qts_own_address_in_lower_case_holds_the_ip6_claim() {
        let other = Ipv6Addr::new(0x3fff, 0x0ed2, 1, 0, 0, 0, 0, 0xb);
        let answer = answer(Some(QT_V6));
        let dial = download(&["[3fff:ed2:1::a]:4662"]);
        assert_eq!(
            outcomes(&lower_cased(publish(QT_V6)), &answer, &dial)[0],
            "held"
        );
        assert_eq!(outcomes(&publish(QT_V6), &answer, &dial)[0], "absent");
        assert_eq!(
            outcomes(&lower_cased(publish(other)), &answer, &dial)[0],
            "absent"
        );
    }

    /// The dial claim needs the storer to have re-served the `ip6` and the
    /// download to have selected emule-qt's IPv6 endpoint and never its IPv4
    /// one.
    #[test]
    fn the_dial_claim_needs_the_re_served_ip6_and_an_ipv6_only_dial() {
        let publish = lower_cased(publish(QT_V6));
        let v6_only = download(&["[3fff:ed2:1::a]:4662"]);
        let both = download(&["[3fff:ed2:1::a]:4662", "45.55.200.10:4662"]);
        assert_eq!(
            outcomes(&publish, &answer(Some(QT_V6)), &v6_only)[1],
            "held"
        );
        assert_eq!(outcomes(&publish, &answer(Some(QT_V6)), &both)[1], "absent");
        assert_eq!(outcomes(&publish, &answer(None), &v6_only)[1], "absent");
    }
}
