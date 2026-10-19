//! `ipv6-kad-tags`: Kad's `ip6` tag (ADR-0087), both ways, against kno's aMule
//! `ab483654` placed in a private Kad mesh by **Seeded Bootstrap**.
//!
//! One kno body plays both counterparty roles at once, on the dialect WAN's
//! fake-public `45.55.200.0/24` (one Kad client per address — aMule's
//! `MAX_CONTACTS_IP`):
//!
//! 1. **Storer.** Its Kad ID is pinned to the key of a file rmule publishes, so
//!    `Process2PublishSourceRequest` (`KademliaUDPListener.cpp:1349`) is inside
//!    `SEARCHTOLERANCE`. The rmule publisher advertises its own IPv6
//!    (`kad join-node --advertised-ipv6`), so its `0x44` carries `ip6`; kno
//!    indexes every tag it does not recognise verbatim (`:1402`, "TODO: Filter
//!    tags"), and the `0x3B` it answers rmule's search with is the evidence that
//!    it stored and returned ours.
//! 2. **Publisher.** kno shares a file, and a rmule storer is pinned at that
//!    file's key and seeded into kno's routing table. kno writes `ip6` into its
//!    own source publish only once an inbound IPv6 connection has verified the
//!    address (`Search.cpp:886-902`, `MayAdvertiseIPv6()` and
//!    `GetVerifiedIPv6Address()`, recorded by `ListenSocket.cpp:205`), so the
//!    flow dials it over IPv6 first. And it publishes a source only when not
//!    firewalled or holding a buddy (`SharedFileList.cpp:1735`): the `ed2ksrv`
//!    body gives it an eD2k High ID, which `CamuleApp::IsFirewalled`
//!    (`amule.cpp:3118`) takes as open. The publish waits for the first
//!    `NODECOMPLETE` self-lookup, three minutes after Kad starts
//!    (`Kademlia.cpp:105`) plus `SEARCHNODE_LIFETIME`.
//!
//! 3. **Storer of a firewalled row** ([`bi6`]). A second rmule
//!    publisher, firewalled, publishes the same file as aMule's type-3 buddy
//!    row closed with `bi6`, and kno's `0x3B` returns it. kno itself writes no
//!    `bi6` — its own publish, from direction 2, is the measured zero.
//!
//! 4. **Download**. A fourth rmule body, a real `Core` with its listener
//!    bound in both families and its Kad seeded with the storer alone, is
//!    handed kno's link and nothing else: the storer's `0x3B` re-serves kno's
//!    High-ID row with its `ip6` beside it, and the **Dial Chooser**
//!    (`dialable.rs`, ADR-0087) settles that one dual-stack source on IPv6,
//!    because the downloader holds a Known IPv6 of its own. The claim is
//!    rmule's: which endpoint its download dialled. The file cannot arrive at
//!    this pin — kno's verified-IPv6 hello answer counts a tag it never writes
//!    (`ipv6-hello-tags`) — so the transfer is a second claim that measures that stop.
//!
//! 5. **Searcher** ([`kno_search`]). A second rmule storer beside kno at
//!    the 2 MiB file's key indexes the firewalled row too; the flow then opens
//!    the image's download gate, kno searches that storer for the file, and
//!    reads the row rmule re-serves with its `bi6`. kno's reader drops the tag
//!    (`Search.cpp:1205-1224`) and calls back through the IPv4 buddy trio.
//!
//! 6. **emule-qt** ([`emuleqt`]). emule-qt `73fff714`, a Kad node
//!    sharing a third file, publishes its own `ip6` — lower-case — to a rmule
//!    storer at that file's key, and a fresh rmule `Core` downloads the file
//!    off the row the storer re-serves. kno's transfer stops at its hello
//!    answer (leg 4); this one is the flow's byte-equal transfer.
//!
//! Evidence is kno's own bytes off the tap on its attachment: the `0x3B` it
//! sent the publisher and the `0x44` it sent the storer, each lifted into the
//! leg dir and read back through rmule's own decoders.

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use rmule_kad::{Kad2Message, KadDecoded, KadPublishedSource, KadSourceCandidate};

use crate::flow::bench::Bench;
use crate::flow::ed2ksrv::ED2KSRV;
use crate::flow::evidence::{count_pcap_rows, write_pcap_first_match};
use crate::flow::gate::wait_for_container_log;
use crate::flow::identity::{hex_lower, parse_ed2k_file_hash, parse_ipv4_octets};
use crate::flow::mesh::KAD_CONTACT_VERSION;
use crate::flow::nat::dialect::bench::{
    HOST_AMULE_KNO, HOST_DRIVER, HOST_ED2KSRV, HOST_KAD_BI6_STORER, HOST_KAD_DOWNLOADER,
    HOST_KAD_FW_PUBLISHER, HOST_KAD_PUBLISHER, HOST_KAD_STORER, Ipv6DialectOptions, Stage,
    body_log, container_name, start_detached_driver,
};
use crate::flow::nat::dialect::legs::hello_leg;
use crate::flow::nat::dialect::verdict::{Body, Claim, DriverRow, Evidence};
use crate::flow::nat::dialect::{BODY_CLIENT_UDP_PORT, BODY_PEER_TCP_PORT, ED2KSRV_TCP_PORT};
use crate::flow::nat::synthetic::{SyntheticFile, write_hashed};
use crate::flow::pcap::first_udp_payload;
use crate::flow::pinned_image::AMULE_KNO;
use crate::kad_seed::{
    KadContact, build_preferences_kad_dat, build_routing_zone_nodes_dat,
    storer_kad_id_for_file_hash,
};

/// kno's user hash, pinned through `preferences.dat` so its source row's ID
/// names one known identity. aMule stamps bytes 5 and 14 on load
/// (`Preferences.cpp:1081-1082`), so the hash it publishes differs there.
const KNO_USER_HASH: &str = "4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b";
/// The rmule publisher's user hash.
const PUBLISHER_USER_HASH: &str = "50505050505050505050505050505050";
/// The rmule storer's user hash.
const STORER_USER_HASH: &str = "53535353535353535353535353535353";
/// The rmule publisher's Kad ID: far from both file keys, asymmetric per word.
const PUBLISHER_KAD_ID: [u8; 16] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
];

/// The file kno shares and publishes a source for.
const KNO_SHARED_BYTES: u64 = 1 << 20;
/// The file rmule publishes a source for; a different size, so a different key.
const RMULE_PUBLISHED_BYTES: u64 = 2 << 20;

/// How long the rmule publisher runs: its publish, kno's ack, its search and
/// kno's answer, with the stimulus retries they may need.
const PUBLISHER_WINDOW_SECS: u64 = 150;
/// How long the rmule storer runs. kno publishes after its first
/// `NODECOMPLETE` self-lookup — three minutes after Kad starts, plus the
/// search's own 45 s lifetime — and the downloader then asks the storer for
/// that row, so the window covers both with room to spare.
const STORER_WINDOW_SECS: u64 = 900;

/// kno's readiness marker in `ed2k-server-kad` mode: it holds its eD2k session.
const KNO_READY_MARKER: &str = "rmule-amule-server-kad-ready";
/// The rmule publisher's line once kno's `0x3B` decoded.
const PUBLISHER_DONE_MARKER: &str = "rmule-kad-stimulus-complete";
/// The rmule storer's event line once it indexed a publish.
const STORER_INDEXED_MARKER: &str = "SourceIndexed";
/// Every `kad join-node` prints this once its socket is bound.
const JOIN_NODE_READY_MARKER: &str = "rmule-kad-join-node-ready";

/// The bodies' leg-dir names, their `/out` subdirectories and their roles.
const PUBLISHER_ROLE: &str = "v6kad-publisher";
const STORER_ROLE: &str = "v6kad-storer";
const DOWNLOADER_ROLE: &str = "v6kad-downloader";

/// The rmule downloader's user hash.
const DOWNLOADER_USER_HASH: &str = "44444444444444444444444444444444";
/// The rmule downloader's Kad ID: far from both file keys, distinct per word.
const DOWNLOADER_KAD_ID: [u8; 16] = [
    0x76, 0x54, 0x32, 0x10, 0xFE, 0xDC, 0xBA, 0x98, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67,
];
/// How long the downloader is given: its first Kad sweep (ten seconds), one
/// walk to a seeded storer, the dial and 1 MiB on a local bridge.
const DOWNLOADER_WINDOW_SECS: u64 = 180;
/// The eD2k server the downloader names. Nothing listens there, by design:
/// `ed2ksrv` would hand it kno's IPv4 as a server source, and the dial this
/// leg measures must come off the Kad row alone.
const DOWNLOADER_ABSENT_SERVER: &str = "192.0.2.1:4661";
/// `ed2k download start --serve` prints this once the listener bound both
/// families — the bind the downloader's Known IPv6 needs.
const DOWNLOADER_READY_MARKER: &str = "serve.serving_started";
/// And this once the file verified and landed.
const DOWNLOADER_DONE_MARKER: &str = "download finalized";

/// The datagrams lifted off kno's tap, by file stem.
const RMULE_PUBLISH: &str = "rmule-publish-source-req-0x44";
const KNO_SEARCH_RES: &str = "amule-kno-search-res-0x3b";
const KNO_PUBLISH: &str = "amule-kno-publish-source-req-0x44";
const RMULE_FW_PUBLISH: &str = "rmule-firewalled-publish-source-req-0x44";
const KNO_FW_SEARCH_RES: &str = "amule-kno-search-res-bi6-0x3b";
const KNO_SEARCH_REQ: &str = "amule-kno-search-source-req-0x34";
const RMULE_BI6_SEARCH_RES: &str = "rmule-storer-search-res-bi6-0x3b";
const KNO_CALLBACK_REQ: &str = "amule-kno-callback-req-0x52";

mod bi6;
mod emuleqt;
mod kno_search;

/// Stand the mesh up: the eD2k server, the rmule storer kno is seeded with,
/// and kno itself. Returns kno's container, which the tap watches.
///
/// # Errors
/// If a container cannot start or kno never reaches its eD2k session.
pub(super) fn start(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &mut Stage,
    suffix: &str,
    timeout: Duration,
) -> Result<String> {
    let shared = write_hashed(&subdir(&stage.leg_dir, "shared")?, KNO_SHARED_BYTES)?;
    let published = write_hashed(&subdir(&stage.leg_dir, "published")?, RMULE_PUBLISHED_BYTES)?;
    let kno_kad_id = storer_kad_id_for_file_hash(parse_ed2k_file_hash(&published.link)?);
    let storer_kad_id = storer_kad_id_for_file_hash(parse_ed2k_file_hash(&shared.link)?);

    let server = format!("rmule-interop-v6srv-{suffix}");
    let ed2ksrv = ED2KSRV.check(&bench.docker, options.ed2ksrv_image)?;
    bench.start_extra(
        &server,
        ed2ksrv
            .container()
            .detach()
            .name(&server)
            .network(&stage.network)
            .ip(stage.v4(HOST_ED2KSRV))
            // Pinned even though the server speaks no IPv6: an unpinned body
            // takes the /64's first free address from Docker's IPAM, which is
            // the one kno is pinned to.
            .ip6(stage.v6(HOST_ED2KSRV))
            .cap_add("NET_ADMIN"),
        "run the ed2k-server that gives kno its High ID",
    )?;

    // The storer is listening before kno boots, so kno's first hello to its
    // seeded contact lands.
    subdir(&stage.leg_dir, STORER_ROLE)?;
    let (storer, ready) = start_detached_driver(
        bench,
        options,
        stage,
        STORER_ROLE,
        HOST_KAD_STORER,
        &join_node_args(
            stage,
            STORER_ROLE,
            storer_kad_id,
            STORER_USER_HASH,
            STORER_WINDOW_SECS,
        ),
        JOIN_NODE_READY_MARKER,
    )?;
    if !ready {
        anyhow::bail!("the rmule storer {storer} never bound its socket");
    }
    let bi6_storer = kno_search::start_storer(bench, options, stage, kno_kad_id)?;

    let seed = subdir(&stage.leg_dir, "kno-seed")?;
    fs::write(
        seed.join("preferencesKad.dat"),
        build_preferences_kad_dat(kno_kad_id),
    )
    .context("write kno's preferencesKad.dat")?;
    fs::write(
        seed.join("nodes.dat"),
        build_routing_zone_nodes_dat(&[
            KadContact {
                kad_id: storer_kad_id,
                ipv4: parse_ipv4_octets(stage.v4(HOST_KAD_STORER))?,
                udp_port: BODY_CLIENT_UDP_PORT,
                tcp_port: BODY_PEER_TCP_PORT,
                version: KAD_CONTACT_VERSION,
            },
            bi6_storer,
        ]),
    )
    .context("write kno's nodes.dat")?;

    let kno = format!("rmule-interop-v6kno-{suffix}");
    let shared_dir = shared.path.parent().context("the shared file has a dir")?;
    let pinned = AMULE_KNO.check(&bench.docker, options.amule_kno_image)?;
    bench.start_extra(
        &kno,
        pinned
            .container()
            .detach()
            .name(&kno)
            .network(&stage.network)
            .ip(stage.v4(HOST_AMULE_KNO))
            .ip6(stage.v6(HOST_AMULE_KNO))
            .cap_add("NET_ADMIN")
            .volume(shared_dir, "/incoming")
            .volume(&seed, "/seed")
            .env("AMULE_SCENARIO_MODE", "ed2k-server-kad")
            .env("ED2K_SERVER_HOST", &server)
            .env("ED2K_SERVER_PORT", ED2KSRV_TCP_PORT.to_string())
            // The fake-public /24 already passes IsGoodIPPort; LAN mode must
            // not engage (Config A).
            .env("AMULE_KAD_FILTER_LAN_IPS", "1")
            .env("AMULE_KAD_PREFS_DAT", "/seed/preferencesKad.dat")
            .env("AMULE_KAD_NODES_DAT", "/seed/nodes.dat")
            .env("AMULE_USER_HASH", KNO_USER_HASH)
            // The kno-searches leg: the link is added only once the
            // flow opens the gate, after the firewalled row is stored.
            .env("AMULE_DOWNLOAD_LINK", &published.link)
            .env(
                "AMULE_DOWNLOAD_GATE",
                format!("/seed/{}", kno_search::DOWNLOAD_GATE),
            ),
        "run kno's aMule in a seeded private Kad mesh",
    )?;
    wait_for_container_log(&bench.docker, &kno, KNO_READY_MARKER, timeout)?;

    stage.bodies.push(Body {
        name: "amule-kno".to_owned(),
        image: options.amule_kno_image.to_owned(),
        pin: pinned.pin(),
        address_v4: stage.v4(HOST_AMULE_KNO).to_owned(),
        address_v6: stage.v6(HOST_AMULE_KNO).to_owned(),
    });
    // Started last, by its own leg; its address is part of the plan from here.
    stage
        .bodies
        .push(emuleqt::body(&bench.docker, options, stage));
    stage.bodies.push(Body {
        name: "ed2ksrv".to_owned(),
        image: options.ed2ksrv_image.to_owned(),
        pin: ed2ksrv.pin(),
        address_v4: stage.v4(HOST_ED2KSRV).to_owned(),
        address_v6: stage.v6(HOST_ED2KSRV).to_owned(),
    });
    stage.shared = Some(shared);
    stage.published = Some(published);
    Ok(kno)
}

/// Drive both directions and draw the claims from kno's own bytes.
///
/// # Errors
/// If a driver cannot run or a lifted datagram cannot be read.
pub(super) fn drive(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
) -> Result<(Vec<Claim>, String)> {
    let published = stage.published.as_ref().context("the published file")?;
    let kno_v4 = stage.v4(HOST_AMULE_KNO).to_owned();
    let kno_v6 = stage.v6(HOST_AMULE_KNO).to_owned();
    let publisher_v4 = stage.v4(HOST_KAD_PUBLISHER).to_owned();
    let publisher_v6 = stage.v6(HOST_KAD_PUBLISHER).to_owned();
    let storer_v4 = stage.v4(HOST_KAD_STORER).to_owned();

    // An inbound native-IPv6 connection is the only thing that verifies kno's
    // address, and kno's own publish reads that verdict.
    let hello = hello_leg(
        bench,
        options,
        stage,
        "hello-amule-kno",
        &format!("[{kno_v6}]:{BODY_PEER_TCP_PORT}"),
        Some(&kno_v6),
    )?;

    subdir(&stage.leg_dir, PUBLISHER_ROLE)?;
    let mut publisher_args = join_node_args(
        stage,
        PUBLISHER_ROLE,
        PUBLISHER_KAD_ID,
        PUBLISHER_USER_HASH,
        PUBLISHER_WINDOW_SECS,
    );
    publisher_args.extend([
        "--publish-file-hash".to_owned(),
        published.file_hash.to_lowercase(),
        "--publish-file-size".to_owned(),
        published.size.to_string(),
        "--advertised-ipv6".to_owned(),
        publisher_v6.clone(),
    ]);
    let (publisher, _) = start_detached_driver(
        bench,
        options,
        stage,
        PUBLISHER_ROLE,
        HOST_KAD_PUBLISHER,
        &publisher_args,
        JOIN_NODE_READY_MARKER,
    )?;
    let searched = wait_for_container_log(
        &bench.docker,
        &publisher,
        PUBLISHER_DONE_MARKER,
        Duration::from_secs(PUBLISHER_WINDOW_SECS + 30),
    )
    .is_ok();
    // After direction 1, so kno's answer to the firewalled publisher carries
    // both rows side by side; inside the storer's window, so it costs no time.
    let (fw_publisher, fw_searched) = bi6::drive(bench, options, stage)?;
    let kno = container_name(options.layout, "v6kno")?;
    let bi6_storer = container_name(options.layout, kno_search::BI6_STORER_ROLE)?;
    let (bi6_indexed, kno_added) = kno_search::drive(bench, stage, &kno, &bi6_storer)?;
    let storer = container_name(options.layout, STORER_ROLE)?;
    let indexed = wait_for_container_log(
        &bench.docker,
        &storer,
        STORER_INDEXED_MARKER,
        Duration::from_secs(STORER_WINDOW_SECS),
    )
    .is_ok();
    let shared = stage.shared.as_ref().context("kno's shared file")?;
    let download = download_leg(
        bench,
        options,
        stage,
        &DownloadSpec {
            role: DOWNLOADER_ROLE,
            host: HOST_KAD_DOWNLOADER,
            file: shared,
            storer_host: HOST_KAD_STORER,
            kad_id: DOWNLOADER_KAD_ID,
            user_hash: DOWNLOADER_USER_HASH,
        },
        indexed,
    )?;
    body_log(bench, stage, &publisher, PUBLISHER_ROLE)?;
    body_log(bench, stage, &fw_publisher, bi6::FW_PUBLISHER_ROLE)?;
    let storer_log = body_log(bench, stage, &storer, STORER_ROLE)?;
    body_log(bench, stage, &bi6_storer, kno_search::BI6_STORER_ROLE)?;
    let kno_log = body_log(bench, stage, &kno, "amule-kno")?;

    let tap = format!("{}-wan", container_name(options.layout, "v6tap")?);
    let lift = |stem: &str, filter: String| lift_datagram(bench, stage, &tap, stem, &filter);
    let rmule_publish = lift(RMULE_PUBLISH, kad_filter(&publisher_v4, &kno_v4, 0x44))?;
    let kno_answer = lift(KNO_SEARCH_RES, kad_filter(&kno_v4, &publisher_v4, 0x3b))?;
    let kno_publish = lift(KNO_PUBLISH, kad_filter(&kno_v4, &storer_v4, 0x44))?;
    let fw_v4 = stage.v4(HOST_KAD_FW_PUBLISHER).to_owned();
    let fw_publish = lift(RMULE_FW_PUBLISH, kad_filter(&fw_v4, &kno_v4, 0x44))?;
    let fw_answer = lift(KNO_FW_SEARCH_RES, kad_filter(&kno_v4, &fw_v4, 0x3b))?;
    let bi6_storer_v4 = stage.v4(HOST_KAD_BI6_STORER).to_owned();
    let kno_search_req = lift(KNO_SEARCH_REQ, kad_filter(&kno_v4, &bi6_storer_v4, 0x34))?;
    let storer_answer = lift(
        RMULE_BI6_SEARCH_RES,
        kad_filter(&bi6_storer_v4, &kno_v4, 0x3b),
    )?;
    let kno_callback = lift(KNO_CALLBACK_REQ, kad_filter(&kno_v4, &publisher_v4, 0x52))?;
    let buddy_v6 = bi6::buddy_ipv6(stage);
    let to_bi6 = count_pcap_rows(
        &bench.docker,
        &tap,
        "/capture/tap-wan.pcap",
        format!("ip6 and src host {kno_v6} and dst host {buddy_v6}"),
    )?;

    let publisher_v6 = publisher_v6.parse().context("the publisher's IPv6")?;
    let kno_v6_addr = kno_v6.parse().context("kno's IPv6")?;
    let ours = rmule_publish.as_deref().map(published_source).transpose()?;
    let answer = kno_answer.as_deref().map(search_rows).transpose()?;
    let theirs = kno_publish.as_deref().map(published_source).transpose()?;
    // kno's two-row answer passes aMule's 200-byte packing line and goes out
    // `0xE5`; the tag is looked for in the logical packet inside.
    let fw_answer_plain = fw_answer
        .as_deref()
        .map(|bytes| plain(bytes).map(|envelope| envelope.encode()))
        .transpose()?;
    let bi6_frames = bi6::Bi6Frames {
        ours: fw_publish
            .as_deref()
            .map(|bytes| published_source(bytes).map(|source| (bytes, source)))
            .transpose()?,
        answer: fw_answer_plain
            .as_deref()
            .map(|bytes| search_rows(bytes).map(|rows| (bytes, rows)))
            .transpose()?,
        kno_publish: kno_publish.as_deref(),
    };

    let returned = answer
        .iter()
        .flatten()
        .find_map(|row| row.facts().and_then(|facts| facts.ipv6));
    let verified_line = format!(
        "Inbound IPv6 connection from {} on {kno_v6}.",
        stage.v6(HOST_DRIVER)
    );
    let high_id = kno_log
        .lines()
        .find(|line| line.contains("eD2k: Connected"))
        .unwrap_or("")
        .trim()
        .to_owned();

    let mut claims = vec![
        // kno's hello cannot say it: the fork counts CT_MOD_IP_V6 and then
        // refuses to write it (`Tag.cpp:393`, the tag-count overrun), so
        // its own accept-path log line is the verification record.
        Claim::about(
            "amule-kno-verified-its-ipv6-on-an-inbound-v6-dial",
            kno_log.contains(&verified_line),
            Evidence::Captured,
            format!(
                "kno logged {verified_line:?}: {}. Its hello answer's 0xAA word read {} with \
                 the ipv6 bit {}, which AdvertisedModMiscOptions sets only once IPv6 is \
                 verified (IPv6Reachability.h:170).",
                kno_log.contains(&verified_line),
                hello.int("mod_misc_word"),
                hello.flag("claims_ipv6")
            ),
        ),
        // rmule's own 0x44 is Stimulus; it is checked here only so a missing
        // tag in kno's answer can be told apart from one we never sent.
        Claim::about(
            "amule-kno-stores-and-returns-the-ip6-tag",
            ours.as_ref().and_then(|source| source.ipv6) == Some(publisher_v6)
                && returned.is_some_and(|endpoint| endpoint.ip == publisher_v6),
            Evidence::Captured,
            format!(
                "Stimulus: rmule's 0x44 to kno ({} bytes) carried ip6 = {:?}. kno's 0x3B to \
                 the publisher ({} bytes, publisher decoded it: {searched}) carried {} row(s); \
                 the ip6 read back: {returned:?}",
                rmule_publish.as_ref().map_or(0, Vec::len),
                ours.as_ref().and_then(|source| source.ipv6),
                kno_answer.as_ref().map_or(0, Vec::len),
                answer.as_ref().map_or(0, Vec::len)
            ),
        ),
        Claim::about(
            "a-search-result-row-parsed-back-with-its-ipv6-endpoint",
            returned.is_some_and(|endpoint| endpoint.port == BODY_PEER_TCP_PORT)
                && answer
                    .iter()
                    .flatten()
                    .any(|row| row.peer_source().is_some()),
            Evidence::Captured,
            format!(
                "decode_source_result on kno's bytes: rows {:?}. A High-ID row keeps its IPv4 \
                 Peer Source and carries the IPv6 endpoint beside it as its IPv6 half; only a \
                 row with no road at all is rescued into PeerSource::Ipv6.",
                answer
                    .iter()
                    .flatten()
                    .map(|row| (row.peer_source(), row.facts().and_then(|f| f.ipv6)))
                    .collect::<Vec<_>>()
            ),
        ),
        Claim::about(
            "amule-kno-publishes-its-own-ip6-tag",
            theirs.as_ref().and_then(|source| source.ipv6) == Some(kno_v6_addr),
            Evidence::Captured,
            format!(
                "kno's 0x44 to the storer ({} bytes; kno's eD2k line: {high_id:?}) carried \
                 ip6 = {:?}",
                kno_publish.as_ref().map_or(0, Vec::len),
                theirs.as_ref().and_then(|source| source.ipv6)
            ),
        ),
        Claim::about(
            "rmule-reads-amule-knos-ip6-and-indexes-the-row",
            theirs.is_some() && indexed,
            Evidence::Captured,
            format!(
                "rmule's publish decoder read kno's row as {theirs:?}; the storer logged \
                 SourceIndexed: {indexed}"
            ),
        ),
    ];
    claims.extend(bi6::claims(&bi6_frames, buddy_v6));
    println!("ipv6-kad-tags firewalled publisher decoded kno's answer: {fw_searched}");
    println!("ipv6-kad-tags bi6 storer indexed: {bi6_indexed}; kno added the link: {kno_added}");
    let storer_answer_plain = storer_answer
        .as_deref()
        .map(|bytes| plain(bytes).map(|envelope| envelope.encode()))
        .transpose()?;
    let key = storer_kad_id_for_file_hash(parse_ed2k_file_hash(&published.link)?);
    claims.extend(kno_search::claims(
        &kno_search::KnoSearchFrames {
            published_bi6: fw_publish.as_deref().and_then(bi6::bi6_tag),
            search: kno_search_req.as_deref(),
            answer: storer_answer_plain
                .as_deref()
                .map(|bytes| search_rows(bytes).map(|rows| (bytes, rows)))
                .transpose()?,
            callback: kno_callback.as_deref(),
            to_bi6,
        },
        key,
        buddy_v6,
    ));
    claims.extend(download_claims(stage, &download, &storer_log, &hello));
    // Last: its bodies take the hosts the legs above have finished with.
    claims.extend(emuleqt::drive(bench, options, stage)?);
    Ok((claims, String::new()))
}

/// One rmule download off a Kad row: the file, the storer its Kad is seeded
/// with (at the file's key), and the body it runs as.
struct DownloadSpec<'a> {
    role: &'a str,
    host: usize,
    file: &'a SyntheticFile,
    storer_host: usize,
    kad_id: [u8; 16],
    user_hash: &'a str,
}

/// What the download leg left behind.
struct DownloadLeg {
    /// The leg ran at all: the storer indexed the publisher's row first, so
    /// there was a source to find.
    ran: bool,
    /// The downloader's own log.
    log: String,
    /// The ED2K hash of the file it wrote, upper-case hex, when it wrote one.
    output_hash: Option<String>,
}

/// Download `spec.file` with rmule, off the Kad row alone.
///
/// The downloader binds its listener in both families (`--serve`), which with
/// the `3fff:ed2:1::/64` address on its interface is what gives it a Known
/// IPv6; its Kad is seeded with the storer only, so the one source it can
/// find is the row the storer re-serves. Its Kad source search runs once, at
/// start (the next is `kad_reask_interval`, an hour, away), so it starts only
/// once the storer holds the row — and is skipped, the claims absent, when
/// the storer never indexed one.
///
/// # Errors
/// If the driver cannot start or its output cannot be read.
fn download_leg(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
    spec: &DownloadSpec<'_>,
    indexed: bool,
) -> Result<DownloadLeg> {
    if !indexed {
        return Ok(DownloadLeg {
            ran: false,
            log: String::new(),
            output_hash: None,
        });
    }
    let storer_kad_id = storer_kad_id_for_file_hash(parse_ed2k_file_hash(&spec.file.link)?);
    let dir = subdir(&stage.leg_dir, spec.role)?;
    let args = [
        "ed2k",
        "download",
        "start",
        "--data-dir",
        // Container-local: the Durable Store needs no archiving, and a bind
        // mount is no place for its file lock.
        "/tmp/rmule-download",
        "--server",
        DOWNLOADER_ABSENT_SERVER,
        "--file",
        &spec.file.link,
        "--out",
        &format!("/out/{}/download.bin", spec.role),
        "--serve",
        "--kad-contact",
        &format!(
            "{}@{}:{BODY_CLIENT_UDP_PORT}",
            hex_lower(&storer_kad_id),
            stage.v4(spec.storer_host)
        ),
        "--kad-id-hex",
        &hex_lower(&spec.kad_id),
        "--udp-port",
        &BODY_CLIENT_UDP_PORT.to_string(),
        "--tcp-port",
        &BODY_PEER_TCP_PORT.to_string(),
        "--user-hash",
        spec.user_hash,
        "--max-seconds",
        &DOWNLOADER_WINDOW_SECS.to_string(),
    ]
    .map(str::to_owned);
    let (downloader, _) = start_detached_driver(
        bench,
        options,
        stage,
        spec.role,
        spec.host,
        &args,
        DOWNLOADER_READY_MARKER,
    )?;
    let _ = wait_for_container_log(
        &bench.docker,
        &downloader,
        DOWNLOADER_DONE_MARKER,
        Duration::from_secs(DOWNLOADER_WINDOW_SECS + 30),
    );
    let log = body_log(bench, stage, &downloader, spec.role)?;
    let output = dir.join("download.bin");
    let output_hash = if output.exists() {
        let file = fs::File::open(&output).with_context(|| format!("open {}", output.display()))?;
        Some(
            rmule_primitives::FileHashSummary::digest_reader(file)
                .with_context(|| format!("hash {}", output.display()))?
                .file_hash()
                .to_hex_upper(),
        )
    } else {
        None
    };
    Ok(DownloadLeg {
        ran: true,
        log,
        output_hash,
    })
}

/// The download leg's claim: rmule's download of kno's file dialled
/// the family the Dial Chooser picked for kno's dual-stack Kad row.
///
/// kno's row is a High ID with its `ip6` beside it, and the downloader holds a
/// Known IPv6, so the chooser's AND picks IPv6: the download's first
/// `peer_selected` line — the endpoint its worker dials, logged before the
/// dial — must name kno's IPv6, and the connection must reach kno. A High-ID
/// row reaches the pool as an IPv6 endpoint only through the chooser (a rescue
/// needs a row with no road), so the line is the chooser's verdict. kno's IPv4
/// may follow only as ADR-0087's other-family fallback: the IPv6 session ended short
/// of a completed handshake (kno's refused answer), so the download dials the
/// row's other family once, and logs that fall before it does (measured on
/// run `1790248139`, whose IPv4 answer over-counts the same way).
///
/// The transfer is the second claim. kno's `OP_HELLOANSWER` at this pin
/// counts `CT_MOD_IP_V6` and never writes it once its IPv6 is verified — and
/// this flow must verify it, or kno publishes no `ip6` to download off (`ipv6-hello-tags`'s
/// `amule-kno-counts-a-tag-it-does-not-write`, measured again on this run's
/// own hello leg). rmule refuses that answer as a strict reader must, so the
/// file cannot arrive; the claim holds only while that measured defect is what
/// stopped it, and turns `absent` the day the file arrives or something else
/// ends the download.
fn download_claims(
    stage: &Stage,
    leg: &DownloadLeg,
    storer_log: &str,
    hello: &DriverRow,
) -> Vec<Claim> {
    let dial = "rmule-dialled-knos-kad-row-in-the-family-the-dial-chooser-picked";
    let transfer = "amule-kno-over-counted-hello-answer-ends-the-download";
    let Some(shared) = stage.shared.as_ref().filter(|_| leg.ran) else {
        let note = "the storer never indexed kno's row, so there was no source to download from";
        return vec![
            Claim::about(dial, false, Evidence::RmuleOnly, note),
            Claim::about(transfer, false, Evidence::DocumentedAbsence, note),
        ];
    };
    let kno_v6 = format!("[{}]:{BODY_PEER_TCP_PORT}", stage.v6(HOST_AMULE_KNO));
    let kno_v4 = format!("{}:{BODY_PEER_TCP_PORT}", stage.v4(HOST_AMULE_KNO));
    let selected: Vec<&str> = leg
        .log
        .lines()
        .filter(|line| line.contains("download.peer_selected"))
        .map(str::trim)
        .collect();
    let dialled_v4 = selected
        .iter()
        .any(|line| line.ends_with(&format!("peer={kno_v4}")));
    let first_v6 = selected
        .first()
        .is_some_and(|line| line.ends_with(&format!("peer={kno_v6}")));
    // ADR-0087: the one fall to the other family, traced before it dials.
    let fell_to_v4 = leg.log.lines().find(|line| {
        line.contains("first-family dial failed")
            && line.contains(&format!("peer={kno_v6}"))
            && line.contains(&format!("other={kno_v4}"))
    });
    let arrived = leg.output_hash.as_deref() == Some(shared.file_hash.as_str());
    // The peer driver's own line once kno's answer arrived and was refused.
    let refused = leg
        .log
        .lines()
        .find(|line| {
            line.contains(&format!("peer_connection{{peer={kno_v6}}}"))
                && line.contains("ProtocolViolation")
        })
        .map(str::trim);
    // The core's own named refusal (ADR-0050), the line the operator's
    // Networks log words.
    let named = leg
        .log
        .lines()
        .find(|line| line.contains("peer.hello_refused code=tag_count_short"))
        .map(str::trim);
    let downloader_v4 = stage.v4(HOST_KAD_DOWNLOADER);
    let served = storer_log
        .lines()
        .find(|line| line.contains("SourceSearchServed") && line.contains(downloader_v4))
        .unwrap_or("")
        .trim();
    let declared = hello.int("answer_tags_declared");
    let read = hello.int("answer_tags_read");
    let over_counted = declared > read;
    vec![
        Claim::about(
            dial,
            first_v6 && (!dialled_v4 || fell_to_v4.is_some()) && (arrived || refused.is_some()),
            Evidence::RmuleOnly,
            format!(
                "rmule's download (Known IPv6 {} from its interface, listener bound in both \
                 families, no answering server) selected {selected:?}: kno's IPv6 {kno_v6} \
                 first {first_v6}, its IPv4 {kno_v4} {dialled_v4} (the other-family fall: \
                 {fell_to_v4:?}); the connection reached kno's hello answer: {}. The storer \
                 served the row: {served:?}.",
                stage.v6(HOST_KAD_DOWNLOADER),
                arrived || refused.is_some(),
            ),
        ),
        if !arrived && over_counted && refused.is_some() && named.is_some() {
            Claim::absence(
                transfer,
                i64::from(arrived),
                format!(
                    "Upstream defect, measured: kno's OP_HELLOANSWER on this run declared \
                     {declared} tags and carried {read} (the hello leg's reading of the same \
                     kno) — CT_MOD_IP_V6 counted under emitModIPv6 and refused by \
                     CTag::WriteTagToFile's restrictive default (BaseClient.cpp:1384/1595, \
                     Tag.cpp:393). The downloader refused it too: {refused:?}, by name: \
                     {named:?}. No file: output \
                     ED2K {:?} against kno's {} ({} bytes). Every strict reader, aMule's own \
                     included, stops here; the family the chooser picked is the claim above.",
                    leg.output_hash, shared.file_hash, shared.size,
                ),
            )
        } else {
            Claim::about(
                transfer,
                false,
                Evidence::DocumentedAbsence,
                format!(
                    "the measured defect is not what this run shows: file arrived {arrived} \
                     (output ED2K {:?} against kno's {}), hello answer declared {declared} and \
                     carried {read}, refusal line {refused:?}, named {named:?}. A whole file means kno's answer \
                     is well-formed now and this row becomes a transfer claim.",
                    leg.output_hash, shared.file_hash,
                ),
            )
        },
    ]
}

/// The `kad join-node` argv every rmule Kad body here shares.
fn join_node_args(
    stage: &Stage,
    role: &str,
    kad_id: [u8; 16],
    user_hash: &str,
    window_secs: u64,
) -> Vec<String> {
    [
        "kad",
        "join-node",
        "--bind",
        &format!("0.0.0.0:{BODY_CLIENT_UDP_PORT}"),
        "--id-hex",
        &hex_lower(&kad_id),
        "--tcp-port",
        &BODY_PEER_TCP_PORT.to_string(),
        "--bootstrap",
        &format!("{}:{BODY_CLIENT_UDP_PORT}", stage.v4(HOST_AMULE_KNO)),
        "--capture-dir",
        &format!("/out/{role}/tap"),
        "--events-file",
        &format!("/out/{role}/events.log"),
        "--run-secs",
        &window_secs.to_string(),
        "--user-hash-hex",
        user_hash,
    ]
    .map(ToOwned::to_owned)
    .to_vec()
}

/// The BPF that picks one plain Kad opcode from `src` to `dst`.
fn kad_filter(src: &str, dst: &str, opcode: u8) -> String {
    format!(
        "udp and src host {src} and dst host {dst} and (udp[8] = 0xe4 or udp[8] = 0xe5) \
         and udp[9] = {opcode:#04x}"
    )
}

/// Lift the first datagram `filter` matches on kno's tap into
/// `<leg>/<stem>.pcap` + `<stem>.bin`, or `None` when the wire never carried it.
fn lift_datagram(
    bench: &Bench,
    stage: &Stage,
    tap: &str,
    stem: &str,
    filter: &str,
) -> Result<Option<Vec<u8>>> {
    lift_datagram_from(bench, stage, (tap, "/capture/tap-wan.pcap"), stem, filter)
}

/// [`lift_datagram`] off any tap whose sidecar writes into the leg dir: the
/// sidecar container and the pcap path inside it.
fn lift_datagram_from(
    bench: &Bench,
    stage: &Stage,
    (tap, pcap): (&str, &str),
    stem: &str,
    filter: &str,
) -> Result<Option<Vec<u8>>> {
    let subset = format!("{stem}.pcap");
    write_pcap_first_match(&bench.docker, tap, pcap, filter, &subset)?;
    let body = first_udp_payload(&stage.leg_dir.join(&subset))?;
    if let Some(bytes) = &body {
        let path = stage.leg_dir.join(format!("{stem}.bin"));
        fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))?;
    }
    println!(
        "ipv6-kad-tags lifted {stem}: {} bytes",
        body.as_ref().map_or(0, Vec::len)
    );
    Ok(body)
}

/// A `0x44` read through rmule's publish decoder.
fn published_source(datagram: &[u8]) -> Result<KadPublishedSource> {
    match Kad2Message::decode(&plain(datagram)?).map_err(|error| anyhow!("{error:?}"))? {
        Kad2Message::PublishSourceReq { source, .. } => Ok(source),
        other => Err(anyhow!("expected a 0x44, decoded {other:?}")),
    }
}

/// A `0x3B` read through rmule's **Kad Source Row Projection**.
fn search_rows(datagram: &[u8]) -> Result<Vec<KadSourceCandidate>> {
    rmule_kad::decode_source_result(&plain(datagram)?).map_err(|error| anyhow!("{error:?}"))
}

fn plain(datagram: &[u8]) -> Result<rmule_kad::KadEnvelope> {
    match rmule_kad::decode_exact(datagram).map_err(|error| anyhow!("{error:?}"))? {
        // aMule packs a Kad datagram past 200 bytes (`0xE5`, zlib); the
        // logical packet inside is the one every claim reads.
        KadDecoded::Plain(envelope) | KadDecoded::Packed(envelope) => Ok(envelope),
    }
}

fn subdir(leg: &Path, name: &str) -> Result<std::path::PathBuf> {
    let dir = leg.join(name);
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    Ok(dir)
}
