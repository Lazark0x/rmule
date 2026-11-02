//! The `natt-udp-selfcheck-amule` topology: `natt-udp-selfcheck-cone`'s self-check
//! bench with the firewalled body swapped for **stock aMule 2.3.3** on the
//! debug image, so the UDP verdict and the publish that follows are aMule's
//! own — the aMule-authored tier of ADR-0061's type-6 row.
//!
//! The WAN side is `natt-udp-selfcheck-cone`'s unchanged: the rmule root every body is seeded
//! with, a storer placed at the Synthetic File's Kad key
//! (`SetValueBE(fileHash)`, the placement flow M's `--publish-source` needs to
//! clear `SEARCHTOLERANCE`), and two open rmule **UDP Firewall Helpers** that
//! only the root knows. Behind a `full-cone-pinned` gateway that forwards the
//! Kad UDP port and nothing else, aMule shares the Synthetic File from a
//! routing-zone `nodes.dat` naming the root and the storer alone.
//!
//! aMule's `CUDPFirewallTester` admits a helper only when its IP is absent
//! from the routing zone (`UDPFirewallTester.cpp:250`, aMule 2.3.3); on this one-`/24`
//! bench `CRoutingBin::AddContact` admits at most two contacts per `/24`
//! (`RoutingBin.cpp:89`), so the seeded root and storer fill that quota and
//! the helpers, learned only as rows of the helper lookup, stay fresh.
//!
//! What the flow reads is aMule's own account: its debug logfile (the
//! `UDPFirewallTester` verdict line, `Starting BuddySearch`,
//! `Search request type: StoreFile`), its `OP_FWCHECKUDPREQ` on the gateway's
//! WAN tap, and any `0x44` on a **Capture Sidecar** in the storer's netns.
//!
//! `--low-id-buddy` runs the **Low-ID Buddy Recipe** ([`lowid`]):
//! the same bench plus an `ed2ksrv` that gives the root a Low ID,
//! aMule's UDP verdict held firewalled until it holds the root as its buddy,
//! then released, then the file shared.

mod claims;
pub(in crate::flow::nat::natt::buddy) mod evidence;
mod lowid;

use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use self::claims::{AmuleFacts, claims};
use self::evidence::{
    amule_logfile, amule_status, count_wire, fwcheck_frame_text, lift_helper_answer, lift_publish,
    wait_for_udp_verdict,
};
use super::super::{
    HASH_TARGET, HOST_BUDDY, HOST_STORER, collect_buddy_log, mesh, parse_hash, start_buddy,
};
use super::{HELPER_KAD_IDS, HOST_HELPERS, start_helper};
use crate::docker::{InternalNetwork, RunContainer};
use crate::fake_public::{MAX_NODES_PER_SUBNET, fake_public_address, subnet_cidr};
use crate::flow::bench::{Bench, run_checked};
use crate::flow::gate::wait_for_container_log;
use crate::flow::identity::parse_ipv4_octets;
use crate::flow::nat::NAT_CLIENT_UDP_PORT;
use crate::flow::nat::claims::Body;
use crate::flow::nat::natt::bench::{Driven, NattOptions};
use crate::flow::nat::natt::punch::proof::{probe_peer_lan, run_reflector};
use crate::flow::nat::natt::punch::{
    ED2KSRV_TCP_PORT, HOST_GATEWAY_B, HOST_PROBE_PRIMARY, HOST_PROBE_SECONDARY, LAN_B, Peer,
    start_gateway_mapped,
};
use crate::flow::nat::natt::verdict::WireRow;
use crate::flow::nat::natt::{BODY_CLIENT_UDP_PORT, BODY_PEER_TCP_PORT, WAN_SUBNET_INDEX};
use crate::flow::taps::{Attachment, PerAttachmentTaps, TapRole, TapRow};
use crate::kad_seed::{KadContact, build_preferences_kad_dat, build_routing_zone_nodes_dat};
use crate::nat::NatType;

/// aMule's pinned Kad ID — `natt-udp-selfcheck-cone`'s target's, so the two rows name the same
/// keyspace point.
const AMULE_KAD_ID: [u8; 16] = mesh::TARGET_KAD_ID;

/// The Kad version the seeded contacts are written with; each body's own
/// `HELLO` overwrites it.
const SEED_CONTACT_VERSION: u8 = 8;

/// The entrypoint's EC password, for the closing `amulecmd status`.
const AMULE_EC_PASSWORD: &str = "rmule";

/// Where the debug build writes its logfile inside the container.
const AMULE_LOGFILE: &str = "/root/.aMule/logfile";

/// How long aMule's UDP verdict may take: past its own six-minute timeout
/// (`UDPFirewallTester.cpp:62`), so a run that never engages a helper ends on
/// aMule's timeout line rather than on ours.
const UDP_VERDICT_TIMEOUT_SECS: u64 = 420;

/// How long aMule is held after its verdict — the publish walk's window.
const PUBLISH_WINDOW_SECS: u64 = 300;

/// aMule's minimum uptime before the flow reads its publish: its NODECOMPLETE
/// self-lookup runs at +3 min (`Kademlia.cpp:100`) and gates
/// `CKademlia::GetPublish()`, and the source loop turns every 2 s after that.
const AMULE_MIN_UPTIME_SECS: u64 = 480;

/// How long the WAN bodies live: setup, the verdict budget, the window, and
/// slack for the harvest.
const RUN_SECS: u64 = UDP_VERDICT_TIMEOUT_SECS + PUBLISH_WINDOW_SECS + 300;

/// The same, on the Low-ID Buddy Recipe: setup, the recipe's own budgets, and
/// slack for the harvest.
const LOW_ID_RUN_SECS: u64 = lowid::RECIPE_SECS + 300;

/// The verdict lines `CUDPFirewallTester::SetUDPFWCheckResult` and
/// `IsFirewalledUDP` write (`UDPFirewallTester.cpp:65, 148, 151, 158`).
pub(in crate::flow::nat::natt::buddy) const UDP_OPEN_LINE: &str =
    "New Kad Firewallstate (UDP): Open";
const UDP_VERDICT_LINES: [&str; 3] = [
    "New Kad Firewallstate (UDP)",
    "New KAD Firewallstate (UDP)",
    "Timeout: Setting UDP status to firewalled",
];

/// `TAG_SOURCETYPE` 6 and the direct-callback bit, as `natt-udp-selfcheck-cone` reads them.
const SOURCE_TYPE_DIRECT_UDP_CALLBACK: u8 = 6;
const CONNECT_OPTIONS_DIRECT_UDP_CALLBACK: u8 = 0x08;

/// The claim the type-6 row settles, on either run.
const PUBLISH_CLAIM: &str = "the-storer-captured-an-amule-type-6-row-stating-0x08";

/// The lifted `0x44`'s file name beside the storer tap's pcap.
const PUBLISH_BODY: &str = "amule-publish-source-req";

/// Stand the aMule self-check topology up, drive it, and hand back the claims.
///
/// # Errors
/// If the bench cannot be built or a body never reports ready. **A verdict
/// that never reads open, or a publish that never leaves, is not an error** —
/// the claims name which link broke and quote aMule's own log for it.
pub(in crate::flow::nat::natt) fn drive(
    bench: &mut Bench,
    options: &NattOptions<'_>,
    nat_type: NatType,
    suffix: &str,
    leg_dir: &Path,
) -> Result<(Driven, Vec<WireRow>, Vec<TapRow>)> {
    let wan = format!("rmule-interop-nattwan-{suffix}");
    bench.create_extra_network(
        &wan,
        bench.docker.create_internal_network(
            InternalNetwork::new(&wan).subnet_v4(&subnet_cidr(WAN_SUBNET_INDEX)?),
        ),
        "create the fake-public WAN",
    )?;
    let address = |host: usize| -> Result<String> {
        Ok(fake_public_address(WAN_SUBNET_INDEX * MAX_NODES_PER_SUBNET + host)?.ip)
    };
    let timeout = Duration::from_secs(options.timeout_secs);
    // The hold matches aMule's `0x60` in the clear.
    anyhow::ensure!(
        !(options.low_id_buddy && options.kad_crypt),
        "--low-id-buddy holds aMule's plaintext KADEMLIA2_PING; run it without --kad-crypt"
    );
    let run_secs = if options.low_id_buddy {
        LOW_ID_RUN_SECS
    } else {
        RUN_SECS
    };

    let root_v4 = address(HOST_BUDDY)?;
    let root_dir = leg_dir.join("root");
    fs::create_dir_all(&root_dir)?;
    let server = if options.low_id_buddy {
        let server_v4 = address(lowid::HOST_SERVER)?;
        let name = lowid::start_low_id_server(
            bench,
            options,
            suffix,
            &wan,
            (&server_v4, &root_v4),
            leg_dir,
        )?;
        Some((name, server_v4))
    } else {
        None
    };
    let server_endpoint = server
        .as_ref()
        .map(|(_, v4)| format!("{v4}:{ED2KSRV_TCP_PORT}"));
    let root = start_buddy(
        bench,
        options,
        suffix,
        &wan,
        &root_v4,
        &root_dir,
        run_secs,
        server_endpoint.as_deref(),
    )?;
    let mut recipe = lowid::Recipe::default();
    if server.is_some() {
        recipe.root_client_id = lowid::await_root_login(bench, &root, timeout);
        println!(
            "natt amule low-id recipe: root client_id {:?}",
            recipe.root_client_id
        );
    }

    let amule_dir = leg_dir.join("amule");
    let incoming = amule_dir.join("incoming");
    let seed_dir = amule_dir.join("seed");
    // On the recipe the file waits outside aMule's share until step 5.
    let staged = amule_dir.join("staged");
    fs::create_dir_all(&incoming)?;
    fs::create_dir_all(&seed_dir)?;
    fs::create_dir_all(&staged)?;
    let file = crate::flow::nat::natt::punch::synthetic_file(if options.low_id_buddy {
        &staged
    } else {
        &incoming
    })?;
    let storer_id = crate::kad_seed::storer_kad_id_for_file_hash(parse_hash(&file.file_hash)?);
    let storer_v4 = address(HOST_STORER)?;
    let storer = mesh::start(
        bench,
        options,
        &mesh::MeshPlan {
            wan: &wan,
            suffix,
            addresses: std::slice::from_ref(&storer_v4),
            kad_ids: &[storer_id],
            buddy_v4: &root_v4,
            leg_dir,
            run_secs,
        },
    )?;
    // The second Capture Sidecar: the publish is addressed to the
    // storer, so only the storer's own netns sees it on the wire.
    let storer_tap_dir = amule_dir.join("storer-tap");
    fs::create_dir_all(&storer_tap_dir)?;
    let storer_tap_prefix = format!("rmule-interop-nattstorertap-{suffix}");
    let storer_taps = PerAttachmentTaps::start(
        bench,
        options.capture_image,
        &storer[0].container,
        &storer_tap_prefix,
        &storer_tap_dir,
        &[Attachment {
            name: "wan",
            interface: "eth0",
            role: TapRole::Evidence,
            bpf: "udp",
        }],
        timeout,
    )?;

    let mut helpers = Vec::new();
    for (index, host) in HOST_HELPERS.iter().enumerate() {
        let helper_v4 = address(*host)?;
        let dir = leg_dir.join(format!("helper-{index}"));
        fs::create_dir_all(&dir)?;
        let name = start_helper(
            bench, options, suffix, &wan, index, &helper_v4, &dir, &root_v4, run_secs,
        )?;
        helpers.push((name, helper_v4, dir));
    }
    std::thread::sleep(mesh::MESH_SETTLE);

    let peer = Peer {
        name: "amule",
        lan: &LAN_B,
        network: format!("rmule-interop-nattlanb-{suffix}"),
        gateway: format!("rmule-interop-nattgwb-{suffix}"),
        gateway_wan: address(HOST_GATEWAY_B)?,
        driver: format!("rmule-interop-nattamule-{suffix}"),
        dir: amule_dir.clone(),
        user_hash: HASH_TARGET,
    };
    start_gateway_mapped(
        bench,
        options,
        &peer,
        &wan,
        nat_type,
        timeout,
        NAT_CLIENT_UDP_PORT,
    )?;
    let gateway_taps = PerAttachmentTaps::start(
        bench,
        options.capture_image,
        &peer.gateway,
        &format!("rmule-interop-nattgwtap-{}-{suffix}", peer.name),
        &peer.dir,
        &[
            Attachment {
                name: "wan",
                interface: "eth0",
                role: TapRole::Evidence,
                bpf: "ip",
            },
            Attachment {
                name: "lan",
                interface: "eth1",
                role: TapRole::Corroboration,
                bpf: "ip",
            },
        ],
        timeout,
    )?;
    let reflector_primary = address(HOST_PROBE_PRIMARY)?;
    let reflector_secondary = address(HOST_PROBE_SECONDARY)?;
    run_reflector(
        bench,
        options,
        &wan,
        &reflector_primary,
        &reflector_secondary,
        suffix,
        timeout,
    )?;
    let proof = probe_peer_lan(
        bench,
        options,
        &peer,
        nat_type,
        (&reflector_primary, &reflector_secondary),
    )?;

    write_seed(&seed_dir, &root_v4, &storer_v4, storer_id)?;
    if options.low_id_buddy {
        lowid::hold(bench, &peer.gateway)?;
    }
    start_amule(bench, options, &peer, &incoming, &seed_dir)?;
    let started = Instant::now();
    wait_for_container_log(
        &bench.docker,
        &peer.driver,
        "rmule-kad-publisher-ready",
        timeout,
    )?;
    let verdict_line = if options.low_id_buddy {
        lowid::run(
            bench,
            &peer.driver,
            &peer.gateway,
            &root,
            (&file.path, &incoming),
            &mut recipe,
        )?
    } else {
        let verdict_line = wait_for_udp_verdict(bench, &peer.driver);
        match &verdict_line {
            Some(line) => println!("natt amule self-check: {line}"),
            None => eprintln!(
                "natt amule self-check: no UDP verdict line in {UDP_VERDICT_TIMEOUT_SECS} s; \
                 the row records how far the chain got"
            ),
        }
        let hold = Duration::from_secs(AMULE_MIN_UPTIME_SECS)
            .saturating_sub(started.elapsed())
            .max(Duration::from_secs(PUBLISH_WINDOW_SECS));
        println!(
            "natt amule self-check: holding {} s for the publish",
            hold.as_secs()
        );
        std::thread::sleep(hold);
        verdict_line
    };

    let status = amule_status(bench, &peer.driver);
    let log = amule_logfile(bench, &peer.driver);
    fs::write(amule_dir.join("amule-logfile.log"), &log)?;
    fs::write(amule_dir.join("amule-status.txt"), &status)?;
    collect_buddy_log(bench, &peer.driver, &amule_dir)?;

    let helper_ips: Vec<&str> = helpers.iter().map(|(_, v4, _)| v4.as_str()).collect();
    let wire = count_wire(
        bench,
        &gateway_taps,
        &storer_taps,
        &peer.gateway_wan,
        &helper_ips,
    )?;
    let publish = lift_publish(
        bench,
        &storer_tap_prefix,
        &storer_tap_dir,
        &peer.gateway_wan,
    )?;
    let helper_answer = lift_helper_answer(
        bench,
        &format!("rmule-interop-nattgwtap-{}-{suffix}", peer.name),
        &amule_dir,
        &peer.gateway_wan,
        &helper_ips,
    )?;
    let fwcheck_dump = fwcheck_frame_text(
        bench,
        &format!("rmule-interop-nattgwtap-{}-{suffix}-wan", peer.name),
        &peer.gateway_wan,
    )?;
    fs::write(
        amule_dir.join("amule-fwcheckudpreq-0xa7.txt"),
        &fwcheck_dump,
    )?;
    let gateway_tap_rows = gateway_taps.rows(&bench.docker, "ip")?;
    run_checked(
        bench.docker.exec(
            peer.gateway.clone(),
            [
                OsString::from("natgw-proof"),
                OsString::from("/proof"),
                OsString::from(nat_type.knob()),
            ],
        ),
        "take the NAT gateway self-proof",
    )?;

    mesh::collect(bench, &storer, leg_dir)?;
    let mut helper_logs = Vec::new();
    for (name, _, dir) in &helpers {
        collect_buddy_log(bench, name, dir)?;
        helper_logs.push(fs::read_to_string(dir.join("driver.log")).unwrap_or_default());
    }
    collect_buddy_log(bench, &root, &root_dir)?;

    let facts = AmuleFacts::read(&log, &status, verdict_line);
    let answered: Vec<bool> = helper_logs
        .iter()
        .map(|log| {
            log.lines().any(|line| {
                line.contains("kad UDP firewall helper: 0x62 sent")
                    && line.contains(&peer.gateway_wan)
                    && line.contains("biased=false")
            })
        })
        .collect();
    let mut claims = claims(
        &proof,
        &facts,
        &answered,
        &wire,
        publish.as_ref(),
        &peer.gateway_wan,
    );
    if options.kad_crypt {
        claims.push(self::claims::keyed_answer(
            &facts,
            &wire,
            helper_answer.as_deref(),
        ));
    }
    if let Some((server, _)) = &server {
        recipe.probes_refused = lowid::probes_refused(bench, options, server);
        claims.extend(lowid::claims(&recipe, &log));
        lowid::settle_publish(&mut claims, &recipe, &log, publish.is_some());
    }

    let mut bodies = vec![Body {
        name: "amule-2.3.3-debug".to_owned(),
        image: options.amule_image.to_owned(),
        pin: "aMule 2.3.3 (Debian source 1:2.3.3-3build5, --enable-debug); behind \
              a full-cone-pinned gateway on LAN 10.78.0.3"
            .to_owned(),
        address_v4: peer.gateway_wan.clone(),
        address_v6: String::new(),
    }];
    bodies.push(Body {
        name: "rmule-root".to_owned(),
        image: options.rmule_tools_image.to_owned(),
        pin: format!(
            "{}; kad id {}",
            crate::run_record::rmule_pin(),
            mesh::hex(&mesh::BUDDY_KAD_ID)
        ),
        address_v4: root_v4,
        address_v6: String::new(),
    });
    bodies.extend(helpers.iter().enumerate().map(|(index, (_, v4, _))| Body {
        name: format!("rmule-udp-helper-{index}"),
        image: options.rmule_tools_image.to_owned(),
        pin: format!(
            "{}; kad id {}",
            crate::run_record::rmule_pin(),
            mesh::hex(&HELPER_KAD_IDS[index])
        ),
        address_v4: v4.clone(),
        address_v6: String::new(),
    }));
    bodies.push(Body {
        name: format!("kad-storer-{}", storer[0].kad_id),
        image: options.rmule_tools_image.to_owned(),
        pin: format!(
            "{}; routing-only Kad Stimulus Node at the file key",
            crate::run_record::rmule_pin()
        ),
        address_v4: storer_v4,
        address_v6: String::new(),
    });
    if let Some((_, server_v4)) = server {
        bodies.push(Body {
            name: "ed2ksrv".to_owned(),
            image: options.ed2ksrv_image.to_owned(),
            pin: format!(
                "{}; its High-ID back-connect to the root dropped in its own netns, so the \
                 root's id is Low",
                crate::flow::ed2ksrv::ED2KSRV.body_pin(&bench.docker, options.ed2ksrv_image),
            ),
            address_v4: server_v4,
            address_v6: String::new(),
        });
    }
    Ok((
        Driven {
            claims,
            bodies,
            wire: Vec::new(),
            note: format!(
                "Stock aMule 2.3.3 (debug build) behind a full-cone-pinned gateway forwarding \
                 its Kad port {NAT_CLIENT_UDP_PORT}, sharing the Synthetic File {}: its own \
                 UDP self-check against two fresh rmule helpers, and whatever publish that \
                 verdict earns, read off the storer's netns. Kad-UDP crypt {}.{}",
                file.file_hash,
                if options.kad_crypt {
                    "armed on aMule (AMULE_KAD_CRYPT=1)"
                } else {
                    "off"
                },
                if options.low_id_buddy {
                    " Low-ID Buddy Recipe: aMule's 0x60 held at the gateway until \
                     it holds the Low-ID root as its buddy, then released, then the file shared."
                } else {
                    ""
                }
            ),
            tunnel_rose: None,
        },
        wire,
        gateway_tap_rows,
    ))
}

/// Write aMule's pinned identity and its routing-zone seed: the root and the
/// storer, the two contacts the one-`/24` quota admits.
fn write_seed(seed_dir: &Path, root_v4: &str, storer_v4: &str, storer_id: [u8; 16]) -> Result<()> {
    fs::write(
        seed_dir.join("preferencesKad.dat"),
        build_preferences_kad_dat(AMULE_KAD_ID),
    )?;
    let contact = |kad_id: [u8; 16], v4: &str| -> Result<KadContact> {
        Ok(KadContact {
            kad_id,
            ipv4: parse_ipv4_octets(v4)?,
            udp_port: BODY_CLIENT_UDP_PORT,
            tcp_port: BODY_PEER_TCP_PORT,
            version: SEED_CONTACT_VERSION,
        })
    };
    let nodes = build_routing_zone_nodes_dat(&[
        contact(mesh::BUDDY_KAD_ID, root_v4)?,
        contact(storer_id, storer_v4)?,
    ]);
    fs::write(seed_dir.join("nodes.dat"), nodes).context("write aMule's nodes.dat")
}

/// Start aMule on the gateway's LAN, its default route through the gateway
/// (ADR-0092's `AMULE_DEFAULT_ROUTE_VIA`), its Kad UDP port the one the
/// gateway pins.
fn start_amule(
    bench: &mut Bench,
    options: &NattOptions<'_>,
    peer: &Peer,
    incoming: &Path,
    seed_dir: &Path,
) -> Result<()> {
    let mut container = RunContainer::new(options.amule_image)
        .detach()
        .name(&peer.driver)
        .network(&peer.network)
        .ip(peer.lan.client)
        .cap_add("NET_ADMIN")
        .volume(incoming, "/incoming")
        .volume(seed_dir, "/seed")
        .env("AMULE_SCENARIO_MODE", "kad-node")
        .env("AMULE_KAD_ROLE", "publisher")
        .env("AMULE_SHARED_DIR", "/incoming")
        .env("AMULE_TCP_PORT", BODY_PEER_TCP_PORT.to_string())
        .env("AMULE_UDP_PORT", NAT_CLIENT_UDP_PORT.to_string())
        .env("AMULE_KAD_PREFS_DAT", "/seed/preferencesKad.dat")
        .env("AMULE_KAD_NODES_DAT", "/seed/nodes.dat")
        .env("AMULE_USER_HASH", HASH_TARGET)
        .env("AMULE_KAD_FILTER_LAN_IPS", "1")
        .env("AMULE_KAD_VERBOSE", "1")
        .env("AMULE_DEFAULT_ROUTE_VIA", peer.lan.gateway);
    if options.kad_crypt {
        container = container.env("AMULE_KAD_CRYPT", "1");
    }
    bench.start_extra(
        &peer.driver,
        container,
        "run stock aMule behind the gateway",
    )
}
