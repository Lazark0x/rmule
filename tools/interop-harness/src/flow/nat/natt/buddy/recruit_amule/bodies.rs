//! The bodies `natt-buddy-recruit-amule` stands up beyond the shared NAT-T
//! ones — stock aMule open on the WAN, the witness, the firewalled target, the
//! callback walker — and the pins its verdict names every body by.

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};

use super::super::selfcheck::HELPER_KAD_IDS;
use super::super::{
    BUDDY_TIMEOUT_SECS, PLACEHOLDER_SHARE, READY_TIMEOUT_SECS, absent_server, collect_buddy_log,
    common_args, mesh,
};
use super::{
    AMULE_KAD_ID, HASH_AMULE, HASH_WITNESS, HOLD_WINDOW_SECS, RUN_SECS, SEED_CONTACT_VERSION,
    TARGET_KAD_ID, WALKER_KAD_ID, WALKER_RUN_SECS, WALKER_TCP_PORT, WITNESS_KAD_ID,
};
use crate::docker::RunContainer;
use crate::flow::bench::Bench;
use crate::flow::gate::{wait_for_container_log, wait_for_host_file};
use crate::flow::kad_member::PlacedMember;
use crate::flow::nat::claims::Body;
use crate::flow::nat::natt::bench::NattOptions;
use crate::flow::nat::natt::punch::Peer;
use crate::flow::nat::natt::{BODY_CLIENT_UDP_PORT, BODY_PEER_TCP_PORT};
use crate::kad_seed::{KadContact, build_preferences_kad_dat, build_routing_zone_nodes_dat};

/// Write aMule's pinned identity and its routing-zone seed: the root and the
/// witness, the two contacts the one-`/24` bin quota admits — and the two
/// TCP firewall testers its `GetFirewalled` needs.
pub(super) fn write_amule_seed(seed_dir: &Path, root_v4: &str, witness_v4: &str) -> Result<()> {
    fs::write(
        seed_dir.join("preferencesKad.dat"),
        build_preferences_kad_dat(AMULE_KAD_ID),
    )?;
    let contact = |kad_id: [u8; 16], v4: &str| -> Result<KadContact> {
        Ok(KadContact {
            kad_id,
            ipv4: crate::flow::identity::parse_ipv4_octets(v4)?,
            udp_port: BODY_CLIENT_UDP_PORT,
            tcp_port: BODY_PEER_TCP_PORT,
            version: SEED_CONTACT_VERSION,
        })
    };
    let nodes = build_routing_zone_nodes_dat(&[
        contact(mesh::BUDDY_KAD_ID, root_v4)?,
        contact(WITNESS_KAD_ID, witness_v4)?,
    ]);
    fs::write(seed_dir.join("nodes.dat"), nodes).context("write aMule's nodes.dat")
}

/// Start stock aMule on the WAN: no gateway, no shared files, its debug
/// logfile verbose so both verdict lines and every Kad packet it sends land
/// in it.
pub(super) fn start_amule(
    bench: &mut Bench,
    options: &NattOptions<'_>,
    name: &str,
    wan: &str,
    amule_v4: &str,
    seed_dir: &Path,
) -> Result<()> {
    let mut container = RunContainer::new(options.amule_image)
        .detach()
        .name(name)
        .network(wan)
        .ip(amule_v4)
        .volume(seed_dir, "/seed")
        .env("AMULE_SCENARIO_MODE", "kad-node")
        .env("AMULE_KAD_ROLE", "routing")
        .env("AMULE_TCP_PORT", BODY_PEER_TCP_PORT.to_string())
        .env("AMULE_UDP_PORT", BODY_CLIENT_UDP_PORT.to_string())
        .env("AMULE_KAD_PREFS_DAT", "/seed/preferencesKad.dat")
        .env("AMULE_KAD_NODES_DAT", "/seed/nodes.dat")
        .env("AMULE_USER_HASH", HASH_AMULE)
        .env("AMULE_KAD_FILTER_LAN_IPS", "1")
        .env("AMULE_KAD_VERBOSE", "1");
    if options.kad_crypt {
        container = container.env("AMULE_KAD_CRYPT", "1");
    }
    bench.start_extra(name, container, "run stock aMule open on the WAN")
}

/// Start the witness: an open Core rmule seeded with the root, so aMule's
/// second routing-zone contact answers its TCP firewall check as the root
/// does.
pub(super) fn start_witness(
    bench: &mut Bench,
    options: &NattOptions<'_>,
    suffix: &str,
    wan: &str,
    witness_v4: &str,
    dir: &Path,
    root_v4: &str,
) -> Result<String> {
    let name = format!("rmule-interop-nattwitness-{suffix}");
    let mut container = RunContainer::new(options.rmule_tools_image)
        .detach()
        .name(&name)
        .network(wan)
        .ip(witness_v4)
        .cap_add("NET_ADMIN")
        .env("RMULE_LOG", "info,rmule_core::adapters::kad_runtime=debug")
        .volume(dir, "/out");
    for arg in common_args(
        "buddy",
        HASH_WITNESS,
        witness_v4,
        RUN_SECS,
        &absent_server(),
        PLACEHOLDER_SHARE,
    ) {
        container = container.arg(arg);
    }
    container = container
        .arg("--kad-id")
        .arg(mesh::hex(&WITNESS_KAD_ID))
        .arg("--assume-open")
        .arg("--kad-contact")
        .arg(mesh::seed_operand(&mesh::hex(&mesh::BUDDY_KAD_ID), root_v4));
    bench.start_extra(&name, container, "run the open rmule witness")?;
    wait_for_container_log(
        &bench.docker,
        &name,
        "rmule-natt-buddy-ready",
        Duration::from_secs(READY_TIMEOUT_SECS),
    )?;
    Ok(name)
}

/// Start the firewalled target: logged in to `server` when `login` (the
/// server variant), seeded with aMule alone, sharing the Synthetic File,
/// holding [`HOLD_WINDOW_SECS`] once its buddy is held. Without `login` the
/// `server` it names is never dialed.
pub(super) fn start_target(
    bench: &mut Bench,
    options: &NattOptions<'_>,
    target: &Peer,
    server: &str,
    amule_v4: &str,
    login: bool,
) -> Result<()> {
    let mut container = RunContainer::new(options.rmule_tools_image)
        .detach()
        .name(&target.driver)
        .network(&target.network)
        .ip(target.lan.client)
        .cap_add("NET_ADMIN")
        .env("RMULE_DEFAULT_ROUTE_VIA", target.lan.gateway)
        // Every decision of the front's lifecycle is traced at debug: the
        // adopt, the dial, a dial that failed, a link lost, a relayed
        // callback dropped. A step that did not happen is diagnosed from
        // these lines and nowhere else.
        .env(
            "RMULE_LOG",
            "info,rmule_core::firewalled=debug,rmule_core::adapters::kad_runtime=debug,\
             rmule_core::server_session=debug",
        )
        .volume(&target.dir, "/out");
    for arg in common_args(
        "target",
        target.user_hash,
        target.lan.client,
        HOLD_WINDOW_SECS,
        server,
        "/out/shared.bin",
    ) {
        container = container.arg(arg);
    }
    container = container
        .arg("--kad-id")
        .arg(mesh::hex(&TARGET_KAD_ID))
        .arg("--kad-contact")
        .arg(mesh::seed_operand(&mesh::hex(&AMULE_KAD_ID), amule_v4))
        .arg("--buddy-out")
        .arg("/out/buddy.toml")
        .arg("--buddy-timeout")
        .arg(BUDDY_TIMEOUT_SECS.to_string());
    if login {
        container = container.arg("--login");
    }
    bench.start_extra(&target.driver, container, "run the firewalled Core rmule")
}

/// Run one Callback Walk toward aMule's Kad ID and wait for it to end.
/// Returns whether the walker logged its end.
#[allow(clippy::too_many_arguments)]
pub(super) fn run_walker(
    bench: &mut Bench,
    options: &NattOptions<'_>,
    suffix: &str,
    wan: &str,
    walker_v4: &str,
    amule_v4: &str,
    file_hash: &str,
    leg_dir: &Path,
) -> Result<bool> {
    let dir = leg_dir.join("walker");
    fs::create_dir_all(&dir)?;
    let name = format!("rmule-interop-nattwalker-{suffix}");
    let kad_id = mesh::hex(&WALKER_KAD_ID);
    let bootstrap = format!("{amule_v4}:{BODY_CLIENT_UDP_PORT}");
    let container = PlacedMember {
        image: options.rmule_tools_image,
        container: &name,
        network: wan,
        address_v4: walker_v4,
        udp_port: BODY_CLIENT_UDP_PORT,
        tcp_port: WALKER_TCP_PORT,
        kad_id: &kad_id,
        bootstrap: Some(&bootstrap),
        host_dir: &dir,
        run_secs: WALKER_RUN_SECS,
    }
    .container_spec()
    .arg("--callback-walk")
    .arg(mesh::hex(&AMULE_KAD_ID))
    .arg("--callback-file-hash")
    .arg(file_hash.to_ascii_lowercase())
    .arg("--callback-tcp-port")
    .arg(WALKER_TCP_PORT.to_string());
    bench.start_extra(&name, container, "run the callback walker")?;
    let ended = wait_for_host_file(
        &dir.join("events.log"),
        "CallbackWalkEnded",
        Duration::from_secs(WALKER_RUN_SECS),
    )?;
    println!("natt buddy-recruit-amule: callback walk ended={ended}");
    // aMule relays inside the datagram's own handler and the target dials on
    // the relay: a few seconds cover both before anything is read.
    std::thread::sleep(Duration::from_secs(5));
    collect_buddy_log(bench, &name, &dir)?;
    Ok(ended)
}

/// Where the bodies a verdict names stood.
pub(super) struct Addresses<'a> {
    pub(super) amule: &'a str,
    /// The target, as the WAN sees it.
    pub(super) gateway_wan: &'a str,
    pub(super) root: &'a str,
    pub(super) witness: &'a str,
    /// The `ed2ksrv`, when the run stood one up.
    pub(super) server: Option<&'a str>,
}

/// The bodies this run stood up, with their pins.
pub(super) fn bodies(
    options: &NattOptions<'_>,
    at: &Addresses<'_>,
    helpers: &[(String, String, std::path::PathBuf)],
) -> Vec<Body> {
    let rmule = |name: String, kad_id: &[u8; 16], role: &str, address_v4: &str| Body {
        name,
        image: options.rmule_tools_image.to_owned(),
        pin: format!(
            "{}; kad id {}; {role}",
            crate::run_record::rmule_pin(),
            mesh::hex(kad_id)
        ),
        address_v4: address_v4.to_owned(),
        address_v6: String::new(),
    };
    let mut bodies = vec![
        Body {
            name: "amule-2.3.3-debug".to_owned(),
            image: options.amule_image.to_owned(),
            pin: format!(
                "aMule 2.3.3 (Debian source 1:2.3.3-3build5, --enable-debug); open on the WAN, \
                 kad id {}",
                mesh::hex(&AMULE_KAD_ID)
            ),
            address_v4: at.amule.to_owned(),
            address_v6: String::new(),
        },
        rmule(
            "rmule-target".to_owned(),
            &TARGET_KAD_ID,
            "the firewalled Core behind the gateway",
            at.gateway_wan,
        ),
        rmule(
            "rmule-root".to_owned(),
            &mesh::BUDDY_KAD_ID,
            "open, aMule's first TCP tester",
            at.root,
        ),
        rmule(
            "rmule-witness".to_owned(),
            &WITNESS_KAD_ID,
            "open, aMule's second TCP tester",
            at.witness,
        ),
    ];
    bodies.extend(helpers.iter().enumerate().map(|(index, (_, v4, _))| {
        rmule(
            format!("rmule-udp-helper-{index}"),
            &HELPER_KAD_IDS[index],
            "a fresh UDP Firewall Helper only the root knows",
            v4,
        )
    }));
    bodies.extend(at.server.map(|server| Body {
        name: "ed2ksrv".to_owned(),
        image: options.ed2ksrv_image.to_owned(),
        pin:
            "the Low-ID login the target holds; its back-connect dropped by the gateway".to_owned(),
        address_v4: server.to_owned(),
        address_v6: String::new(),
    }));
    bodies
}
