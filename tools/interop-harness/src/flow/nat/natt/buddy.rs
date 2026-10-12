//! The `natt-buddy-rendezvous-{cone,restricted,symmetric}` topology: ADR-0091
//! rung 1 through its **second** Rendezvous coordinator.
//!
//! Five bodies on one fake-public WAN and two masquerade-free LANs:
//!
//! - an **open buddy** with no gateway, running Kad in the **Core-Pumped
//!   Stimulus Node** posture so the open-node buddy service can
//!   accept a recruit at all — neither ADR-0058 self-check can settle *open*
//!   in a mesh this size, and a node that reads unverified refuses every
//!   `FINDBUDDY_REQ`;
//! - two **routing-only Kad mesh members** on their own fake-public addresses
//!   ([`mesh`]), which are the alternatives the walk rejects;
//! - a **firewalled target** behind its own gateway, seeded with the mesh and
//!   recruiting the buddy over a live `0x51`/`0x5A` walk;
//! - a **firewalled requester** behind its own gateway, which embeds an
//!   `OP_RENDEZVOUS` in a `0x94` addressed to that buddy.
//!
//! One gateway per firewalled body, for the reason the punch topology records:
//! each needs its own fake-public address for the far side to punch toward.
//!
//! **No `ed2ksrv` stands on this WAN.** ADR-0091 tries the server coordinator
//! first whenever the candidate is on our connected server, so a server on the
//! path would re-measure `natt-server-punch-cone`. The `0x60` row is counted
//! anyway, at zero, so that absence is stated rather than assumed.
//!
//! The `-symmetric` variant is a **negative** and carries the whole ADR-0045
//! kit in the same run: both gateways' NAT Type Proof including the pinned-port
//! leg, the RFC 5780 Reflector Probe beside the claim, the `[UNREPLIED]`
//! conntrack mappings, and the counterparty's own zero off the LAN taps.

mod claims;
mod hello_tags;
mod mesh;
pub(in crate::flow::nat::natt) mod recruit_amule;
pub(in crate::flow::nat::natt) mod selfcheck;
mod wire;

use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::docker::{InternalNetwork, RunContainer};
use crate::fake_public::{MAX_NODES_PER_SUBNET, fake_public_address, subnet_cidr};
use crate::flow::bench::{Bench, run_checked};
use crate::flow::gate::wait_for_container_log;
use crate::flow::nat::claims::{Body, DriverRow};
use crate::flow::nat::natt::bench::{Driven, NattOptions};
use crate::flow::nat::natt::punch::proof::{probe_peer_lan, run_reflector};
use crate::flow::nat::natt::punch::wire::{collect_driver_log, count_punch_mappings};
use crate::flow::nat::natt::punch::{
    HOST_GATEWAY_A, HOST_GATEWAY_B, HOST_PROBE_PRIMARY, HOST_PROBE_SECONDARY, LAN_A, LAN_B, Peer,
    WINDOW_SECS, start_gateway, wait_for_container_exit,
};
use crate::flow::nat::natt::{BODY_CLIENT_UDP_PORT, BODY_PEER_TCP_PORT, NattFlow};
use crate::flow::taps::{Attachment, PerAttachmentTaps, TapRole};
use crate::nat::NatType;

pub(crate) use self::claims::wire_claims;

/// The buddy's WAN host index. The `ed2ksrv` this flow does not stand up held
/// it in the punch topology, so the two address plans stay comparable.
const HOST_BUDDY: usize = 0;
/// The routing-only mesh members' host indices.
const HOST_MESH: [usize; 2] = [5, 6];
/// The transfer rows' placed storer — the mesh member at the file's own Kad
/// key.
const HOST_STORER: usize = 7;

/// The window a transfer row's target and requester hold once their part has
/// begun: the requester's Kad sweep has to find the row the target publishes
/// at the moment its buddy is held, and the file still has to cross the
/// Tunnel, so the rendezvous row's dial-budget window is too short.
const TRANSFER_WINDOW_SECS: u64 = 300;

/// The three bodies' fixed user hashes, so a relay, a hint and a hello name
/// values a verdict can quote.
const HASH_REQUESTER: &str = "41414141414141414141414141414141";
const HASH_TARGET: &str = "42424242424242424242424242424242";
const HASH_BUDDY: &str = "43434343434343434343434343434343";

/// The eD2k endpoint every body's `StartServing` names. Nothing listens on it:
/// it is a documentation address on the WAN, and the login it fails is the
/// price of the bind each body actually needs.
const ABSENT_SERVER_PORT: u16 = 4661;

/// How long the target is given to reach a held buddy.
///
/// The recruit gate reads *both* ADR-0058 verdicts, and the UDP one settles
/// firewalled only by its six-minute timeout (`UDP_TEST_TIMEOUT`, aMule's
/// `IsFirewalledUDP`): the target's Helper Lookup finds no helper it may use
/// here — the buddy and the mesh are in its seed, and the other firewalled
/// body's TCP port is unreachable. That timeout runs from Kad
/// start, because the pump injects the
/// node's own TCP verdict as a level there; the trigger then ticks
/// every thirty seconds. So the walk cannot fire before roughly six and a half
/// minutes however healthy the mesh is, and this budget is that plus slack —
/// not a guess at how long a walk takes.
const BUDDY_TIMEOUT_SECS: u64 = 540;

/// How long a body is given to announce that its listener came up.
const READY_TIMEOUT_SECS: u64 = 90;

/// Stand the buddy topology up, drive it, and hand back the claims.
///
/// # Errors
/// If the bench cannot be built, a gateway never reports ready, or a driver's
/// row cannot be read. **A rendezvous that does not land is not an error** —
/// behind a symmetric gateway it is the measurement.
pub(crate) fn drive(
    bench: &mut Bench,
    options: &NattOptions<'_>,
    nat_type: NatType,
    suffix: &str,
    leg_dir: &Path,
) -> Result<(
    Driven,
    Vec<crate::flow::nat::natt::verdict::WireRow>,
    Vec<crate::flow::taps::TapRow>,
)> {
    let flow = options.flow;
    let transfer = flow == NattFlow::BuddyTransferCone;
    let window = if transfer {
        TRANSFER_WINDOW_SECS
    } else {
        WINDOW_SECS
    };
    let subnet_v4 = subnet_cidr(super::WAN_SUBNET_INDEX)?;
    let wan = format!("rmule-interop-nattwan-{suffix}");
    bench.create_extra_network(
        &wan,
        bench
            .docker
            .create_internal_network(InternalNetwork::new(&wan).subnet_v4(&subnet_v4)),
        "create the fake-public WAN",
    )?;
    let address = |host: usize| -> Result<String> {
        Ok(fake_public_address(super::WAN_SUBNET_INDEX * MAX_NODES_PER_SUBNET + host)?.ip)
    };
    let timeout = Duration::from_secs(options.timeout_secs);

    // The whole run's budget, as the bodies that outlive a single window need
    // it: the buddy and the mesh members must still be up when the requester's
    // window ends.
    let run_secs = BUDDY_TIMEOUT_SECS + window + 60;

    let buddy_v4 = address(HOST_BUDDY)?;
    let buddy_dir = leg_dir.join("buddy");
    fs::create_dir_all(&buddy_dir)?;
    let buddy = start_buddy(
        bench, options, suffix, &wan, &buddy_v4, &buddy_dir, run_secs, None,
    )?;

    // A transfer row's **Synthetic File** is written into the target's own
    // mount before anything starts, because its hash places the storer.
    let target_dir = leg_dir.join("target");
    fs::create_dir_all(&target_dir).with_context(|| format!("create {}", target_dir.display()))?;
    let shared = transfer
        .then(|| super::punch::synthetic_file(&target_dir))
        .transpose()?;

    // The mesh comes up after the buddy, because each member bootstraps to it.
    let mut mesh_hosts = HOST_MESH.to_vec();
    let mut mesh_ids = mesh::MESH_KAD_IDS.to_vec();
    if let Some(file) = shared.as_ref() {
        mesh_hosts.push(HOST_STORER);
        mesh_ids.push(crate::kad_seed::storer_kad_id_for_file_hash(parse_hash(
            &file.file_hash,
        )?));
    }
    let mesh_addresses = mesh_hosts
        .iter()
        .map(|host| address(*host))
        .collect::<Result<Vec<_>>>()?;
    let mesh = mesh::start(
        bench,
        options,
        &mesh::MeshPlan {
            wan: &wan,
            suffix,
            addresses: &mesh_addresses,
            kad_ids: &mesh_ids,
            buddy_v4: &buddy_v4,
            leg_dir,
            run_secs,
        },
    )?;
    std::thread::sleep(mesh::MESH_SETTLE);

    let peers = [
        Peer {
            name: "requester",
            lan: &LAN_A,
            network: format!("rmule-interop-nattlana-{suffix}"),
            gateway: format!("rmule-interop-nattgwa-{suffix}"),
            gateway_wan: address(HOST_GATEWAY_A)?,
            driver: format!("rmule-interop-nattpeera-{suffix}"),
            dir: leg_dir.join("requester"),
            user_hash: HASH_REQUESTER,
        },
        Peer {
            name: "target",
            lan: &LAN_B,
            network: format!("rmule-interop-nattlanb-{suffix}"),
            gateway: format!("rmule-interop-nattgwb-{suffix}"),
            gateway_wan: address(HOST_GATEWAY_B)?,
            driver: format!("rmule-interop-nattpeerb-{suffix}"),
            dir: target_dir.clone(),
            user_hash: HASH_TARGET,
        },
    ];
    for peer in &peers {
        fs::create_dir_all(&peer.dir).with_context(|| format!("create {}", peer.dir.display()))?;
        start_gateway(bench, options, peer, &wan, nat_type, timeout)?;
    }

    // The buddy's attachment is the only place a counterparty statement can be
    // made in this topology: the recruit it answers, the relay it forwards and
    // the hint it emits are all its own bytes. Each gateway's WAN tap
    // corroborates the punch and its LAN tap is part of the NAT Type Proof.
    let buddy_taps = PerAttachmentTaps::start(
        bench,
        options.capture_image,
        &buddy,
        &format!("rmule-interop-nattbuddytap-{suffix}"),
        &buddy_dir,
        &[Attachment {
            name: wire::BUDDY_ATTACHMENT,
            interface: "eth0",
            role: TapRole::Evidence,
            bpf: "ip",
        }],
        timeout,
    )?;
    let mut gateway_taps = Vec::new();
    for peer in &peers {
        gateway_taps.push(PerAttachmentTaps::start(
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
        )?);
    }

    // The **NAT Type Proof**'s observation half, before a single driver runs
    // A gateway that cannot forward the pinned port fails here in
    // seconds rather than as a silent zero nine minutes later.
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
    let mut proofs = Vec::new();
    for peer in &peers {
        proofs.push(probe_peer_lan(
            bench,
            options,
            peer,
            nat_type,
            (&reflector_primary, &reflector_secondary),
        )?);
    }

    let seed: Vec<String> = std::iter::once(mesh::seed_operand(
        &mesh::hex(&mesh::BUDDY_KAD_ID),
        &buddy_v4,
    ))
    .chain(mesh.iter().map(mesh::MeshNode::seed_operand))
    .collect();
    start_peer(
        bench,
        options,
        &peers[1],
        PeerPlan::Target {
            seed: &seed,
            publish: shared.is_some(),
        },
        window,
    )?;
    let requester_plan = match shared.as_ref() {
        Some(file) => PeerPlan::Downloader {
            seed: &seed,
            link: &file.link,
        },
        None => PeerPlan::Requester,
    };
    start_peer(bench, options, &peers[0], requester_plan, window)?;
    for peer in &peers {
        wait_for_container_log(
            &bench.docker,
            &peer.driver,
            "rmule-natt-buddy-ready",
            Duration::from_secs(READY_TIMEOUT_SECS),
        )?;
    }

    // The **Readiness Gate** the whole flow turns on: the requester is told
    // nothing until the target's own slot reads `Held`, so a rendezvous can
    // never be aimed at a relation that does not exist yet. A recruit that
    // never lands leaves the file absent, the requester's target file never
    // written, and the row says so — never a sleep.
    let held = wait_for_container_log(
        &bench.docker,
        &peers[1].driver,
        "rmule-natt-buddy-held",
        Duration::from_secs(BUDDY_TIMEOUT_SECS + 60),
    );
    match &held {
        Ok(line) => {
            println!("natt buddy recruited: {}", line.trim());
            write_target(&peers[0].dir.join("target.toml"), &buddy_v4)?;
            take_inflight_proof(bench, &peers, nat_type, window)?;
        }
        Err(error) => eprintln!(
            "natt buddy: the target never reached a held buddy ({error}); the requester is \
             told nothing and the row records the absence"
        ),
    }

    for peer in &peers {
        wait_for_container_exit(bench, &peer.driver)?;
    }
    // **The taps are read before the buddy exits, and the order is
    // load-bearing.** A capture sidecar shares its subject's network
    // namespace, so it dies with it — and the body under observation here is a
    // driver that ends its own window, unlike the punch topology's coordinator
    // which outlives every run. Counting after the wait cost run `1790067079`
    // its whole wire half ("container ... is not running").
    let wire = wire::count(
        bench,
        &buddy_taps,
        &gateway_taps,
        wire::rows(&buddy_v4, BODY_PEER_TCP_PORT, &peers),
    )?;
    // The buddy-hello leg: the target's hello over the Tunnel, lifted while the
    // requester's gateway tap still runs.
    let target_hello = if flow == NattFlow::BuddyRendezvousCone && held.is_ok() {
        Some(hello_tags::lift(
            bench,
            &gateway_taps[0],
            peers[0].lan.client,
            &peers[0].dir,
        )?)
    } else {
        None
    };
    let taps = buddy_taps.rows(&bench.docker, "ip")?;
    wait_for_container_exit(bench, &buddy)?;

    for peer in &peers {
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
        collect_driver_log(bench, peer)?;
    }
    collect_buddy_log(bench, &buddy, &buddy_dir)?;
    mesh::collect(bench, &mesh, leg_dir)?;

    let rows = [
        DriverRow::read(&peers[0].dir.join("buddy-rendezvous.toml"))?,
        DriverRow::read(&peers[1].dir.join("buddy-rendezvous.toml"))?,
        DriverRow::read(&buddy_dir.join("buddy-rendezvous.toml"))?,
    ];

    // The **`inflight-`** dump, not the teardown one: `take_inflight_proof`
    // took it while the burst's mappings were still live, which is the whole
    // fix for the symmetric negative's late conntrack read — the teardown
    // dump, read after the driver's whole window, is kept as an artifact but
    // no longer as this claim's source, because by then the mappings have
    // aged out by design. A run whose requester never dialed
    // (`take_inflight_proof`'s own timeout) leaves the file absent, which
    // reads as zero mappings rather than a fabricated one.
    let gateway_proofs = peers
        .iter()
        .zip(proofs)
        .enumerate()
        .map(|(index, (peer, proof))| {
            let other = &peers[1 - index];
            let inflight = peer.dir.join("inflight-conntrack.txt");
            let dump = if inflight.is_file() {
                fs::read_to_string(&inflight)
                    .with_context(|| format!("read {}", inflight.display()))?
            } else {
                String::new()
            };
            let (punch_mappings, unreplied) = count_punch_mappings(
                &dump,
                peer.lan.client,
                &other.gateway_wan,
                BODY_CLIENT_UDP_PORT,
            );
            Ok(super::legs::GatewayProof {
                wan: peer.gateway_wan.clone(),
                proof,
                punch_mappings,
                unreplied,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let mut bodies = vec![Body {
        name: "rmule-buddy".to_owned(),
        image: options.rmule_tools_image.to_owned(),
        pin: format!("this worktree; kad id {}", mesh::hex(&mesh::BUDDY_KAD_ID)),
        address_v4: buddy_v4.clone(),
        address_v6: String::new(),
    }];
    bodies.extend(mesh.iter().map(|node| Body {
        name: format!("kad-mesh-{}", node.kad_id),
        image: options.rmule_tools_image.to_owned(),
        pin: "this worktree; routing-only Kad Stimulus Node".to_owned(),
        address_v4: node.address_v4.clone(),
        address_v6: String::new(),
    }));
    let transferred = shared.as_ref().map(|file| claims::Transferred {
        file_hash: &file.file_hash,
        size: file.size,
    });
    let mut driven = claims::driven(flow, &rows, &gateway_proofs, bodies, transferred);
    if let Some(read) = target_hello {
        driven.claims.push(hello_tags::claim(
            read.as_ref(),
            &buddy_v4,
            BODY_CLIENT_UDP_PORT,
        ));
    }
    Ok((driven, wire, taps))
}

/// What a gatewayed body is asked to be.
enum PeerPlan<'a> {
    /// The firewalled half being reached: a Kad citizen seeded with the mesh,
    /// sharing the transfer file once its buddy is held when `publish`.
    Target { seed: &'a [String], publish: bool },
    /// The firewalled half doing the reaching: no Kad of its own — the buddy's
    /// UDP endpoint is known, so the buddy rung needs no walk from this side.
    Requester,
    /// The transfer row's requester: a Kad citizen handed only
    /// the ed2k link, whose download finds the target's buddy row over Kad.
    Downloader { seed: &'a [String], link: &'a str },
    /// `natt-udp-selfcheck-cone`'s target: a Kad citizen seeded
    /// with `seed` that publishes the Synthetic File once its ADR-0058 UDP
    /// verdict reads open, waiting at most `timeout_secs` for it.
    UdpSelfCheck {
        seed: &'a [String],
        timeout_secs: u64,
    },
}

/// Start the open rmule buddy. `server` is the eD2k endpoint it logs in to —
/// `None` for the absent one, a live `ed2ksrv` when the row needs the buddy's
/// hello to carry a server-assigned Low ID.
#[allow(clippy::too_many_arguments)]
fn start_buddy(
    bench: &mut Bench,
    options: &NattOptions<'_>,
    suffix: &str,
    wan: &str,
    buddy_v4: &str,
    dir: &Path,
    run_secs: u64,
    server: Option<&str>,
) -> Result<String> {
    let name = format!("rmule-interop-nattbuddy-{suffix}");
    let mut container = RunContainer::new(options.rmule_tools_image)
        .detach()
        .name(&name)
        .network(wan)
        .ip(buddy_v4)
        .cap_add("NET_ADMIN")
        // `inbound_triage` at debug for its `buddy link attached` line — the
        // held link's own statement (the Low-ID buddy recipe waits on it).
        .env(
            "RMULE_LOG",
            "info,rmule_core::natt=debug,rmule_core::adapters::kad_runtime=debug,\
             rmule_core::adapters::inbound_triage=debug",
        )
        .volume(dir, "/out");
    let server = server.map_or_else(absent_server, str::to_owned);
    for arg in common_args(
        "buddy",
        HASH_BUDDY,
        buddy_v4,
        run_secs,
        &server,
        PLACEHOLDER_SHARE,
    ) {
        container = container.arg(arg);
    }
    for arg in [
        "--kad-id".to_owned(),
        mesh::hex(&mesh::BUDDY_KAD_ID),
        "--assume-open".to_owned(),
    ] {
        container = container.arg(arg);
    }
    bench.start_extra(&name, container, "run the open rmule buddy")?;
    wait_for_container_log(
        &bench.docker,
        &name,
        "rmule-natt-buddy-ready",
        Duration::from_secs(READY_TIMEOUT_SECS),
    )?;
    Ok(name)
}

fn start_peer(
    bench: &mut Bench,
    options: &NattOptions<'_>,
    peer: &Peer,
    plan: PeerPlan<'_>,
    window: u64,
) -> Result<()> {
    let role = match plan {
        PeerPlan::Target { .. } | PeerPlan::UdpSelfCheck { .. } => "target",
        PeerPlan::Requester | PeerPlan::Downloader { .. } => "requester",
    };
    // Both bodies hold the same window, and it starts at different moments:
    // the target's when its recruit lands, the requester's when it is told
    // whom to reach. Everything before those two moments is the buddy wait,
    // which each body bounds with its own gate.
    let mut container = RunContainer::new(options.rmule_tools_image)
        .detach()
        .name(&peer.driver)
        .network(&peer.network)
        .ip(peer.lan.client)
        .cap_add("NET_ADMIN")
        .env("RMULE_DEFAULT_ROUTE_VIA", peer.lan.gateway)
        // Every silent drop on the NAT-T and buddy paths is traced at debug —
        // a refused hint, a relay that did not match the slot, an introduction
        // the front did not take. A rendezvous that does not land is diagnosed
        // from those lines and nowhere else.
        .env(
            "RMULE_LOG",
            "info,rmule_core::natt=debug,rmule_net::natt=debug,\
             rmule_core::firewalled=debug,rmule_core::adapters::kad_runtime=debug",
        )
        .volume(&peer.dir, "/out");
    for arg in common_args(
        role,
        peer.user_hash,
        peer.lan.client,
        window,
        &absent_server(),
        PLACEHOLDER_SHARE,
    ) {
        container = container.arg(arg);
    }
    let gate = [
        "--target-file".to_owned(),
        "/out/target.toml".to_owned(),
        "--target-timeout".to_owned(),
        (BUDDY_TIMEOUT_SECS + 60).to_string(),
    ];
    match plan {
        PeerPlan::Target { seed, publish } => {
            if publish {
                container = container
                    .arg("--publish".to_owned())
                    .arg("/out/shared.bin".to_owned());
            }
            for arg in [
                "--kad-id".to_owned(),
                mesh::hex(&mesh::TARGET_KAD_ID),
                "--buddy-out".to_owned(),
                "/out/buddy.toml".to_owned(),
                "--buddy-timeout".to_owned(),
                BUDDY_TIMEOUT_SECS.to_string(),
            ] {
                container = container.arg(arg);
            }
            for operand in seed {
                container = container.arg("--kad-contact".to_owned());
                container = container.arg(operand.clone());
            }
        }
        PeerPlan::UdpSelfCheck { seed, timeout_secs } => {
            for arg in [
                "--kad-id".to_owned(),
                mesh::hex(&mesh::TARGET_KAD_ID),
                "--publish-on-udp-open".to_owned(),
                "/out/shared.bin".to_owned(),
                "--buddy-timeout".to_owned(),
                timeout_secs.to_string(),
            ] {
                container = container.arg(arg);
            }
            for operand in seed {
                container = container.arg("--kad-contact".to_owned());
                container = container.arg(operand.clone());
            }
        }
        PeerPlan::Requester => {
            for arg in gate {
                container = container.arg(arg);
            }
        }
        PeerPlan::Downloader { seed, link } => {
            for arg in gate.into_iter().chain([
                "--kad-id".to_owned(),
                mesh::hex(&mesh::REQUESTER_KAD_ID),
                "--file".to_owned(),
                link.to_owned(),
                "--download-out".to_owned(),
                "/out/dl/download.bin".to_owned(),
            ]) {
                container = container.arg(arg);
            }
            for operand in seed {
                container = container.arg("--kad-contact".to_owned());
                container = container.arg(operand.clone());
            }
        }
    }
    bench.start_extra(&peer.driver, container, "run an rmule NAT-T body")
}

/// The operands every body of this flow shares.
/// What a body shares when nothing in the flow asks for a particular file:
/// the serve activity needs one, and no claim reads which.
const PLACEHOLDER_SHARE: &str = "/etc/hostname";

/// The eD2k endpoint a body with no server on its WAN logs in to. Nothing
/// listens here; the bind is what the body needs.
fn absent_server() -> String {
    format!("192.0.2.1:{ABSENT_SERVER_PORT}")
}

fn common_args(
    role: &str,
    user_hash: &str,
    own_ip: &str,
    window: u64,
    server: &str,
    share: &str,
) -> Vec<String> {
    vec![
        "natt".to_owned(),
        "buddy-rendezvous".to_owned(),
        "--role".to_owned(),
        role.to_owned(),
        "--server".to_owned(),
        server.to_owned(),
        "--listen".to_owned(),
        format!("0.0.0.0:{BODY_PEER_TCP_PORT}"),
        "--udp-port".to_owned(),
        BODY_CLIENT_UDP_PORT.to_string(),
        "--user-hash".to_owned(),
        user_hash.to_owned(),
        "--own-ip".to_owned(),
        own_ip.to_owned(),
        "--share".to_owned(),
        share.to_owned(),
        "--window".to_owned(),
        window.to_string(),
        "--out".to_owned(),
        "/out/buddy-rendezvous.toml".to_owned(),
    ]
}

/// Write the requester's target file in one `write`, so its own gate never
/// reads a half-arrived file.
fn write_target(path: &Path, buddy_v4: &str) -> Result<()> {
    fs::write(
        path,
        format!(
            "user_hash={HASH_TARGET}\nbuddy_id={}\nbuddy_udp={buddy_v4}:{BODY_CLIENT_UDP_PORT}\n",
            mesh::hex(&mesh::BUDDY_KAD_ID),
        ),
    )
    .with_context(|| format!("write {}", path.display()))
}

/// Take the in-flight **NAT Type Proof** on both gateways, triggered by the
/// requester's own `rmule-natt-first-dial` marker: the one
/// host-observable signal that both gateways' bursts have already left,
/// since the requester dial follows its own burst in the same tick, and that
/// burst only fires once the target's own burst has already answered the
/// hint round trip. Tagged `inflight` so it never overwrites the teardown
/// dump every gateway still takes on its own exit — that later, untagged
/// dump is kept too, because an empty read on it is what proves the
/// mappings this one caught actually die (run `1790071214`).
///
/// Bounded by the requester's own `window` — the transfer rows' is longer
/// than the rendezvous rows' — because a requester that never dials at all
/// is a fact its row already records on its own (`dials = 0`), not a reason
/// to hang the whole run: a timeout here is logged and the flow carries on
/// without an in-flight artifact, which the acceptance wrapper accepts only
/// beside that zero.
fn take_inflight_proof(
    bench: &Bench,
    peers: &[Peer],
    nat_type: NatType,
    window: u64,
) -> Result<()> {
    match wait_for_container_log(
        &bench.docker,
        &peers[0].driver,
        "rmule-natt-first-dial",
        Duration::from_secs(window),
    ) {
        Ok(line) => {
            println!("natt buddy first dial: {}", line.trim());
            for peer in peers {
                run_checked(
                    bench.docker.exec(
                        peer.gateway.clone(),
                        [
                            OsString::from("natgw-proof"),
                            OsString::from("/proof"),
                            OsString::from(nat_type.knob()),
                            OsString::from("inflight"),
                        ],
                    ),
                    "take the in-flight NAT gateway proof",
                )?;
            }
            Ok(())
        }
        Err(error) => {
            eprintln!(
                "natt buddy: the requester never logged its first dial within its own window \
                 ({error}); no in-flight NAT Type Proof was taken, and the negative claim \
                 below reads whatever the teardown dump still carries"
            );
            Ok(())
        }
    }
}

fn collect_buddy_log(bench: &Bench, container: &str, dir: &Path) -> Result<()> {
    let output = bench
        .docker
        .logs(container.to_owned())
        .to_command()
        .output()
        .with_context(|| format!("docker logs {container}"))?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    let path = dir.join("driver.log");
    fs::write(&path, &text).with_context(|| format!("write {}", path.display()))
}

/// The flow's own sanity check on its address plan, so a plan that outgrew the
/// `/24` fails where it is written rather than three minutes into a run.
const _PLAN_FITS: () = assert!(
    HOST_MESH[1] < MAX_NODES_PER_SUBNET && HOST_STORER < MAX_NODES_PER_SUBNET,
    "the buddy topology's bodies must fit one fake-public /24"
);

/// A 32-character hex hash as bytes — the Synthetic File's ED2K hash, which
/// places the storer.
fn parse_hash(hex: &str) -> Result<[u8; 16]> {
    let mut out = [0u8; 16];
    anyhow::ensure!(
        hex.len() == 32,
        "a 16-byte hash is 32 hex characters, got {hex}"
    );
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .with_context(|| format!("parse hash {hex}"))?;
    }
    Ok(out)
}
