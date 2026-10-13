//! The `natt-udp-selfcheck-cone` topology: ADR-0058's **UDP
//! self-check** end to end, on the buddy topology's WAN and address plan.
//!
//! Five bodies on the fake-public WAN and one masquerade-free LAN:
//!
//! - the **root** — the buddy body in the stimulus posture, here only the
//!   contact everyone else is seeded with;
//! - a **storer** — a routing-only member placed at the Synthetic File's Kad
//!   key, whose own capture holds the publish (the same placement flow M and
//!   `natt-buddy-transfer-cone` need);
//! - two **UDP Firewall Helpers** — open rmule Cores seeded with the root's
//!   contact, which the target is *never* seeded with. A helper is only
//!   usable while the requester has never sent it a datagram (aMule's
//!   `QueryNextClient` rules), so the target can learn of them in exactly one
//!   way: as rows of its own helper lookup, answered by the root. Seeding
//!   used to leave a helper unreached — a seeded contact merges
//!   already-responded and used to sit unvisited until a live datagram
//!   marked it alive (measured in run `1790118192`, where the target's
//!   lookup came back naming only the storer). The Small-Timer
//!   Hello Pass treats a never-checked seeded contact as due at once, so a
//!   helper greets the root within about a second of its own Kad start
//!   regardless — seeding is what the wire does, and this row now doubles
//!   as that pass's live proof (run `1790135545`);
//! - the **firewalled target** behind a `full-cone-pinned` gateway: its TCP
//!   port is unreachable, its pinned Kad UDP port is not. It publishes the
//!   Synthetic File only once its UDP verdict reads open.
//!
//! What the flow measures is the chain the issue names: the helper lookup
//! finds fresh helpers, the target dials them with `OP_FWCHECKUDPREQ`, a
//! helper answers `KADEMLIA2_FIREWALLUDP` through the gateway, the verdict
//! reads open, and the publish carries the direct-callback bit `0x08` on a
//! type-6 row — read back out of the storer's own capture. Every body is
//! rmule, so every claim is `rmule-only`: the rmule-authored tier of the
//! type-6 row, not the aMule-authored one.
//!
//! `natt-udp-selfcheck-remapped` is the same topology with the
//! gateway pinning the target's Kad port to a **different** public port. A
//! helper's `0x62` to the intern port then dies at the gateway, so the
//! verdict reads open only if the target learned its **Extern Kad Port** from
//! its `0x60` pings before it asked anyone, and put it in the `0xA7`. Two
//! more claims read that off the gateway's WAN tap.

pub(in crate::flow::nat::natt) mod amule;
mod direct_callback;

use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};

use super::{
    HOST_BUDDY, HOST_STORER, PLACEHOLDER_SHARE, PeerPlan, READY_TIMEOUT_SECS, absent_server,
    collect_buddy_log, common_args, mesh, parse_hash, start_buddy, start_peer,
};
use crate::docker::{InternalNetwork, RunContainer};
use crate::fake_public::{MAX_NODES_PER_SUBNET, fake_public_address, subnet_cidr};
use crate::flow::bench::{Bench, run_checked};
use crate::flow::evidence::read_tap_frames;
use crate::flow::gate::wait_for_container_log;
use crate::flow::nat::NAT_CLIENT_UDP_PORT;
use crate::flow::nat::claims::{Body, Claim, DriverRow, Evidence, gateways_probed_as_claimed};
use crate::flow::nat::natt::NattFlow;
use crate::flow::nat::natt::bench::{Driven, NattOptions};
use crate::flow::nat::natt::punch::proof::{probe_peer_lan, run_reflector};
use crate::flow::nat::natt::punch::wire::collect_driver_log;
use crate::flow::nat::natt::punch::{
    HOST_GATEWAY_B, HOST_PROBE_PRIMARY, HOST_PROBE_SECONDARY, LAN_B, Peer, start_gateway_mapped,
    wait_for_container_exit,
};
use crate::flow::taps::{Attachment, PerAttachmentTaps, TapRole};
use crate::nat::NatType;

/// The public port the remapped row's gateway pins the target's Kad port
/// to — anything but the client's own port.
const REMAPPED_PUBLIC_PORT: u16 = 14672;

/// The helpers' WAN host indices — the two routing-only slots the buddy rows
/// use, since this row needs no walk alternatives and the `/24` holds eight.
pub(super) const HOST_HELPERS: [usize; 2] = [5, 6];

/// The helpers' fixed user hashes and Kad IDs, far from the target's
/// `0x11…` and the storer's key so nothing about them is placement.
const HASH_HELPERS: [&str; 2] = [
    "45454545454545454545454545454545",
    "46464646464646464646464646464646",
];
pub(super) const HELPER_KAD_IDS: [[u8; 16]; 2] = [[0x66; 16], [0x99; 16]];

/// The target's user hash — the buddy rows' target, so the two rows name the
/// same body the same way.
const HASH_TARGET: &str = super::HASH_TARGET;

/// How long the target waits for its UDP verdict to read open. The helper
/// lookup launches on its first Kad datagram and a helper answers within one
/// TCP handshake; the budget is the six-minute timeout's own order only so a
/// run that fails says so as a verdict, not as a hang.
const UDP_OPEN_TIMEOUT_SECS: u64 = 240;

/// How long the target holds after publishing — the publish walk's window.
const PUBLISH_WINDOW_SECS: u64 = 60;

/// How long the root, the storer and the helpers live. The storer finalizes
/// its capture only on its own deadline, so this is also when its evidence
/// can be read.
const RUN_SECS: u64 = UDP_OPEN_TIMEOUT_SECS + PUBLISH_WINDOW_SECS + 180;

/// `TAG_SOURCETYPE` 6: aMule's firewalled-but-UDP-callable source row
/// (`Search.cpp:821-829`).
const SOURCE_TYPE_DIRECT_UDP_CALLBACK: u8 = 6;

/// Bit 3 of `TAG_ENCRYPTION`: the publisher accepts a direct UDP callback
/// (`Prefs.cpp:224-226`).
const CONNECT_OPTIONS_DIRECT_UDP_CALLBACK: u8 = 0x08;

/// Stand the self-check topology up, drive it, and hand back the claims.
///
/// # Errors
/// If the bench cannot be built, a body never reports ready, or a row cannot
/// be read. **A verdict that never reads open is not an error** — it is the
/// row, and the claims say which link of the chain broke.
pub(in crate::flow::nat::natt) fn drive(
    bench: &mut Bench,
    options: &NattOptions<'_>,
    flow: NattFlow,
    nat_type: NatType,
    suffix: &str,
    leg_dir: &Path,
) -> Result<(
    Driven,
    Vec<crate::flow::nat::natt::verdict::WireRow>,
    Vec<crate::flow::taps::TapRow>,
)> {
    let subnet_v4 = subnet_cidr(super::super::WAN_SUBNET_INDEX)?;
    let wan = format!("rmule-interop-nattwan-{suffix}");
    bench.create_extra_network(
        &wan,
        bench
            .docker
            .create_internal_network(InternalNetwork::new(&wan).subnet_v4(&subnet_v4)),
        "create the fake-public WAN",
    )?;
    let address = |host: usize| -> Result<String> {
        Ok(fake_public_address(super::super::WAN_SUBNET_INDEX * MAX_NODES_PER_SUBNET + host)?.ip)
    };
    let timeout = Duration::from_secs(options.timeout_secs);
    let public_port = if flow == NattFlow::UdpSelfCheckRemapped {
        REMAPPED_PUBLIC_PORT
    } else {
        NAT_CLIENT_UDP_PORT
    };

    let root_v4 = address(HOST_BUDDY)?;
    let root_dir = leg_dir.join("root");
    fs::create_dir_all(&root_dir)?;
    let root = start_buddy(
        bench, options, suffix, &wan, &root_v4, &root_dir, RUN_SECS, None,
    )?;

    let target_dir = leg_dir.join("target");
    fs::create_dir_all(&target_dir).with_context(|| format!("create {}", target_dir.display()))?;
    let file = crate::flow::nat::natt::punch::synthetic_file(&target_dir)?;
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
            run_secs: RUN_SECS,
        },
    )?;
    let seed: Vec<String> = [
        mesh::seed_operand(&mesh::hex(&mesh::BUDDY_KAD_ID), &root_v4),
        storer[0].seed_operand(),
    ]
    .into();

    let mut helpers = Vec::new();
    for (index, host) in HOST_HELPERS.iter().enumerate() {
        let helper_v4 = address(*host)?;
        let dir = leg_dir.join(format!("helper-{index}"));
        fs::create_dir_all(&dir)?;
        let name = start_helper(
            bench, options, suffix, &wan, index, &helper_v4, &dir, &root_v4, RUN_SECS,
        )?;
        helpers.push((name, helper_v4, dir));
    }
    // Each helper's own Small-Timer Hello Pass treats its seeded,
    // never-checked root contact as due at once and greets it within about a
    // second of the helper's own Kad start; the root merges the helper on
    // receipt, landing it in the table the target's helper lookup reads
    // from. This settle just gives that greet room to land before the
    // gateway/reflector/probe setup that follows — the target's
    // UDP_OPEN_TIMEOUT_SECS retry window covers the rest.
    std::thread::sleep(mesh::MESH_SETTLE);

    let peer = Peer {
        name: "target",
        lan: &LAN_B,
        network: format!("rmule-interop-nattlanb-{suffix}"),
        gateway: format!("rmule-interop-nattgwb-{suffix}"),
        gateway_wan: address(HOST_GATEWAY_B)?,
        driver: format!("rmule-interop-nattpeerb-{suffix}"),
        dir: target_dir.clone(),
        user_hash: HASH_TARGET,
    };
    start_gateway_mapped(bench, options, &peer, &wan, nat_type, timeout, public_port)?;
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

    start_peer(
        bench,
        options,
        &peer,
        PeerPlan::UdpSelfCheck {
            seed: &seed,
            timeout_secs: UDP_OPEN_TIMEOUT_SECS,
        },
        PUBLISH_WINDOW_SECS,
    )?;
    wait_for_container_log(
        &bench.docker,
        &peer.driver,
        "rmule-natt-buddy-ready",
        Duration::from_secs(READY_TIMEOUT_SECS),
    )?;
    let open_port = match wait_for_container_log(
        &bench.docker,
        &peer.driver,
        "rmule-natt-udp-open",
        Duration::from_secs(UDP_OPEN_TIMEOUT_SECS + 60),
    ) {
        Ok(line) => {
            println!("natt udp self-check: {}", line.trim());
            line.split_whitespace()
                .find_map(|field| field.strip_prefix("port="))
                .and_then(|port| port.parse::<u16>().ok())
        }
        Err(error) => {
            eprintln!(
                "natt udp self-check: the target's UDP verdict never read open ({error}); the \
                 row records how far the chain got"
            );
            None
        }
    };
    // Once the verdict reads open, a direct-callback requester draws the
    // target's post-verdict hello.
    let requester_v4 = address(direct_callback::HOST_REQUESTER)?;
    let requester_dir = leg_dir.join("requester");
    fs::create_dir_all(&requester_dir)?;
    let requester = match open_port {
        Some(_) => Some(direct_callback::start_requester(
            bench,
            options,
            suffix,
            &wan,
            &requester_v4,
            &requester_dir,
            &root_v4,
            &format!("{}:{public_port}", peer.gateway_wan),
        )?),
        None => None,
    };
    wait_for_container_exit(bench, &peer.driver)?;
    let gateway_tap_rows = gateway_taps.rows(&bench.docker, "ip")?;
    let hellos = direct_callback::lift(
        bench,
        &gateway_taps,
        &peer.gateway_wan,
        &requester_v4,
        &target_dir,
    )?;
    let routed = match &requester {
        Some(name) => {
            wait_for_container_exit(bench, name)?;
            collect_buddy_log(bench, name, &requester_dir)?;
            DriverRow::read(&requester_dir.join("buddy-rendezvous.toml"))
                .map(|row| row.text("routed"))
                .unwrap_or_else(|error| format!("no requester row ({error})"))
        }
        None => "no requester: the verdict never read open".to_owned(),
    };
    let remap = if flow == NattFlow::UdpSelfCheckRemapped {
        Some(RemapTaps::count(
            &gateway_taps,
            bench,
            &peer.gateway_wan,
            public_port,
        )?)
    } else {
        None
    };
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
    collect_driver_log(bench, &peer)?;

    // The storer writes `datagrams.toml` only on its own deadline, so its
    // evidence is read after it exits — and the helpers' logs after theirs.
    wait_for_container_exit(bench, &storer[0].container)?;
    mesh::collect(bench, &storer, leg_dir)?;
    let mut helper_logs = Vec::new();
    for (name, _, dir) in &helpers {
        collect_buddy_log(bench, name, dir)?;
        helper_logs.push(fs::read_to_string(dir.join("driver.log")).unwrap_or_default());
    }
    collect_buddy_log(bench, &root, &root_dir)?;

    let target = DriverRow::read(&target_dir.join("buddy-rendezvous.toml"))?;
    let publish = storer_publish(
        &leg_dir.join("mesh-0").join("capture"),
        &peer.gateway_wan,
        &storer_id,
    )?;
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
        &target,
        &answered,
        publish.as_ref(),
        &peer.gateway_wan,
    );
    if let Some(remap) = &remap {
        claims.extend(remap.claims(&peer.gateway_wan, public_port, open_port));
    }
    claims.push(direct_callback::claim(&hellos, &routed));
    let mut bodies = vec![Body {
        name: "rmule-root".to_owned(),
        image: options.rmule_tools_image.to_owned(),
        pin: format!(
            "{}; kad id {}",
            crate::run_record::rmule_pin(),
            mesh::hex(&mesh::BUDDY_KAD_ID)
        ),
        address_v4: root_v4,
        address_v6: String::new(),
    }];
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
    if requester.is_some() {
        bodies.push(Body {
            name: "rmule-direct-callback-requester".to_owned(),
            image: options.rmule_tools_image.to_owned(),
            pin: format!(
                "{}; open Core sending the 0x95",
                crate::run_record::rmule_pin()
            ),
            address_v4: requester_v4,
            address_v6: String::new(),
        });
    }
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
    Ok((
        Driven {
            claims,
            bodies,
            wire: Vec::new(),
            note: format!(
                "ADR-0058's UDP self-check behind a full-cone-pinned gateway{}: fresh helpers \
                 found by the target's own helper lookup, 0xA7 over peer TCP, 0x62 through \
                 the pinned port, and the publish that verdict earns. Every body is rmule, \
                 so the type-6 row reached here is the rmule-authored tier; the \
                 aMule-authored one stays capture-pending (ADR-0061).",
                if remap.is_some() {
                    format!(
                        " that remaps the target's Kad port {NAT_CLIENT_UDP_PORT} to \
                         {public_port}, learned first from its own 0x60 pings"
                    )
                } else {
                    String::new()
                }
            ),
            tunnel_rose: None,
        },
        Vec::new(),
        gateway_tap_rows,
    ))
}

/// The remapped row's WAN-tap counts: the plain `KADEMLIA2_PING` our target
/// sent out through the remap, and the helpers' `0x62` at the gateway on
/// each of the two ports the `0xA7` could have named. Every Kad datagram on
/// this bench is plaintext — no Core arms Kad-UDP crypt —
/// so the opcode sits at UDP payload offset 1.
struct RemapTaps {
    pings_out: u64,
    results_to_extern: u64,
    results_to_intern: u64,
}

impl RemapTaps {
    fn count(
        taps: &PerAttachmentTaps,
        bench: &Bench,
        gateway_wan: &str,
        public_port: u16,
    ) -> Result<Self> {
        let wan = |filter: String| -> Result<u64> {
            Ok(taps
                .rows(&bench.docker, &filter)?
                .into_iter()
                .find(|row| row.attachment == "wan")
                .map_or(0, |row| row.packets))
        };
        Ok(Self {
            pings_out: wan(format!(
                "udp and src host {gateway_wan} and src port {public_port} and udp[8:2] = 0xe460"
            ))?,
            results_to_extern: wan(format!(
                "udp and dst host {gateway_wan} and dst port {public_port} and udp[8:2] = 0xe462"
            ))?,
            results_to_intern: wan(format!(
                "udp and dst host {gateway_wan} and dst port {NAT_CLIENT_UDP_PORT} and \
                 udp[8:2] = 0xe462"
            ))?,
        })
    }

    fn claims(&self, gateway_wan: &str, public_port: u16, open_port: Option<u16>) -> Vec<Claim> {
        vec![
            Claim::about(
                "the-target-pinged-for-its-extern-port-through-the-remap",
                self.pings_out > 0,
                Evidence::RmuleOnly,
                format!(
                    "WAN tap: {} KADEMLIA2_PING (0x60) from {gateway_wan}:{public_port} — the \
                     target's Kad port {NAT_CLIENT_UDP_PORT} as the gateway remaps it, the \
                     port each 0x61 names back",
                    self.pings_out
                ),
            ),
            Claim::about(
                "the-0x62-landed-on-the-learned-extern-port",
                self.results_to_extern > 0 && open_port == Some(public_port),
                Evidence::RmuleOnly,
                format!(
                    "WAN tap: {} KADEMLIA2_FIREWALLUDP (0x62) to {gateway_wan}:{public_port}, {} \
                     to the intern port {NAT_CLIENT_UDP_PORT} (no rule forwards it); the \
                     target read open on port {open_port:?}",
                    self.results_to_extern, self.results_to_intern
                ),
            ),
        ]
    }
}

/// Start one open **UDP Firewall Helper**: an rmule Core in the stimulus
/// posture, bootstrapping from the root so the root's table names it.
#[allow(clippy::too_many_arguments)]
pub(super) fn start_helper(
    bench: &mut Bench,
    options: &NattOptions<'_>,
    suffix: &str,
    wan: &str,
    index: usize,
    helper_v4: &str,
    dir: &Path,
    root_v4: &str,
    run_secs: u64,
) -> Result<String> {
    let name = format!("rmule-interop-nattudphelper{index}-{suffix}");
    let mut container = RunContainer::new(options.rmule_tools_image)
        .detach()
        .name(&name)
        .network(wan)
        .ip(helper_v4)
        .cap_add("NET_ADMIN")
        .env("RMULE_LOG", "info,rmule_core::adapters::kad_runtime=debug")
        .volume(dir, "/out");
    for arg in common_args(
        "buddy",
        HASH_HELPERS[index],
        helper_v4,
        run_secs,
        &absent_server(),
        PLACEHOLDER_SHARE,
    ) {
        container = container.arg(arg);
    }
    container = container
        .arg("--kad-id".to_owned())
        .arg(mesh::hex(&HELPER_KAD_IDS[index]))
        .arg("--assume-open".to_owned())
        .arg("--kad-contact".to_owned())
        .arg(mesh::seed_operand(&mesh::hex(&mesh::BUDDY_KAD_ID), root_v4));
    // A crypt-armed requester's `0xA7` carries a verify key; an armed helper
    // keys its `0x62` on it, an unarmed one answers in the clear.
    if options.kad_crypt {
        container = container
            .arg("--peer-crypt".to_owned())
            .arg("requested".to_owned());
    }
    bench.start_extra(&name, container, "run an rmule UDP Firewall Helper")?;
    wait_for_container_log(
        &bench.docker,
        &name,
        "rmule-natt-buddy-ready",
        Duration::from_secs(READY_TIMEOUT_SECS),
    )?;
    Ok(name)
}

/// What the storer's capture says the target published: the inbound
/// `KADEMLIA2_PUBLISH_SOURCE_REQ` from the target's gateway under the
/// Synthetic File's key — the storer's own ID — decoded. Keyed, because the
/// target publishes every file it shares and the others land here too, then
/// fail the storer's tolerance gate (run `1790120419`).
struct StoredPublish {
    source_type: Option<u8>,
    connect_options: Option<u8>,
    bytes: usize,
}

fn storer_publish(
    capture: &Path,
    gateway_wan: &str,
    file_key: &[u8; 16],
) -> Result<Option<StoredPublish>> {
    let from_gateway = format!("{gateway_wan}:");
    for frame in read_tap_frames(capture)? {
        if frame.direction != "in"
            || !frame.remote.starts_with(&from_gateway)
            || frame.bytes.get(2..18) != Some(file_key.as_slice())
        {
            continue;
        }
        let Ok(rmule_kad::KadDecoded::Plain(envelope) | rmule_kad::KadDecoded::Packed(envelope)) =
            rmule_kad::decode_exact(&frame.bytes)
        else {
            continue;
        };
        if let Ok(rmule_kad::Kad2Message::PublishSourceReq { source, .. }) =
            rmule_kad::Kad2Message::decode(&envelope)
        {
            return Ok(Some(StoredPublish {
                source_type: source.source_type,
                connect_options: source.encryption,
                bytes: frame.bytes.len(),
            }));
        }
    }
    Ok(None)
}

fn claims(
    proof: &crate::nat::NatTypeProof,
    target: &DriverRow,
    answered: &[bool],
    publish: Option<&StoredPublish>,
    gateway_wan: &str,
) -> Vec<Claim> {
    let byte = publish.and_then(|row| row.connect_options);
    vec![
        Claim::about(
            "the-lan-reached-the-wan-on-the-pinned-port",
            proof.pinned_port_reachable && proof.pinned_port != 0,
            Evidence::RmuleOnly,
            format!(
                "{gateway_wan}: one datagram to the Pinned-Port Sink at port {} {}; RFC 4787 \
                 axes observed {}/{} against a {} claim (agrees = {})",
                proof.pinned_port,
                if proof.pinned_port_reachable {
                    "arrived"
                } else {
                    "never arrived"
                },
                proof.observed_mapping,
                proof.observed_filtering,
                proof.nat_type.knob(),
                proof.agrees,
            ),
        ),
        gateways_probed_as_claimed([(gateway_wan, proof)]),
        Claim::about(
            "a-fresh-helper-answered-0x62-to-the-gateway",
            answered.iter().any(|answered| *answered),
            Evidence::RmuleOnly,
            format!(
                "helpers that logged an unbiased 0x62 toward {gateway_wan}: {answered:?}. Neither \
                 was in the target's seed; its helper lookup is the only way it could name them"
            ),
        ),
        Claim::about(
            "the-target-udp-verdict-read-open",
            target.text("udp_verdict") == "open",
            Evidence::RmuleOnly,
            format!(
                "udp_verdict = {:?} after {} s (-1 = never); the TCP port stays unreachable \
                 behind the gateway, so this is the verdict aMule's GetMyConnectOptions turns \
                 into bit 0x08",
                target.text("udp_verdict"),
                target.int("udp_open_after_secs"),
            ),
        ),
        Claim::about(
            "the-storer-captured-a-type-6-row-stating-0x08",
            publish.is_some_and(|row| {
                row.source_type == Some(SOURCE_TYPE_DIRECT_UDP_CALLBACK)
                    && byte.is_some_and(|byte| byte & CONNECT_OPTIONS_DIRECT_UDP_CALLBACK != 0)
            }),
            Evidence::RmuleOnly,
            match publish {
                Some(row) => format!(
                    "the storer's own capture holds a {}-byte 0x44 from {gateway_wan}: \
                     TAG_SOURCETYPE = {:?}, TAG_ENCRYPTION = {}",
                    row.bytes,
                    row.source_type,
                    byte.map_or_else(|| "absent".to_owned(), |byte| format!("{byte:#04x}")),
                ),
                None => format!("no 0x44 from {gateway_wan} in the storer's capture"),
            },
        ),
    ]
}
