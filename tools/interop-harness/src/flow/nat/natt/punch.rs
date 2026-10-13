//! The `natt-server-punch-{cone,symmetric}` topology: an `ed2ksrv` on the
//! fake-public WAN and **two rmule peers, each behind its own NAT Gateway**.
//!
//! One gateway per peer is not tidiness. ADR-0091 records that
//! `ed2k-server` `4da4774` keys `observed_udp_ports` by IPv4 address alone, so
//! two NAT-T clients behind one NAT overwrite each other's observed port and
//! each is introduced at whichever `0x9F` keepalive landed last. Two gateways
//! give the server two addresses to key on.
//!
//! **Both ends of the punch are rmule**, so this is an `rmule-only` row
//! (ADR-0045's 2026-09-16 amendment): what the *server* emits — `0x60` in,
//! `0x61` out to both — is counterparty evidence, and the punch and the Tunnel
//! between the peers are scored *exercised* against a proven NAT, never
//! captured.
//!
//! The `-symmetric` variant is a **negative** and therefore carries the whole
//! ADR-0045 kit in the same run: both gateways' **NAT Type Proof**, the RFC
//! 5780 **Reflector Probe** beside the claim, the outbound conntrack entry
//! showing the mapping existed, and the counterparty's own zero. A punch
//! failure missing any of the four is a fabricated row.
//!
//! The probe runs for **every** gateway type, not only the negative, and it
//! runs **before** the drivers. Two reasons, both learned the expensive way,
//! on a server-introduced punch whose pinhole nobody dialled through. Its
//! sixth test addresses the **Pinned-Port Sink** on the WAN, so a gateway rule
//! keyed on the pinned client port — the one port every punch and every uTP
//! opener is aimed at, and the one port RFC 5780 can never see — is proven
//! reachable before three minutes are spent measuring a punch it would have
//! eaten. And the `nat-type.toml` it feeds is the readable half of the **NAT
//! Type Proof** the row cites.

pub(super) mod drivers;
mod prediction;
pub(super) mod proof;
pub(super) mod wire;

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::bench_doctor::CONNTRACK_UDP_TIMEOUT_SECS;
use crate::docker::{InternalNetwork, RunContainer};
use crate::fake_public::{MAX_NODES_PER_SUBNET, fake_public_address, subnet_cidr};
use crate::flow::bench::{Bench, run_checked};
use crate::flow::ed2ksrv::ED2KSRV;
use crate::flow::gate::wait_for_container_log;
use crate::flow::nat::NAT_CLIENT_UDP_PORT;
use crate::flow::nat::claims::Body;
use crate::flow::nat::claims::DriverRow;
use crate::flow::nat::natt::bench::{Driven, NattOptions};
use crate::flow::nat::natt::{BODY_CLIENT_UDP_PORT, NattFlow};
use crate::flow::taps::{Attachment, PerAttachmentTaps, TapRole};
use crate::nat::NatType;

pub(in crate::flow::nat::natt) use self::drivers::synthetic_file;
use self::drivers::{TransferPlan, start_driver};
use self::proof::{probe_peer_lan, run_reflector};
use self::wire::{collect_driver_log, count_punch_mappings, count_wire, wire_rows};

/// The eD2k TCP port `ed2ksrv` listens on.
pub(super) const ED2KSRV_TCP_PORT: u16 = 4661;

/// The two peers' LANs. Two `/24`s rather than two addresses on one, because
/// the whole point is that each peer's gateway holds its **own** fake-public
/// address for the server to key an observed port on.
pub(super) const LAN_A: LanPlan = LanPlan {
    subnet: "10.77.0.0/24",
    gateway: "10.77.0.2",
    client: "10.77.0.3",
};
pub(super) const LAN_B: LanPlan = LanPlan {
    subnet: "10.78.0.0/24",
    gateway: "10.78.0.2",
    client: "10.78.0.3",
};

/// One peer's masquerade-free LAN.
pub(super) struct LanPlan {
    pub(super) subnet: &'static str,
    pub(super) gateway: &'static str,
    pub(super) client: &'static str,
}

/// The WAN host indices, pinned so two runs are comparable.
const HOST_ED2KSRV: usize = 0;
pub(super) const HOST_GATEWAY_A: usize = 1;
pub(super) const HOST_GATEWAY_B: usize = 2;
pub(super) const HOST_PROBE_PRIMARY: usize = 3;
pub(super) const HOST_PROBE_SECONDARY: usize = 4;

/// How long a peer is given to log in and publish its identity.
pub(super) const IDENTITY_TIMEOUT_SECS: u64 = 90;

/// How long the responder waits for a target file it is never given. Short,
/// because its job is to *accept*: the wait exists only so the two drivers
/// share one code path, and the window after it is what the row needs.
const TARGET_TIMEOUT_SECS: u64 = 20;

/// The window both peers hold open after the introduction.
///
/// It must be **longer than the thing it measures**. ADR-0091 gives a dial
/// attempt a 120 s budget, and a dial that fails does so by spending all of it;
/// a 120 s window therefore ended at the same instant the front reached its own
/// verdict, so the run recorded "never dialed" and "dialed and got nothing" as
/// the same zero and lost the driver's own account of which it was.
/// Thirty seconds past the budget is enough for the attempt to retire,
/// the front to say so, and the diagnostics snapshot to carry it.
pub(super) const DIAL_BUDGET_SECS: u64 = 120;
pub(super) const WINDOW_SECS: u64 = DIAL_BUDGET_SECS + 30;

/// One peer's staged containers and the paths its driver reads and writes.
pub(super) struct Peer {
    pub(super) name: &'static str,
    pub(super) lan: &'static LanPlan,
    pub(super) network: String,
    pub(super) gateway: String,
    pub(super) gateway_wan: String,
    pub(super) driver: String,
    pub(super) dir: PathBuf,
    pub(super) user_hash: &'static str,
}

impl Peer {
    pub(super) fn identity_path(&self) -> PathBuf {
        self.dir.join("identity.toml")
    }

    pub(super) fn target_path(&self) -> PathBuf {
        self.dir.join("target.toml")
    }

    pub(super) fn row_path(&self) -> PathBuf {
        self.dir.join("punch.toml")
    }
}

/// The two peers' fixed user hashes. Fixed so a `0x61` introduction and the
/// front's ledger name values a verdict can quote.
pub(super) const HASH_A: &str = "41414141414141414141414141414141";
pub(super) const HASH_B: &str = "42424242424242424242424242424242";

/// Stand the punch topology up, drive it, and hand back the claims.
///
/// # Errors
/// If the bench cannot be built, a gateway never reports ready, or a driver's
/// row cannot be read. **A punch that does not land is not an error** — behind
/// a symmetric gateway it is the measurement.
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
    // Requester first. Every row but the one-symmetric one stands both peers
    // behind `nat_type`.
    let peer_types = flow.peer_nat_types().unwrap_or([nat_type; 2]);
    // Port prediction runs on the one-symmetric row always, and on the
    // both-symmetric row when asked, to show the knob leaves it a negative.
    let predicting = flow == NattFlow::ServerPunchOneSymmetric
        || (flow == NattFlow::ServerPunchSymmetric && options.port_prediction);
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

    let server_v4 = address(HOST_ED2KSRV)?;
    let server = start_server(bench, options, suffix, &wan, &server_v4, leg_dir, timeout)?;

    let peers = [
        Peer {
            name: "a",
            lan: &LAN_A,
            network: format!("rmule-interop-nattlana-{suffix}"),
            gateway: format!("rmule-interop-nattgwa-{suffix}"),
            gateway_wan: address(HOST_GATEWAY_A)?,
            driver: format!("rmule-interop-nattpeera-{suffix}"),
            dir: leg_dir.join("peer-a"),
            user_hash: HASH_A,
        },
        Peer {
            name: "b",
            lan: &LAN_B,
            network: format!("rmule-interop-nattlanb-{suffix}"),
            gateway: format!("rmule-interop-nattgwb-{suffix}"),
            gateway_wan: address(HOST_GATEWAY_B)?,
            driver: format!("rmule-interop-nattpeerb-{suffix}"),
            dir: leg_dir.join("peer-b"),
            user_hash: HASH_B,
        },
    ];

    for (peer, peer_type) in peers.iter().zip(peer_types) {
        fs::create_dir_all(&peer.dir).with_context(|| format!("create {}", peer.dir.display()))?;
        start_gateway(bench, options, peer, &wan, peer_type, timeout)?;
    }

    // The evidence tap is the SERVER's attachment: its `0x60` in and its two
    // `0x61` out are the only counterparty bytes in this topology. Each
    // gateway's WAN tap corroborates the punch, and its LAN tap is part of the
    // NAT Type Proof.
    let server_taps = PerAttachmentTaps::start(
        bench,
        options.capture_image,
        &server,
        &format!("rmule-interop-nattsrvtap-{suffix}"),
        leg_dir,
        &[Attachment {
            name: "server",
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

    // The **NAT Type Proof**'s observation half, before a single driver runs:
    // the RFC 5780 probe plus the pinned-port leg, from inside each peer's own
    // LAN. A gateway that cannot forward the pinned port at all fails here in
    // seconds rather than as a silent zero three minutes later.
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
    for (peer, peer_type) in peers.iter().zip(peer_types) {
        proofs.push(probe_peer_lan(
            bench,
            options,
            peer,
            peer_type,
            (&reflector_primary, &reflector_secondary),
        )?);
    }
    // The Kad observers that tell each peer its own mapping: up before any
    // driver, because a driver's Extern Port Round starts at its Kad start.
    let observers = if predicting {
        Some(prediction::Observers::start(
            bench,
            options,
            &wan,
            suffix,
            [
                address(prediction::HOST_OBSERVERS[0])?,
                address(prediction::HOST_OBSERVERS[1])?,
                address(prediction::HOST_OBSERVERS[2])?,
            ],
            leg_dir,
        )?)
    } else {
        None
    };

    // `natt-tunnel-transfer` shares one **Synthetic File** between the two
    // peers: B is its only source and A is downloading it, so the link both
    // halves name is computed here, once, from the bytes on disk.
    let transfer = (flow == NattFlow::TunnelTransfer)
        .then(|| synthetic_file(&leg_dir.join("peer-b")))
        .transpose()?;
    for (index, peer) in peers.iter().enumerate() {
        // Peer B is the sharing half; peer A downloads.
        let plan = TransferPlan {
            link: transfer.as_ref().map(|file| file.link.as_str()),
            share: transfer
                .as_ref()
                .filter(|_| index == 1)
                .map(|file| file.path.as_path()),
        };
        let extra = observers
            .as_ref()
            .map(|observers| observers.driver_args(index))
            .unwrap_or_default();
        start_driver(bench, options, peer, &plan, &server_v4, &extra)?;
    }

    // Each peer's Low ID is the server's to assign, so neither can be told the
    // other's before both have one. The gate is on the identity file each
    // driver writes at its own `Connected`.
    let ready_marker = if flow == NattFlow::TunnelTransfer {
        "rmule-natt-transfer-ready"
    } else {
        "rmule-natt-punch-ready"
    };
    let identities = peers
        .iter()
        .map(|peer| {
            wait_for_container_log(
                &bench.docker,
                &peer.driver,
                ready_marker,
                // A predicting driver holds its identity back until its Own
                // Mapping reads known.
                Duration::from_secs(
                    IDENTITY_TIMEOUT_SECS
                        + if predicting {
                            prediction::OWN_MAPPING_TIMEOUT_SECS
                        } else {
                            0
                        },
                ),
            )?;
            read_identity(&peer.identity_path())
        })
        .collect::<Result<Vec<_>>>()?;

    // Peer A is the requester: it asks for the introduction, so it dials and B
    // accepts (ADR-0091, and the `0x61` role byte is read for
    // exactly that). B is told nothing, which is what makes the single `0x60`
    // on the server's tap attributable. On the transfer row the same file
    // names B as the download's one Low-ID source.
    let named = if flow == NattFlow::TunnelTransfer {
        peers[0].dir.join("source.toml")
    } else {
        peers[0].target_path()
    };
    write_target(&named, &identities[1])?;

    // The two drivers run their own windows out and exit; the rows land on the
    // mounted dirs.
    for peer in &peers {
        wait_for_container_exit(bench, &peer.driver)?;
    }

    for (peer, peer_type) in peers.iter().zip(peer_types) {
        run_checked(
            bench.docker.exec(
                peer.gateway.clone(),
                [
                    OsString::from("natgw-proof"),
                    OsString::from("/proof"),
                    OsString::from(peer_type.knob()),
                ],
            ),
            "take the NAT gateway self-proof",
        )?;
    }

    // The driver containers are gone from the run dir the moment the bench
    // tears down, so their whole output is lifted first: a punch that did not
    // land is diagnosed from what the two nodes said, and nowhere else.
    for peer in &peers {
        collect_driver_log(bench, peer)?;
    }
    let rows = peers
        .iter()
        .map(|peer| DriverRow::read(&peer.row_path()))
        .collect::<Result<Vec<_>>>()?;

    let wire = count_wire(
        bench,
        &server_taps,
        &gateway_taps,
        wire_rows(&server_v4, &peers),
    )?;
    let taps = server_taps.rows(&bench.docker, "ip")?;
    let prediction = match &observers {
        Some(observers) => {
            observers.collect(bench, leg_dir)?;
            Some(prediction_evidence(bench, &peers, &gateway_taps)?)
        }
        None => None,
    };
    // The conntrack half is read *after* the dump is taken — the punch's own
    // mappings are what the negative rests on, and they do not exist until the
    // drivers have run.
    let gateway_proofs = peers
        .iter()
        .zip(proofs)
        .enumerate()
        .map(|(index, (peer, proof))| {
            let other = &peers[1 - index];
            let dump = fs::read_to_string(peer.dir.join("conntrack.txt"))
                .with_context(|| format!("read {}", peer.dir.join("conntrack.txt").display()))?;
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
    let mut driven = super::legs::punch_claims(
        flow,
        &rows,
        &gateway_proofs,
        &server_v4,
        transfer.as_ref().map_or("", |file| file.file_hash.as_str()),
        transfer.as_ref().map_or(0, |file| file.size),
        vec![Body {
            name: "ed2ksrv".to_owned(),
            image: options.ed2ksrv_image.to_owned(),
            pin: crate::flow::ed2ksrv::ED2KSRV.body_pin(&bench.docker, options.ed2ksrv_image),
            address_v4: server_v4.clone(),
            address_v6: String::new(),
        }],
    );
    if let Some(evidence) = &prediction {
        driven
            .claims
            .extend(prediction::claims(flow, &rows, evidence));
        if flow == NattFlow::ServerPunchOneSymmetric {
            driven.tunnel_rose = prediction::tunnel_rose(&rows);
        }
    }
    Ok((driven, wire, taps))
}

/// Read one run's two port sets back: each gateway's Fan mappings off
/// its conntrack dump, and each side's pinned-port punches off its LAN tap.
fn prediction_evidence(
    bench: &Bench,
    peers: &[Peer; 2],
    gateway_taps: &[PerAttachmentTaps],
) -> Result<prediction::PredictionEvidence> {
    let mut fan_ports: [std::collections::BTreeSet<u16>; 2] = Default::default();
    let mut punches: [prediction::PinnedPunches; 2] = Default::default();
    for (index, peer) in peers.iter().enumerate() {
        let other = &peers[1 - index];
        let dump = fs::read_to_string(peer.dir.join("conntrack.txt"))
            .with_context(|| format!("read {}", peer.dir.join("conntrack.txt").display()))?;
        fan_ports[index] = prediction::fan_ports(
            &dump,
            peer.lan.client,
            &other.gateway_wan,
            BODY_CLIENT_UDP_PORT,
        );
        gateway_taps[index].lift(
            &bench.docker,
            "lan",
            &prediction::punches_toward(peer, &other.gateway_wan),
            prediction::PUNCHES_PCAP,
        )?;
        let ports = crate::flow::pcap::udp4_ports(&peer.dir.join(prediction::PUNCHES_PCAP))?;
        punches[index] = prediction::PinnedPunches::from_ports(&ports, BODY_CLIENT_UDP_PORT);
    }
    Ok(prediction::PredictionEvidence { fan_ports, punches })
}

/// Stand the `ed2ksrv` coordinator up at `server_v4`, its config's `this_ip`
/// rendered to that address, and wait for its TCP listener.
pub(super) fn start_server(
    bench: &mut Bench,
    options: &NattOptions<'_>,
    suffix: &str,
    wan: &str,
    server_v4: &str,
    leg_dir: &Path,
    timeout: Duration,
) -> Result<String> {
    // The server's `this_ip` drives `OP_IDCHANGE`, the `SERVERIDENT` address
    // and the obfuscation seckey, and must equal the container's own address —
    // so the bench config is rendered per run rather than pinned. Authored
    // counterparty *state* is sanctioned (ADR-0045); the binary is untouched.
    let config = fs::read_to_string(options.ed2ksrv_config)
        .with_context(|| format!("read {}", options.ed2ksrv_config.display()))?;
    let rendered = config
        .lines()
        .map(|line| {
            if line.starts_with("this_ip") {
                format!("this_ip = \"{server_v4}\"")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let config_path = leg_dir.join("ed2ksrv-config.toml");
    fs::write(&config_path, rendered)
        .with_context(|| format!("write {}", config_path.display()))?;

    let name = format!("rmule-interop-nattsrv-{suffix}");
    let ed2ksrv = ED2KSRV.check(&bench.docker, options.ed2ksrv_image)?;
    bench.start_extra(
        &name,
        ed2ksrv
            .container()
            .detach()
            .name(&name)
            .network(wan)
            .ip(server_v4)
            .volume(&config_path, "/etc/ed2k-server/config.toml"),
        "run the ed2k-server coordinator",
    )?;
    wait_for_container_log(&bench.docker, &name, "TCP listener ready", timeout)?;
    Ok(name)
}

pub(super) fn start_gateway(
    bench: &mut Bench,
    options: &NattOptions<'_>,
    peer: &Peer,
    wan: &str,
    nat_type: NatType,
    timeout: Duration,
) -> Result<()> {
    start_gateway_mapped(
        bench,
        options,
        peer,
        wan,
        nat_type,
        timeout,
        NAT_CLIENT_UDP_PORT,
    )
}

/// [`start_gateway`] with the client's UDP port pinned to `public_port` on
/// the WAN (`NAT_PUBLIC_PORT`) — a **port-remapping** gateway whenever it
/// differs from the client's own port. Only the pinned types read it.
pub(super) fn start_gateway_mapped(
    bench: &mut Bench,
    options: &NattOptions<'_>,
    peer: &Peer,
    wan: &str,
    nat_type: NatType,
    timeout: Duration,
    public_port: u16,
) -> Result<()> {
    bench.create_extra_network(
        &peer.network,
        bench
            .docker
            .create_lan_bridge(&peer.network, peer.lan.subnet),
        "create a masquerade-free LAN bridge",
    )?;
    bench.start_extra(
        &peer.gateway,
        RunContainer::new(options.natgw_image)
            .detach()
            .name(&peer.gateway)
            .network(wan)
            .ip(&peer.gateway_wan)
            .cap_add("NET_ADMIN")
            .sysctl("net.ipv4.ip_forward", "1")
            .sysctl("net.ipv6.conf.all.forwarding", "1")
            .sysctl(
                "net.netfilter.nf_conntrack_udp_timeout",
                CONNTRACK_UDP_TIMEOUT_SECS.to_string(),
            )
            .volume(&peer.dir, "/proof")
            .env("NAT_TYPE", nat_type.knob())
            .env("NAT_LAN_CLIENT", peer.lan.client)
            .env("NAT_CLIENT_PORT", NAT_CLIENT_UDP_PORT.to_string())
            .env("NAT_PUBLIC_PORT", public_port.to_string()),
        "run the NAT gateway",
    )?;
    run_checked(
        bench.docker.connect_network(
            peer.network.clone(),
            peer.gateway.clone(),
            Some(OsString::from(peer.lan.gateway)),
            None,
        ),
        "attach the NAT gateway to its LAN",
    )?;
    wait_for_container_log(&bench.docker, &peer.gateway, "rmule-natgw-ready", timeout)?;
    Ok(())
}

/// One peer's published identity, as its driver wrote it.
struct Identity {
    id: String,
    user_hash: String,
}

fn read_identity(path: &Path) -> Result<Identity> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("read the peer identity {}", path.display()))?;
    let field = |key: &str| {
        text.lines()
            .find_map(|line| line.trim().strip_prefix(&format!("{key}=")))
            .map(|value| value.trim().to_owned())
    };
    let (Some(id), Some(user_hash)) = (field("id"), field("user_hash")) else {
        bail!("the peer identity {} names no id and hash", path.display());
    };
    Ok(Identity { id, user_hash })
}

/// Write one peer's target file in a single `write`, so the driver's own gate
/// never reads a half-arrived file.
fn write_target(path: &Path, target: &Identity) -> Result<()> {
    fs::write(
        path,
        format!("id={}\nuser_hash={}\n", target.id, target.user_hash),
    )
    .with_context(|| format!("write {}", path.display()))
}

/// Wait for a detached driver container to exit, so its row is complete before
/// it is read. `docker wait` blocks on the container's own state; the driver
/// bounds its own window, so there is nothing here to time out against that the
/// driver has not already decided.
pub(super) fn wait_for_container_exit(bench: &Bench, name: &str) -> Result<()> {
    run_checked(
        bench.docker.wait(name.to_owned()),
        "wait for the peer driver",
    )
    .map(drop)
}
