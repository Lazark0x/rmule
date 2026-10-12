//! The `natt-buddy-recruit-amule` topology: rmule's **Firewalled Front**
//! against a stock aMule 2.3.3 buddy — the firewalled half of ADR-0061 run
//! by a Core rmule, the open half by aMule.
//!
//! Every other buddy flow has rmule on the open side (flow M: stock aMule
//! recruits rmule) or rmule on both (`natt-buddy-rendezvous-*`). Here a
//! firewalled Core rmule walks to aMule, adopts its `0x5A`, dials it, holds the
//! link, pings it, and acts on the `OP_CALLBACK` aMule relays over it.
//!
//! # The open aMule
//!
//! aMule answers a `0x51` only while it reads itself open on both verdicts
//! and verified (`KademliaUDPListener.cpp:1430`), which no lone aMule on the
//! fake-public WAN can. So the WAN gives it what a home user's would:
//!
//! - **two open rmule Cores in its routing zone** — the root and a witness,
//!   the two contacts the one-`/24` bin quota admits (`RoutingBin.cpp:89`) —
//!   whose dial-back brokers answer its `KADEMLIA_FIREWALLED2_REQ` with
//!   `OP_KAD_FWTCPCHECK_ACK`, the two acks `CPrefs::GetFirewalled` needs
//!   (`Prefs.cpp:161`);
//! - **two fresh rmule UDP Firewall Helpers** only the root knows — the
//!   `natt-udp-selfcheck-amule` recipe, which read aMule's UDP verdict open in
//!   runs `1790147257` and `1790148195`.
//!
//! aMule's own log is the readiness gate: `Connected to Kad (ok)` and its UDP
//! verdict line, before the target starts.
//!
//! # The firewalled target
//!
//! A Core rmule behind a `port-restricted` gateway, logged in to an
//! `ed2ksrv` whose High-ID back-connect the gateway drops — a server Low ID
//! and a Kad-firewalled node, the posture a home user behind a NAT has. The
//! Low ID is load-bearing: an open aMule keeps a buddy only while its hello
//! reads Low (`ClientList.cpp:706-712`), and a hello naming no id is read as
//! the dialer's address (`BaseClient.cpp:678`). It is seeded with aMule alone,
//! at `~targetKadID`, so its FINDBUDDY walk converges on aMule at distance
//! zero, and it shares the **Synthetic File**, whose hash the callback names.
//!
//! # Without a server
//!
//! `--no-server` stands no `ed2ksrv`: the target is firewalled on Kad alone.
//! An aMule there presents `1` (`GetID`, `amule.cpp:2051-2053`), a Low ID an
//! open aMule keeps as a buddy, and the posture claim reads that id off every
//! `OP_HELLO` the target sent aMule's eD2k port, on aMule's own tap.
//!
//! # The callback
//!
//! Once the target reads `Held`, a `kad join-node` walker runs one **Callback
//! Walk** toward aMule's Kad ID — `~targetKadID`, the `TAG_BUDDYHASH` an
//! ID-only row of the target's would carry — so its `0x52` lands on aMule,
//! which relays `OP_CALLBACK` over whatever `GetBuddy()` names
//! (`KademliaUDPListener.cpp:1489-1518`). The target's dial-back leaves its
//! gateway toward the walker's port, where nothing listens: the SYN on the
//! gateway's WAN is the act, recorded rather than answered.
//!
//! Every counterparty statement is on aMule's own attachment (a **Capture
//! Sidecar** in its netns): the `0x5A`, the hello answer, the `OP_BUDDYPONG`
//! (aMule pongs only `GetBuddy()`, `ClientTCPSocket.cpp:1669-1673`), and the
//! relayed `0x99`.

mod bodies;
mod claims;
mod wire;

use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Result;

use self::bodies::{
    Addresses, bodies, run_walker, start_amule, start_target, start_witness, write_amule_seed,
};
use self::claims::{AmuleLog, Gates, Posture, TargetRow, claims};
use super::selfcheck::amule::UDP_OPEN_LINE;
use super::selfcheck::amule::evidence::{amule_logfile, amule_status, wait_for_log_line};
use super::selfcheck::{HOST_HELPERS, start_helper};
use super::{
    BUDDY_TIMEOUT_SECS, HOST_BUDDY, READY_TIMEOUT_SECS, collect_buddy_log, mesh, start_buddy,
};
use crate::docker::InternalNetwork;
use crate::fake_public::{subnet_cidr, subnet_host_address};
use crate::flow::bench::{Bench, run_checked};
use crate::flow::gate::wait_for_container_log;
use crate::flow::nat::claims::DriverRow;
use crate::flow::nat::natt::WAN_SUBNET_INDEX;
use crate::flow::nat::natt::bench::{Driven, NattOptions};
use crate::flow::nat::natt::punch::proof::{probe_peer_lan, run_reflector};
use crate::flow::nat::natt::punch::wire::collect_driver_log;
use crate::flow::nat::natt::punch::{
    ED2KSRV_TCP_PORT, HOST_GATEWAY_B, HOST_PROBE_PRIMARY, HOST_PROBE_SECONDARY, LAN_B, Peer,
    start_gateway, start_server, wait_for_container_exit,
};
use crate::flow::nat::natt::verdict::WireRow;
use crate::flow::taps::{Attachment, PerAttachmentTaps, TapRole, TapRow};
use crate::nat::NatType;

/// The WAN plan. The root, the gateway, the reflector and the helpers keep
/// the host indices every NAT-T row gives them; the server takes the slot
/// the second gateway would, and aMule, the witness and the walker follow.
/// Seven of these bodies are Kad nodes, inside the `/24`'s Kad bound.
const HOST_SERVER: usize = 1;
const HOST_AMULE: usize = 7;
const HOST_WITNESS: usize = 8;
const HOST_WALKER: usize = 9;

/// The target's Kad ID, and aMule's — its complement, the walk's target
/// (`~ourKadID`), so the walk converges on aMule at distance zero. The
/// complement commutes with any byte permutation, so the pairing holds in
/// whichever word order each side writes a 128-bit ID; the ID itself is
/// asymmetric so that a word-order slip in the `0x5A`'s echoed buddy ID or the
/// `0x99`'s check field cannot pass unnoticed. Far from the root's `0xEE…`,
/// the witness's `0x22…` and the helpers' `0x66…`/`0x99…`, so no rmule body
/// sits nearer the walk's target than aMule does.
const TARGET_KAD_ID: [u8; 16] = [
    0x31, 0x41, 0x59, 0x26, 0x53, 0x58, 0x97, 0x93, 0x23, 0x84, 0x62, 0x64, 0x33, 0x83, 0x27, 0x95,
];
const AMULE_KAD_ID: [u8; 16] = complement(TARGET_KAD_ID);

/// The target's user hash, asymmetric for the same reason: aMule records the
/// hash a `0x51` carries, word-swapped on the Kad wire, as the accepted
/// client's (`ClientList.cpp:926-928`) until the hello overwrites it, so the
/// `0x51` on aMule's tap shows which order rmule wrote — a palindromic hash
/// reads the same either way.
const HASH_TARGET: &str = "8e302db5b806a25c9385fc23f21062d2";
/// The witness — aMule's second routing-zone contact and second TCP firewall
/// tester — and the walker, both far from aMule's key.
const WITNESS_KAD_ID: [u8; 16] = [0x22; 16];
const WALKER_KAD_ID: [u8; 16] = [0x5A; 16];

/// Fixed user hashes, so a hello and a verdict name the same bodies.
const HASH_AMULE: &str = "4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c";
const HASH_WITNESS: &str = "47474747474747474747474747474747";

/// The Kad version the seeded contacts are written with; each body's own
/// `HELLO` overwrites it.
const SEED_CONTACT_VERSION: u8 = 8;

/// The port the walker's `0x52` names. Nothing listens there: the target's
/// dial-back SYN is the act the flow records.
const WALKER_TCP_PORT: u16 = 4662;
/// How long the walker lives; its walk ends in under 24 s even in silence.
const WALKER_RUN_SECS: u64 = 150;

/// The Synthetic File's size. It only has to be shared — the callback's
/// file-known gate reads its hash — so it is small.
const SHARED_FILE_BYTES: u64 = 1 << 20;

/// How long aMule is given to read itself open on both verdicts. Its UDP
/// tester times out firewalled at six minutes (`UDPFirewallTester.cpp:62`), so
/// a run whose helpers never answer ends on aMule's own line, not on ours.
const AMULE_OPEN_TIMEOUT_SECS: u64 = 420;

/// How long the target holds once its buddy is held: two keepalive intervals
/// (`BUDDY_PING_INTERVAL`, ten minutes, aMule's own cadence) and room for the
/// pong and the diagnostics snapshot after the second. Two, because aMule
/// answers no ping inside thirteen minutes of the stamp it sets ten minutes
/// ahead when it creates the client (`BaseClient.cpp:278`,
/// `updownclient.h:488-489`): the first ping, ten minutes in, is dropped
/// unanswered, as it is between two aMules, and the second is the first that
/// earns an `OP_BUDDYPONG` (run `1791800356`: one ping, no pong).
const HOLD_WINDOW_SECS: u64 = 2 * 600 + 180;

/// How long the WAN bodies live: aMule's gate, the recruit and its gate's
/// slack, the hold, and ten minutes for the bench to stand up around them
/// and harvest after — the root and the witness are aMule's routing zone for
/// the whole run.
const RUN_SECS: u64 = AMULE_OPEN_TIMEOUT_SECS + BUDDY_TIMEOUT_SECS + 60 + HOLD_WINDOW_SECS + 600;

/// aMule's line for a Kad TCP verdict read open (`amule.cpp:1915`).
const AMULE_TCP_OPEN_LINE: &str = "Connected to Kad (ok)";

/// Every bit of `id` flipped — `~id`, the FINDBUDDY walk's target.
const fn complement(id: [u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut index = 0;
    while index < 16 {
        out[index] = !id[index];
        index += 1;
    }
    out
}

/// Stand the topology up, drive it, and hand back the claims.
///
/// # Errors
/// If the bench cannot be built or a body never reports ready. **A recruit
/// aMule refuses, a link it drops or a relay it never sends is not an error**
/// — those are the claims.
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
    let address = |host: usize| subnet_host_address(WAN_SUBNET_INDEX, host);
    let timeout = Duration::from_secs(options.timeout_secs);
    anyhow::ensure!(
        !options.kad_crypt,
        "natt-buddy-recruit-amule counts plaintext Kad rows off aMule's tap; run it without \
         --kad-crypt"
    );

    // The server first: the target logs in to it, and nothing else does.
    // Without one, its address names no body, and the target's `--server`
    // (the endpoint a download would name) is never dialed.
    let server_v4 = address(HOST_SERVER)?;
    let server = if options.no_server {
        None
    } else {
        Some(start_server(
            bench, options, suffix, &wan, &server_v4, leg_dir, timeout,
        )?)
    };

    // The open half of aMule's world: the root, the witness, the helpers.
    let root_v4 = address(HOST_BUDDY)?;
    let root_dir = leg_dir.join("root");
    fs::create_dir_all(&root_dir)?;
    let root = start_buddy(
        bench, options, suffix, &wan, &root_v4, &root_dir, RUN_SECS, None,
    )?;
    let witness_v4 = address(HOST_WITNESS)?;
    let witness_dir = leg_dir.join("witness");
    fs::create_dir_all(&witness_dir)?;
    let witness = start_witness(
        bench,
        options,
        suffix,
        &wan,
        &witness_v4,
        &witness_dir,
        &root_v4,
    )?;
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
    std::thread::sleep(mesh::MESH_SETTLE);

    // aMule, on the WAN itself, with its tap attached long before the target
    // exists.
    let amule_v4 = address(HOST_AMULE)?;
    let amule_dir = leg_dir.join("amule");
    let seed_dir = amule_dir.join("seed");
    fs::create_dir_all(&seed_dir)?;
    write_amule_seed(&seed_dir, &root_v4, &witness_v4)?;
    let amule = format!("rmule-interop-nattamule-{suffix}");
    start_amule(bench, options, &amule, &wan, &amule_v4, &seed_dir)?;
    let amule_taps = PerAttachmentTaps::start(
        bench,
        options.capture_image,
        &amule,
        &format!("rmule-interop-nattamuletap-{suffix}"),
        &amule_dir,
        &[Attachment {
            name: wire::WAN,
            interface: "eth0",
            role: TapRole::Evidence,
            bpf: "ip",
        }],
        timeout,
    )?;
    wait_for_container_log(&bench.docker, &amule, "rmule-kad-routing-ready", timeout)?;
    // The **Readiness Gate**: aMule's own two verdict lines. The target is
    // started either way — a walk aMule refuses is a measurement too — but
    // the claims read which gate stayed shut.
    // One budget for both lines, so a gate that never opens costs it once.
    let open_by = Instant::now() + Duration::from_secs(AMULE_OPEN_TIMEOUT_SECS);
    // At least one read each, so a line already written is never missed.
    let left = || {
        open_by
            .saturating_duration_since(Instant::now())
            .max(Duration::from_secs(5))
    };
    let amule_tcp_open = wait_for_log_line(bench, &amule, &[AMULE_TCP_OPEN_LINE], left());
    let amule_udp_open = wait_for_log_line(bench, &amule, &[UDP_OPEN_LINE], left());
    println!("natt buddy-recruit-amule: aMule tcp {amule_tcp_open:?}, udp {amule_udp_open:?}");

    // The target behind its gateway, with the NAT Type Proof taken first.
    let target_dir = leg_dir.join("target");
    fs::create_dir_all(&target_dir)?;
    let shared = crate::flow::nat::synthetic::write_hashed(&target_dir, SHARED_FILE_BYTES)?;
    let target = Peer {
        name: "target",
        lan: &LAN_B,
        network: format!("rmule-interop-nattlanb-{suffix}"),
        gateway: format!("rmule-interop-nattgwb-{suffix}"),
        gateway_wan: address(HOST_GATEWAY_B)?,
        driver: format!("rmule-interop-nattpeerb-{suffix}"),
        dir: target_dir.clone(),
        user_hash: HASH_TARGET,
    };
    start_gateway(bench, options, &target, &wan, nat_type, timeout)?;
    let gateway_taps = PerAttachmentTaps::start(
        bench,
        options.capture_image,
        &target.gateway,
        &format!("rmule-interop-nattgwtap-{}-{suffix}", target.name),
        &target.dir,
        &[
            Attachment {
                name: wire::WAN,
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
    let reflector = (address(HOST_PROBE_PRIMARY)?, address(HOST_PROBE_SECONDARY)?);
    run_reflector(
        bench,
        options,
        &wan,
        &reflector.0,
        &reflector.1,
        suffix,
        timeout,
    )?;
    let proof = probe_peer_lan(
        bench,
        options,
        &target,
        nat_type,
        (&reflector.0, &reflector.1),
    )?;
    start_target(
        bench,
        options,
        &target,
        &format!("{server_v4}:{ED2KSRV_TCP_PORT}"),
        &amule_v4,
        server.is_some(),
    )?;
    wait_for_container_log(
        &bench.docker,
        &target.driver,
        "rmule-natt-buddy-ready",
        Duration::from_secs(READY_TIMEOUT_SECS),
    )?;

    // The second gate: the target's own slot reading `Held`. Only then is
    // there a link for aMule to relay a callback over.
    let held = wait_for_container_log(
        &bench.docker,
        &target.driver,
        "rmule-natt-buddy-held",
        Duration::from_secs(BUDDY_TIMEOUT_SECS + 60),
    );
    let walked = match &held {
        Ok(line) => {
            println!("natt buddy-recruit-amule: {}", line.trim());
            run_walker(
                bench,
                options,
                suffix,
                &wan,
                &address(HOST_WALKER)?,
                &amule_v4,
                &shared.file_hash,
                leg_dir,
            )?
        }
        Err(error) => {
            eprintln!(
                "natt buddy-recruit-amule: the target never held a buddy ({error}); no \
                 callback is walked and the row records how far the recruit got"
            );
            false
        }
    };

    // The keepalive window runs out on the target's own clock.
    wait_for_container_exit(bench, &target.driver)?;

    // **Taps before teardown**, as every NAT-T row reads them.
    let walker_v4 = address(HOST_WALKER)?;
    let hosts = wire::Hosts {
        amule: &amule_v4,
        gateway: &target.gateway_wan,
        walker: &walker_v4,
    };
    let wire = wire::count(bench, &amule_taps, &gateway_taps, &hosts)?;
    let posture = if options.no_server {
        Posture::Serverless {
            hello_ids: wire::target_hello_ids(bench, &amule_taps, &hosts, &amule_dir)?,
        }
    } else {
        Posture::ServerLowId
    };
    let taps = amule_taps.rows(&bench.docker, "ip")?;
    let log = amule_logfile(bench, &amule);
    let status = amule_status(bench, &amule);
    fs::write(amule_dir.join("amule-logfile.log"), &log)?;
    fs::write(amule_dir.join("amule-status.txt"), &status)?;
    run_checked(
        bench.docker.exec(
            target.gateway.clone(),
            [
                OsString::from("natgw-proof"),
                OsString::from("/proof"),
                OsString::from(nat_type.knob()),
            ],
        ),
        "take the NAT gateway self-proof",
    )?;
    collect_driver_log(bench, &target)?;
    collect_buddy_log(bench, &root, &root_dir)?;
    collect_buddy_log(bench, &witness, &witness_dir)?;
    if let Some(server) = &server {
        let server_dir = leg_dir.join("ed2ksrv");
        fs::create_dir_all(&server_dir)?;
        collect_buddy_log(bench, server, &server_dir)?;
    }
    for (name, _, dir) in &helpers {
        collect_buddy_log(bench, name, dir)?;
    }

    let row = DriverRow::read(&target_dir.join("buddy-rendezvous.toml"))?;
    let claims = claims(
        &proof,
        &posture,
        &AmuleLog::read(&log, amule_tcp_open, amule_udp_open),
        &TargetRow::read(&row),
        &Gates {
            held: held.is_ok(),
            walked,
        },
        &wire,
        &target.gateway_wan,
    );
    Ok((
        Driven {
            claims,
            bodies: bodies(
                options,
                &Addresses {
                    amule: &amule_v4,
                    gateway_wan: &target.gateway_wan,
                    root: &root_v4,
                    witness: &witness_v4,
                    server: server.is_some().then_some(server_v4.as_str()),
                },
                &helpers,
            ),
            wire: Vec::new(),
            note: format!(
                "Stock aMule 2.3.3 (debug build) open on the fake-public WAN at {amule_v4}, its \
                 routing zone seeded with two open rmule Cores and its UDP verdict left to two \
                 fresh rmule helpers; the firewalled Core rmule behind a {} gateway at {}, {}, \
                 sharing the Synthetic File {}. The callback is one Callback Walk from \
                 {walker_v4} toward aMule's Kad ID.",
                nat_type.knob(),
                target.gateway_wan,
                if server.is_some() {
                    format!("logged in to an ed2ksrv at {server_v4} for a Low ID")
                } else {
                    "with no server on the WAN (firewalled on Kad alone)".to_owned()
                },
                shared.file_hash,
            ),
            tunnel_rose: None,
        },
        wire,
        taps,
    ))
}
