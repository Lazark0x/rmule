//! The **Pinned-Pair Reach** leg: a second gateway of the same `NAT_TYPE`, with
//! a client of its own, and the two clients aiming the pinned port at each
//! other's WAN address.
//!
//! The RFC 5780 **Reflector Probe** beside it cannot ask this. Its sixth test
//! addresses a **Pinned-Port Sink** on the reflector — an *untranslated* host —
//! so it proves the LAN reaches the WAN on that port and stops there. A punch
//! aims the pinned port at a host that is itself behind a gateway pinning the
//! same port, and that arrangement has a failure mode of its own: the far
//! gateway accepts our unsolicited opener locally, conntrack commits an entry
//! whose original tuple is `us:4672 -> them:4672`, and the mapping their own
//! client then needs collides with it. `restricted` and `full-cone-pinned` drop
//! the datagram outright (`insert_failed`); `port-restricted` silently remaps
//! off the pinned port and loses the Endpoint-Independent Mapping it exists to
//! provide. That defect was invisible to every leg before this one.
//!
//! **The stagger is the measurement.** The `first` client sends while the
//! second is still silent — the unsolicited opener is what poisons — and only
//! then does the second start. Two clients bursting at once would reproduce the
//! collision on a coin flip.
//!
//! Expected to cross on `port-restricted`, `restricted` and
//! `full-cone-pinned`, and **not** on `symmetric`, whose mapping is a fresh
//! random port per destination and therefore is not at the pinned port the far
//! side addresses. The three positives are proven in the same run and before
//! it, in `NatType::ALL` order, so the negative is never the only thing this
//! leg has measured.

use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::bench_doctor::CONNTRACK_UDP_TIMEOUT_SECS;
use crate::docker::RunContainer;
use crate::flow::bench::{Bench, run_checked};
use crate::flow::gate::wait_for_container_log;
use crate::flow::nat::{
    NAT_CLIENT_UDP_PORT, NAT_LAN_CLIENT, NAT_LAN_GATEWAY, NAT_PEER_LAN_CLIENT, NAT_PEER_LAN_GATEWAY,
};
use crate::flow::taps::{Attachment, PerAttachmentTaps, TapRole, TapRow};
use crate::nat::NatType;

/// The peer gateway's tap filter. All UDP, as the first gateway's is: the leg's
/// traffic is UDP and nothing else crosses these bridges.
const TAP_FILTER: &str = "udp";

/// How long the `second` client holds before its first send. It absorbs the two
/// containers' start skew as well as the stagger the leg needs.
const LEAD_MS: u64 = 4000;

/// How long each client sends and listens. Long enough that the `first` client
/// is still sending well after the `second` has opened its own mapping —
/// otherwise a gateway with Address-Dependent Filtering would read as broken
/// for having done exactly what it claims.
const WINDOW_MS: u64 = 12_000;

/// The two sides' directories under the leg dir. The first client's row lands
/// beside the first gateway's own proof; the peer gateway gets a mirror of that
/// directory, so its ruleset, conntrack dump and two pcaps are retained exactly
/// as the first's are.
const PEER_DIR: &str = "peer";

/// What the leg is given: the first gateway is already up, and everything the
/// second one needs to be stood up beside it.
pub(super) struct PairPlan<'a> {
    /// The run-dir directory of this `NAT_TYPE`'s leg.
    pub(super) leg_dir: &'a Path,
    /// The suffix every container name in this run carries.
    pub(super) suffix: &'a str,
    /// The fake-public WAN both gateways attach to.
    pub(super) wan_network: &'a str,
    /// The first gateway's LAN, which the `first` client joins.
    pub(super) lan_network: &'a str,
    /// The second gateway's LAN. Made once for the whole run, because the
    /// subnet is fixed and a per-leg bridge would overlap the last leg's.
    pub(super) peer_lan_network: &'a str,
    /// The first gateway's WAN address — what the peer client aims at.
    pub(super) gateway_wan: &'a str,
    /// The peer gateway's WAN address — what the first client aims at.
    pub(super) peer_gateway_wan: &'a str,
    /// The type both gateways build.
    pub(super) nat_type: NatType,
    /// Per-step readiness budget.
    pub(super) timeout: Duration,
}

/// One side's row, as its driver wrote it.
#[derive(Debug, Deserialize)]
struct ReachRow {
    sent: u32,
    received: u32,
    reached: bool,
    first_received_after_ms: i64,
}

/// The leg's verdict for one gateway type.
#[derive(Debug, Serialize)]
pub(super) struct PinnedPairProof {
    /// The peer gateway's WAN address, so the row names both ends.
    pub(super) peer_wan: String,
    /// The pinned port both gateways translate and both clients address.
    pub(super) pinned_port: u16,
    /// Datagrams the `first` client sent, and how many of the peer's it heard.
    pub(super) first_sent: u32,
    pub(super) first_received: u32,
    /// The same for the `second` client, which held its lead before sending.
    pub(super) second_sent: u32,
    pub(super) second_received: u32,
    /// When the `second` client first heard the `first`, in milliseconds from
    /// its own start, or `-1` for never. Under Endpoint-Independent Filtering
    /// this is well under the lead — the opener arrived before the second side
    /// had sent anything at all — and under Address-Dependent Filtering it is
    /// after it. The two behaviours are visible in this one number.
    pub(super) second_first_received_after_ms: i64,
    /// Whether datagrams crossed in **both** directions. One-way is not a
    /// crossing: a punch needs both mappings.
    pub(super) crossed: bool,
    /// Whether this type is supposed to cross at all. `symmetric` is not, and
    /// its `crossed = false` is the leg's negative rather than a failure.
    pub(super) expected_to_cross: bool,
    /// Whether the two agree — the field the flow's verdict reads.
    pub(super) as_expected: bool,
    /// The peer gateway's own dumps, named relative to the leg dir.
    pub(super) peer_ruleset_file: String,
    pub(super) peer_conntrack_file: String,
    /// The peer gateway's taps.
    pub(super) peer_tap: Vec<TapRow>,
}

/// Stand the second gateway up, run both clients at each other, and judge.
///
/// # Errors
/// If the peer gateway cannot be started or a client's row cannot be read. A
/// crossing that does not happen is **not** an error — on `symmetric` it is the
/// expected outcome, and on any other type it is a finding about the bench that
/// the row states.
pub(super) fn prove(
    bench: &mut Bench,
    options: &super::NatGatewaySelfProofOptions<'_>,
    plan: &PairPlan<'_>,
) -> Result<PinnedPairProof> {
    let peer_dir = plan.leg_dir.join(PEER_DIR);
    fs::create_dir_all(&peer_dir).with_context(|| format!("create {}", peer_dir.display()))?;

    let knob = plan.nat_type.knob();
    let peer_gateway = format!("rmule-interop-natpeergw-{}-{}", knob, plan.suffix);
    start_peer_gateway(bench, options, plan, &peer_gateway, &peer_dir)?;

    let tap_prefix = format!("rmule-interop-natpeertap-{}-{}", knob, plan.suffix);
    let taps = PerAttachmentTaps::start(
        bench,
        options.capture_image,
        &peer_gateway,
        &tap_prefix,
        &peer_dir,
        &[
            Attachment {
                name: "wan",
                interface: "eth0",
                role: TapRole::Evidence,
                bpf: TAP_FILTER,
            },
            Attachment {
                name: "lan",
                interface: "eth1",
                role: TapRole::Corroboration,
                bpf: TAP_FILTER,
            },
        ],
        plan.timeout,
    )?;

    // The `second` client is started first and holds its lead, so the ordering
    // the leg depends on survives the two `docker run`s taking different
    // amounts of time.
    let second = start_client(
        bench,
        options,
        ClientPlan {
            name: format!("rmule-interop-natpeerb-{}-{}", knob, plan.suffix),
            network: plan.peer_lan_network,
            address: NAT_PEER_LAN_CLIENT,
            route_via: NAT_PEER_LAN_GATEWAY,
            dir: &peer_dir,
            peer: plan.gateway_wan,
            role: "second",
        },
    )?;
    let first = start_client(
        bench,
        options,
        ClientPlan {
            name: format!("rmule-interop-natpeera-{}-{}", knob, plan.suffix),
            network: plan.lan_network,
            address: NAT_LAN_CLIENT,
            route_via: NAT_LAN_GATEWAY,
            dir: plan.leg_dir,
            peer: plan.peer_gateway_wan,
            role: "first",
        },
    )?;
    for client in [&first, &second] {
        run_checked(
            bench.docker.wait(client.clone()),
            "wait for a pinned-pair client",
        )?;
    }
    collect_log(bench, &first, &plan.leg_dir.join("peer-reach.log"))?;
    collect_log(bench, &second, &peer_dir.join("peer-reach.log"))?;

    // The peer gateway's dump is taken while its own mappings are still live —
    // the leg's conntrack evidence is the pair's mappings, and on a broken
    // gateway the `insert_failed` counter beside them is the whole diagnosis.
    run_checked(
        bench.docker.exec(
            peer_gateway.clone(),
            [
                OsString::from("natgw-proof"),
                OsString::from("/proof"),
                OsString::from(knob),
            ],
        ),
        "take the peer NAT gateway self-proof",
    )?;
    let tap_rows = taps.rows(&bench.docker, TAP_FILTER)?;

    let first_row = read_row(&plan.leg_dir.join("peer-reach.toml"))?;
    let second_row = read_row(&peer_dir.join("peer-reach.toml"))?;

    for attachment in ["wan", "lan"] {
        bench.stop_extra(&format!("{tap_prefix}-{attachment}"));
    }
    for client in [&first, &second] {
        bench.stop_extra(client);
    }
    bench.stop_extra(&peer_gateway);

    let crossed = first_row.reached && second_row.reached;
    let expected_to_cross = plan.nat_type != NatType::Symmetric;
    let proof = PinnedPairProof {
        peer_wan: plan.peer_gateway_wan.to_owned(),
        pinned_port: NAT_CLIENT_UDP_PORT,
        first_sent: first_row.sent,
        first_received: first_row.received,
        second_sent: second_row.sent,
        second_received: second_row.received,
        second_first_received_after_ms: second_row.first_received_after_ms,
        crossed,
        expected_to_cross,
        as_expected: as_expected(expected_to_cross, crossed, first_row.sent, second_row.sent),
        peer_ruleset_file: format!("{PEER_DIR}/nft-ruleset.txt"),
        peer_conntrack_file: format!("{PEER_DIR}/conntrack.txt"),
        peer_tap: tap_rows,
    };
    println!(
        "natgw-selfproof pinned-pair leg={knob} first={}/{} second={}/{} crossed={} expected={} \
         second_heard_at_ms={}",
        proof.first_received,
        proof.first_sent,
        proof.second_received,
        proof.second_sent,
        proof.crossed,
        proof.expected_to_cross,
        proof.second_first_received_after_ms,
    );
    Ok(proof)
}

/// Whether a pair behaved as its type demands. A crossing type must cross.
/// `symmetric`'s negative is a silence only when both clients actually sent:
/// two clients that sent nothing never crossed either, and that is a leg that
/// did not run, not the gateway refusing a punch.
fn as_expected(expected_to_cross: bool, crossed: bool, first_sent: u32, second_sent: u32) -> bool {
    if expected_to_cross {
        crossed
    } else {
        !crossed && first_sent > 0 && second_sent > 0
    }
}

fn start_peer_gateway(
    bench: &mut Bench,
    options: &super::NatGatewaySelfProofOptions<'_>,
    plan: &PairPlan<'_>,
    gateway: &str,
    peer_dir: &Path,
) -> Result<()> {
    bench.start_extra(
        gateway,
        RunContainer::new(options.natgw_image)
            .detach()
            .name(gateway)
            .network(plan.wan_network)
            .ip(plan.peer_gateway_wan)
            .cap_add("NET_ADMIN")
            .sysctl("net.ipv4.ip_forward", "1")
            .sysctl("net.ipv6.conf.all.forwarding", "1")
            .sysctl(
                "net.netfilter.nf_conntrack_udp_timeout",
                CONNTRACK_UDP_TIMEOUT_SECS.to_string(),
            )
            .volume(peer_dir, "/proof")
            .env("NAT_TYPE", plan.nat_type.knob())
            .env("NAT_LAN_CLIENT", NAT_PEER_LAN_CLIENT)
            .env("NAT_CLIENT_PORT", NAT_CLIENT_UDP_PORT.to_string()),
        "run the peer NAT gateway",
    )?;
    run_checked(
        bench.docker.connect_network(
            plan.peer_lan_network.to_owned(),
            gateway.to_owned(),
            Some(OsString::from(NAT_PEER_LAN_GATEWAY)),
            None,
        ),
        "attach the peer NAT gateway to its LAN",
    )?;
    wait_for_container_log(&bench.docker, gateway, "rmule-natgw-ready", plan.timeout).map(drop)
}

/// One client's placement: which LAN it sits on and whose WAN it addresses.
struct ClientPlan<'a> {
    name: String,
    network: &'a str,
    address: &'a str,
    route_via: &'a str,
    dir: &'a Path,
    peer: &'a str,
    role: &'a str,
}

fn start_client(
    bench: &mut Bench,
    options: &super::NatGatewaySelfProofOptions<'_>,
    plan: ClientPlan<'_>,
) -> Result<String> {
    bench.start_extra(
        &plan.name,
        RunContainer::new(options.rmule_tools_image)
            .detach()
            .name(&plan.name)
            .network(plan.network)
            .ip(plan.address)
            .cap_add("NET_ADMIN")
            .volume(plan.dir, "/out")
            .env("RMULE_DEFAULT_ROUTE_VIA", plan.route_via)
            .arg("nat")
            .arg("peer-reach")
            .arg("--role")
            .arg(plan.role)
            .arg("--peer")
            .arg(plan.peer)
            .arg("--peer-port")
            .arg(NAT_CLIENT_UDP_PORT.to_string())
            .arg("--local-port")
            .arg(NAT_CLIENT_UDP_PORT.to_string())
            .arg("--lead-ms")
            .arg(LEAD_MS.to_string())
            .arg("--window-ms")
            .arg(WINDOW_MS.to_string())
            .arg("--out")
            .arg("/out/peer-reach.toml"),
        "run a pinned-pair client",
    )?;
    Ok(plan.name)
}

fn collect_log(bench: &Bench, container: &str, path: &Path) -> Result<()> {
    let output = bench
        .docker
        .logs(container.to_owned())
        .to_command()
        .output()
        .with_context(|| format!("docker logs {container}"))?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    fs::write(path, &text).with_context(|| format!("write {}", path.display()))
}

fn read_row(path: &Path) -> Result<ReachRow> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parse {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::as_expected;

    /// Symmetric's negative needs both clients to have sent: a silent pair
    /// is a leg that never ran, which `natgw-selfproof`'s `as_expected` count must refuse.
    #[test]
    fn a_symmetric_negative_needs_both_sides_to_have_sent() {
        assert!(as_expected(false, false, 20, 20));
        assert!(!as_expected(false, false, 0, 20));
        assert!(!as_expected(false, false, 20, 0));
        assert!(!as_expected(false, true, 20, 20));
    }

    #[test]
    fn a_crossing_type_must_cross() {
        assert!(as_expected(true, true, 20, 20));
        assert!(!as_expected(true, false, 20, 20));
    }
}
