//! The stock-aMule **Kad helpers** `portmap-highid` stands on the fake-public
//! WAN, and the evidence their answers leave behind.
//!
//! ADR-0092's fourth `portmap-highid` assertion — the Kad verdict flips open
//! because the mapping made the node reachable — cannot be driven by rmule
//! alone. The ≥2-ack rule (ADR-0058) counts *connect-backs*, and a connect-back
//! is by definition somebody else dialing the mapped port. So the flow needs
//! counterparties that will run the responder half honestly, and it needs
//! **two** of them: each helper answers one check, so one helper can prove at
//! most one leg.
//!
//! They sit on the **WAN**, which is the whole point. A helper on the LAN would
//! reach rmule's listener directly and prove nothing about the mapping; from the
//! WAN the only path to rmule's eD2k port is the redirect the gateway installed,
//! so a landed ack is a statement about the port mapping and not about Docker.
//!
//! What they contribute is **evidence** in the ADR-0045 sense — aMule's own
//! datagrams and its own connect-back, read off the gateway's WAN tap. rmule's
//! row says what rmule concluded; these bytes say what the counterparty did.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::docker::{Docker, RunContainer};
use crate::flow::bench::{Bench, run_checked};
use crate::flow::evidence::count_pcap_rows;
use crate::flow::gate::wait_for_container_log;
use crate::flow::wire_filter::{OP_EMULEPROT, WireFilter};

/// Each helper's eD2k TCP port. Never dialed by this flow — a helper is asked to
/// dial *us* — but aMule wants one bound.
const HELPER_TCP_PORT: u16 = 4662;

/// Each helper's Kad UDP port: the datagram source rmule's `0x53` goes back to,
/// and the port its seeded contact row names.
const HELPER_UDP_PORT: u16 = 4672;

/// The aMule readiness line a `kad-node` routing seed prints once its Kad is up.
const HELPER_READY: &str = "rmule-kad-routing-ready";

/// One planned helper: the address and identity the harness fixes *before* it
/// starts anything, so rmule can be handed the contact row rather than having to
/// discover it. Deterministic on purpose — the bootstrap dial loop stops at the
/// first answer (ADR-0067), so a discovered swarm could only ever deliver one
/// helper, and one helper cannot satisfy a two-ack rule.
pub(crate) struct KadHelper {
    /// The container name.
    pub(crate) container: String,
    /// Its fake-public WAN address.
    pub(crate) ip: String,
    /// Its seeded Kad ID.
    pub(crate) kad_id: [u8; 16],
}

impl KadHelper {
    /// The `--kad-contact` operand rmule merges into its routing table.
    pub(crate) fn contact_arg(&self) -> String {
        format!(
            "{}:{HELPER_UDP_PORT}:{HELPER_TCP_PORT}:{}",
            self.ip,
            hex_lower(&self.kad_id)
        )
    }
}

/// Start `count` stock-aMule Kad helpers on `network`, each at the address
/// `address(index)` yields, and hold until each reports its Kad is up.
///
/// # Errors
/// If a seed cannot be written, a container fails to start, or one never reports
/// ready — a helper that is not listening would make the whole claim read as a
/// documented absence for a bench reason rather than a protocol one.
pub(crate) fn start_helpers(
    bench: &mut Bench,
    amule_image: &str,
    suffix: &str,
    network: &str,
    seed_root: &Path,
    addresses: &[String],
    timeout: std::time::Duration,
) -> Result<Vec<KadHelper>> {
    let mut helpers = Vec::with_capacity(addresses.len());
    for (index, ip) in addresses.iter().enumerate() {
        let container = format!("rmule-interop-pmkad{index}-{suffix}");
        let kad_id = helper_kad_id(index);
        let seed_dir = seed_root.join(format!("kad-helper-{index}"));
        fs::create_dir_all(&seed_dir).with_context(|| format!("create {}", seed_dir.display()))?;
        fs::write(
            seed_dir.join("preferencesKad.dat"),
            crate::kad_seed::build_preferences_kad_dat(kad_id),
        )
        .context("write the helper's Kad identity seed")?;

        bench.start_extra(
            &container,
            RunContainer::new(amule_image)
                .detach()
                .name(&container)
                .network(network)
                .ip(ip)
                .volume(seed_dir, "/seed")
                .env("AMULE_SCENARIO_MODE", "kad-node")
                .env("AMULE_KAD_ROLE", "routing")
                .env("AMULE_TCP_PORT", HELPER_TCP_PORT.to_string())
                .env("AMULE_UDP_PORT", HELPER_UDP_PORT.to_string())
                .env("AMULE_KAD_PREFS_DAT", "/seed/preferencesKad.dat")
                // The WAN is a fake-public `/24`, so aMule must stay on its
                // ordinary non-LAN paths: LAN mode short-circuits the very
                // firewall machinery this flow is measuring.
                .env("AMULE_KAD_FILTER_LAN_IPS", "1")
                // The responder's own account of what it did
                // (`OP_KAD_FWTCPCHECK_ACK to <ip>`), collected beside the pcap.
                .env("AMULE_KAD_VERBOSE", "1"),
            "run a stock-aMule Kad helper",
        )?;
        wait_for_container_log(&bench.docker, &container, HELPER_READY, timeout)?;
        helpers.push(KadHelper {
            container,
            ip: ip.clone(),
            kad_id,
        });
    }
    Ok(helpers)
}

/// Collect each helper's own aMule logfile into `leg_dir`.
///
/// Best effort: a helper whose log cannot be read still leaves its bytes on the
/// WAN tap, which is the evidence a verdict rests on.
pub(crate) fn collect_logs(bench: &Bench, helpers: &[KadHelper], leg_dir: &Path) {
    for (index, helper) in helpers.iter().enumerate() {
        let script = "cat /root/.aMule/logfile 2>/dev/null || true";
        let Ok(text) = run_checked(
            bench.docker.exec(
                helper.container.clone(),
                [
                    std::ffi::OsString::from("sh"),
                    std::ffi::OsString::from("-c"),
                    std::ffi::OsString::from(script),
                ],
            ),
            "read a Kad helper's own logfile",
        ) else {
            continue;
        };
        let _ = fs::write(leg_dir.join(format!("kad-helper-{index}.log")), text);
    }
}

/// What the counterparties actually did, counted off the gateway's **WAN** tap.
///
/// Every field is a count of aMule's or rmule's bytes *outside* the translation,
/// which is the only side a verdict may cite (`TapRole::Evidence`). The
/// `legacy_acks` row is a control, not a target: a `0x59` here would mean the
/// helper judged rmule a pre-v7 node and took the deprecated UDP ack path, so
/// the `OP_KAD_FWTCPCHECK_ACK` wiring was never exercised at all.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub(crate) struct KadHelperWire {
    /// `0x53 KADEMLIA_FIREWALLED2_REQ` datagrams rmule sent the helpers.
    pub(crate) checks_out: u64,
    /// `0x58 KADEMLIA_FIREWALLED_RES` datagrams the helpers answered with.
    pub(crate) responses_in: u64,
    /// TCP connect-backs the helpers opened toward the mapped eD2k port.
    pub(crate) connect_backs: u64,
    /// `OP_KAD_FWTCPCHECK_ACK` (`0xA8`) packets delivered on those links.
    pub(crate) tcp_acks: u64,
    /// Legacy `0x59` UDP acks — the control; expected zero.
    pub(crate) legacy_acks: u64,
}

/// Count the firewall-check exchange on the WAN tap.
///
/// `wan_tap` is the tap sidecar's container (tcpdump reads the pcap from inside
/// it, the one place the file and a reader share a namespace) and `wan_address`
/// is the gateway's own WAN address — which is where the world reaches rmule,
/// so it is both the source the helpers saw the checks come from and the
/// destination they dialed back to.
///
/// # Errors
/// If a count fails; a rejected filter must surface rather than silently read as
/// "the counterparty did nothing".
pub(crate) fn count_wire(
    docker: &Docker,
    wan_tap: &str,
    pcap: &str,
    wan_address: &str,
    tcp_port: u16,
) -> Result<KadHelperWire> {
    let count = |filter: WireFilter| count_pcap_rows(docker, wan_tap, pcap, filter);
    Ok(KadHelperWire {
        checks_out: count(
            format!("udp and src host {wan_address} and udp[8] = 0xe4 and udp[9] = 0x53").into(),
        )?,
        responses_in: count(
            format!("udp and dst host {wan_address} and udp[8] = 0xe4 and udp[9] = 0x58").into(),
        )?,
        // A connect-back is the SYN that opens the link, counted without its
        // ACK so a retransmit-free handshake reads as one dial.
        connect_backs: count(
            format!(
                "tcp and dst host {wan_address} and dst port {tcp_port} \
             and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack = 0"
            )
            .into(),
        )?,
        // `[0xC5 emule-protocol][u32 size][0xA8 opcode]`, wherever it sits in
        // the reassembled link.
        tcp_acks: count(WireFilter::ed2k(
            format!("dst host {wan_address} and dst port {tcp_port}"),
            &[OP_EMULEPROT],
            0xa8,
        ))?,
        legacy_acks: count(
            format!("udp and dst host {wan_address} and udp[8] = 0xe4 and udp[9] = 0x59").into(),
        )?,
    })
}

/// A distinct, non-secret Kad ID per helper. The high byte keeps them out of
/// each other's neighbourhood and the low byte separates them; nothing here
/// needs to rendezvous with a target, unlike the publish/search meshes.
fn helper_kad_id(index: usize) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[0] = 0xF0;
    id[15] = u8::try_from(index).unwrap_or(0);
    id
}

/// Lowercase hex, the spelling `--kad-contact` and `parse_hex16` share.
fn hex_lower(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The fake-public WAN address of helper `index`, taken from the same host
/// numbering the rest of the bench draws from.
///
/// # Errors
/// If the host index falls outside the fake-public plan.
pub(crate) fn helper_address(base_host: usize, index: usize) -> Result<String> {
    Ok(crate::fake_public::fake_public_address(base_host + index)?.ip)
}
