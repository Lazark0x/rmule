//! **Port prediction** on the punch topology (ADR-0091's amendment):
//! the Kad observers that tell each peer its own mapping, the driver operands
//! that turn the knob on, and the claims that check one run's draw against the
//! artifacts rather than against luck.
//!
//! One run is one draw of a probabilistic pairing, so no single run is judged
//! by whether a Tunnel rose. A run is judged by whether the Tunnel agrees with
//! the two port sets it can read back:
//!
//! - **the Fan's mappings**, from the symmetric gateway's own `conntrack -L`:
//!   every mapping from the client's address to the other gateway whose source
//!   is *not* the pinned client port was opened by a Fan socket, and its reply
//!   tuple names the external port the gateway drew;
//! - **the ports the easy side punched**, from its gateway's LAN tap: every
//!   `0xA1` it sent from the pinned port toward the hard gateway, the baseline
//!   sweep and the Probe Sets together.
//!
//! A Tunnel must rise **exactly when** the two sets meet. Across runs the row
//! needs 4 of 10 to raise one: the harness has no repeat flag, so each verdict
//! carries `tunnel_rose` as its own field (the claim's note repeats it), and
//! the `natt-server-punch-one-symmetric` wrapper counts that field across ten runs.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::Result;

use crate::flow::bench::Bench;
use crate::flow::kad_member::{PlacedMember, hex, seed_operand};
use crate::flow::nat::claims::{Claim, DriverRow, Evidence, measured_total};
use crate::flow::nat::natt::bench::NattOptions;
use crate::flow::nat::natt::{BODY_CLIENT_UDP_PORT, BODY_PEER_TCP_PORT, NattFlow};

use super::Peer;

/// The observers' WAN host indices, clear of the punch topology's 0–4.
pub(super) const HOST_OBSERVERS: [usize; 3] = [5, 6, 7];

/// The observers' Kad IDs. Any three distinct IDs serve: they are pinged, not
/// walked toward.
const OBSERVER_KAD_IDS: [[u8; 16]; 3] = [[0x22; 16], [0x66; 16], [0xAA; 16]];

/// The two peers' Kad IDs, requester first.
const PEER_KAD_IDS: [[u8; 16]; 2] = [[0x41; 16], [0x42; 16]];

/// How long a peer's driver waits for its Own Mapping before it publishes its
/// identity. The Extern Port Round pings one observer every 15 s and needs
/// three, and Kad has to bootstrap first.
pub(super) const OWN_MAPPING_TIMEOUT_SECS: u64 = 150;

/// How long an observer runs: the login, the mapping gate and the window, with
/// room to spare.
const OBSERVER_RUN_SECS: u64 = 600;

/// The Fan's size and a Probe Set's (`rmule_peer::natt`'s N and M).
const PREDICTION_SOCKETS: usize = 256;

/// The baseline sweep's half-width around the nominal port.
const SWEEP: u16 = 16;

/// The observers as the flow stood them up.
pub(super) struct Observers {
    nodes: Vec<(String, String, String)>,
}

impl Observers {
    /// Stand three open Kad members on the WAN. The first bootstraps to
    /// nobody and the others to it.
    pub(super) fn start(
        bench: &mut Bench,
        options: &NattOptions<'_>,
        wan: &str,
        suffix: &str,
        addresses: [String; 3],
        leg_dir: &Path,
    ) -> Result<Self> {
        let mut nodes = Vec::new();
        for (index, (address, kad_id)) in addresses.iter().zip(OBSERVER_KAD_IDS).enumerate() {
            let kad_id = hex(&kad_id);
            let container = format!("rmule-interop-nattobs{index}-{suffix}");
            let dir = leg_dir.join(format!("observer-{index}"));
            std::fs::create_dir_all(&dir)?;
            let bootstrap = (index > 0).then(|| format!("{}:{BODY_CLIENT_UDP_PORT}", addresses[0]));
            bench.start_extra(
                &container,
                PlacedMember {
                    image: options.rmule_tools_image,
                    container: &container,
                    network: wan,
                    address_v4: address,
                    udp_port: BODY_CLIENT_UDP_PORT,
                    tcp_port: BODY_PEER_TCP_PORT,
                    kad_id: &kad_id,
                    bootstrap: bootstrap.as_deref(),
                    host_dir: &dir,
                    run_secs: OBSERVER_RUN_SECS,
                }
                .container_spec(),
                "run a Kad observer",
            )?;
            nodes.push((container, address.clone(), kad_id));
        }
        Ok(Self { nodes })
    }

    /// The operands that turn the knob on for peer `index` and seed it with
    /// every observer.
    pub(super) fn driver_args(&self, index: usize) -> Vec<String> {
        let mut args = vec![
            "--port-prediction".to_owned(),
            "birthday".to_owned(),
            "--kad-id".to_owned(),
            hex(&PEER_KAD_IDS[index]),
            "--own-mapping-timeout".to_owned(),
            OWN_MAPPING_TIMEOUT_SECS.to_string(),
        ];
        for (_, address, kad_id) in &self.nodes {
            args.push("--kad-contact".to_owned());
            args.push(seed_operand(kad_id, address, BODY_CLIENT_UDP_PORT));
        }
        args
    }

    /// Lift each observer's log beside its capture.
    pub(super) fn collect(&self, bench: &Bench, leg_dir: &Path) -> Result<()> {
        for (index, (container, ..)) in self.nodes.iter().enumerate() {
            let output = bench.docker.logs(container.clone()).to_command().output()?;
            let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&output.stderr));
            std::fs::write(
                leg_dir.join(format!("observer-{index}")).join("node.log"),
                text,
            )?;
        }
        Ok(())
    }
}

/// The BPF that lifts one peer's `0xA1` toward the other gateway off its LAN.
pub(super) fn punches_toward(peer: &Peer, other_gateway: &str) -> String {
    format!(
        "udp and src host {} and dst host {other_gateway} and udp[8] = 0xc5 and udp[9] = 0xa1",
        peer.lan.client
    )
}

/// The pcap each peer's lifted punches land in.
pub(super) const PUNCHES_PCAP: &str = "prediction-punches.pcap";

/// The external ports a gateway's `conntrack -L` shows Fan sockets were
/// mapped to: mappings from `lan_client` to `other_gateway` whose original
/// source port is not `pinned`, read off the reply tuple's destination port.
pub(super) fn fan_ports(
    conntrack: &str,
    lan_client: &str,
    other_gateway: &str,
    pinned: u16,
) -> BTreeSet<u16> {
    conntrack
        .lines()
        .filter(|line| line.trim_start().starts_with("udp"))
        .filter_map(|line| {
            let fields: Vec<(&str, &str)> = line
                .split_whitespace()
                .filter_map(|token| token.split_once('='))
                .collect();
            let value = |key: &str, nth: usize| {
                fields
                    .iter()
                    .filter(|(name, _)| *name == key)
                    .nth(nth)
                    .map(|(_, value)| *value)
            };
            let fanned = value("src", 0) == Some(lan_client)
                && value("dst", 0) == Some(other_gateway)
                && value("sport", 0).and_then(|port| port.parse::<u16>().ok()) != Some(pinned);
            fanned
                .then(|| value("dport", 1).and_then(|port| port.parse().ok()))
                .flatten()
        })
        .collect()
}

/// One side's pinned-port punches toward the other gateway, split into the
/// baseline sweep (the nominal port, which the burst hits six times, ± 16) and
/// everything else — which only a Probe sends.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct PinnedPunches {
    /// The ports inside the baseline sweep window.
    pub(super) window: BTreeSet<u16>,
    /// The ports outside it.
    pub(super) probes: BTreeSet<u16>,
}

impl PinnedPunches {
    /// Split the `(source, destination)` ports of one side's lifted punches.
    /// A Fan's datagrams leave from ephemeral ports and are not counted here.
    pub(super) fn from_ports(ports: &[(u16, u16)], pinned: u16) -> Self {
        let pinned: Vec<u16> = ports
            .iter()
            .filter(|(source, _)| *source == pinned)
            .map(|(_, destination)| *destination)
            .collect();
        let Some(nominal) = mode(&pinned) else {
            return Self::default();
        };
        let (window, probes) = pinned
            .into_iter()
            .partition(|port: &u16| port.abs_diff(nominal) <= SWEEP);
        Self { window, probes }
    }

    /// Every port this side punched on the other gateway.
    pub(super) fn all(&self) -> BTreeSet<u16> {
        self.window.union(&self.probes).copied().collect()
    }
}

/// The most frequent value, the lowest on a tie.
fn mode(values: &[u16]) -> Option<u16> {
    let mut counts = std::collections::BTreeMap::new();
    for value in values {
        *counts.entry(*value).or_insert(0_usize) += 1;
    }
    counts
        .into_iter()
        .max_by(|(a_port, a), (b_port, b)| a.cmp(b).then(b_port.cmp(a_port)))
        .map(|(port, _)| port)
}

/// What one run left behind, per peer, requester first.
pub(super) struct PredictionEvidence {
    /// The external ports each gateway mapped Fan sockets to.
    pub(super) fan_ports: [BTreeSet<u16>; 2],
    /// Each side's pinned-port punches toward the other gateway.
    pub(super) punches: [PinnedPunches; 2],
}

/// Whether this draw raised a Tunnel, from both driver rows; `None` when a
/// side never read its counters. The verdict carries it as its own field so
/// the `natt-server-punch-one-symmetric` wrapper's ten-run tally reads a value rather than a note.
pub(super) fn tunnel_rose(rows: &[DriverRow]) -> Option<bool> {
    let tunnels = measured_total(
        rows.iter()
            .flat_map(|row| [row.int("tunnels_dialed"), row.int("tunnels_accepted")]),
    );
    (tunnels >= 0).then_some(tunnels >= 1)
}

/// The prediction claims for `flow`: the one-symmetric row's draw, or the
/// both-symmetric row's "the knob changed nothing it must not".
pub(super) fn claims(
    flow: NattFlow,
    rows: &[DriverRow],
    evidence: &PredictionEvidence,
) -> Vec<Claim> {
    let mapping = |row: &DriverRow| row.text("own_mapping");
    // `-1` when either side never read its counters: one side's unread `-1`s
    // must not cancel the other's Tunnel into a zero.
    let tunnels = measured_total(
        rows.iter()
            .flat_map(|row| [row.int("tunnels_dialed"), row.int("tunnels_accepted")]),
    );
    if flow == NattFlow::ServerPunchSymmetric {
        return both_hard_claims(rows, evidence, tunnels);
    }
    let (hard, easy) = (&rows[0], &rows[1]);
    let fans = &evidence.fan_ports[0];
    let easy_punches = &evidence.punches[1];
    let met: BTreeSet<u16> = fans.intersection(&easy_punches.all()).copied().collect();
    let tunnel_rose = tunnels >= 1;
    let easy_attempts = easy.int("prediction_attempts");
    vec![
        Claim::about(
            "each-side-read-its-own-mapping-off-its-kad-observers",
            mapping(hard) == "endpoint-dependent" && mapping(easy) == "endpoint-independent",
            Evidence::RmuleOnly,
            format!(
                "requester (symmetric gateway) reads {:?}, responder (port-restricted) reads \
                 {:?}; the role follows from this alone",
                mapping(hard),
                mapping(easy)
            ),
        ),
        Claim::about(
            "the-symmetric-gateway-mapped-every-fan-socket",
            fans.len() >= PREDICTION_SOCKETS
                && i64::try_from(fans.len()).unwrap_or(i64::MAX) == hard.int("prediction_probes"),
            Evidence::RmuleOnly,
            format!(
                "{} distinct Fan mappings toward the responder's gateway in conntrack, against \
                 {} Fan datagrams over {} attempts in the requester's row",
                fans.len(),
                hard.int("prediction_probes"),
                hard.int("prediction_attempts"),
            ),
        ),
        Claim::about(
            "the-port-restricted-side-sent-its-probe-sets",
            easy_attempts >= 1
                && easy.int("prediction_probes") == 256 * easy_attempts
                && easy_punches.probes.len() + usize::from(2 * SWEEP + 1)
                    >= PREDICTION_SOCKETS * usize::try_from(easy_attempts).unwrap_or(0),
            Evidence::RmuleOnly,
            format!(
                "{} probes over {easy_attempts} attempts in the responder's row; its LAN tap \
                 shows {} distinct ports outside the baseline window and {} inside it (a \
                 Probe Set port can fall inside the window and merge with the sweep)",
                easy.int("prediction_probes"),
                easy_punches.probes.len(),
                easy_punches.window.len(),
            ),
        ),
        Claim::about(
            "a-tunnel-rose-exactly-when-the-port-sets-met",
            tunnel_rose != met.is_empty(),
            Evidence::RmuleOnly,
            format!(
                "{} Fan mappings ∩ {} punched ports = {:?}; {tunnels} tunnels; hits {} on the \
                 requester, {} on the responder. tunnel_rose={tunnel_rose}",
                fans.len(),
                easy_punches.all().len(),
                met,
                hard.int("prediction_hits"),
                easy.int("prediction_hits"),
            ),
        ),
    ]
}

/// `natt-server-punch-symmetric` run with the knob on: both sides read
/// endpoint-dependent, so each may Fan and neither may Probe. The negative
/// stays a negative and never becomes a port scan.
fn both_hard_claims(rows: &[DriverRow], evidence: &PredictionEvidence, tunnels: i64) -> Vec<Claim> {
    let dependent = rows
        .iter()
        .all(|row| row.text("own_mapping") == "endpoint-dependent");
    let probed: Vec<usize> = evidence
        .punches
        .iter()
        .map(|punches| punches.probes.len())
        .collect();
    vec![Claim::about(
        "the-knob-left-the-both-hard-pair-a-negative-and-no-scan",
        dependent && tunnels == 0 && probed.iter().all(|probes| *probes == 0),
        Evidence::RmuleOnly,
        format!(
            "own mappings {:?}/{:?}; {tunnels} tunnels; ports punched from the pinned port \
             outside the baseline window: {} and {}; Fan mappings {} and {}",
            rows[0].text("own_mapping"),
            rows[1].text("own_mapping"),
            probed[0],
            probed[1],
            evidence.fan_ports[0].len(),
            evidence.fan_ports[1].len(),
        ),
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `natt-server-punch-one-symmetric`'s tally reads this value from
    /// its own verdict field; a side that never read its counters is no
    /// draw at all, not a draw with no Tunnel.
    #[test]
    fn a_draw_s_tunnel_is_read_off_both_rows_or_not_at_all() {
        let row = |dialed: i64, accepted: i64| {
            crate::flow::nat::claims::DriverRow::parse(&format!(
                "tunnels_dialed = {dialed}\ntunnels_accepted = {accepted}\n"
            ))
            .expect("a hand-built row parses")
        };
        assert_eq!(super::tunnel_rose(&[row(1, 0), row(0, 1)]), Some(true));
        assert_eq!(super::tunnel_rose(&[row(0, 0), row(0, 0)]), Some(false));
        assert_eq!(super::tunnel_rose(&[row(-1, -1), row(1, 1)]), None);
    }

    /// The symmetric gateway's dump from `natt-server-punch-symmetric`'s own run, plus two Fan
    /// mappings: only the ones that left an ephemeral port count, and each is
    /// read off its reply tuple.
    #[test]
    fn a_fan_mapping_is_read_off_its_reply_tuple_and_the_pinned_port_is_not_one() {
        let dump = "\
udp      17 179 src=10.77.0.3 dst=45.55.200.4 sport=4672 dport=43871 [UNREPLIED] src=45.55.200.4 dst=45.55.200.3 sport=43871 dport=33682 mark=0 use=1
udp      17 177 src=10.77.0.3 dst=45.55.200.4 sport=51012 dport=4672 [UNREPLIED] src=45.55.200.4 dst=45.55.200.3 sport=4672 dport=12007 mark=0 use=1
udp      17 177 src=10.77.0.3 dst=45.55.200.4 sport=51013 dport=4672 src=45.55.200.4 dst=45.55.200.3 sport=4672 dport=60311 [ASSURED] mark=0 use=1
udp      17 170 src=10.77.0.3 dst=45.55.200.9 sport=51014 dport=4672 [UNREPLIED] src=45.55.200.9 dst=45.55.200.3 sport=4672 dport=2222 mark=0 use=1
";
        assert_eq!(
            fan_ports(dump, "10.77.0.3", "45.55.200.4", 4672),
            BTreeSet::from([12007, 60311])
        );
    }

    /// The nominal port is the one the burst hit six times; its ± 16 is the
    /// sweep, and every other pinned-port punch is a probe. A Fan's datagram,
    /// from an ephemeral port, is neither.
    #[test]
    fn pinned_punches_split_into_the_sweep_window_and_the_probes() {
        let mut ports: Vec<(u16, u16)> = std::iter::repeat_n((4672, 30_000), 6).collect();
        ports
            .extend((1..=16).flat_map(|offset| [(4672, 30_000 + offset), (4672, 30_000 - offset)]));
        ports.extend([(4672, 1_500), (4672, 61_000), (50_001, 9_999)]);
        let split = PinnedPunches::from_ports(&ports, 4672);
        assert_eq!(split.window.len(), 33);
        assert_eq!(split.probes, BTreeSet::from([1_500, 61_000]));
    }
}
