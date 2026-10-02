//! What the punch topology counts off its pcaps, and what its gateways'
//! conntrack tables say about the same exchange.
//!
//! Two kinds of measurement live here because they answer one question from two
//! sides: the **Wire Rows** are what crossed a named attachment, and the
//! conntrack parse is what the kernel recorded about the mappings those
//! datagrams opened. A negative row needs both — ADR-0045 makes "no tunnel
//! rose" evidence only beside the outbound mapping that proves a punch was
//! fired at all.

use std::collections::BTreeMap;
use std::fs;

use anyhow::{Context, Result};

use crate::flow::bench::Bench;
use crate::flow::nat::natt::bench::WireRowRequest;
use crate::flow::taps::PerAttachmentTaps;
use crate::flow::wire_filter::{OP_EDONKEYPROT, WireFilter};

use super::Peer;

/// Which one attachment a **Wire Row** is counted on.
///
/// Scoping is not tidiness. Every gateway's WAN tap sits on the *same* bridge,
/// so a datagram peer A sends to peer B is recorded twice — leaving A's
/// gateway and arriving at B's — and a row summed over both taps reports
/// roughly double what was sent. Measured in run `1790033093`: 39 `0xA1`
/// "from a" against 23 the same burst put on A's own LAN. A row that is meant
/// to answer "what left this gateway" therefore names one attachment, and a
/// filter that attachment never matches is a measured zero.
#[derive(Clone, Copy)]
pub(in crate::flow::nat::natt) enum RowScope {
    /// The coordinator's own attachment.
    Server,
    /// One peer's gateway, by index into `peers`, and which side of it.
    Gateway {
        peer: usize,
        attachment: &'static str,
    },
}

/// One **Wire Row** and the attachment it is counted on.
pub(in crate::flow::nat::natt) struct ScopedRow {
    pub(in crate::flow::nat::natt) request: WireRowRequest,
    pub(in crate::flow::nat::natt) scope: RowScope,
}

/// Count each declared **Wire Row** on the one attachment that answers its
/// question.
pub(in crate::flow::nat::natt) fn count_wire(
    bench: &Bench,
    server: &PerAttachmentTaps,
    gateways: &[PerAttachmentTaps],
    declared: Vec<ScopedRow>,
) -> Result<Vec<crate::flow::nat::natt::verdict::WireRow>> {
    declared
        .into_iter()
        .map(|scoped| {
            let (taps, attachment) = match scoped.scope {
                RowScope::Server => (server, "server"),
                RowScope::Gateway { peer, attachment } => (&gateways[peer], attachment),
            };
            let packets = taps
                .rows(&bench.docker, &scoped.request.bpf)?
                .into_iter()
                .filter(|row| row.attachment == attachment)
                .map(|row| row.packets)
                .sum();
            Ok(crate::flow::nat::natt::verdict::WireRow {
                name: scoped.request.name,
                bpf: scoped.request.bpf.to_string(),
                packets,
            })
        })
        .collect()
}

/// Lift one peer driver's whole output into its own directory.
pub(in crate::flow::nat::natt) fn collect_driver_log(bench: &Bench, peer: &Peer) -> Result<()> {
    let output = bench
        .docker
        .logs(peer.driver.clone())
        .to_command()
        .output()
        .with_context(|| format!("docker logs {}", peer.driver))?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    let path = peer.dir.join("driver.log");
    fs::write(&path, &text).with_context(|| format!("write {}", path.display()))
}

/// The **Wire Rows** this topology cuts, each on the one attachment that
/// answers its question.
///
/// The `0x60` and `0x61` ride the eD2k **session**, so they are eD2k frames
/// counted off the reassembled server link — a frame need not open its
/// segment. The `0x9F` keepalive and the `0xA1` punch are datagrams.
pub(super) fn wire_rows(server_v4: &str, peers: &[Peer]) -> Vec<ScopedRow> {
    let server_row = |name: &str, bpf: WireFilter| ScopedRow {
        request: WireRowRequest {
            name: name.to_owned(),
            bpf,
        },
        scope: RowScope::Server,
    };
    let mut rows = vec![
        server_row(
            "holepunch-request-in",
            WireFilter::ed2k(format!("dst host {server_v4}"), &[OP_EDONKEYPROT], 0x60),
        ),
        server_row(
            "holepunch-info-out",
            WireFilter::ed2k(format!("src host {server_v4}"), &[OP_EDONKEYPROT], 0x61),
        ),
        server_row(
            "holepunch-fail-out",
            WireFilter::ed2k(format!("src host {server_v4}"), &[OP_EDONKEYPROT], 0x62),
        ),
        server_row(
            "natt-keepalive-in",
            format!("udp and dst host {server_v4} and udp[8] = 0xe3 and udp[9] = 0x9f").into(),
        ),
    ];
    for (index, peer) in peers.iter().enumerate() {
        let mut gateway_row = |name: String, bpf: String, attachment: &'static str| {
            rows.push(ScopedRow {
                request: WireRowRequest {
                    name,
                    bpf: bpf.into(),
                },
                scope: RowScope::Gateway {
                    peer: index,
                    attachment,
                },
            });
        };
        // Post-translation, on this peer's own gateway: what actually left.
        gateway_row(
            format!("holepunch-datagrams-from-{}", peer.name),
            format!(
                "udp and src host {} and udp[8] = 0xc5 and udp[9] = 0xa1",
                peer.gateway_wan
            ),
            "wan",
        );
        gateway_row(
            format!("natt-transport-from-{}", peer.name),
            format!("udp and src host {} and udp[8] = 0xb2", peer.gateway_wan),
            "wan",
        );
        gateway_row(
            format!("natt-transport-data-from-{}", peer.name),
            format!(
                "udp and src host {} and udp[8] = 0xb2 and udp[9] = 0x00",
                peer.gateway_wan
            ),
            "wan",
        );
        gateway_row(
            format!("natt-transport-to-{}", peer.name),
            format!("udp and dst host {} and udp[8] = 0xb2", peer.gateway_wan),
            "wan",
        );
        // Pre-translation, on the same gateway's LAN side: what the node fired
        // and what reached it. A row cut on a WAN address cannot match here and
        // vice versa, so each pair is two measurements of one exchange and the
        // difference between them is the gateway's behaviour. Run
        // `1790028867`'s decisive artifact was exactly this and was captured,
        // never read.
        gateway_row(
            format!("holepunch-lan-out-from-{}", peer.name),
            format!(
                "udp and src host {} and udp[8] = 0xc5 and udp[9] = 0xa1",
                peer.lan.client
            ),
            "lan",
        );
        gateway_row(
            format!("natt-transport-lan-out-{}", peer.name),
            format!("udp and src host {} and udp[8] = 0xb2", peer.lan.client),
            "lan",
        );
        gateway_row(
            format!("natt-transport-lan-in-{}", peer.name),
            format!("udp and dst host {} and udp[8] = 0xb2", peer.lan.client),
            "lan",
        );
        gateway_row(
            format!("natt-transport-lan-data-in-{}", peer.name),
            format!(
                "udp and dst host {} and udp[8] = 0xb2 and udp[9] = 0x00",
                peer.lan.client
            ),
            "lan",
        );
    }
    rows
}

/// What one gateway's own `conntrack -L` dump says about the punch's outbound
/// half: the mappings that left the client's pinned port toward the *other*
/// peer's gateway, and how many of them never saw a packet back.
///
/// Parsed rather than eyeballed because ADR-0045 makes this one of the four
/// things a punch-failure row must carry, and a claim that merely cited the
/// file would be satisfied by an empty one. A `conntrack` line reads
/// `udp 17 179 src=… dst=… sport=… dport=… [UNREPLIED] src=… …`, and only the
/// **original** tuple — the fields before the reply tuple restarts at `src=` —
/// describes what the client sent.
///
/// The dump holds `conntrack -L` and then `conntrack -L -p udp`, so every UDP
/// flow is listed twice. A mapping is therefore counted once per original
/// tuple, and `[UNREPLIED]` read off its first listing.
pub(in crate::flow::nat::natt) fn count_punch_mappings(
    text: &str,
    lan_client: &str,
    peer_gateway: &str,
    pinned: u16,
) -> (usize, usize) {
    let mut mappings: BTreeMap<Vec<&str>, bool> = BTreeMap::new();
    for line in text.lines() {
        if !line.trim_start().starts_with("udp") {
            continue;
        }
        let original: Vec<&str> = line.split_whitespace().skip(3).take(4).collect();
        let has = |key: &str, value: &str| {
            original
                .iter()
                .any(|field| *field == format!("{key}={value}"))
        };
        if has("src", lan_client) && has("dst", peer_gateway) && has("sport", &pinned.to_string()) {
            mappings
                .entry(original)
                .or_insert_with(|| line.contains("[UNREPLIED]"));
        }
    }
    let unreplied = mappings.values().filter(|unreplied| **unreplied).count();
    (mappings.len(), unreplied)
}

#[cfg(test)]
mod tests {
    use super::count_punch_mappings;

    /// `natgw-proof.sh`'s layout: the full listing, then the UDP-only one, so
    /// each flow appears twice. Two mappings are two, not four.
    #[test]
    fn a_mapping_listed_in_both_dumps_is_counted_once() {
        let flow = |dport: u16, state: &str| {
            format!(
                "udp      17 170 src=10.77.0.3 dst=198.18.0.3 sport=4672 dport={dport} {state}\
                 src=198.18.0.3 dst=198.18.0.2 sport={dport} dport=4672 mark=0 use=1\n"
            )
        };
        let listing = format!("{}{}", flow(4672, "[UNREPLIED] "), flow(4673, ""));
        let dump = format!(
            "# conntrack -L\n{listing}\n# conntrack -L -p udp\n{listing}\n# conntrack -S\n"
        );
        assert_eq!(
            count_punch_mappings(&dump, "10.77.0.3", "198.18.0.3", 4672),
            (2, 1)
        );
    }
}
