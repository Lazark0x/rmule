//! What the buddy rendezvous counts off its pcaps.
//!
//! Three attachments carry the exchange and each answers a different question,
//! so every row names exactly one of them (the lesson of run `1790033093`: two
//! gateway WAN taps sit on the same bridge, and a row summed over both reports
//! roughly double what was sent).
//!
//! - The **buddy's own attachment** is where the counterparty half of this
//!   topology lives: the `0x51` recruit arriving from the target's gateway, the
//!   `0x5A` going back, the buddy link's TCP SYN, the requester's `0x94`, the
//!   `0x9A` relayed onto the held link and the `0xAA` hint. It is also what
//!   makes the self-proof a measurement — a `0x51` counted on *this* body's
//!   wire, sourced at the target's gateway, is the recruit landing on the
//!   intended buddy.
//! - Each gateway's **WAN** side is what actually left after translation.
//! - Each gateway's **LAN** side is what the node fired and what reached it.
//!   Read, not merely captured.

use anyhow::Result;

use crate::flow::bench::Bench;
use crate::flow::nat::natt::bench::WireRowRequest;
use crate::flow::nat::natt::punch::Peer;
use crate::flow::nat::natt::verdict::WireRow;
use crate::flow::taps::PerAttachmentTaps;
use crate::flow::wire_filter::{OP_EDONKEYPROT, OP_EMULEPROT, WireFilter};

/// Which one attachment a row is counted on.
#[derive(Clone, Copy)]
pub(super) enum Scope {
    /// The buddy's own attachment.
    Buddy,
    /// One gatewayed peer's own gateway, by index, and which side of it.
    Gateway {
        peer: usize,
        attachment: &'static str,
    },
}

/// One row and the attachment that answers its question.
pub(super) struct ScopedRow {
    request: WireRowRequest,
    scope: Scope,
}

/// Count each declared row on the one attachment that answers its question.
///
/// # Errors
/// If a tap cannot be read back.
pub(super) fn count(
    bench: &Bench,
    buddy: &PerAttachmentTaps,
    gateways: &[PerAttachmentTaps],
    declared: Vec<ScopedRow>,
) -> Result<Vec<WireRow>> {
    declared
        .into_iter()
        .map(|scoped| {
            let (taps, attachment) = match scoped.scope {
                Scope::Buddy => (buddy, BUDDY_ATTACHMENT),
                Scope::Gateway { peer, attachment } => (&gateways[peer], attachment),
            };
            let packets = taps
                .rows(&bench.docker, &scoped.request.bpf)?
                .into_iter()
                .filter(|row| row.attachment == attachment)
                .map(|row| row.packets)
                .sum();
            Ok(WireRow {
                name: scoped.request.name,
                bpf: scoped.request.bpf.to_string(),
                packets,
            })
        })
        .collect()
}

/// The buddy tap's attachment name — the one evidence attachment in this
/// topology.
pub(super) const BUDDY_ATTACHMENT: &str = "buddy";

/// The eMule client-UDP protocol byte, as a BPF operand.
const UDP_EMULEPROT: &str = "0xc5";

/// The rows this topology cuts.
pub(super) fn rows(buddy_v4: &str, peer_tcp_port: u16, peers: &[Peer]) -> Vec<ScopedRow> {
    let buddy_row = |name: &str, bpf: WireFilter| ScopedRow {
        request: WireRowRequest {
            name: name.to_owned(),
            bpf,
        },
        scope: Scope::Buddy,
    };
    // A peer-TCP opcode is read off the link's reassembled eD2k frames: a
    // frame need not open its segment.
    //
    // **Either protocol byte, and that is measured rather than assumed.** The
    // relayed `0x9A` is an eMule extension, so the buddy frames it
    // `c5 40 00 00 00 9a …` — run `1790068463` counted zero against an
    // `0xE3`-only filter while the segment was on the pcap, 69 bytes long,
    // carrying the requester's injected endpoint. A row that asked for one
    // byte would keep reporting a relay that happened as a relay that did not.
    let tcp_opcode = |direction: &str, host: &str, opcode: u8| {
        WireFilter::ed2k(
            format!("{direction} host {host}"),
            &[OP_EDONKEYPROT, OP_EMULEPROT],
            opcode,
        )
    };
    let udp_opcode = |direction: &str, host: &str, proto: &str, opcode: &str| {
        WireFilter::from(format!(
            "udp and {direction} host {host} and udp[8] = {proto} and udp[9] = {opcode}"
        ))
    };

    let mut rows = vec![
        // The self-proof's two halves, on the buddy's own wire.
        buddy_row(
            "findbuddy-recruit-in",
            udp_opcode("dst", buddy_v4, "0xe4", "0x51"),
        ),
        buddy_row(
            "findbuddy-accept-out",
            udp_opcode("src", buddy_v4, "0xe4", "0x5a"),
        ),
        buddy_row(
            "buddy-link-syn-in",
            format!(
                "tcp and dst host {buddy_v4} and dst port {peer_tcp_port} \
                 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack = 0"
            )
            .into(),
        ),
        // The rendezvous half.
        buddy_row(
            "rendezvous-in",
            udp_opcode("dst", buddy_v4, UDP_EMULEPROT, "0x94"),
        ),
        buddy_row(
            "relayed-reask-callback-out",
            tcp_opcode("src", buddy_v4, 0x9a),
        ),
        buddy_row(
            "endpoint-hint-out",
            udp_opcode("src", buddy_v4, UDP_EMULEPROT, "0xaa"),
        ),
        // The coordinator this flow did NOT use, counted so its zero is
        // stated rather than assumed: no eD2k server stands on this WAN, so a
        // `0x60` anywhere would mean the row measured the server rung.
        buddy_row(
            "server-holepunch-request-anywhere",
            WireFilter::ed2k("ip or ip6", &[OP_EDONKEYPROT], 0x60),
        ),
    ];
    for (index, peer) in peers.iter().enumerate() {
        let mut gateway_row = |name: String, bpf: WireFilter, attachment: &'static str| {
            rows.push(ScopedRow {
                request: WireRowRequest { name, bpf },
                scope: Scope::Gateway {
                    peer: index,
                    attachment,
                },
            });
        };
        let wan = peer.gateway_wan.clone();
        let lan = peer.lan.client;
        gateway_row(
            format!("rendezvous-from-{}", peer.name),
            udp_opcode("src", &wan, UDP_EMULEPROT, "0x94"),
            "wan",
        );
        gateway_row(
            format!("endpoint-hint-to-{}", peer.name),
            udp_opcode("dst", &wan, UDP_EMULEPROT, "0xaa"),
            "wan",
        );
        gateway_row(
            format!("holepunch-from-{}", peer.name),
            udp_opcode("src", &wan, UDP_EMULEPROT, "0xa1"),
            "wan",
        );
        gateway_row(
            format!("natt-transport-from-{}", peer.name),
            format!("udp and src host {wan} and udp[8] = 0xb2").into(),
            "wan",
        );
        gateway_row(
            format!("natt-transport-to-{}", peer.name),
            format!("udp and dst host {wan} and udp[8] = 0xb2").into(),
            "wan",
        );
        gateway_row(
            format!("findbuddy-recruit-from-{}", peer.name),
            udp_opcode("src", &wan, "0xe4", "0x51"),
            "wan",
        );
        // Pre-translation: what the node itself fired and what reached it.
        gateway_row(
            format!("holepunch-lan-out-from-{}", peer.name),
            udp_opcode("src", lan, UDP_EMULEPROT, "0xa1"),
            "lan",
        );
        // The other side's burst reaching this node: behind an
        // endpoint-independent filter it can land inside the requester's
        // ½-RTT hold, which the Tunnel it dials into then cancels.
        gateway_row(
            format!("holepunch-lan-in-{}", peer.name),
            udp_opcode("dst", lan, UDP_EMULEPROT, "0xa1"),
            "lan",
        );
        gateway_row(
            format!("endpoint-hint-lan-in-{}", peer.name),
            udp_opcode("dst", lan, UDP_EMULEPROT, "0xaa"),
            "lan",
        );
        gateway_row(
            format!("natt-transport-lan-out-{}", peer.name),
            format!("udp and src host {lan} and udp[8] = 0xb2").into(),
            "lan",
        );
        gateway_row(
            format!("natt-transport-lan-in-{}", peer.name),
            format!("udp and dst host {lan} and udp[8] = 0xb2").into(),
            "lan",
        );
    }
    rows
}
