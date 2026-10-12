//! What the legs of this binary share and no second crate wants: the capture
//! reader, the Kad wire opcode bytes the capture legs assert against, the node
//! a join leg starts cold, and the two captured identities that appear on both
//! sides of a recorded exchange.
//!
//! Anything a second crate would want lives in `rmule-testkit` instead — the
//! node vocabulary (`kad_node`), the mesh labels (`kad_mesh`), and the source
//! and keyword fixtures (`kad_source`, `kad_keyword`) are all there.

use rmule_kad::KadInstant;
use rmule_kad::KadNodeStart;
use std::net::Ipv4Addr;
use std::time::Duration;

use rmule_kad::{Kad2Message, Kad2NodeInfo, KadId, KadNode, KadNodeConfig, KadNodeEndpoint};

// ---- recorded bytes ---------------------------------------------------------

/// One datagram of a capture, by the capture's directory (relative to `tests/`)
/// and the file inside it.
pub fn captured(dir: &str, name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(dir)
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
}

/// The little-endian `u16` at the head of `bytes` — every port, count and tag
/// width on the Kad wire is written this way.
pub fn le_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

// ---- wire bytes the capture legs assert against -----------------------------

/// `OP_KADEMLIAHEADER` — the packet protocol byte every Kad datagram carries.
pub const KAD_PROTO: u8 = 0xE4;
/// `OP_EDONKEYPROT` — the peer-TCP protocol byte a buddy link's hello carries.
pub const ED2K_PROTO: u8 = 0xE3;
/// `OP_HELLO` on the peer-TCP link.
pub const OP_HELLO: u8 = 0x01;
/// `KADEMLIA2_HELLO_RES`.
pub const OP_HELLO_RES: u8 = 0x19;
/// `KADEMLIA_FIREWALLED2_REQ` — the v7+ TCP firewall self-check.
pub const OP_FIREWALLED2_REQ: u8 = 0x53;
/// `KADEMLIA_FIREWALLED_RES` — the observed-IP reply to it.
pub const OP_FIREWALLED_RES: u8 = 0x58;
/// `KADEMLIA_FINDBUDDY_REQ`.
pub const OP_FINDBUDDY_REQ: u8 = 0x51;
/// `KADEMLIA_FINDBUDDY_RES`.
pub const OP_FINDBUDDY_RES: u8 = 0x5A;

/// The counterparty aMule's eD2k TCP port in every fake-public swarm capture
/// (the harness pins it to the default).
pub const AMULE_TCP_PORT: u16 = 4662;

// ---- identities that appear on both sides of a capture ----------------------

/// The keyword rmule published and then searched for in the fake-public swarm.
pub const KEYWORD: &str = "rmulekadkeyword";

/// The Kad ID of the file rmule published under [`KEYWORD`] — what the
/// counterparty indexed and handed back.
pub const PUBLISHED_FILE_ID: [u8; 16] = [
    0xB5, 0x2D, 0x30, 0x8E, 0x5C, 0xA2, 0x06, 0xB8, 0x23, 0xFC, 0x85, 0x93, 0xD2, 0x62, 0x10, 0xF2,
];

// ---- a node joining the network ---------------------------------------------

/// The Kad ID a joining node runs with.
pub const OWN_ID: [u8; 16] = [0x0F; 16];

/// The start both joining fixtures build their node from.
fn join_start() -> KadNodeStart {
    KadNodeStart::new(
        KadNodeConfig {
            id: KadId::from_bytes(OWN_ID),
            tcp_port: 4662,
            udp_port: 4672,
            user_hash: rmule_kad::UserHash::from_bytes([0xEE; 16]),
        },
        KadInstant::EPOCH,
    )
}

/// A cold node: no contacts, nothing outstanding, ready to be told to join.
pub fn join_node() -> KadNode {
    KadNode::new(join_start())
}

/// A [`join_node`] already running its forced self-lookup schedule from the
/// epoch.
pub fn joining_node() -> KadNode {
    KadNode::new(join_start().self_lookup())
}

/// A candidate's endpoint, by last octet, on the default Kad UDP port.
pub fn ep(last_octet: u8) -> KadNodeEndpoint {
    KadNodeEndpoint::new(Ipv4Addr::new(203, 0, 113, last_octet), 4672)
}

/// The bytes of a `BOOTSTRAP_REQ` — the payload-free datagram a dial is.
pub fn bootstrap_req_bytes() -> Vec<u8> {
    Kad2Message::BootstrapReq.encode().encode()
}

/// The `BOOTSTRAP_REQ` destinations among a node's drained datagrams — a dial is
/// the only thing that emits one, so this is exactly "who did the node dial".
pub fn dial_destinations(datagrams: &[(KadNodeEndpoint, Vec<u8>)]) -> Vec<KadNodeEndpoint> {
    let req = bootstrap_req_bytes();
    datagrams
        .iter()
        .filter(|(_, bytes)| *bytes == req)
        .map(|(to, _)| *to)
        .collect()
}

/// The bytes of a `BOOTSTRAP_RES` naming `sender_id`, with no hearsay rows —
/// what a dialed bootstrap answer looks like on the wire.
pub fn bootstrap_res_bytes(sender_id: [u8; 16]) -> Vec<u8> {
    Kad2Message::BootstrapRes {
        sender: Kad2NodeInfo {
            id: KadId::from_bytes(sender_id),
            tcp_port: 4662,
            version: 8,
            udp_port_tag: None,
            misc_options: 0,
        },
        contacts: Vec::new(),
    }
    .encode()
    .encode()
}

// ---- the clock the timer legs step ------------------------------------------

/// One second of the explicit-time clock.
pub const SECOND: Duration = Duration::from_secs(1);
/// The routing table's refresh period.
pub const TWENTY_MIN: Duration = Duration::from_secs(20 * 60);

// ---- nodes.dat rows ---------------------------------------------------------

/// A contact's address, by last octet — TEST-NET, so nothing here reads as LAN.
pub fn ip(byte: u8) -> Ipv4Addr {
    Ipv4Addr::new(203, 0, 113, byte)
}
