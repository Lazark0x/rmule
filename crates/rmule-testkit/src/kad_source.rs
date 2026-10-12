//! The shared vocabulary of the Kad source publish/store tests: the file key
//! every suite publishes, the storer and publisher endpoints it talks to, and
//! the datagram builders and readers that drive one publish or search leg.

use rmule_kad::KadInstant;
use rmule_kad::KadNodeStart;
use std::net::Ipv4Addr;

use rmule_kad::{
    Kad2Message, KadId, KadNode, KadNodeConfig, KadNodeEndpoint, KadPublishRequest,
    KadPublishedSource, decode_exact, decode_source_result,
};
use rmule_primitives::{FileHash, SourceLookupTarget, UserHash, kad_wire_id};

/// The published file key every storer test uses.
pub const FILE_KEY: [u8; 16] = [
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
];

/// The published file key every storer test uses.
pub fn key() -> KadId {
    KadId::from_bytes(FILE_KEY)
}

/// A storer whose own ID is far from every test key: LAN senders must pass
/// through the LAN bypass, WAN senders sit outside the tolerance gate.
pub fn far_storer() -> KadNode {
    KadNode::new(KadNodeStart::new(
        storer_config(KadId::from_bytes([0x0F; 16])),
        KadInstant::EPOCH,
    ))
}

/// A storer node's config at the default port pair, with only its ID — the
/// fact the tolerance gate turns on — left to the caller.
pub fn storer_config(id: KadId) -> KadNodeConfig {
    KadNodeConfig {
        id,
        tcp_port: 4662,
        udp_port: 4672,
        user_hash: UserHash::from_bytes([0xEE; 16]),
    }
}

/// A LAN publisher endpoint (RFC1918: bypasses the tolerance gate).
pub fn lan_publisher(d: u8) -> KadNodeEndpoint {
    KadNodeEndpoint::new(Ipv4Addr::new(10, 0, 0, d), 4_000 + u16::from(d))
}

/// The endpoint a source search arrives from and answers go back to.
pub fn searcher() -> KadNodeEndpoint {
    KadNodeEndpoint::new(Ipv4Addr::new(10, 9, 9, 9), 4_999)
}

/// The bytes of a `KADEMLIA2_PUBLISH_SOURCE_REQ` advertising `source` for
/// `file`, with every published field left to the caller.
pub fn publish_datagram(file: KadId, source_id: [u8; 16], source: KadPublishedSource) -> Vec<u8> {
    Kad2Message::PublishSourceReq {
        file,
        source_id,
        source,
    }
    .encode()
    .encode()
}

/// A publish of one complete, directly-reachable source for `file`, with
/// `marker` standing in for the source ID — the ordinary row a cap or
/// dedup test fills a store with.
pub fn direct_publish(file: KadId, marker: u8) -> Vec<u8> {
    publish_datagram(
        file,
        [marker; 16],
        KadPublishedSource {
            source_type: Some(1),
            tcp_port: Some(4662),
            udp_port_tag: Some(4700),
            file_size: Some(65_536),
            encryption: Some(0x0B),
            ..KadPublishedSource::default()
        },
    )
}

/// The bytes of a `KADEMLIA2_SEARCH_SOURCE_REQ`. `start_position` is the
/// paging cursor a searcher advances to walk past the first answer.
pub fn search_datagram(target: KadId, start_position: u16, file_size: u64) -> Vec<u8> {
    Kad2Message::SearchSourceReq {
        target,
        start_position,
        file_size,
    }
    .encode()
    .encode()
}

/// Decode every `0x3B` datagram sent to `to` into projected candidate rows.
pub fn rows_answered_to(
    datagrams: &[(KadNodeEndpoint, Vec<u8>)],
    to: KadNodeEndpoint,
) -> Vec<rmule_kad::KadSourceCandidate> {
    datagrams
        .iter()
        .filter(|(dest, _)| *dest == to)
        .flat_map(|(_, bytes)| {
            let rmule_kad::KadDecoded::Plain(envelope) =
                decode_exact(bytes).expect("storer answers are well-formed")
            else {
                panic!("storer answers are plain 0xE4");
            };
            assert_eq!(envelope.opcode(), 0x3B);
            decode_source_result(&envelope).expect("storer answers re-decode")
        })
        .collect()
}

// --- storer: publish acceptance ---------------------------------------------

/// A publish request whose walk target is exactly [`key`].
pub fn publish_request(file_size: u64) -> KadPublishRequest {
    // The request carries the FILE hash; the walk target is its word-swap.
    // Using the key's word-swap as the file hash makes the walk target equal
    // `key()` (the transform is self-inverse), so contacts near `key()` are
    // near the publish target.
    KadPublishRequest::new(SourceLookupTarget::new(
        FileHash::from_bytes(kad_wire_id(FILE_KEY)),
        file_size,
    ))
}

/// A routing-table contact's endpoint, in the documentation range.
pub fn contact_endpoint(d: u8) -> KadNodeEndpoint {
    KadNodeEndpoint::new(Ipv4Addr::new(203, 0, 113, d), 4_000 + u16::from(d))
}

/// An ID a short XOR distance from [`key`] — a contact the publish walk must
/// consider close enough to store at.
pub fn id_near_key(d: u8) -> KadId {
    let mut bytes = FILE_KEY;
    bytes[12] ^= d;
    KadId::from_bytes(bytes)
}
