//! The type-6 source row, from the publisher's own bytes: a
//! TCP-firewalled stock aMule 2.3.3 whose UDP verdict read open on its intern
//! port, holding a Low-ID rmule as its buddy, publishing a file it had just
//! shared (interop flow `natt-udp-selfcheck-amule --low-id-buddy`, run
//! `1790155945`).
//!
//! ADR-0061's "row that needs no buddy" was pinned from source and captured
//! from rmule's publisher; this is the aMule-authored tier. The recipe
//! that got stock 2.3.3 past its buddy-only publish gate, and the log lines
//! each step left, are in `meta.toml` beside the frame.

const FIXTURE_DIR: &str = "fixtures/firewalled/captured/amule-233-publish-source-type6-20260923/";

use rmule_kad::{Kad2Message, KadPublishedSource};
use rmule_primitives::kad_wire_id;

use crate::fixture::{AMULE_TCP_PORT, KAD_PROTO};

/// `KADEMLIA2_PUBLISH_SOURCE_REQ`.
const OP_PUBLISH_SOURCE_REQ: u8 = 0x44;
/// aMule's intern Kad UDP port — the port its UDP verdict read open on.
const AMULE_KAD_UDP_PORT: u16 = 4672;
/// The Synthetic File's size.
const FILE_SIZE: u64 = 19_460_096;
/// The connect-options byte a crypt-less 2.3.3 states once UDP is verified
/// open while TCP is firewalled: bit 3, the direct UDP callback, alone.
const DIRECT_CALLBACK_ONLY: u8 = 0x08;
/// `TAG_SOURCEUPORT` as the publisher wrote it: `UINT16`, name `0xFC`, 4672.
const SOURCEUPORT_TAG: [u8; 6] = [0x08, 0x01, 0x00, 0xFC, 0x40, 0x12];
/// Where that tag starts: header (34) + count (1) + `SOURCETYPE` (5) +
/// `SOURCEPORT` (6).
const SOURCEUPORT_AT: usize = 46;

fn frame() -> Vec<u8> {
    crate::fixture::captured(FIXTURE_DIR, "publish_source_req_0x44.bin")
}

fn decoded() -> Kad2Message {
    let rmule_kad::KadDecoded::Plain(envelope) =
        rmule_kad::decode_exact(&frame()).expect("a well-formed publish")
    else {
        panic!("the counterparty published in the clear");
    };
    Kad2Message::decode(&envelope).expect("rmule's codec reads aMule's publish")
}

/// The whole row through rmule's reader: type 6, its own TCP port, the intern
/// Kad port it read open on, the size, the direct-callback bit — and no buddy
/// trio although a buddy was held, because `StorePacket` tests the direct
/// callback before it reads the buddy slot (`Search.cpp:595-605`).
#[test]
fn the_captured_publish_decodes_to_the_direct_callback_row() {
    let f = frame();
    assert_eq!(f[0], KAD_PROTO);
    assert_eq!(f[1], OP_PUBLISH_SOURCE_REQ);
    assert_eq!(f[34], 5, "five tags: SOURCEUPORT rides beside the four");

    let Kad2Message::PublishSourceReq { source, .. } = decoded() else {
        panic!("0x44 decodes to a publish");
    };
    assert_eq!(
        source,
        KadPublishedSource {
            source_type: Some(6),
            tcp_port: Some(AMULE_TCP_PORT),
            udp_port_tag: Some(AMULE_KAD_UDP_PORT),
            file_size: Some(FILE_SIZE),
            encryption: Some(DIRECT_CALLBACK_ONLY),
            ipv6: None,
            buddy: None,
        },
    );
}

/// Tag order and widths, off the bytes: `SOURCETYPE, SOURCEPORT, SOURCEUPORT,
/// FILESIZE, ENCRYPTION`, `SOURCETYPE` narrowed to `UINT8` by `CTagVarInt`,
/// `SOURCEUPORT` a fixed `CTagInt16`, `ENCRYPTION` appended last.
#[test]
fn the_publisher_writes_five_tags_in_one_order_at_pinned_widths() {
    let f = frame();
    let mut at = 35;
    let mut seen = Vec::new();
    for _ in 0..f[34] {
        let (tag_type, name) = (f[at], f[at + 3]);
        let value_len = match tag_type {
            0x03 => 4,
            0x08 => 2,
            0x09 => 1,
            other => panic!("unmodelled tag type {other:#04x}"),
        };
        seen.push((name, tag_type));
        at += 4 + value_len;
    }
    assert_eq!(at, f.len(), "the tag list accounts for the whole datagram");
    assert_eq!(
        seen,
        vec![
            (0xFF, 0x09), // SOURCETYPE,  UINT8
            (0xFD, 0x08), // SOURCEPORT,  UINT16
            (0xFC, 0x08), // SOURCEUPORT, UINT16
            (0x02, 0x03), // FILESIZE,    UINT32
            (0xF3, 0x09), // ENCRYPTION,  UINT8
        ],
    );
    assert_eq!(f[SOURCEUPORT_AT..SOURCEUPORT_AT + 6], SOURCEUPORT_TAG);
}

/// The KAT: rmule's publisher, told the facts this publisher held — its user
/// hash, TCP port, the file and its size, no buddy slot needed, the
/// direct-callback byte — fans out the counterparty's datagram with exactly
/// one documented difference. rmule writes no `TAG_SOURCEUPORT` (ADR-0061):
/// the storer substitutes the port it observed the datagram arrive from
/// (`KademliaUDPListener.cpp:1171-1173`), the one Kad UDP port a NAT in the
/// path leaves correct. Everything else is byte for byte.
#[test]
fn rmules_publisher_reproduces_the_captured_datagram_less_its_sourceuport() {
    use rmule_kad::{KadCommand, KadId, KadInstant, KadNode, KadNodeConfig, KadNodeEndpoint};

    let Kad2Message::PublishSourceReq {
        file, source_id, ..
    } = decoded()
    else {
        panic!("0x44 decodes to a publish");
    };
    let now = KadInstant::EPOCH;
    let mut node = KadNode::new(KadNodeConfig {
        id: KadId::from_bytes([0x11; 16]),
        tcp_port: AMULE_TCP_PORT,
        udp_port: AMULE_KAD_UDP_PORT,
        user_hash: rmule_primitives::UserHash::from_bytes(kad_wire_id(source_id)),
    });
    node.handle_command(
        now,
        KadCommand::SetPublishPosture {
            posture: rmule_kad::KadPublishPosture::Firewalled { buddy: None },
        },
    );
    node.handle_command(
        now,
        KadCommand::SetPublishConnectOptions {
            options: Some(DIRECT_CALLBACK_ONLY),
        },
    );
    let storer = KadNodeEndpoint::new(std::net::Ipv4Addr::new(45, 55, 200, 9), 4672);
    let mut near = *file.as_bytes();
    near[15] ^= 0x01;
    node.handle_datagram(
        now,
        storer,
        &rmule_testkit::kad_node::hello_req_from(KadId::from_bytes(near), storer),
    );
    let _ = rmule_testkit::drain_split(&mut node);
    node.handle_command(
        now,
        KadCommand::PublishSource {
            request: rmule_kad::KadPublishRequest::new(rmule_primitives::SourceLookupTarget::new(
                rmule_primitives::FileHash::from_bytes(kad_wire_id(*file.as_bytes())),
                FILE_SIZE,
            )),
        },
    );
    let _ = rmule_testkit::drain_split(&mut node);
    node.handle_datagram(
        now,
        storer,
        &rmule_testkit::kad_node::lookup_res_bytes(file, &[]),
    );
    let (datagrams, _) = rmule_testkit::drain_split(&mut node);
    let published: Vec<_> = datagrams
        .iter()
        .filter(|(_, bytes)| bytes.get(1) == Some(&OP_PUBLISH_SOURCE_REQ))
        .collect();
    assert_eq!(published.len(), 1, "one storer, one publish");

    let mut expected = frame();
    expected.drain(SOURCEUPORT_AT..SOURCEUPORT_AT + SOURCEUPORT_TAG.len());
    expected[34] -= 1;
    assert_eq!(
        published[0].1, expected,
        "the counterparty's datagram, less TAG_SOURCEUPORT"
    );
}
