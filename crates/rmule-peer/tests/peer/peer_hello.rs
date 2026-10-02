//! `OP_HELLO` / `OP_HELLOANSWER` codec: the hello carries a 16-byte hash-size
//! prefix the answer does not, both round-trip their tags, and a wrong size
//! byte is refused rather than guessed at. What follows the connected server
//! is `hello_read_surface`'s.

use std::net::Ipv4Addr;

use rmule_peer::{Hello, HelloAnswer, PeerHelloBody};
use rmule_primitives::{
    ClientId, Ed2kText, Ipv4Endpoint, Packet, PacketProtocol, Tag, TagName, TagValue, UserHash,
};

fn sample_body() -> PeerHelloBody {
    PeerHelloBody {
        user_hash: UserHash::from_bytes([0xAA; UserHash::BYTE_LEN]),
        client_id: ClientId::from_u32(0x04030201),
        tcp_port: 4662,
        tags: vec![Tag::new(
            TagName::length_prefixed_id(0x01),
            TagValue::String(Ed2kText::from_utf8("rmule")),
        )],
        connected_server: Ipv4Endpoint::new(Ipv4Addr::new(192, 0, 2, 1), 4661),
    }
}

fn encoded_tags_len(body: &PeerHelloBody) -> usize {
    body.tags.iter().map(|t| t.encode().len()).sum::<usize>()
}

#[test]
fn hello_round_trips_with_size_byte_prefix() {
    let body = sample_body();
    let hello = Hello::new(body.clone());
    let packet = hello.encode_packet();

    assert_eq!(packet.protocol(), PacketProtocol::Edonkey);
    assert_eq!(packet.opcode(), 0x01);

    let payload = packet.payload();
    // First byte is the legacy "hash size" prefix (16); the OP_HELLOANSWER
    // form below must NOT carry this byte.
    assert_eq!(payload[0], UserHash::BYTE_LEN as u8);
    let expected_len =
        1 + UserHash::BYTE_LEN + 4 + 2 + 4 + encoded_tags_len(&body) + Ipv4Endpoint::WIRE_LEN;
    assert_eq!(payload.len(), expected_len);

    let decoded = Hello::decode_packet(&packet).expect("hello decodes");
    assert_eq!(decoded.body(), &body);
    assert_eq!(decoded.encode_packet().encode(), packet.encode());
}

#[test]
fn hello_answer_round_trips_without_size_byte_prefix() {
    let body = sample_body();
    let answer = HelloAnswer::new(body.clone());
    let packet = answer.encode_packet();

    assert_eq!(packet.opcode(), 0x4C);
    let payload = packet.payload();
    // First byte must be the first user-hash byte, not the 0x10 size
    // prefix; HelloAnswer omits the legacy hash-size byte.
    assert_eq!(payload[0], 0xAA);
    let expected_len =
        UserHash::BYTE_LEN + 4 + 2 + 4 + encoded_tags_len(&body) + Ipv4Endpoint::WIRE_LEN;
    assert_eq!(payload.len(), expected_len);

    let decoded = HelloAnswer::decode_packet(&packet).expect("hello answer decodes");
    assert_eq!(decoded.body(), &body);
    assert_eq!(decoded.encode_packet().encode(), packet.encode());
}

#[test]
fn hello_rejects_wrong_hash_size_byte() {
    let body = sample_body();
    let hello = Hello::new(body);
    let mut packet = hello.encode_packet();
    let mut payload = packet.payload().to_vec();
    payload[0] = 0x0F;
    packet = Packet::new(PacketProtocol::Edonkey, 0x01, payload);
    assert!(Hello::decode_packet(&packet).is_err());
}
