//! The dialect's address-tag reading rules, each proven by what it refuses.

use std::net::Ipv6Addr;

use rmule_primitives::{
    CT_EMULE_SERVINGBUDDYIPV6, CT_MOD_IP_V6, CT_MOD_SVR_IP_V6, CT_MOD_YOUR_IP, PacketProtocol, Tag,
    TagName, TagValue,
};

use super::{ChangeClientIpV6, PeerIpv6Tags};
use crate::error::PeerIpv6DecodeError;
use rmule_primitives::ipv6_address_tag;

fn address(text: &str) -> Ipv6Addr {
    text.parse().unwrap()
}

/// The spec's worked `CT_MOD_IP_V6` hex, both ways: `01 01 00 AE` then the
/// address MSB-first.
#[test]
fn the_ip_v6_tag_is_the_specs_worked_bytes_and_reads_back() {
    let advertised = address("2a01:4f8::1");
    let tag = ipv6_address_tag(CT_MOD_IP_V6, advertised);

    let mut expected = vec![0x01, 0x01, 0x00, 0xAE];
    expected.extend_from_slice(&advertised.octets());
    assert_eq!(tag.encode(), expected);

    let read = PeerIpv6Tags::from_hello_tags(&[tag]);
    assert_eq!(read.peer_ipv6, Some(advertised));
}

/// `CT_MOD_SVR_IP_V6` (`0xAF`) is a server tag: in a peer hello it names
/// nothing rmule may believe, so no field takes it.
#[test]
fn the_server_tag_is_refused_in_a_peer_hello() {
    let read = PeerIpv6Tags::from_hello_tags(&[ipv6_address_tag(
        CT_MOD_SVR_IP_V6,
        address("2001:db8::9"),
    )]);
    assert_eq!(read, PeerIpv6Tags::default());
}

/// `CT_MOD_YOUR_IP`'s integer form names an IPv4, and one unverified peer must
/// never set what rmule believes its own public address to be. Only the hash
/// form is read.
#[test]
fn your_ip_is_read_in_its_hash_form_and_refused_in_its_integer_form() {
    let integer_form = Tag::new(
        TagName::length_prefixed_id(CT_MOD_YOUR_IP),
        TagValue::U32(0xC6336401),
    );
    assert_eq!(
        PeerIpv6Tags::from_hello_tags(&[integer_form]),
        PeerIpv6Tags::default()
    );

    let reflected = address("2001:db8::7");
    let read = PeerIpv6Tags::from_hello_tags(&[ipv6_address_tag(CT_MOD_YOUR_IP, reflected)]);
    assert_eq!(read.reflected_ipv6, Some(reflected));
}

/// A tag address that is not global unicast is refused whichever tag carries
/// it — the scope a socket has and a tag does not.
#[test]
fn a_tag_address_that_is_not_global_unicast_is_refused_in_every_slot() {
    let unusable = [
        address("fe80::1"),
        address("fd00::1"),
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::UNSPECIFIED,
    ];
    for id in [CT_MOD_IP_V6, CT_MOD_YOUR_IP, CT_EMULE_SERVINGBUDDYIPV6] {
        for bad in unusable {
            assert_eq!(
                PeerIpv6Tags::from_hello_tags(&[ipv6_address_tag(id, bad)]),
                PeerIpv6Tags::default(),
                "tag 0x{id:02X} accepted {bad}"
            );
        }
    }
}

/// All three readable tags in one hello, with the buddy's v6 alongside the
/// peer's own — the shape a buddy-serving dialect peer actually sends. A
/// repeated tag overwrites the first, as every reference assigns per tag
/// (kno's aMule `BaseClient.cpp:687-700`, eMuleAI `BaseClient.cpp:1162-1164`).
#[test]
fn a_full_hello_reads_every_slot_and_keeps_the_last_of_a_repeat() {
    let peer_ipv6 = address("2a01:4f8::1");
    let reflected = address("2001:db8::2");
    let buddy = address("2001:db8::3");
    let tags = vec![
        ipv6_address_tag(CT_MOD_IP_V6, address("2001:db8::bad")),
        ipv6_address_tag(CT_MOD_YOUR_IP, reflected),
        ipv6_address_tag(CT_EMULE_SERVINGBUDDYIPV6, buddy),
        ipv6_address_tag(CT_MOD_IP_V6, peer_ipv6),
    ];

    assert_eq!(
        PeerIpv6Tags::from_hello_tags(&tags),
        PeerIpv6Tags {
            peer_ipv6: Some(peer_ipv6),
            reflected_ipv6: Some(reflected),
            serving_buddy_ipv6: Some(buddy),
        }
    );
}

/// `OP_CHANGE_CLIENT_IP` (`0xAC`): sixteen raw bytes under `OP_EDONKEYPROT`,
/// no tag wrapper. A short payload has no length field to catch it, so the
/// decoder's own size check is the only guard.
#[test]
fn change_client_ip_frames_sixteen_raw_bytes_under_the_edonkey_protocol() {
    let announced = address("2a01:4f8::abc");
    let packet = ChangeClientIpV6::new(announced).unwrap().encode_packet();

    assert_eq!(packet.protocol(), PacketProtocol::Edonkey);
    assert_eq!(packet.opcode(), 0xAC);
    assert_eq!(packet.payload(), announced.octets());
    assert_eq!(
        ChangeClientIpV6::decode_packet(&packet).unwrap().address(),
        announced
    );
}

/// A truncated announcement is a size error; a well-formed one naming a
/// link-local address is refused for the same reason the hello tag is.
#[test]
fn change_client_ip_refuses_a_short_payload_and_an_unusable_address() {
    let short = rmule_primitives::Packet::new(PacketProtocol::Edonkey, 0xAC, vec![0x20; 15]);
    assert_eq!(
        ChangeClientIpV6::decode_packet(&short),
        Err(PeerIpv6DecodeError::WrongSize {
            expected: 16,
            actual: 15
        })
    );

    let link_local = address("fe80::1");
    assert!(ChangeClientIpV6::new(link_local).is_none());
    let packet =
        rmule_primitives::Packet::new(PacketProtocol::Edonkey, 0xAC, link_local.octets().to_vec());
    assert_eq!(
        ChangeClientIpV6::decode_packet(&packet),
        Err(PeerIpv6DecodeError::UnusableAddress {
            address: link_local
        })
    );
}
