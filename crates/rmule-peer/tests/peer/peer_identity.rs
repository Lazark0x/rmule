//! What a counterparty's hello tells us about it: the nickname and protocol
//! version its typed tags project to, why a typed tag is never also reported
//! as unknown, the absent server endpoint of an unconnected peer, and the Kad
//! endpoint that only becomes a handoff candidate above Kad version 1.

use std::net::Ipv4Addr;

use crate::fixture::{CT_EMULE_UDPPORTS, CT_NAME, CT_VERSION};
use rmule_peer::{MiscOptions1, MiscOptions2, PeerHelloBody, PeerIdentity};
use rmule_primitives::{ClientId, Ed2kText, Ipv4Endpoint, Tag, TagName, TagValue, UserHash};

const OPAQUE_TAG: u8 = 0x55;
fn body_with(tags: Vec<Tag>, server: Ipv4Endpoint) -> PeerHelloBody {
    PeerHelloBody {
        user_hash: UserHash::from_bytes([0x42; UserHash::BYTE_LEN]),
        client_id: ClientId::from_u32(0x01020304),
        tcp_port: 4662,
        tags,
        connected_server: server,
    }
}

fn unspecified() -> Ipv4Endpoint {
    Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0)
}

/// Pack the eMule `CT_EMULE_UDPPORTS` layout: kad UDP port high, client UDP low.
fn udp_ports_tag(client_udp: u16, kad_udp: u16) -> Tag {
    Tag::new(
        TagName::compact_id(CT_EMULE_UDPPORTS),
        TagValue::U32((u32::from(kad_udp) << 16) | u32::from(client_udp)),
    )
}

/// A `CT_EMULE_MISCOPTIONS2` tag carrying `kad_version` in its low nibble.
fn kad_version_tag(kad_version: u8) -> Tag {
    MiscOptions2::from_bits(u32::from(kad_version & 0x0f)).to_tag()
}

/// A `CT_EMULE_MISCOPTIONS1` tag carrying `udp_version` in its UDP nibble (bits
/// [24..28), aMule `m_byUDPVer`).
fn udp_version_tag(udp_version: u8) -> Tag {
    MiscOptions1::from_bits(u32::from(udp_version & 0x0f) << 24).to_tag()
}

#[test]
fn typed_tags_project_to_nickname_and_protocol_version() {
    let tags = vec![
        Tag::new(
            TagName::length_prefixed_id(CT_NAME),
            TagValue::String(Ed2kText::from_utf8("peer-nick")),
        ),
        Tag::new(TagName::length_prefixed_id(CT_VERSION), TagValue::U32(0x3C)),
        Tag::new(
            TagName::length_prefixed_id(OPAQUE_TAG),
            TagValue::U32(0xDEADBEEF),
        ),
    ];
    let body = body_with(tags, Ipv4Endpoint::new(Ipv4Addr::new(192, 0, 2, 1), 4661));

    let identity = PeerIdentity::from_hello_body(&body);

    assert_eq!(identity.user_hash(), body.user_hash);
    assert_eq!(identity.client_id(), body.client_id);
    assert_eq!(identity.tcp_port(), 4662);
    assert_eq!(
        identity.nickname().map(Ed2kText::to_display_string),
        Some("peer-nick".to_owned())
    );
    assert_eq!(identity.protocol_version(), Some(0x3C));
    assert_eq!(
        identity.connected_server(),
        Some(Ipv4Endpoint::new(Ipv4Addr::new(192, 0, 2, 1), 4661))
    );
    assert_eq!(identity.unknown_tags().len(), 1);
    assert_eq!(identity.unknown_tags()[0].name().id(), Some(OPAQUE_TAG));
}

#[test]
fn typed_tags_are_not_duplicated_into_unknown_tags() {
    let tags = vec![
        Tag::new(
            TagName::length_prefixed_id(CT_NAME),
            TagValue::String(Ed2kText::from_utf8("peer")),
        ),
        Tag::new(TagName::length_prefixed_id(CT_VERSION), TagValue::U32(60)),
    ];
    let identity = PeerIdentity::from_hello_body(&body_with(
        tags,
        Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0),
    ));

    assert!(identity.unknown_tags().is_empty());
    assert!(identity.nickname().is_some());
    assert_eq!(identity.protocol_version(), Some(60));
}

#[test]
fn unconnected_wire_endpoint_projects_to_none() {
    let identity = PeerIdentity::from_hello_body(&body_with(
        Vec::new(),
        Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0),
    ));
    assert_eq!(identity.connected_server(), None);
}

// --- the ed2k→Kad handoff peer-tag consume (ADR-0067 / ADR-0047 counterpart) ---

#[test]
fn a_peer_kad_endpoint_projects_when_the_handoff_gate_opens() {
    // The Kad hint an eD2k peer carries: the Kad UDP port is the high half of
    // CT_EMULE_UDPPORTS, the Kad version the low nibble of MiscOptions2. aMule's
    // handoff gate (KadPort ∧ KadVersion > 1) opens, so the peer is a Kad
    // bootstrap candidate.
    let tags = vec![udp_ports_tag(4665, 4672), kad_version_tag(8)];
    let identity = PeerIdentity::from_hello_body(&body_with(tags, unspecified()));

    assert_eq!(identity.kad_bootstrap_port(), Some(4672));
    // The tags are *read*, not stripped: the untyped-tag byte fidelity contract
    // (a later read may consume the client-UDP half, ADR-0057) is preserved.
    assert_eq!(identity.unknown_tags().len(), 2);
}

#[test]
fn a_kad_version_of_one_or_less_is_no_handoff_candidate() {
    // aMule's KadVersion > 1 gate: a v0/v1 (or version-less) peer cannot really
    // be a Kad2 node, so its port is not a bootstrap target.
    for kad_version in [0u8, 1] {
        let tags = vec![udp_ports_tag(4665, 4672), kad_version_tag(kad_version)];
        let identity = PeerIdentity::from_hello_body(&body_with(tags, unspecified()));
        assert_eq!(
            identity.kad_bootstrap_port(),
            None,
            "kad version {kad_version} is not Kad2"
        );
    }
}

#[test]
fn a_zero_kad_port_is_no_handoff_candidate() {
    // The peer advertises Kad2 but runs no Kad UDP listener (kad half zero) —
    // aMule's KadPort leg of the gate.
    let tags = vec![udp_ports_tag(4665, 0), kad_version_tag(8)];
    let identity = PeerIdentity::from_hello_body(&body_with(tags, unspecified()));
    assert_eq!(identity.kad_bootstrap_port(), None);
}

#[test]
fn a_hello_without_the_udp_ports_tag_is_no_handoff_candidate() {
    // A non-Kad or pre-extended peer sends no CT_EMULE_UDPPORTS at all.
    let identity =
        PeerIdentity::from_hello_body(&body_with(vec![kad_version_tag(8)], unspecified()));
    assert_eq!(identity.kad_bootstrap_port(), None);
}

// --- the ADR-0057 source-reask peer-tag consume (the client-UDP half) ---

#[test]
fn a_peer_client_udp_reask_contact_projects_from_the_udpports_low_half() {
    // The reask contact an eD2k peer carries: the client-UDP port is the LOW
    // half of CT_EMULE_UDPPORTS (the Kad port is the high half), the peer-UDP
    // version the UDP nibble of MiscOptions1. Both present ⇒ a UDP-reaskable
    // source. The kad half (4672) must not bleed into the client half.
    let tags = vec![udp_ports_tag(12345, 4672), udp_version_tag(4)];
    let identity = PeerIdentity::from_hello_body(&body_with(tags, unspecified()));
    assert_eq!(identity.client_udp_reask(), Some((12345, 4)));
}

#[test]
fn a_client_udp_contact_without_a_miscoptions1_tag_defaults_the_version_to_zero() {
    // A peer that advertises a client-UDP port but no MiscOptions1 (version-less)
    // still reask-able; the version gates only the body extras, so it defaults
    // to 0 (aMule's `m_byUDPVer` default), yielding the bare `0x90`.
    let identity =
        PeerIdentity::from_hello_body(&body_with(vec![udp_ports_tag(4665, 0)], unspecified()));
    assert_eq!(identity.client_udp_reask(), Some((4665, 0)));
}

#[test]
fn a_zero_client_udp_port_is_no_reask_contact() {
    // Kad-only advert (client half zero) or no UDP-ports tag at all: the source
    // can only be TCP-reasked, so no client-UDP contact projects.
    let kad_only = PeerIdentity::from_hello_body(&body_with(
        vec![udp_ports_tag(0, 4672), udp_version_tag(4)],
        unspecified(),
    ));
    assert_eq!(kad_only.client_udp_reask(), None);
    let no_tag = PeerIdentity::from_hello_body(&body_with(Vec::new(), unspecified()));
    assert_eq!(no_tag.client_udp_reask(), None);
}

// --- the counterparty crypt-stance consume (MiscOptions2 bits 7/8/9) ---

#[test]
fn a_dishonest_crypt_ladder_reads_at_the_tier_amule_would_read_it() {
    // MiscOptions2 = 0x0280: supports (bit 7) ∧ requires (bit 9), requests (bit 8)
    // dark. aMule normalises this on *receive*, three lines below its own bit
    // reads — `m_fRequestsCryptLayer &= m_fSupportsCryptLayer;
    // m_fRequiresCryptLayer &= m_fRequestsCryptLayer;` (BaseClient.cpp:600-601 in
    // ProcessHelloTypePacket) — so aMule reads this peer as crypt-*optional*, and
    // rmule must reach the same verdict or it would dial a peer differently than
    // aMule does. Pinned here because the two-step ladder looks like an own-advert
    // honesty rule and invites a "the read path shouldn't collapse `requires`"
    // correction; it is aMule's receive rule too.
    let identity = PeerIdentity::from_hello_body(&body_with(
        vec![MiscOptions2::from_bits(0x0280).to_tag()],
        unspecified(),
    ));
    let crypt = identity.crypt_stance();

    assert!(crypt.supports(), "bit 7 survives — it has no predecessor");
    assert!(!crypt.requests(), "bit 8 was never advertised");
    assert!(
        !crypt.requires(),
        "requires collapses with requests, exactly as aMule's receive side collapses it"
    );
}

#[test]
fn an_honest_crypt_ladder_survives_the_consume_intact() {
    // The vacuity guard for the row above: 0x0380 (all three lit) must arrive
    // whole, or the collapse assertions would pass against a decoder that simply
    // reads nothing.
    let identity = PeerIdentity::from_hello_body(&body_with(
        vec![MiscOptions2::from_bits(0x0380).to_tag()],
        unspecified(),
    ));
    let crypt = identity.crypt_stance();

    assert!(crypt.supports() && crypt.requests() && crypt.requires());
}

#[test]
fn wrong_type_typed_tag_falls_through_to_unknown_tags() {
    // CT_NAME (0x01) carrying a u32 instead of a string is not the
    // canonical typed shape; preserve it as unknown rather than
    // mis-typing the projection.
    let tags = vec![Tag::new(
        TagName::length_prefixed_id(CT_NAME),
        TagValue::U32(0xCAFEBABE),
    )];
    let identity = PeerIdentity::from_hello_body(&body_with(
        tags,
        Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0),
    ));
    assert!(identity.nickname().is_none());
    assert_eq!(identity.unknown_tags().len(), 1);
}

/// A peer's hello names its serving buddy, read by aMule's rules
/// (`BaseClient.cpp:542-557`): the tags in aMule's order — `CT_EMULE_UDPPORTS`,
/// `0xFC`, `0xFD`, `CT_EMULE_MISCOPTIONS1` — with the `0xFC`/`0xFD` bytes
/// reused verbatim from the capture (run `1790229931`), and
/// `0xA0` appended where the IPv6 dialect's mod block puts it.
#[test]
fn a_hello_naming_its_buddy_decodes_to_the_buddy_endpoint() {
    use rmule_peer::{HelloAnswer, ServingBuddyAdvert};
    use rmule_primitives::{Packet, PacketProtocol};

    let buddy_v6: std::net::Ipv6Addr = "2a01:4f8::b0dd".parse().unwrap();
    let mut payload = Vec::new();
    payload.extend_from_slice(&[0x42; UserHash::BYTE_LEN]);
    payload.extend_from_slice(&0x0000_2A00_u32.to_le_bytes()); // a Low ID
    payload.extend_from_slice(&4662_u16.to_le_bytes());
    payload.extend_from_slice(&5_u32.to_le_bytes());
    payload.extend_from_slice(&[0x03, 0x01, 0x00, 0xF9, 0x40, 0x12, 0x40, 0x12]);
    payload.extend_from_slice(&[0x03, 0x01, 0x00, 0xFC, 0x2D, 0x37, 0xC8, 0x02]);
    payload.extend_from_slice(&[0x03, 0x01, 0x00, 0xFD, 0x40, 0x12, 0x00, 0x00]);
    payload.extend_from_slice(&[0x03, 0x01, 0x00, 0xFA, 0x00, 0x00, 0x00, 0x04]);
    payload.extend_from_slice(&[0x01, 0x01, 0x00, 0xA0]);
    payload.extend_from_slice(&buddy_v6.octets());
    payload.extend_from_slice(&[0; 6]); // no server
    let packet = Packet::new(PacketProtocol::Edonkey, 0x4C, payload);

    let answer = HelloAnswer::decode_packet(&packet).expect("the answer decodes");
    let identity = PeerIdentity::from_hello_body(answer.body());

    assert_eq!(
        identity.serving_buddy(),
        Some(ServingBuddyAdvert {
            buddy_udp: Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 2), 4672),
            ipv6: Some(buddy_v6),
        }),
    );
}

/// aMule reads either buddy tag with `GetInt()`, so any integer width is the
/// same fact; a zero address or port names no buddy (`GetBuddyIP() &&
/// GetBuddyPort()`).
#[test]
fn a_buddy_needs_both_a_non_zero_address_and_port_in_any_integer_width() {
    use rmule_peer::{CT_EMULE_BUDDYIP, CT_EMULE_BUDDYUDP};
    let tag = |id, value| Tag::new(TagName::length_prefixed_id(id), value);
    let buddy =
        |tags| PeerIdentity::from_hello_body(&body_with(tags, unspecified())).serving_buddy();

    let narrow = buddy(vec![
        tag(CT_EMULE_BUDDYIP, TagValue::U64(0x02C8_372D)),
        tag(CT_EMULE_BUDDYUDP, TagValue::U16(4672)),
    ]);
    assert_eq!(
        narrow.map(|b| b.buddy_udp),
        Some(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 2), 4672))
    );
    assert_eq!(
        buddy(vec![
            tag(CT_EMULE_BUDDYIP, TagValue::U32(0x02C8_372D)),
            tag(CT_EMULE_BUDDYUDP, TagValue::U32(0)),
        ]),
        None,
        "no port, no buddy"
    );
    assert_eq!(
        buddy(vec![tag(CT_EMULE_BUDDYUDP, TagValue::U32(4672))]),
        None,
        "no address, no buddy"
    );
}
