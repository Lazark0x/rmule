//! What our own side of a handshake puts on the wire: the identity tags a
//! `PeerHandshakeContext` projects into a hello, the zeroed endpoint an
//! unconnected context sends, extra tags forwarded while canonical collisions
//! are dropped, and the three adverts that only light when the feature behind
//! them is actually serving — UDP ports, secure identification, crypt stance.

use std::net::Ipv4Addr;

use crate::fixture::{CT_EMULE_MISCOPTIONS1, CT_EMULE_UDPPORTS, CT_NAME, CT_VERSION};
use rmule_peer::{
    CT_EMULE_BUDDYIP, CT_EMULE_BUDDYUDP, HelloAdvert, MiscOptions2, PeerHandshakeContext,
    PeerHelloBody, ServingBuddyAdvert, UdpPortsAdvert,
};
use rmule_primitives::{
    ClientId, ClientIdentity, Ed2kText, Ipv4Endpoint, Tag, TagName, TagValue, UserHash,
};

const CT_EMULE_MISCOPTIONS2: u8 = 0xFE;
const CT_MULEVERSION: u8 = 0xFB;
const CT_MOD_MISCOPTIONS: u8 = 0xAA;
const CT_MOD_IP_V6: u8 = 0xAE;
const CT_EMULE_SERVINGBUDDYIPV6: u8 = 0xA0;
const CT_MOD_VERSION: u8 = 0x55;

fn ctx_with(identity: ClientIdentity, server: Option<Ipv4Endpoint>) -> PeerHandshakeContext {
    PeerHandshakeContext {
        identity,
        client_id: ClientId::from_u32(0x10000001),
        ed2k_client_id: ClientId::from_u32(0x10000001),
        public_ip: None,
        connected_server: server,
    }
}

#[test]
fn from_handshake_context_emits_identity_plus_compression_capability() {
    let identity = ClientIdentity::new(
        UserHash::from_bytes([0xAA; UserHash::BYTE_LEN]),
        Ed2kText::from_utf8("rmule-peer"),
        4662,
        0x3C,
    );
    let server = Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 1), 4661);
    let ctx = ctx_with(identity, Some(server));

    let body = PeerHelloBody::from_handshake_context(&ctx, &HelloAdvert::default());

    assert_eq!(body.user_hash, ctx.identity.user_hash());
    assert_eq!(body.client_id, ctx.client_id);
    assert_eq!(body.tcp_port, 4662);
    assert_eq!(body.connected_server, server);

    // Honest Capability Advertisement (ADR-0047/0041) extends ADR-0047's
    // identity-only hello with the capability tag plus CT_EMULE_VERSION —
    // eMule treats a hello without 0xFB as a non-extended client and never
    // initiates Secure User Identification (2026-07-06 capture).
    let ids: Vec<u8> = body.tags.iter().filter_map(|t| t.name().id()).collect();
    assert_eq!(
        ids,
        vec![
            CT_NAME,
            CT_VERSION,
            CT_EMULE_MISCOPTIONS1,
            CT_EMULE_MISCOPTIONS2,
            CT_MULEVERSION,
            CT_MOD_MISCOPTIONS,
            CT_MOD_VERSION
        ]
    );

    // The 0xFB value is registry-derived (ADR-0047) so this surface and the
    // server-login tag can never drift apart.
    let mule_version = body
        .tags
        .iter()
        .find(|t| t.name().id() == Some(CT_MULEVERSION))
        .expect("0xFB present");
    // aMule emits the identical version word on the peer hello
    // (BaseClient.cpp#L1077) as on server login: the aMule 2.3.3 parity value
    // 0x0304_0D80, not rmule's own version.
    assert_eq!(*mule_version.value(), TagValue::U32(0x0304_0D80));
}

#[test]
fn unconnected_context_zeros_wire_endpoint() {
    let identity = ClientIdentity::new(
        UserHash::from_bytes([0; UserHash::BYTE_LEN]),
        Ed2kText::from_utf8("rmule"),
        4662,
        60,
    );
    let body =
        PeerHelloBody::from_handshake_context(&ctx_with(identity, None), &HelloAdvert::default());
    assert_eq!(
        body.connected_server,
        Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0)
    );
}

#[test]
fn extra_tags_are_forwarded_but_canonical_collisions_dropped() {
    // ADR-0047 minimum-honest hello: forward ClientIdentity::extra_tags
    // byte-faithful; drop tags whose numeric ID collides with the
    // canonical projection so we never emit two CT_NAME or two
    // CT_VERSION on the wire.
    let extras = vec![
        Tag::new(
            TagName::length_prefixed_id(CT_MULEVERSION),
            TagValue::U32(0x69),
        ),
        Tag::new(
            TagName::length_prefixed_id(CT_NAME),
            TagValue::String(Ed2kText::from_utf8("collision")),
        ),
    ];
    let identity = ClientIdentity::new(
        UserHash::from_bytes([0; UserHash::BYTE_LEN]),
        Ed2kText::from_utf8("real"),
        4662,
        60,
    )
    .with_extra_tags(extras);

    let body =
        PeerHelloBody::from_handshake_context(&ctx_with(identity, None), &HelloAdvert::default());

    let ids: Vec<u8> = body.tags.iter().filter_map(|t| t.name().id()).collect();
    assert_eq!(
        ids,
        vec![
            CT_NAME,
            CT_VERSION,
            CT_EMULE_MISCOPTIONS1,
            CT_EMULE_MISCOPTIONS2,
            CT_MULEVERSION,
            CT_MOD_MISCOPTIONS,
            CT_MOD_VERSION
        ]
    );
    // The extra 0xFB (value 0x69) collided with the canonical CT_EMULE_VERSION
    // and was dropped — the emitted one is the canonical projection.
    let mule_version = body
        .tags
        .iter()
        .find_map(|t| match (t.name().id(), t.value()) {
            (Some(CT_MULEVERSION), TagValue::U32(v)) => Some(*v),
            _ => None,
        })
        .expect("canonical CT_EMULE_VERSION present");
    assert_ne!(
        mule_version, 0x69,
        "the colliding extra tag must be dropped"
    );
}

#[test]
fn udp_ports_advert_rides_the_hello_only_when_the_client_udp_socket_serves() {
    // ADR-0057/0047: the hello carries `CT_EMULE_UDPPORTS` (0xF9) with rmule's
    // real bound ports AND lights the MiscOptions1 UDP-version nibble (aMule's 4)
    // — but only when the live client-UDP socket serves. A node that binds no
    // client-UDP socket (advert `None`) omits both, so no peer learns a reask
    // endpoint rmule cannot answer (Honest Capability Advertisement).
    let identity = ClientIdentity::new(
        UserHash::from_bytes([0x55; UserHash::BYTE_LEN]),
        Ed2kText::from_utf8("rmule"),
        4662,
        60,
    );
    let ctx = ctx_with(identity, None);
    let udp_version = |body: &PeerHelloBody| -> u8 {
        body.tags
            .iter()
            .find_map(|t| match (t.name().id(), t.value()) {
                (Some(CT_EMULE_MISCOPTIONS1), TagValue::U32(bits)) => {
                    Some(((*bits >> 24) & 0x0f) as u8)
                }
                _ => None,
            })
            .expect("MiscOptions1 tag present")
    };

    // Serving: real client port 0x1240, Kad not running (high half 0).
    let serving = PeerHelloBody::from_handshake_context(
        &ctx,
        &HelloAdvert {
            udp_ports: Some(UdpPortsAdvert::new(0x1240, 0)),
            ..HelloAdvert::default()
        },
    );
    let ids: Vec<u8> = serving.tags.iter().filter_map(|t| t.name().id()).collect();
    // aMule's contiguous eMule tag block: 0xF9 sits between CT_VERSION and 0xFA.
    assert_eq!(
        ids,
        vec![
            CT_NAME,
            CT_VERSION,
            CT_EMULE_UDPPORTS,
            CT_EMULE_MISCOPTIONS1,
            CT_EMULE_MISCOPTIONS2,
            CT_MULEVERSION,
            CT_MOD_MISCOPTIONS,
            CT_MOD_VERSION
        ]
    );
    let ports = serving
        .tags
        .iter()
        .find_map(|t| match (t.name().id(), t.value()) {
            (Some(CT_EMULE_UDPPORTS), TagValue::U32(word)) => Some(*word),
            _ => None,
        })
        .expect("CT_EMULE_UDPPORTS present when serving");
    assert_eq!(ports, 0x0000_1240, "Kad half 0, client half the real port");
    assert_eq!(udp_version(&serving), 4, "peer-UDP version nibble lit to 4");

    // Not serving: no client-UDP socket → no port tag, UDP version nibble dark.
    let idle = PeerHelloBody::from_handshake_context(&ctx, &HelloAdvert::default());
    assert!(
        !idle
            .tags
            .iter()
            .any(|t| t.name().id() == Some(CT_EMULE_UDPPORTS)),
        "no CT_EMULE_UDPPORTS when the client-UDP socket is not serving"
    );
    assert_eq!(
        udp_version(&idle),
        0,
        "UDP version nibble stays dark when idle"
    );

    // An all-zero advert is treated as nothing bound — the tag is omitted.
    let empty = PeerHelloBody::from_handshake_context(
        &ctx,
        &HelloAdvert {
            udp_ports: Some(UdpPortsAdvert::new(0, 0)),
            ..HelloAdvert::default()
        },
    );
    assert!(
        !empty
            .tags
            .iter()
            .any(|t| t.name().id() == Some(CT_EMULE_UDPPORTS)),
        "an empty (0/0) advert omits the tag rather than emitting a zero word"
    );
    assert_eq!(udp_version(&empty), 0);
}

#[test]
fn secure_ident_advertisement_lights_the_nibble_only_when_enabled() {
    // ADR-0041 Honest Capability Advertisement: the SecIdent nibble
    // (MiscOptions1 bits [16..20)) is lit iff the session holds a keypair, so a
    // peer never asks us to sign a challenge we cannot answer.
    let identity = ClientIdentity::new(
        UserHash::from_bytes([0x33; UserHash::BYTE_LEN]),
        Ed2kText::from_utf8("rmule"),
        4662,
        60,
    );
    let sui_nibble = |body: &PeerHelloBody| -> u8 {
        body.tags
            .iter()
            .find_map(|t| match (t.name().id(), t.value()) {
                (Some(CT_EMULE_MISCOPTIONS1), TagValue::U32(bits)) => {
                    Some(((*bits >> 16) & 0x0f) as u8)
                }
                _ => None,
            })
            .expect("MiscOptions1 tag present")
    };

    let with_sui = PeerHelloBody::from_handshake_context(
        &ctx_with(identity.clone(), None),
        &HelloAdvert {
            secure_ident: true,
            ..HelloAdvert::default()
        },
    );
    let without_sui =
        PeerHelloBody::from_handshake_context(&ctx_with(identity, None), &HelloAdvert::default());
    assert_eq!(
        sui_nibble(&with_sui),
        3,
        "SUI advertised → bitmask 3 (V1|V2), matching real eMule/aMule"
    );
    assert_eq!(sui_nibble(&without_sui), 0, "SUI off → nibble stays 0");
}

#[test]
fn crypt_stance_advertised_in_misc_options2_folds_in_shipped_multipacket_ext() {
    // ADR-0042/0054/0055: the hello's MiscOptions2 (0xFE) word carries the
    // crypt stance when the connection supplies one, but always folds in the
    // registry's ExtMultiPacket + SourceExchange2 bits — so neither a
    // fully-dark crypt stance nor the complete absence of a crypt policy
    // suppresses the tag: rmule advertises the capabilities it implements.
    let identity = ClientIdentity::new(
        UserHash::from_bytes([0x44; UserHash::BYTE_LEN]),
        Ed2kText::from_utf8("rmule"),
        4662,
        60,
    );
    let ctx = ctx_with(identity, None);

    let advertised = PeerHelloBody::from_handshake_context(
        &ctx,
        &HelloAdvert {
            crypt: Some(MiscOptions2::rmule_advertised(true, true, false)),
            ..HelloAdvert::default()
        },
    );
    let crypt = advertised
        .tags
        .iter()
        .find_map(|t| match (t.name().id(), t.value()) {
            (Some(CT_EMULE_MISCOPTIONS2), TagValue::U32(bits)) => {
                Some(MiscOptions2::from_bits(*bits))
            }
            _ => None,
        })
        .expect("MiscOptions2 crypt tag present when advertised");
    assert!(crypt.supports_crypt_layer());
    assert!(crypt.requests_crypt_layer());
    assert!(!crypt.requires_crypt_layer());

    // No crypt policy still carries the tag: rmule advertises the two
    // capabilities it implements (ExtMultiPacket + SourceExchange2), just with
    // every crypt bit dark — Honest Capability Advertisement (ADR-0054/0055).
    let plain = PeerHelloBody::from_handshake_context(&ctx, &HelloAdvert::default());
    let plain_misc2 = plain
        .tags
        .iter()
        .find_map(|t| match (t.name().id(), t.value()) {
            (Some(CT_EMULE_MISCOPTIONS2), TagValue::U32(bits)) => {
                Some(MiscOptions2::from_bits(*bits))
            }
            _ => None,
        })
        .expect("MiscOptions2 tag present even with no crypt policy");
    assert!(!plain_misc2.supports_crypt_layer());
    assert!(!plain_misc2.requests_crypt_layer());
    assert!(!plain_misc2.requires_crypt_layer());
    assert!(
        plain_misc2.supports_multipacket_ext(),
        "ExtMultiPacket rides even with no crypt policy"
    );
    assert!(
        plain_misc2.supports_source_exchange2(),
        "SourceExchange2 rides even with no crypt policy"
    );

    // A fully-dark crypt stance still carries the tag: the registry's
    // ExtMultiPacket bit (ADR-0054) is folded in regardless of crypt policy.
    let empty = PeerHelloBody::from_handshake_context(
        &ctx,
        &HelloAdvert {
            crypt: Some(MiscOptions2::rmule_advertised(false, false, false)),
            ..HelloAdvert::default()
        },
    );
    let ext_multipacket = empty
        .tags
        .iter()
        .find_map(|t| match (t.name().id(), t.value()) {
            (Some(CT_EMULE_MISCOPTIONS2), TagValue::U32(bits)) => {
                Some(MiscOptions2::from_bits(*bits))
            }
            _ => None,
        })
        .expect("MiscOptions2 tag present even with crypt fully dark");
    assert!(!ext_multipacket.supports_crypt_layer());
    assert!(!ext_multipacket.requests_crypt_layer());
    assert!(!ext_multipacket.requires_crypt_layer());
    assert!(ext_multipacket.supports_multipacket_ext());
}

/// The IPv6 dialect's two-channel advert (ADR-0087): the
/// `CT_MOD_MISCOPTIONS` **Static Capability Claim** rides every hello, whether
/// or not rmule holds an address, because a peer reads an absent bit as "no
/// support" and would then never offer an IPv6 source. The address tag rides
/// only when the Advertised Endpoints chooser settled one.
#[test]
fn the_mod_misc_claim_is_static_while_the_ipv6_tag_follows_the_chooser() {
    let identity = ClientIdentity::new(
        UserHash::from_bytes([0x5A; UserHash::BYTE_LEN]),
        Ed2kText::from_utf8("rmule"),
        4662,
        60,
    );
    let ctx = ctx_with(identity, None);

    let claim_of = |body: &PeerHelloBody| {
        body.tags
            .iter()
            .find_map(|t| match (t.name().id(), t.value()) {
                (Some(CT_MOD_MISCOPTIONS), TagValue::U32(bits)) => Some(*bits),
                _ => None,
            })
    };
    let fact_of = |body: &PeerHelloBody| {
        body.tags
            .iter()
            .find_map(|t| match (t.name().id(), t.value()) {
                (Some(CT_MOD_IP_V6), TagValue::Hash(bytes)) => {
                    Some(std::net::Ipv6Addr::from(*bytes))
                }
                _ => None,
            })
    };

    let addressless = PeerHelloBody::from_handshake_context(&ctx, &HelloAdvert::default());
    assert_eq!(
        claim_of(&addressless),
        Some(0x27),
        "EXTXS | NAT_TRAVERSAL | IPV6 | EXTXS_SKIPTAGS, claimed with no address to back it"
    );
    assert_eq!(fact_of(&addressless), None, "no chooser verdict, no tag");

    let known: std::net::Ipv6Addr = "2a01:4f8::1".parse().unwrap();
    let advertised = PeerHelloBody::from_handshake_context(
        &ctx,
        &HelloAdvert {
            ipv6: Some(known),
            ..HelloAdvert::default()
        },
    );
    assert_eq!(claim_of(&advertised), Some(0x27));
    assert_eq!(fact_of(&advertised), Some(known));
}

/// ADR-0061's buddy contact rides as one advert: `CT_EMULE_BUDDYIP` and
/// `CT_EMULE_BUDDYUDP` whenever a buddy is supplied, written as aMule writes
/// them (`BaseClient.cpp:1484-1495`: right after `CT_EMULE_UDPPORTS`, forced
/// `uint32`, the IP's octets in wire order), and `CT_EMULE_SERVINGBUDDYIPV6`
/// only when that buddy also has an IPv6.
#[test]
fn the_buddy_tags_ride_only_when_a_buddy_is_supplied() {
    let identity = ClientIdentity::new(
        UserHash::from_bytes([0x6B; UserHash::BYTE_LEN]),
        Ed2kText::from_utf8("rmule"),
        4662,
        60,
    );
    let ctx = ctx_with(identity, None);
    let buddy_udp = Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 2), 4672);
    let buddy_v6: std::net::Ipv6Addr = "2001:db8::b0dd".parse().unwrap();
    let hello = |serving_buddy| {
        PeerHelloBody::from_handshake_context(
            &ctx,
            &HelloAdvert {
                udp_ports: Some(UdpPortsAdvert::new(4672, 4665)),
                serving_buddy,
                ..HelloAdvert::default()
            },
        )
    };
    let ids = |body: &PeerHelloBody| {
        body.tags
            .iter()
            .filter_map(|t| t.name().id())
            .collect::<Vec<_>>()
    };

    let absent = hello(None);
    assert!(
        !ids(&absent).iter().any(|id| [
            CT_EMULE_BUDDYIP,
            CT_EMULE_BUDDYUDP,
            CT_EMULE_SERVINGBUDDYIPV6
        ]
        .contains(id)),
        "no buddy, no buddy tag"
    );

    let v4_only = hello(Some(ServingBuddyAdvert {
        buddy_udp,
        ipv6: None,
    }));
    let at = ids(&v4_only)
        .iter()
        .position(|id| *id == CT_EMULE_UDPPORTS)
        .expect("ports ride");
    assert_eq!(
        v4_only.tags[at + 1].encode(),
        [0x03, 0x01, 0x00, CT_EMULE_BUDDYIP, 45, 55, 200, 2]
    );
    assert_eq!(
        v4_only.tags[at + 2].encode(),
        [0x03, 0x01, 0x00, CT_EMULE_BUDDYUDP, 0x40, 0x12, 0x00, 0x00]
    );
    assert!(!ids(&v4_only).contains(&CT_EMULE_SERVINGBUDDYIPV6));

    let dual = hello(Some(ServingBuddyAdvert {
        buddy_udp,
        ipv6: Some(buddy_v6),
    }));
    // The v6 half rides after the v4 tags, before the closing mod name.
    let v4_ids = ids(&v4_only);
    let (v4_mod_name, v4_head) = v4_ids.split_last().expect("tags");
    assert_eq!(ids(&dual)[..v4_head.len()], v4_head[..]);
    assert_eq!(ids(&dual).last(), Some(v4_mod_name));
    assert_eq!(
        dual.tags
            .iter()
            .rev()
            .nth(1)
            .map(|t| (t.name().id(), t.value().clone())),
        Some((
            Some(CT_EMULE_SERVINGBUDDYIPV6),
            TagValue::Hash(buddy_v6.octets())
        ))
    );
}

/// The hello writes `MiscOptions2` bit 12
/// (`SupportsDirectUDPCallback`) when core's Self Reach says we accept a
/// `0x95` — aMule's writer, `BaseClient.cpp:1131-1132` — and leaves the rest of
/// the word as it was; a hello that does not accept keeps the bit dark.
#[test]
fn the_direct_udp_callback_advert_lights_misc_options2_bit_12() {
    let identity = ClientIdentity::new(
        UserHash::from_bytes([0x55; UserHash::BYTE_LEN]),
        Ed2kText::from_utf8("rmule"),
        4662,
        60,
    );
    let ctx = ctx_with(identity, None);
    let misc2 = |advert: &HelloAdvert| {
        MiscOptions2::from_tags(&PeerHelloBody::from_handshake_context(&ctx, advert).tags)
            .expect("MiscOptions2 rides every hello")
    };
    let dark = misc2(&HelloAdvert::default());
    let lit = misc2(&HelloAdvert {
        direct_udp_callback: true,
        ..HelloAdvert::default()
    });
    assert!(!dark.supports_direct_udp_callback());
    assert!(lit.supports_direct_udp_callback());
    assert_eq!(
        lit,
        MiscOptions2::from_bits(0x1000 | 0x420),
        "bit 12 beside ExtMultiPacket (5) and SourceExchange2 (10), nothing else"
    );
}
