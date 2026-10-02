//! `LoginRequest::from_identity` wire-shape evidence (ADR-0047, deterministic
//! tier): aMule-exact tag shape (`ServerConnect.cpp#L219-L259` @ `4e8f2b3c`),
//! registry-derived capability bits that are never aspirational, and
//! login-tag golden vectors.

use rmule_ed2k::{LoginAdvert, LoginRequest, UdpPortsAdvert, server_capability_flags};
use rmule_primitives::{
    Capabilities, ClientIdentity, CryptStance, Ed2kText, Packet, Tag, TagName, TagValue, UserHash,
};

fn sample_identity() -> ClientIdentity {
    ClientIdentity::new(
        UserHash::from_hex("00112233445566778899AABBCCDDEEFF").unwrap(),
        Ed2kText::from_utf8("rmule-test"),
        4662,
        60,
    )
}

fn shipped_no_crypt() -> Capabilities {
    Capabilities::shipped(CryptStance::disabled())
}

#[test]
fn from_identity_emits_amule_exact_tag_shape() {
    let request = LoginRequest::from_identity(&sample_identity(), &shipped_no_crypt());
    let tags = request.tags();

    // aMule 2.3.3 sends tagcount exactly 4 — CT_NAME, CT_VERSION,
    // CT_SERVER_FLAGS, CT_EMULE_VERSION in that order; the port rides only
    // the fixed field (CT_PORT 0x0F is commented out in aMule itself).
    let ids: Vec<_> = tags.iter().map(|t| t.name().id()).collect();
    assert_eq!(ids, vec![Some(0x01), Some(0x11), Some(0x20), Some(0xFB)]);

    match tags[0].value() {
        TagValue::String(text) => assert_eq!(text.as_bytes(), b"rmule-test"),
        _ => panic!("nickname tag must be string"),
    }
    match tags[1].value() {
        TagValue::U32(v) => assert_eq!(*v, 60),
        _ => panic!("version tag must be u32"),
    }
    match tags[2].value() {
        TagValue::U32(v) => assert_eq!(*v, server_capability_flags(&shipped_no_crypt())),
        _ => panic!("server-flags tag must be u32"),
    }
    match tags[3].value() {
        // aMule 2.3.3's own version word (SO_AMULE<<24 |
        // make_full_ed2k_version(2,3,3) = 0x0304_0D80, ServerConnect.cpp#L253);
        // rmule masquerades as this so Lugdunum's min-version gate accepts the
        // login rather than rejecting rmule's real 0.1.0.
        TagValue::U32(v) => assert_eq!(*v, 0x0304_0D80),
        _ => panic!("emule-version tag must be u32"),
    }
}

/// Registry derivation is never aspirational (ADR-0047): with crypt policy
/// off, the flags word lights exactly the shipped set — ZLIB (0xD4 inflate
/// ships), NEWTAGS (compact tag decode ships), UNICODE (byte-preserving
/// text), LARGEFILES (64-bit dispatch) — and keeps AUXPORT dark (the IDCHANGE
/// extension is unprojected) along with every crypt bit.
#[test]
fn server_flags_light_exactly_the_shipped_set() {
    assert_eq!(
        server_capability_flags(&shipped_no_crypt()),
        0x0001 | 0x0008 | 0x0010 | 0x0100,
        "ZLIB | NEWTAGS | UNICODE | LARGEFILES, nothing else"
    );
}

#[test]
fn server_flags_route_the_crypt_stance_ladder() {
    let base = server_capability_flags(&shipped_no_crypt());

    let supports = Capabilities::shipped(CryptStance::new(true, false, false));
    assert_eq!(server_capability_flags(&supports), base | 0x0200);

    let requests = Capabilities::shipped(CryptStance::new(true, true, false));
    assert_eq!(server_capability_flags(&requests), base | 0x0200 | 0x0400);

    let requires = Capabilities::shipped(CryptStance::new(true, true, true));
    assert_eq!(
        server_capability_flags(&requires),
        base | 0x0200 | 0x0400 | 0x0800
    );

    // The stance constructor collapses dishonest ladders before the
    // flags word can advertise them.
    let dishonest = Capabilities::shipped(CryptStance::new(false, true, true));
    assert_eq!(server_capability_flags(&dishonest), base);
}

/// Login-tag golden vector (ADR-0047 evidence): the full encoded login
/// packet, byte for byte — fixed fields, tagcount 4, and the two
/// capability tags in aMule's old-style (length-prefixed) tag encoding.
#[test]
fn login_packet_golden_vector() {
    let bytes = LoginRequest::from_identity(&sample_identity(), &shipped_no_crypt())
        .encode_packet()
        .encode();

    let mut expected = vec![
        0xE3, // PacketProtocol::Edonkey
    ];
    let payload: Vec<u8> = [
        // user hash
        &[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ][..],
        &0u32.to_le_bytes(), // client id placeholder
        &4662u16.to_le_bytes(),
        &4u32.to_le_bytes(), // tagcount
        // CT_NAME: string tag, length-prefixed id 0x01, "rmule-test"
        &[0x02, 0x01, 0x00, 0x01, 0x0A, 0x00],
        b"rmule-test",
        // CT_VERSION: u32 tag, id 0x11, EDONKEYVERSION 60
        &[0x03, 0x01, 0x00, 0x11, 0x3C, 0x00, 0x00, 0x00],
        // CT_SERVER_FLAGS: u32 tag, id 0x20, ZLIB|NEWTAGS|UNICODE|LARGEFILES
        &[0x03, 0x01, 0x00, 0x20, 0x19, 0x01, 0x00, 0x00],
        // CT_EMULE_VERSION: u32 tag, id 0xFB, aMule 2.3.3 parity word
        // 0x0304_0D80 (SO_AMULE<<24 | make_full_ed2k_version(2,3,3)), LE
        &[0x03, 0x01, 0x00, 0xFB, 0x80, 0x0D, 0x04, 0x03],
    ]
    .concat();
    expected.extend_from_slice(&(u32::try_from(payload.len() + 1).unwrap()).to_le_bytes());
    expected.push(0x01); // Opcode::LoginRequest
    expected.extend_from_slice(&payload);

    assert_eq!(bytes, expected);
}

#[test]
fn from_identity_drops_extra_tags_that_collide_with_canonical_login_tag_ids() {
    // `ClientIdentity` exposes `with_extra_tags` without filtering; the
    // collision defence lives in `from_identity` so the typed canonical
    // tags stay authoritative — including CT_PORT (0x0F), which must not
    // reappear on the wire via extras, and the registry-derived 0x20/0xFB.
    let identity = sample_identity().with_extra_tags(vec![
        Tag::new(
            TagName::length_prefixed_id(0x01),
            TagValue::String(Ed2kText::from_utf8("colliding-name")),
        ),
        Tag::new(TagName::compact_id(0x0F), TagValue::U32(4242)),
        Tag::new(TagName::compact_id(0x20), TagValue::U32(0xFFFF_FFFF)),
        Tag::new(TagName::compact_id(0xFB), TagValue::U32(0xDEAD_BEEF)),
        Tag::new(TagName::compact_id(0x99), TagValue::U32(7)),
    ]);

    let request = LoginRequest::from_identity(&identity, &shipped_no_crypt());
    let ids: Vec<_> = request.tags().iter().map(|t| t.name().id()).collect();
    assert_eq!(
        ids,
        vec![Some(0x01), Some(0x11), Some(0x20), Some(0xFB), Some(0x99)],
        "colliders dropped; only the non-colliding extra survives"
    );
    if let TagValue::String(text) = request.tags()[0].value() {
        assert_eq!(text.as_bytes(), b"rmule-test", "canonical nickname wins");
    } else {
        panic!("first tag must be string");
    }
    if let TagValue::U32(flags) = request.tags()[2].value() {
        assert_eq!(
            *flags,
            server_capability_flags(&shipped_no_crypt()),
            "registry-derived flags win over a smuggled 0x20"
        );
    } else {
        panic!("flags tag must be u32");
    }
}

#[test]
fn from_identity_preserves_non_utf8_nickname_bytes() {
    let identity = ClientIdentity::new(
        UserHash::from_hex("00112233445566778899AABBCCDDEEFF").unwrap(),
        Ed2kText::from_bytes(vec![0xff, 0xfe, b'h', b'i']),
        4662,
        60,
    );

    let bytes = LoginRequest::from_identity(&identity, &shipped_no_crypt())
        .encode_packet()
        .encode();
    let packet = Packet::decode_exact(&bytes).expect("decode packet");
    let decoded = LoginRequest::decode_packet(&packet).expect("decode login");

    match decoded.tags()[0].value() {
        TagValue::String(text) => assert_eq!(text.as_bytes(), &[0xff, 0xfe, b'h', b'i']),
        _ => panic!("nickname tag must be string"),
    }
}

/// ADR-0087 §4.1's fifth login tag and its coupled flag bit, from the spec's
/// own worked bytes (`01 01 00 AE` then sixteen raw address bytes).
///
/// Evidence: **deterministic tier only, awaiting a pinned IPv6 server.** The
/// one server implementing the dialect has no pinnable artefact — its `master`
/// carries no IPv6 at all and the last release predates the work — so these
/// bytes are the spec's, not a capture's. The row upgrades to captured when a pinned
/// ed2k-server build exists; eNode-go is the second oracle for the shared
/// login surface, which is why this row is *not* `single-oracle`.
#[test]
fn an_advertised_ipv6_rides_as_the_fifth_tag_with_its_flag_bit() {
    let address: std::net::Ipv6Addr = "2a01:4f8::1".parse().unwrap();
    let request = LoginRequest::from_identity_advertising(
        &sample_identity(),
        &shipped_no_crypt(),
        LoginAdvert {
            ipv6: Some(address),
            udp_ports: None,
        },
    );
    let tags = request.tags();
    let ids: Vec<_> = tags.iter().map(|t| t.name().id()).collect();
    assert_eq!(
        ids,
        vec![Some(0x01), Some(0x11), Some(0x20), Some(0xFB), Some(0xAE)],
        "the advert appends a fifth tag and reorders nothing"
    );

    // SRVCAP_IPV6 (0x1000) rides with it, and with nothing else changed.
    match tags[2].value() {
        TagValue::U32(flags) => assert_eq!(
            *flags,
            server_capability_flags(&shipped_no_crypt()) | 0x1000
        ),
        other => panic!("server-flags tag must be u32, got {other:?}"),
    }

    // `01 01 00 AE` + 16 raw bytes: TAGTYPE_HASH under a length-prefixed
    // numeric name, which is the only format a server can read before it has
    // parsed SRVCAP_NEWTAGS.
    let mut expected = vec![0x01, 0x01, 0x00, 0xAE];
    expected.extend_from_slice(&address.octets());
    assert_eq!(tags[4].encode(), expected);
}

/// The coupling is "send both or neither", and one input decides both — so
/// there is no representable state where the bit rides without the tag.
#[test]
fn without_an_advertised_ipv6_neither_the_tag_nor_the_bit_rides() {
    let request = LoginRequest::from_identity_advertising(
        &sample_identity(),
        &shipped_no_crypt(),
        LoginAdvert::default(),
    );
    assert_eq!(request.tags().len(), 4);
    assert!(
        request
            .tags()
            .iter()
            .all(|tag| tag.name().id() != Some(0xAE))
    );
    match request.tags()[2].value() {
        TagValue::U32(flags) => assert_eq!(*flags & 0x1000, 0),
        other => panic!("server-flags tag must be u32, got {other:?}"),
    }
}

/// An `extra_tags` caller cannot smuggle a `CT_MOD_IP_V6` past the coupling:
/// the tag would claim an address the flag bit never backed.
#[test]
fn an_extra_ct_mod_ip_v6_tag_is_dropped_like_every_other_canonical_id() {
    let smuggled = ClientIdentity::new(
        UserHash::from_hex("00112233445566778899AABBCCDDEEFF").unwrap(),
        Ed2kText::from_utf8("rmule-test"),
        4662,
        60,
    )
    .with_extra_tags(vec![Tag::new(
        TagName::length_prefixed_id(0xAE),
        TagValue::Hash([0x42; 16]),
    )]);
    let request = LoginRequest::from_identity(&smuggled, &shipped_no_crypt());
    assert_eq!(request.tags().len(), 4);
}

/// ADR-0091, ed2k-server's NAT-T contract. `0xF9` is `(kadUDP << 16) |
/// clientUDP` in the old length-prefixed tag format, and it rides after the
/// IPv6 advert so neither moves the other. Its *presence* is the capability
/// claim — the server refuses to introduce anyone to a client that sent none —
/// so a login built without it must stay byte for byte aMule's four tags, and
/// an `extra_tags` caller must not be able to make the claim from outside.
#[test]
fn the_udp_ports_advert_rides_last_and_only_when_given() {
    let ports = UdpPortsAdvert {
        kad_udp: 4672,
        client_udp: 4665,
    };
    let address: std::net::Ipv6Addr = "2a01:4f8::1".parse().unwrap();
    let request = LoginRequest::from_identity_advertising(
        &sample_identity(),
        &shipped_no_crypt(),
        LoginAdvert {
            ipv6: Some(address),
            udp_ports: Some(ports),
        },
    );
    let ids: Vec<_> = request.tags().iter().map(|t| t.name().id()).collect();
    assert_eq!(
        ids,
        vec![
            Some(0x01),
            Some(0x11),
            Some(0x20),
            Some(0xFB),
            Some(0xAE),
            Some(0xF9)
        ]
    );
    let tag = request.tags().last().expect("six tags");
    assert_eq!(tag.value(), &TagValue::U32(0x1240_1239));
    // Old format: type 0x03, name length 1, name 0xF9, then the u32.
    assert_eq!(
        tag.encode(),
        [0x03, 0x01, 0x00, 0xF9, 0x39, 0x12, 0x40, 0x12]
    );

    let plain = LoginRequest::from_identity(&sample_identity(), &shipped_no_crypt());
    assert!(plain.tags().iter().all(|t| t.name().id() != Some(0xF9)));
}
