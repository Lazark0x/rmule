//! The address gate on a source row's UDP endpoints. A buddy's
//! `TAG_SERVERIP` is the publisher's claim, relayed verbatim by any storer, so
//! both readers (`0x3B` and `0x44`) refuse any address that cannot be a remote
//! unicast host before it becomes somewhere rmule sends a `0x52` or a
//! rendezvous. eMuleAI's IPv6-buddy row, whose `TAG_SERVERIP` is a stand-in
//! and whose address rides `bi6`, keeps its endpoint in `buddy_udp_ipv6`.

use std::net::{Ipv4Addr, Ipv6Addr};

use rmule_kad::{
    Kad2Message, KadDecoded, KadEnvelope, KadInstant, KadSourceCandidate, decode_exact,
    decode_source_result,
};
use rmule_primitives::{Ed2kText, Ipv4Endpoint, Ipv6Endpoint, Tag, TagName, TagValue};
use rmule_testkit::drain_split;
use rmule_testkit::kad_source::{
    FILE_KEY, far_storer, key, lan_publisher, rows_answered_to, search_datagram, searcher,
};

const TAG_SOURCETYPE: u8 = 0xFF;
const TAG_SOURCEIP: u8 = 0xFE;
const TAG_SOURCEPORT: u8 = 0xFD;
const TAG_SOURCEUPORT: u8 = 0xFC;
const TAG_SERVERIP: u8 = 0xFB;
const TAG_SERVERPORT: u8 = 0xFA;
const TAG_BUDDYHASH: u8 = 0xF8;
const TAG_ENCRYPTION: u8 = 0xF3;

/// eMuleAI's `TAG_SERVERIP` for a buddy held over IPv6: `CAddress::ToUInt32`
/// returns `UINT_MAX` for an IPv6 address (eMuleAI `Address.cpp:91-92`), and
/// the publisher writes that value unchecked (`Search.cpp:886`).
const EMULEAI_IPV6_BUDDY_WORD: u32 = u32::MAX;
const BUDDY_PORT: u16 = 4672;
const BUDDY_IPV6: &str = "3fff:ed2:1::8";

fn int(name: u8, value: TagValue) -> Tag {
    Tag::new(TagName::length_prefixed_id(name), value)
}

/// `TAG_SERVERIP` as both families write it: the buddy's network-order word,
/// not byte-swapped (the reader hands it to `SendPacket` as is).
fn server_ip(ip: Ipv4Addr) -> Tag {
    int(TAG_SERVERIP, TagValue::U32(u32::from_le_bytes(ip.octets())))
}

fn buddy_hash() -> Tag {
    int(
        TAG_BUDDYHASH,
        TagValue::String(Ed2kText::from_utf8("C".repeat(32))),
    )
}

fn bi6(address: Ipv6Addr) -> Tag {
    Tag::new(
        TagName::text("bi6").unwrap(),
        TagValue::String(Ed2kText::from_utf8(rmule_kad::ipv6_tags::encode_ipv6_hex(
            address,
        ))),
    )
}

/// A one-row `0x3B` whose row carries exactly `tags`.
fn result_row(tags: &[Tag]) -> KadEnvelope {
    let mut payload = vec![0u8; 32];
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.extend_from_slice(&[0x5A; 16]);
    payload.push(u8::try_from(tags.len()).unwrap());
    for tag in tags {
        payload.extend_from_slice(&tag.encode());
    }
    KadEnvelope::plain(0x3B, payload)
}

/// A type-3 row as a storer re-serves it: the observed source, then the
/// publisher's buddy trio with `server_ip_tag` as its `TAG_SERVERIP`.
fn buddy_row(server_ip_tag: Tag, extra: &[Tag]) -> KadSourceCandidate {
    let mut tags = vec![
        int(
            TAG_SOURCEIP,
            TagValue::U32(u32::from_be_bytes([45, 55, 200, 7])),
        ),
        int(TAG_SOURCETYPE, TagValue::U8(3)),
        int(TAG_SOURCEPORT, TagValue::U16(4662)),
        int(TAG_SOURCEUPORT, TagValue::U16(4672)),
        server_ip_tag,
        int(TAG_SERVERPORT, TagValue::U16(BUDDY_PORT)),
        buddy_hash(),
    ];
    tags.extend_from_slice(extra);
    let rows = decode_source_result(&result_row(&tags)).unwrap();
    let [row] = rows.as_slice() else {
        panic!("one row: {rows:?}");
    };
    *row
}

/// A row that names loopback, link-local, multicast or broadcast as its
/// buddy keeps its buddy by ID but gets no endpoint, so the road is the
/// Callback Walk toward that ID and never a datagram to that address.
#[test]
fn a_buddy_row_naming_an_unusable_address_yields_no_buddy_endpoint() {
    for refused in [
        Ipv4Addr::LOCALHOST,
        Ipv4Addr::new(127, 9, 9, 9),
        Ipv4Addr::new(169, 254, 1, 1),
        Ipv4Addr::new(224, 0, 0, 1),
        Ipv4Addr::new(240, 0, 0, 1),
        Ipv4Addr::BROADCAST,
    ] {
        let row = buddy_row(server_ip(refused), &[]);
        // `buddy()` answers only for a buddy-reachable row: the walk stands.
        let buddy = row.buddy().expect("the hash still names a buddy");
        assert_eq!(buddy.buddy_udp, None, "{refused} is no buddy endpoint");
    }

    // A public address and a private one stay the endpoint (the private
    // ranges are a LAN policy no ADR has made).
    for admitted in [Ipv4Addr::new(45, 55, 200, 9), Ipv4Addr::new(10, 0, 0, 8)] {
        let buddy = buddy_row(server_ip(admitted), &[]).buddy().unwrap();
        assert_eq!(
            buddy.buddy_udp,
            Some(Ipv4Endpoint::new(admitted, BUDDY_PORT))
        );
    }
}

/// eMuleAI's firewalled publisher whose serving buddy is on IPv6 writes
/// `TAG_SERVERIP` = `UINT_MAX` and the buddy's address as `bi6`
/// (`Search.cpp:886-889`, `:920-923`); eMuleAI's reader pairs `bi6` with
/// `TAG_SERVERPORT` (`DownloadQueue.cpp:5005-5008`). The contact carries that
/// IPv6 endpoint and no IPv4 one.
#[test]
fn an_emuleai_ipv6_buddy_row_yields_the_bi6_endpoint() {
    let address: Ipv6Addr = BUDDY_IPV6.parse().unwrap();
    let row = buddy_row(
        int(TAG_SERVERIP, TagValue::U32(EMULEAI_IPV6_BUDDY_WORD)),
        &[int(TAG_ENCRYPTION, TagValue::U8(0x80)), bi6(address)],
    );

    let buddy = row.buddy().expect("the row names its buddy");
    assert_eq!(buddy.buddy_udp, None, "UINT_MAX is not an address");
    assert_eq!(
        buddy.buddy_udp_ipv6,
        Some(Ipv6Endpoint::new(address, BUDDY_PORT))
    );
    assert_eq!(buddy.buddy_ipv6, Some(address));
    assert_eq!(row.peer_source(), None, "`bi6` never rescues the row");
}

/// The type-6 `0x95` target is the storer's observation of the publish: an
/// address that cannot be one host is refused there too, while loopback (a
/// storer sharing a host with its publisher) stays an observation.
#[test]
fn a_type6_row_observed_at_a_non_unicast_address_has_no_callback_endpoint() {
    let row = |source_ip: Ipv4Addr| {
        let tags = [
            int(
                TAG_SOURCEIP,
                TagValue::U32(u32::from_be_bytes(source_ip.octets())),
            ),
            int(TAG_SOURCETYPE, TagValue::U8(6)),
            int(TAG_SOURCEPORT, TagValue::U16(4662)),
            int(TAG_SOURCEUPORT, TagValue::U16(4672)),
            int(TAG_ENCRYPTION, TagValue::U8(0x08)),
        ];
        decode_source_result(&result_row(&tags)).unwrap()[0]
    };

    for refused in [Ipv4Addr::BROADCAST, Ipv4Addr::new(239, 1, 1, 1)] {
        let candidate = row(refused);
        assert_eq!(candidate.facts().and_then(|facts| facts.kad_udp), None);
        assert_eq!(candidate.direct_udp_callback(), None, "{refused}");
    }
    assert_eq!(
        row(Ipv4Addr::LOCALHOST).direct_udp_callback(),
        Some(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4672))
    );
}

/// A `0x44` in eMuleAI's firewalled order (`Search.cpp:884-923`) naming
/// `server_ip_tag` as its buddy, closing with `bi6`.
fn emuleai_publish(server_ip_tag: Tag) -> Vec<u8> {
    let tags = [
        int(TAG_SOURCETYPE, TagValue::U8(3)),
        server_ip_tag,
        int(TAG_SERVERPORT, TagValue::U16(BUDDY_PORT)),
        buddy_hash(),
        int(TAG_SOURCEPORT, TagValue::U16(4662)),
        int(TAG_ENCRYPTION, TagValue::U8(0x80)),
        bi6(BUDDY_IPV6.parse().unwrap()),
    ];
    let mut payload = FILE_KEY.to_vec();
    payload.extend_from_slice(&[0xB3; 16]);
    payload.push(u8::try_from(tags.len()).unwrap());
    for tag in &tags {
        payload.extend_from_slice(&tag.encode());
    }
    KadEnvelope::plain(0x44, payload).encode()
}

/// The storer's reader applies the same gate, so a hostile publish cannot
/// seed the index with a loopback buddy that every searcher is then served.
/// An eMuleAI IPv6-buddy publish goes back out as `TAG_SERVERPORT` beside
/// `bi6` and without the `UINT_MAX` stand-in: an eMuleAI searcher gets the
/// endpoint its publisher wrote, and an aMule one reads IP 0 and walks.
#[test]
fn a_storer_indexes_no_unusable_buddy_endpoint_and_re_serves_an_emuleai_ipv6_buddy() {
    let KadDecoded::Plain(envelope) =
        decode_exact(&emuleai_publish(server_ip(Ipv4Addr::LOCALHOST))).unwrap()
    else {
        panic!("a plain vector");
    };
    let Ok(Kad2Message::PublishSourceReq { source, .. }) = Kad2Message::decode(&envelope) else {
        panic!("a well-formed publish decodes");
    };
    let buddy = source.buddy.expect("the hash names a buddy");
    assert_eq!(buddy.buddy_udp, None, "loopback is never indexed");

    let now = KadInstant::EPOCH;
    let mut node = far_storer();
    let publish = emuleai_publish(int(TAG_SERVERIP, TagValue::U32(EMULEAI_IPV6_BUDDY_WORD)));
    node.handle_datagram(now, lan_publisher(7), &publish);
    let _ = drain_split(&mut node);
    node.handle_datagram(now, searcher(), &search_datagram(key(), 0, 0));
    let (datagrams, _) = drain_split(&mut node);

    let [(_, bytes)] = datagrams.as_slice() else {
        panic!("one row, one answer: {datagrams:?}");
    };
    let stand_in = server_ip(Ipv4Addr::BROADCAST).encode();
    assert!(
        !bytes.windows(stand_in.len()).any(|w| w == stand_in),
        "the UINT_MAX stand-in is not re-served: {bytes:02X?}"
    );
    let rows = rows_answered_to(&datagrams, searcher());
    let buddy = rows[0].buddy().expect("the row keeps its buddy");
    assert_eq!(buddy.buddy_udp, None);
    assert_eq!(
        buddy.buddy_udp_ipv6,
        Some(Ipv6Endpoint::new(BUDDY_IPV6.parse().unwrap(), BUDDY_PORT)),
        "the port rides back out beside `bi6`"
    );
}
