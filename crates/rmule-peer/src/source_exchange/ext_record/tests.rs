//! The ExtSX record against the spec's own worked hex, plus the three rules
//! that make it different from a classic entry: no fixed size, unknown tags
//! skipped, the two families judged apart.

use std::net::{Ipv4Addr, Ipv6Addr};

use rmule_primitives::{
    ClientId, ExchangedSource, Ipv4Endpoint, Ipv6Endpoint, PeerSource, SourceCryptOptions, Tag,
    TagName, TagValue, UserHash,
};

use super::{ExtSourceRecordError, ExtSxEmission, decode_ext_records, encode_ext_record};
use crate::source_exchange::SourceExchangeEntry;

/// The spec's worked record: source `10.0.0.1:4662`, server `1.2.3.4:4661`,
/// IPv6 `2a01:4f8::1`.
fn worked_bytes() -> Vec<u8> {
    let mut bytes = vec![
        0x0a, 0x00, 0x00, 0x01, // clientID — the octets in wire order
        0x36, 0x12, // tcpPort 4662, little-endian
        0x03, // tagCount
        0x83, 0xba, 0x01, 0x02, 0x03, 0x04, // CT_EMULE_SERVERIP,  UINT32
        0x88, 0xbb, 0x35, 0x12, // CT_EMULE_SERVERTCP, UINT16
        0x81, 0xae, // CT_MOD_IP_V6, HASH16
    ];
    bytes.extend_from_slice(&"2a01:4f8::1".parse::<Ipv6Addr>().unwrap().octets());
    bytes
}

/// The worked example decodes to exactly the source, server and address it
/// describes. The `clientID` field is the dotted octets in wire order — the
/// spec spells it `htonl(userIDHybrid)`, and `0a 00 00 01` is `10.0.0.1` only
/// under that reading, never under a second byte swap.
#[test]
fn the_specs_worked_record_decodes_to_the_source_it_describes() {
    let records = decode_ext_records(&worked_bytes(), 1).unwrap();
    let [record] = records.as_slice() else {
        panic!("one record");
    };

    assert_eq!(
        record.source().peer_source(),
        PeerSource::HighId(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 1), 4662))
    );
    assert_eq!(
        record.server(),
        Some(Ipv4Endpoint::new(Ipv4Addr::new(1, 2, 3, 4), 4661))
    );
    assert_eq!(
        record.ipv6(),
        Some(Ipv6Endpoint::new("2a01:4f8::1".parse().unwrap(), 4662)),
        "one port pair serves both families"
    );
}

/// And re-encodes byte-for-byte: the widths the spec shows are the widths
/// eMule's own integer narrowing produces.
#[test]
fn the_specs_worked_record_re_encodes_byte_for_byte() {
    let records = decode_ext_records(&worked_bytes(), 1).unwrap();
    let mut out = Vec::new();
    encode_ext_record(&mut out, records[0], ExtSxEmission::default());
    assert_eq!(out, worked_bytes());
}

/// A record with no fixed size cannot be validated by `count × stride`, so the
/// guards are the walk's own bounds and the requirement that it end exactly
/// where the body does.
#[test]
fn a_truncated_record_and_a_trailing_tail_are_both_refused() {
    let full = worked_bytes();
    let short = &full[..full.len() - 4];
    assert!(matches!(
        decode_ext_records(short, 1),
        Err(ExtSourceRecordError::Truncated { .. })
    ));

    let mut with_tail = full.clone();
    with_tail.extend_from_slice(&[0xFF, 0xFF]);
    assert_eq!(
        decode_ext_records(&with_tail, 1),
        Err(ExtSourceRecordError::TrailingBytes {
            count: 1,
            remaining: 2
        })
    );

    // A count larger than the body can hold runs out rather than allocating
    // for it.
    assert!(matches!(
        decode_ext_records(&full, 500),
        Err(ExtSourceRecordError::Truncated { .. })
    ));
}

/// One unrecognised tag costs that tag and nothing else — the eMuleAI bug
/// `MODMISC_EXTXS_SKIPTAGS` exists to work around. Two records, the unknown
/// tag in the first: the second still arrives.
#[test]
fn an_unknown_tag_is_skipped_by_type_and_the_rest_of_the_packet_survives() {
    let unknown = Tag::new(TagName::compact_id(0x77), TagValue::U32(0xDEAD_BEEF)).encode();
    let mut body = Vec::new();
    // First record: the worked one with a fourth, unrecognised tag.
    let mut first = worked_bytes();
    first[6] = 4;
    first.extend_from_slice(&unknown);
    body.extend_from_slice(&first);
    // Second record: a plain High ID, no tags.
    body.extend_from_slice(&[0x0b, 0x00, 0x00, 0x02, 0x36, 0x12, 0x00]);

    let records = decode_ext_records(&body, 2).unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records[0].ipv6().map(|it| it.ip),
        "2a01:4f8::1".parse().ok()
    );
    assert_eq!(
        records[1].source().peer_source(),
        PeerSource::HighId(Ipv4Endpoint::new(Ipv4Addr::new(11, 0, 0, 2), 4662))
    );
}

/// rmule claims `MODMISC_EXTXS_SKIPTAGS`, so every tag type eD2k
/// defines — not only the six a `TagValue` models — costs that tag alone.
/// Sizes per eMule `CTag` (eMuleAI `Packets.cpp:483-511`) and emule-qt
/// `Tag.cpp:172-201`.
#[test]
fn every_defined_tag_type_is_skipped_by_its_width() {
    let unmodelled: [&[u8]; 6] = [
        &[0x84, 0x77, 0x00, 0x00, 0x80, 0x3f],          // FLOAT32 1.0
        &[0x85, 0x78, 0x01],                            // BOOL
        &[0x86, 0x79, 0x0a, 0x00, 0xff, 0x03],          // BOOLARRAY, 10 bits: 10/8+1 bytes
        &[0x87, 0x7a, 0x03, 0x00, 0x00, 0x00, 1, 2, 3], // BLOB, 3 bytes
        &[0x8a, 0x7b, 0x02, 0xaa, 0xbb],                // BSOB, 2 bytes
        &[
            0xa1, 0x7c, b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'a', b'b',
            b'c', b'd', b'e', b'f', b'g',
        ], // STR17
    ];
    for tag in unmodelled {
        let mut first = worked_bytes();
        first[6] = 4;
        first.extend_from_slice(tag);
        let mut body = first;
        body.extend_from_slice(&[0x0b, 0x00, 0x00, 0x02, 0x36, 0x12, 0x00]);

        let records = decode_ext_records(&body, 2).unwrap_or_else(|error| {
            panic!("type 0x{:02x} dropped the answer: {error}", tag[0] & 0x7f)
        });
        assert_eq!(
            records[0].ipv6().map(|it| it.ip),
            "2a01:4f8::1".parse().ok()
        );
        assert_eq!(
            records[1].source().peer_source(),
            PeerSource::HighId(Ipv4Endpoint::new(Ipv4Addr::new(11, 0, 0, 2), 4662))
        );
    }

    // A type eD2k does not define has no width: that ends the walk, and says so.
    let mut undefined = worked_bytes();
    undefined[6] = 4;
    undefined.extend_from_slice(&[0x8c, 0x7d, 0x00]);
    assert_eq!(
        decode_ext_records(&undefined, 1),
        Err(ExtSourceRecordError::UnknownTagType { tag_type: 0x0c })
    );
}

/// The server pair is read together: an address with no port, or a port with
/// no address, names no server a Low-ID routing rule could use.
#[test]
fn a_server_pair_with_one_half_zero_names_no_server() {
    for (ip, port) in [([1u8, 2, 3, 4], 0u16), ([0, 0, 0, 0], 4661)] {
        let mut bytes = vec![0x07, 0x00, 0x00, 0x00, 0x36, 0x12, 0x02];
        bytes.extend_from_slice(&[0x83, 0xba]);
        bytes.extend_from_slice(&ip);
        bytes.extend_from_slice(&[0x88, 0xbb]);
        bytes.extend_from_slice(&port.to_le_bytes());
        let records = decode_ext_records(&bytes, 1).unwrap();
        assert_eq!(records[0].server(), None, "{ip:?}:{port}");
    }
}

/// The two families are judged independently. A Low-ID source with a usable
/// IPv6 survives — the exact inverse of the classic Low-ID rule — and an
/// unusable tag address costs the record only its IPv6 half.
#[test]
fn a_low_id_source_keeps_a_usable_ipv6_and_loses_an_unusable_one() {
    let with_v6 = entry_bytes(ClientId::from_u32(42), 4662, Some("2001:db8::5"));
    let records = decode_ext_records(&with_v6, 1).unwrap();
    assert_eq!(
        records[0].source().peer_source(),
        PeerSource::LowId {
            id: ClientId::from_u32(42),
            port: 4662
        },
        "the Low ID stands; the classic callback rule applies to it alone"
    );
    assert_eq!(
        records[0].ipv6().map(|it| it.ip),
        "2001:db8::5".parse().ok()
    );

    let link_local = entry_bytes(ClientId::from_u32(42), 4662, Some("fe80::5"));
    let records = decode_ext_records(&link_local, 1).unwrap();
    assert_eq!(records[0].ipv6(), None, "a scope-less tag cannot name it");
}

/// An IPv6-only source has no ed2k wire form, so its id field takes the
/// **Placeholder Low ID** rather than a `0` that would read as a Low ID with
/// no server to broker it. It round-trips back to the one IPv6 representation
/// the sentinel reader also produces.
#[test]
fn an_ipv6_only_source_round_trips_through_the_placeholder_low_id() {
    let endpoint = Ipv6Endpoint::new("2a01:4f8::9".parse().unwrap(), 4662);
    let entry = SourceExchangeEntry::plain(ExchangedSource::plain(PeerSource::Ipv6(endpoint)));

    let mut out = Vec::new();
    encode_ext_record(&mut out, entry, ExtSxEmission::default());
    assert_eq!(
        &out[..4],
        &ClientId::IPV6_ONLY_PLACEHOLDER.as_u32().to_le_bytes(),
        "never a bare zero"
    );

    let records = decode_ext_records(&out, 1).unwrap();
    assert_eq!(
        records[0].source().peer_source(),
        PeerSource::Ipv6(endpoint)
    );
    assert_eq!(records[0].ipv6(), Some(endpoint));
}

/// The optional identity tags are emission-gated on the peer's `SKIPTAGS`
/// claim and accepted from anybody — a receiver never punishes a sender for
/// tags it did not ask for.
#[test]
fn the_optional_identity_tags_are_gated_on_emit_and_accepted_on_read() {
    let source = ExchangedSource::new(
        PeerSource::HighId(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 1), 4662)),
        Some(UserHash::from_bytes([0x3C; UserHash::BYTE_LEN])),
        Some(SourceCryptOptions::from_byte(0x05)),
    );
    let entry = SourceExchangeEntry::plain(source);

    let mut ungated = Vec::new();
    encode_ext_record(&mut ungated, entry, ExtSxEmission::default());
    assert_eq!(
        ungated[6], 0,
        "a peer that never claimed SKIPTAGS gets none"
    );

    let mut gated = Vec::new();
    encode_ext_record(&mut gated, entry, ExtSxEmission { skip_tags: true });
    assert_eq!(gated[6], 2);

    // Read back from anyone, claim or no claim.
    let records = decode_ext_records(&gated, 1).unwrap();
    assert_eq!(records[0].user_hash(), source.user_hash());
    assert_eq!(records[0].crypt_options(), source.crypt_options());
}

/// A record with the given id, port and optional IPv6 tag.
fn entry_bytes(id: ClientId, port: u16, ipv6: Option<&str>) -> Vec<u8> {
    let mut bytes = id.as_u32().to_le_bytes().to_vec();
    bytes.extend_from_slice(&port.to_le_bytes());
    match ipv6 {
        None => bytes.push(0),
        Some(text) => {
            bytes.push(1);
            bytes.extend_from_slice(&[0x81, 0xae]);
            bytes.extend_from_slice(&text.parse::<Ipv6Addr>().unwrap().octets());
        }
    }
    bytes
}
