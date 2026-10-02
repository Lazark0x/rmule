//! Tag encoding both ways: every name encoding and value width round-trips,
//! a compact uint narrows to its smallest width, and a truncated or unknown
//! tag is rejected rather than guessed at.

use rmule_primitives::{Tag, TagName, TagNameEncoding, TagValue};

#[test]
fn u32_tag_with_numeric_name_round_trips() {
    let bytes = [0x83, 0x01, 0x2A, 0x00, 0x00, 0x00];
    let tag = Tag::decode(&bytes).unwrap();
    assert_eq!(tag.name(), &TagName::compact_id(0x01));
    assert_eq!(tag.value(), &TagValue::U32(42));
    assert_eq!(tag.encode(), bytes);
}

#[test]
fn string_tag_with_text_name_round_trips() {
    let bytes = [
        0x02, 0x04, 0x00, b'n', b'a', b'm', b'e', 0x05, 0x00, b'h', b'e', b'l', b'l', b'o',
    ];
    let tag = Tag::decode(&bytes).unwrap();
    assert_eq!(tag.name(), &TagName::text("name").unwrap());
    let TagValue::String(text) = tag.value() else {
        panic!("expected string tag value");
    };
    assert_eq!(text.as_bytes(), b"hello");
    assert_eq!(tag.encode(), bytes);
}

#[test]
fn u32_tag_with_length_prefixed_numeric_name_round_trips_without_normalization() {
    let bytes = [0x03, 0x01, 0x00, 0x11, 0x3c, 0x00, 0x00, 0x00];
    let tag = Tag::decode(&bytes).unwrap();
    assert_eq!(tag.name().id(), Some(0x11));
    assert_eq!(tag.name().encoding(), TagNameEncoding::LengthPrefixed);
    assert_eq!(tag.value(), &TagValue::U32(60));
    assert_eq!(tag.encode(), bytes);
}

#[test]
fn u32_tag_with_compact_numeric_name_round_trips_without_normalization() {
    let bytes = [0x83, 0x11, 0x3c, 0x00, 0x00, 0x00];
    let tag = Tag::decode(&bytes).unwrap();
    assert_eq!(tag.name().id(), Some(0x11));
    assert_eq!(tag.name().encoding(), TagNameEncoding::Compact);
    assert_eq!(tag.value(), &TagValue::U32(60));
    assert_eq!(tag.encode(), bytes);
}

#[test]
fn tag_decode_prefix_reports_consumed_length() {
    let bytes = [0x83, 0x11, 0x3c, 0x00, 0x00, 0x00, 0xaa];
    let (tag, consumed) = Tag::decode_prefix(&bytes).unwrap();
    assert_eq!(tag.name().id(), Some(0x11));
    assert_eq!(consumed, 6);
}

#[test]
fn truncated_string_tag_is_rejected() {
    let bytes = [0x02, 0x04, 0x00, b'n', b'a', b'm', b'e', 0x05, 0x00, b'h'];
    assert!(Tag::decode(&bytes).is_err());
}

#[test]
fn unsupported_tag_type_is_rejected() {
    // 0x84 = compact name flag | TAGTYPE_FLOAT32 (0x04). FLOAT32 is not
    // implemented and is not part of the STR<N> compact-string range,
    // so it must remain a hard reject.
    let bytes = [0x84, 0x01, 0x00, 0x00, 0x00, 0x00];
    assert!(Tag::decode(&bytes).is_err());
}

#[test]
fn compact_string_str11_tag_decodes_as_string_value() {
    // Lugdunum-era servers ship short string tags using TAGTYPE_STR<N>
    // (0x11..=0x20), where the type byte encodes the string length
    // directly (no u16 prefix). Wire sample captured 2026-05-19 from
    // 171.25.158.106:4661 — server name "Test_server" as STR11.
    let bytes = [
        0x9B, 0x01, b'T', b'e', b's', b't', b'_', b's', b'e', b'r', b'v', b'e', b'r',
    ];
    let tag = Tag::decode(&bytes).unwrap();
    assert_eq!(tag.name(), &TagName::compact_id(0x01));
    let TagValue::String(text) = tag.value() else {
        panic!("expected string tag value");
    };
    assert_eq!(text.as_bytes(), b"Test_server");
}

#[test]
fn u16_tag_with_compact_numeric_name_round_trips() {
    // TAGTYPE_UINT16 (0x08) | compact-name flag (0x80) = 0x88; name 0x3A
    // (FT_FILESIZE_HI); value 1 as little-endian u16. This is the
    // large-file high-size tag OP_OFFERFILES emits for files > 4 GiB.
    let bytes = [0x88, 0x3A, 0x01, 0x00];
    let tag = Tag::decode(&bytes).unwrap();
    assert_eq!(tag.name(), &TagName::compact_id(0x3A));
    assert_eq!(tag.value(), &TagValue::U16(1));
    assert_eq!(tag.encode(), bytes);
}

#[test]
fn u8_tag_with_compact_numeric_name_round_trips() {
    // Lugdunum OP_SEARCHRESULT rows encode short source-count style
    // descriptor tags as TAGTYPE_UINT8 (0x09) with compact numeric
    // names: 0x89, tag id, one-byte value.
    let bytes = [0x89, 0x15, 0x01];
    let tag = Tag::decode(&bytes).unwrap();
    assert_eq!(tag.name(), &TagName::compact_id(0x15));
    assert_eq!(tag.value(), &TagValue::U8(1));
    assert_eq!(tag.encode(), bytes);
}

#[test]
fn compact_uint_narrows_to_the_smallest_width_at_each_boundary() {
    // eMule/aMule's CTag::WriteTagToFile narrows an integer tag by magnitude;
    // the boundaries are what a byte-for-byte Kad emit rides (SOURCES 0 -> u8,
    // FILESIZE 65536 -> u32 in the captured aMule 0x43).
    assert_eq!(TagValue::compact_uint(0), TagValue::U8(0));
    assert_eq!(TagValue::compact_uint(255), TagValue::U8(255));
    assert_eq!(TagValue::compact_uint(256), TagValue::U16(256));
    assert_eq!(TagValue::compact_uint(65_535), TagValue::U16(65_535));
    assert_eq!(TagValue::compact_uint(65_536), TagValue::U32(65_536));
}

#[test]
fn compact_uint64_narrows_to_the_smallest_width_at_each_boundary() {
    // aMule's CTagVarInt::SizedInit ladder (Tag.h:186-195, Fork Pin
    // ab483654): <= 0xFF -> UINT8, <= 0xFFFF -> UINT16, <= 0xFFFFFFFF ->
    // UINT32, else UINT64. Kad's TAG_FILESIZE rides this past
    // u32::MAX, where TagValue::compact_uint has no room left to narrow into.
    assert_eq!(TagValue::compact_uint64(0), TagValue::U8(0));
    assert_eq!(TagValue::compact_uint64(255), TagValue::U8(255));
    assert_eq!(TagValue::compact_uint64(256), TagValue::U16(256));
    assert_eq!(TagValue::compact_uint64(65_535), TagValue::U16(65_535));
    assert_eq!(TagValue::compact_uint64(65_536), TagValue::U32(65_536));
    assert_eq!(
        TagValue::compact_uint64(u32::MAX as u64),
        TagValue::U32(u32::MAX)
    );
    assert_eq!(
        TagValue::compact_uint64(u32::MAX as u64 + 1),
        TagValue::U64(u32::MAX as u64 + 1)
    );
    assert_eq!(TagValue::compact_uint64(u64::MAX), TagValue::U64(u64::MAX));
}

/// `TAGTYPE_UINT64` (`0x0B`) — the eight-byte width `TAG_FILESIZE` widens to
/// past 4 GiB. No aMule capture carries one yet (ADR-0061,
/// `[capture pending]`); this vector is handwritten from `Tag.h`'s
/// `CTagVarInt` layout, documentation provenance like the file's other
/// handwritten vectors.
#[test]
fn u64_tag_round_trips() {
    let bytes = [0x8B, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
    let tag = Tag::decode(&bytes).unwrap();
    assert_eq!(tag.name(), &TagName::compact_id(0x02));
    assert_eq!(tag.value(), &TagValue::U64(u32::MAX as u64 + 1));
    assert_eq!(tag.encode(), bytes);
}

/// `TAGTYPE_HASH` (`0x01`) — 16 raw bytes with no length prefix, the form the
/// IPv6 dialect's four address tags ride in (ADR-0087). The KAT is the spec's
/// own worked `CT_MOD_IP_V6` hex: type `01`, a length-prefixed one-byte name
/// `AE`, then the address MSB-first.
#[test]
fn hash_tag_carries_sixteen_raw_bytes_under_the_length_prefixed_name() {
    let mut bytes = vec![0x01, 0x01, 0x00, 0xAE];
    let address = [
        0x2a, 0x01, 0x04, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ];
    bytes.extend_from_slice(&address);

    let tag = Tag::decode(&bytes).unwrap();
    assert_eq!(tag.name().id(), Some(0xAE));
    assert_eq!(tag.name().encoding(), TagNameEncoding::LengthPrefixed);
    assert_eq!(tag.value(), &TagValue::Hash(address));
    assert_eq!(tag.encode(), bytes);
}

/// The same value under the compact name spelling — `81 ae …`, the form the
/// ExtSX record's worked example carries (ADR-0087).
#[test]
fn hash_tag_round_trips_under_the_compact_name_too() {
    let mut bytes = vec![0x81, 0xAE];
    let address = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x07,
    ];
    bytes.extend_from_slice(&address);

    let tag = Tag::decode(&bytes).unwrap();
    assert_eq!(tag.name(), &TagName::compact_id(0xAE));
    assert_eq!(tag.value(), &TagValue::Hash(address));
    assert_eq!(tag.encode(), bytes);
}

/// A hash tag that stops short is a truncation, never a short address read as
/// whatever follows it — the failure mode the dialect's own implementers hit
/// when they wrote the tag as `TAGTYPE_BLOB`.
#[test]
fn a_truncated_hash_tag_is_rejected() {
    let bytes = [0x01, 0x01, 0x00, 0xAE, 0x2a, 0x01, 0x04];
    assert!(Tag::decode(&bytes).is_err());
}

/// Made bytes, not a capture: two compact `UINT8` tags under a count of
/// `u32::MAX`. The reservation follows the bytes (two slots), and the walk
/// fails on the third, missing tag.
#[test]
fn a_tag_block_reserves_by_its_bytes_not_by_its_claimed_count() {
    let bytes = [0x89, 0x11, 0x3C, 0x89, 0x20, 0x07];
    let claimed = u32::MAX as usize;

    assert_eq!(Tag::block_capacity(claimed, &bytes), 2);
    assert!(Tag::decode_block(&bytes, claimed).is_err());

    let (tags, used) = Tag::decode_block(&bytes, 2).unwrap();
    assert_eq!((tags.len(), used), (2, bytes.len()));
}
