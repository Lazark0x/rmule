//! Kad's two IPv6 tags (ADR-0087): `ip6` — a source's own address — and
//! `bi6` — its buddy's.
//!
//! They are **string** tags carrying exactly 32 ASCII hex characters,
//! MSB-first, and nothing else about Kad changes: no opcode, no version, no
//! contact format. Kad contacts themselves stay IPv4 end to end (ADR-0085's
//! invariant); these tags ride *inside* a source publish and a source result,
//! which is why a 128-bit address can appear on a network whose routing table
//! is 32-bit.
//!
//! ```text
//! 02 | 03 00 | 'i' 'p' '6' | 20 00 | <32 ASCII hex>     = 40 bytes
//! ```
//!
//! Two reader rules the spec states as MUSTs: parse **case-insensitively**,
//! and ignore any value whose length is not exactly 32. A shorter or longer
//! string is not a truncated address to be salvaged — it is a tag whose
//! meaning the writer and the reader do not share.
//!
//! rmule **writes** upper case, as the two writers that define the dialect do
//! — eMuleAI's `CUInt128::ToHexString` (`UInt128.h:170-182`, `a2f05dc8`) and
//! kno's `CMD4Hash::Encode` (captured, `amule-kno-ab483654-kad-ip6-20260923`)
//! — and as rmule's own `TAG_BUDDYHASH` on the same row already is. emule-qt
//! writes lower case (`QByteArray::toHex`); the reader rule is what lets every
//! spelling meet.

use std::net::Ipv6Addr;

use rmule_primitives::{Ed2kText, Tag, TagName, TagValue};

/// The tag naming a source's own IPv6.
pub const TAG_SOURCE_IPV6: &str = "ip6";

/// The tag naming a firewalled source's buddy's IPv6.
pub const TAG_BUDDY_IPV6: &str = "bi6";

/// How many characters the hex form has — 16 bytes, two characters each.
const HEX_LEN: usize = 32;

/// Write an address as the tag's 32 upper-case hex characters, MSB-first.
#[must_use]
pub fn encode_ipv6_hex(address: Ipv6Addr) -> String {
    address
        .octets()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

/// Read the tag's hex form, or `None` for anything that is not exactly 32 hex
/// characters. Case-insensitive, per the spec's MUST.
#[must_use]
pub fn decode_ipv6_hex(text: &str) -> Option<Ipv6Addr> {
    if text.len() != HEX_LEN {
        return None;
    }
    // Digit by digit, as `TAG_BUDDYHASH` is read: `u8::from_str_radix` would
    // take a `+` sign as the first character of a pair.
    crate::source_result::hex_md4(text).map(Ipv6Addr::from)
}

/// Build one of the two tags.
#[must_use]
pub(crate) fn ipv6_tag(name: &str, address: Ipv6Addr) -> Tag {
    Tag::new(
        TagName::text(name).expect("a three-character literal name"),
        TagValue::String(Ed2kText::from_utf8(encode_ipv6_hex(address))),
    )
}

/// Read the address out of a tag, when the tag is one of the two and its value
/// is a well-formed hex address.
#[must_use]
pub(crate) fn ipv6_from_tag(tag: &Tag, name: &str) -> Option<Ipv6Addr> {
    if tag.name().text_value() != Some(name) {
        return None;
    }
    match tag.value() {
        TagValue::String(text) => decode_ipv6_hex(&text.to_display_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tag's exact 40 bytes, and back.
    #[test]
    fn the_source_tag_is_forty_bytes_of_string_name_and_hex_value() {
        let address: Ipv6Addr = "2a01:4f8::1".parse().unwrap();
        let encoded = ipv6_tag(TAG_SOURCE_IPV6, address).encode();

        let mut expected = vec![0x02, 0x03, 0x00, b'i', b'p', b'6', 0x20, 0x00];
        expected.extend_from_slice(b"2A0104F8000000000000000000000001");
        assert_eq!(encoded, expected);
        assert_eq!(encoded.len(), 40);

        let tag = Tag::decode(&encoded).unwrap();
        assert_eq!(ipv6_from_tag(&tag, TAG_SOURCE_IPV6), Some(address));
        assert_eq!(
            ipv6_from_tag(&tag, TAG_BUDDY_IPV6),
            None,
            "the two tags are told apart by name, never by shape"
        );
    }

    /// Parsed case-insensitively; any length but 32 is ignored rather than
    /// salvaged.
    #[test]
    fn the_hex_form_is_case_insensitive_and_exactly_thirty_two_characters() {
        let address: Ipv6Addr = "2A01:4F8::1".parse().unwrap();
        assert_eq!(
            decode_ipv6_hex("2A0104F8000000000000000000000001"),
            Some(address)
        );
        assert_eq!(
            decode_ipv6_hex("2a0104f8000000000000000000000001"),
            Some(address)
        );

        assert_eq!(decode_ipv6_hex("2a0104f80000000000000000000000"), None);
        assert_eq!(decode_ipv6_hex("2a0104f80000000000000000000000012"), None);
        assert_eq!(decode_ipv6_hex(""), None);
        assert_eq!(decode_ipv6_hex("2a0104f800000000000000000000000z"), None);
        // A multi-byte character can make `len()` 32 with fewer than 32
        // characters; its bytes are no hex digits, so the byte-wise read
        // refuses it.
        assert_eq!(decode_ipv6_hex(&"é".repeat(16)), None);
        // A sign is not a hex digit: `from_str_radix` read
        // this as 20a:104:f08::1.
        assert_eq!(decode_ipv6_hex("+2+A+1+4+F+8+0+00000000000000001"), None);
    }
}
