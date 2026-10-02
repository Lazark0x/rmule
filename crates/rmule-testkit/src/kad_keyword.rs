//! The shared vocabulary of the Kad keyword-store tests: the keyword and file
//! identities every suite publishes under, the tag builders that shape a
//! publish row, and the publish helper that drives one batch into a store.

use std::net::Ipv4Addr;

use rmule_kad::keyword_store::{
    KeywordPublishFile, KeywordPublishOutcome, KeywordStore, decode_publish_key_req,
};
use rmule_kad::{KadEnvelope, KadId, KadInstant};
use rmule_primitives::{Ed2kText, Tag, TagName, TagValue};

/// The keyword every suite publishes under, as raw bytes.
pub const KEYWORD_BYTES: [u8; 16] = [0xA0; 16];
/// The storing node's own ID, as raw bytes, chosen to sit *inside* the
/// tolerance gate for [`KEYWORD_BYTES`].
///
/// The gate only compares the top 32-bit word (the first four bytes,
/// little-endian): identical there keeps the XOR distance zero regardless of
/// the rest, so a WAN sender always clears SEARCHTOLERANCE against
/// [`keyword`].
pub const OWN_ID_BYTES: [u8; 16] = [
    0xA0, 0xA0, 0xA0, 0xA0, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1,
];

/// The keyword ID every suite publishes under.
pub fn keyword() -> KadId {
    KadId::from_bytes(KEYWORD_BYTES)
}

/// The storing node's own ID — near enough to [`keyword`] that a WAN publish
/// clears the tolerance gate.
pub fn own_id() -> KadId {
    KadId::from_bytes(OWN_ID_BYTES)
}

/// A storing-node ID *outside* the tolerance gate: it differs from
/// [`keyword`] in the top 32-bit word, so a non-LAN sender's publish is
/// refused. The counterpart of [`own_id`].
pub fn far_own_id() -> KadId {
    KadId::from_bytes([0x5F; 16])
}

/// A published file's ID, one repeated byte, so rows stay distinguishable in a
/// failure message.
pub fn file_id(byte: u8) -> KadId {
    KadId::from_bytes([byte; 16])
}

/// A routable publisher address (documentation range): subject to the
/// tolerance gate and to the per-IP publish caps.
pub fn wan_ip(last: u8) -> Ipv4Addr {
    Ipv4Addr::new(198, 51, 100, last)
}

/// An RFC1918 publisher address: takes the LAN bypass around the tolerance
/// gate.
pub fn lan_ip(last: u8) -> Ipv4Addr {
    Ipv4Addr::new(10, 0, 0, last)
}

/// The `FILENAME` tag (`0x01`) — one of the two the accept path types rather
/// than keeping verbatim.
pub fn name_tag(name: &str) -> Tag {
    Tag::new(
        TagName::length_prefixed_id(0x01),
        TagValue::String(Ed2kText::from_utf8(name.to_owned())),
    )
}

/// The `FILESIZE` tag (`0x02`) — the other typed tag the accept path reads.
pub fn size_tag(size: u32) -> Tag {
    Tag::new(TagName::length_prefixed_id(0x02), TagValue::U32(size))
}

/// Any other tag by numeric ID: the store must carry it through untouched,
/// which is what "rest verbatim" means.
pub fn verbatim_tag(id: u8, value: TagValue) -> Tag {
    Tag::new(TagName::length_prefixed_id(id), value)
}

/// One publish row: name and size tags plus whatever `extra` the leg needs,
/// round-tripped through the real codec by [`decode_publish_file_from_tags`].
pub fn publish_file(id: u8, name: &str, size: u32, extra: Vec<Tag>) -> KeywordPublishFile {
    let mut tags = vec![name_tag(name), size_tag(size)];
    tags.extend(extra);
    decode_publish_file_from_tags(id, tags)
}

/// Round-trips through the real wire encode/decode rather than constructing
/// `KeywordPublishFile` fields directly, so every test exercises the same
/// FILENAME/FILESIZE-typed, rest-verbatim split the accept path performs.
pub fn decode_publish_file_from_tags(id: u8, tags: Vec<Tag>) -> KeywordPublishFile {
    let mut payload = Vec::new();
    payload.extend_from_slice(file_id(id).as_bytes());
    payload.push(u8::try_from(tags.len()).unwrap());
    for tag in &tags {
        payload.extend_from_slice(&tag.encode());
    }
    let (keyword, mut files) = decode_publish_key_req(&publish_envelope(keyword(), payload, 1))
        .expect("well-formed single-file publish decodes");
    assert_eq!(keyword, self::keyword());
    files.remove(0)
}

/// A `KADEMLIA2_PUBLISH_KEY_REQ` (`0x43`) envelope over pre-encoded
/// `file_rows`. `count` is written as sent, so a leg can claim a count the
/// rows do not match and assert what the decoder does about it.
pub fn publish_envelope(keyword: KadId, mut file_rows: Vec<u8>, count: u16) -> KadEnvelope {
    let mut payload = Vec::new();
    payload.extend_from_slice(keyword.as_bytes());
    payload.extend_from_slice(&count.to_le_bytes());
    payload.append(&mut file_rows);
    KadEnvelope::plain(0x43, payload)
}

/// Drive one publish batch into `store` from `from`, as a non-LAN sender under
/// [`own_id`] and [`keyword`]. The outcome carries the per-row verdicts.
pub fn publish(
    store: &mut KeywordStore,
    now: KadInstant,
    from: Ipv4Addr,
    files: Vec<KeywordPublishFile>,
) -> KeywordPublishOutcome {
    store.publish_batch(now, own_id(), false, from, keyword(), files)
}

/// Helper used by the cap-filling tests: builds a decoded publish file for an
/// arbitrary caller-chosen `KadId`, still routed through the real tag codec.
pub fn decode_publish_file_with_id(id: KadId, name: &str, size: u32) -> KeywordPublishFile {
    let tags = vec![name_tag(name), size_tag(size)];
    let mut payload = Vec::new();
    payload.extend_from_slice(id.as_bytes());
    payload.push(u8::try_from(tags.len()).unwrap());
    for tag in &tags {
        payload.extend_from_slice(&tag.encode());
    }
    let (_, mut files) = decode_publish_key_req(&publish_envelope(keyword(), payload, 1)).unwrap();
    files.remove(0)
}
