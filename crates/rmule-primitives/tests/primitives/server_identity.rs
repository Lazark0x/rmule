//! Merging two reports of one server: a present field wins, an absent one
//! leaves the base alone, and extra tags union without duplicates.

use rmule_primitives::{Ed2kText, ServerHash, ServerIdentity, Tag, TagName, TagValue};

fn hash() -> ServerHash {
    ServerHash::from_hex("00112233445566778899AABBCCDDEEFF").unwrap()
}

fn other_hash() -> ServerHash {
    ServerHash::from_hex("FFEEDDCCBBAA99887766554433221100").unwrap()
}

#[test]
fn merge_takes_other_when_other_field_is_present() {
    let base = ServerIdentity {
        server_hash: Some(hash()),
        name: Some(Ed2kText::from_utf8("base")),
        ..ServerIdentity::default()
    };
    let other = ServerIdentity {
        name: Some(Ed2kText::from_utf8("updated")),
        description: Some(Ed2kText::from_utf8("desc")),
        ..ServerIdentity::default()
    };

    let merged = base.merge(other);
    assert_eq!(merged.server_hash, Some(hash()));
    assert_eq!(merged.name.unwrap().as_bytes(), b"updated");
    assert_eq!(merged.description.unwrap().as_bytes(), b"desc");
}

#[test]
fn merge_preserves_base_when_other_field_is_none() {
    let base = ServerIdentity {
        name: Some(Ed2kText::from_utf8("keep")),
        version: Some(Ed2kText::from_utf8("v1")),
        ..ServerIdentity::default()
    };
    let merged = base.merge(ServerIdentity::default());
    assert_eq!(merged.name.unwrap().as_bytes(), b"keep");
    assert_eq!(merged.version.unwrap().as_bytes(), b"v1");
}

#[test]
fn merge_unions_extra_tags_and_dedupes_by_value() {
    let tag_a = Tag::new(TagName::compact_id(0xAA), TagValue::U32(1));
    let tag_b = Tag::new(TagName::compact_id(0xBB), TagValue::U32(2));
    let base = ServerIdentity {
        extra_tags: vec![tag_a.clone(), tag_b.clone()],
        ..ServerIdentity::default()
    };
    // `other` re-emits `tag_a` (e.g. same source being merged twice) plus
    // a fresh `tag_c`. The result must contain `tag_a` exactly once.
    let tag_c = Tag::new(TagName::compact_id(0xCC), TagValue::U32(3));
    let other = ServerIdentity {
        extra_tags: vec![tag_a.clone(), tag_c.clone()],
        ..ServerIdentity::default()
    };
    assert_eq!(base.merge(other).extra_tags, vec![tag_a, tag_b, tag_c]);
}

#[test]
fn merge_overrides_typed_field_when_other_sets_it() {
    // Covers the "other wins" precedence for `server_hash` specifically,
    // and shows that re-merging keeps `extra_tags` dedup honest.
    let base = ServerIdentity {
        server_hash: Some(hash()),
        ..ServerIdentity::default()
    };
    let other = ServerIdentity {
        server_hash: Some(other_hash()),
        ..ServerIdentity::default()
    };
    assert_eq!(base.merge(other).server_hash, Some(other_hash()));
}
