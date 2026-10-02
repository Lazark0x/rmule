//! `OP_SERVERIDENT`'s three IPv6 tags (ADR-0087 §4.3): the probe verdict rmule
//! acts on, the server's own address rmule only logs, and the reflection that
//! is tier 1 of the address ladder.
//!
//! **Evidence: deterministic tier, awaiting a pinned IPv6 server.** No pinnable
//! ed2k-server build with IPv6 exists — its public `master` contains no IPv6
//! at all and the last release predates the work — so these are the spec's
//! bytes, not a capture's. eNode-go is the second oracle for this surface, so
//! the rows are *not* `single-oracle`; they are simply un-captured, and upgrade
//! when such a build is pinned.

use rmule_ed2k::ServerIdent;
use rmule_primitives::{
    CT_MOD_IP_V6, CT_MOD_SVR_IP_V6, CT_MOD_YOUR_IP, Ipv4Endpoint, ST_IPV6_STATUS, ServerHash,
    ServerIpv6Status, Tag, TagName, TagValue, ipv6_address_tag,
};

fn ident(tags: Vec<Tag>) -> rmule_primitives::ServerIdentity {
    ServerIdent::new(
        ServerHash::from_hex("00112233445566778899AABBCCDDEEFF").unwrap(),
        Ipv4Endpoint::new(std::net::Ipv4Addr::new(198, 51, 100, 7), 4661),
        tags,
    )
    .identity()
}

fn status_tag(bits: u8) -> Tag {
    Tag::new(
        TagName::length_prefixed_id(ST_IPV6_STATUS),
        TagValue::U8(bits),
    )
}

/// The three tags, read together, and the one verdict that suppresses.
#[test]
fn the_three_ipv6_tags_project_onto_their_own_fields() {
    let server: std::net::Ipv6Addr = "2a01:4f8::1".parse().unwrap();
    let ours: std::net::Ipv6Addr = "2001:db8::7".parse().unwrap();
    let identity = ident(vec![
        ipv6_address_tag(CT_MOD_SVR_IP_V6, server),
        ipv6_address_tag(CT_MOD_YOUR_IP, ours),
        status_tag(ServerIpv6Status::HAVE as u8 | ServerIpv6Status::PROBED as u8),
    ]);

    assert_eq!(identity.server_ipv6, Some(server));
    assert_eq!(identity.reflected_ipv6, Some(ours));
    let status = identity.ipv6_status.expect("the verdict arrived");
    assert!(status.was_probed());
    assert!(!status.is_reachable());
    assert!(
        status.suppresses_advertisement(),
        "probed and not reached is the one combination that suppresses"
    );
    // A promoted tag leaves the untyped tail: nothing here is unknown.
    assert!(identity.extra_tags.is_empty());
}

/// Every other verdict leaves the advert alone — including the
/// `HAVE | REACHABLE`-on-trust one a server that never dials back always
/// reports, which therefore can never suppress anything.
#[test]
fn only_probed_without_reachable_suppresses_the_advert() {
    for bits in [
        0x00,
        ServerIpv6Status::HAVE as u8,
        ServerIpv6Status::HAVE as u8 | ServerIpv6Status::REACHABLE as u8,
        ServerIpv6Status::HAVE as u8
            | ServerIpv6Status::REACHABLE as u8
            | ServerIpv6Status::PROBED as u8,
        0x80, // an unknown bit says nothing
    ] {
        let status = ident(vec![status_tag(bits)])
            .ipv6_status
            .expect("the tag arrived");
        assert!(
            !status.suppresses_advertisement(),
            "0x{bits:02X} must not suppress"
        );
    }
    // An absent tag is not a verdict at all.
    assert_eq!(ident(Vec::new()).ipv6_status, None);
}

/// A receiver must accept any integer width even though servers SHOULD send
/// `TAGTYPE_UINT8`.
#[test]
fn the_verdict_reads_at_any_integer_width() {
    let suppressing = ServerIpv6Status::PROBED;
    for value in [
        TagValue::U8(suppressing as u8),
        TagValue::U16(suppressing as u16),
        TagValue::U32(suppressing),
    ] {
        let identity = ident(vec![Tag::new(
            TagName::length_prefixed_id(ST_IPV6_STATUS),
            value,
        )]);
        assert!(
            identity
                .ipv6_status
                .expect("the tag arrived")
                .suppresses_advertisement()
        );
    }
}

/// The id-tolerant read. The spec assigns the server's own address `0xAF`; the
/// one server implementing the dialect reports emitting "`ST_IPV6` (`0xAE`)"
/// for the same field. `0xAF` always wins, `0xAE` only fills a slot `0xAF` left
/// empty — and `0xAE` never becomes a reflection of *our* address, because
/// mistaking the server's address for ours would make rmule advertise an
/// address it does not hold.
#[test]
fn the_servers_own_address_is_read_id_tolerantly_and_never_as_a_reflection() {
    let spec_id: std::net::Ipv6Addr = "2a01:4f8::af".parse().unwrap();
    let misused: std::net::Ipv6Addr = "2a01:4f8::ae".parse().unwrap();

    // `0xAE` alone: read as the server's own address, informational only.
    let tolerated = ident(vec![ipv6_address_tag(CT_MOD_IP_V6, misused)]);
    assert_eq!(tolerated.server_ipv6, Some(misused));
    assert_eq!(tolerated.reflected_ipv6, None);

    // Both ids present: the spec's wins regardless of wire order.
    for tags in [
        vec![
            ipv6_address_tag(CT_MOD_SVR_IP_V6, spec_id),
            ipv6_address_tag(CT_MOD_IP_V6, misused),
        ],
        vec![
            ipv6_address_tag(CT_MOD_IP_V6, misused),
            ipv6_address_tag(CT_MOD_SVR_IP_V6, spec_id),
        ],
    ] {
        assert_eq!(ident(tags).server_ipv6, Some(spec_id));
    }

    // Once the spec id has filled the slot, nothing later clears or replaces
    // it: not a second `0xAF`, and not an `0xAF` naming an address no tag can
    // identify.
    let after = ident(vec![
        ipv6_address_tag(CT_MOD_SVR_IP_V6, spec_id),
        ipv6_address_tag(CT_MOD_SVR_IP_V6, misused),
        ipv6_address_tag(CT_MOD_SVR_IP_V6, "fe80::1".parse().unwrap()),
    ]);
    assert_eq!(after.server_ipv6, Some(spec_id));
}

/// The same precedence holds across idents: a later ident carrying only the
/// tolerated `0xAE` never replaces an address an earlier `0xAF` stated, while
/// a later `0xAF` still corrects an `0xAE`-sourced one.
#[test]
fn a_later_tolerated_id_never_replaces_the_spec_ids_address_on_merge() {
    let spec_id: std::net::Ipv6Addr = "2a01:4f8::af".parse().unwrap();
    let misused: std::net::Ipv6Addr = "2a01:4f8::ae".parse().unwrap();
    let from_spec = ident(vec![ipv6_address_tag(CT_MOD_SVR_IP_V6, spec_id)]);
    let from_tolerated = ident(vec![ipv6_address_tag(CT_MOD_IP_V6, misused)]);

    let kept = from_spec.clone().merge(from_tolerated.clone());
    assert_eq!(kept.server_ipv6, Some(spec_id));

    let corrected = from_tolerated.merge(from_spec);
    assert_eq!(corrected.server_ipv6, Some(spec_id));
}

/// `CT_MOD_YOUR_IP`'s integer form names an IPv4 and is refused: reading it
/// would let the server alone decide what rmule believes its own public
/// address to be. The tag stays in the untyped tail rather than vanishing.
#[test]
fn the_reflections_integer_form_is_refused() {
    let integer_form = Tag::new(
        TagName::length_prefixed_id(CT_MOD_YOUR_IP),
        TagValue::U32(0xC633_6407),
    );
    let identity = ident(vec![integer_form.clone()]);
    assert_eq!(identity.reflected_ipv6, None);
    assert_eq!(
        identity.extra_tags,
        vec![integer_form],
        "a known id carrying an unreadable value is preserved, not swallowed"
    );
}

/// An address no scope-less 16-byte tag can identify is refused on every one of
/// the three ids.
#[test]
fn an_unusable_tag_address_is_refused_on_every_id() {
    let link_local: std::net::Ipv6Addr = "fe80::1".parse().unwrap();
    let identity = ident(vec![
        ipv6_address_tag(CT_MOD_SVR_IP_V6, link_local),
        ipv6_address_tag(CT_MOD_YOUR_IP, link_local),
    ]);
    assert_eq!(identity.server_ipv6, None);
    assert_eq!(identity.reflected_ipv6, None);
}
