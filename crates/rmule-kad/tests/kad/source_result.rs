//! A `0x3B` source result row projects to a candidate only when it is
//! reachable; a Low-ID row stays a diagnostic.

use rmule_kad::opcode::{KADEMLIA2_HELLO_REQ, KADEMLIA2_SEARCH_RES};
use rmule_kad::{
    KadEnvelope, KadEvidence, KadSourceCandidate, KadSourceDiagnostic, KadSourceResultDecodeError,
    SOURCE_RESULT_BLOCKED_BY, decode_source_result,
};

#[test]
fn malformed_search_result_payload_is_a_typed_error_not_a_panic() {
    // A plain KADEMLIA2_SEARCH_RES whose payload is too short to even hold the
    // [16B sender][16B target][2B count] header. The decoder now parses the
    // proven row shape, so a too-short payload must be a typed MalformedPayload,
    // never a panic and never silently empty.
    let envelope = KadEnvelope::plain(KADEMLIA2_SEARCH_RES, vec![0xde, 0xad, 0xbe, 0xef]);

    assert!(matches!(
        decode_source_result(&envelope),
        Err(KadSourceResultDecodeError::MalformedPayload { .. })
    ));
}

#[test]
fn empty_result_set_decodes_to_no_candidates() {
    // A well-formed header declaring zero rows is a valid (empty) result, not an
    // error: sender + target + count(0), no rows, no trailing bytes.
    let mut payload = vec![0u8; 32];
    payload.extend_from_slice(&0u16.to_le_bytes());
    let envelope = KadEnvelope::plain(KADEMLIA2_SEARCH_RES, payload);

    assert_eq!(decode_source_result(&envelope), Ok(Vec::new()));
}

#[test]
fn no_evidence_blocks_the_source_result_decoder() {
    // The 2026-07-07 controlled-identity 0x3B capture (ADR-0043)
    // upgraded SourceIpTagByteOrder and SourceIdMeaning from documentation to
    // captured, joining the already-proven KadIdByteOrder and the
    // HighIdSourceResultFixture — so nothing blocks the decoder any longer.
    assert!(
        SOURCE_RESULT_BLOCKED_BY.is_empty(),
        "the genuine 0x3B capture emptied the block list"
    );
    // KadEvidence stays the canonical vocabulary; the variants still exist.
    let _ = (
        KadEvidence::SourceIpTagByteOrder,
        KadEvidence::SourceIdMeaning,
    );
}

#[test]
fn non_search_result_envelopes_are_not_routed_as_source_results() {
    let envelope = KadEnvelope::plain(KADEMLIA2_HELLO_REQ, Vec::new());

    assert_eq!(
        decode_source_result(&envelope).unwrap_err(),
        KadSourceResultDecodeError::NotASearchResult {
            opcode: KADEMLIA2_HELLO_REQ,
        }
    );
}

#[test]
fn diagnostics_stay_representable_but_carry_no_peer_source() {
    // `Direct` has no public constructor and `from_peer_source` is gone, so the
    // only candidate a caller can build is a diagnostic, which yields no source.
    let candidate = KadSourceCandidate::diagnostic(KadSourceDiagnostic::Firewalled);

    assert_eq!(candidate.peer_source(), None);
}

/// A firewalled row carrying `ip6` becomes a dialable IPv6 source (ADR-0087).
/// This is the dialect's whole payoff on Kad: the 32-bit projection says
/// "callback only", and the tag says there is an address that needs none.
#[test]
fn an_ip6_tag_rescues_a_row_the_thirty_two_bit_projection_could_not_dial() {
    let address: std::net::Ipv6Addr = "2a01:4f8::7".parse().unwrap();
    let candidates = decode_source_result(&firewalled_row_with_ip6(Some(
        &rmule_kad::ipv6_tags::encode_ipv6_hex(address),
    )))
    .unwrap();

    assert_eq!(
        candidates[0].peer_source(),
        Some(rmule_primitives::PeerSource::Ipv6(
            rmule_primitives::Ipv6Endpoint::new(address, 4662)
        ))
    );

    // Without the tag the same row is exactly what it was before: a callback
    // diagnostic, not a source.
    let bare = decode_source_result(&firewalled_row_with_ip6(None)).unwrap();
    assert_eq!(bare[0].peer_source(), None);
}

/// A deprecated type 2 or an unknown type is no source, whatever `ip6` it
/// carries: eMuleAI's `KademliaSearchFile` builds nothing for either
/// (`DownloadQueue.cpp:4924-4926`, no `default` arm), so the rescue that
/// turns a no-road row into an IPv6 source must not fire for them.
#[test]
fn an_ip6_tag_never_rescues_a_deprecated_or_unknown_source_type() {
    let address: std::net::Ipv6Addr = "2a01:4f8::7".parse().unwrap();
    let hex = rmule_kad::ipv6_tags::encode_ipv6_hex(address);
    for source_type in [2u8, 9] {
        let mut payload = vec![0u8; 32];
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.extend_from_slice(&[0x5A; 16]);
        payload.push(3);
        payload.extend_from_slice(&[0x09, 0x01, 0x00, 0xFF, source_type]);
        payload.extend_from_slice(&[0x08, 0x01, 0x00, 0xFD, 0x36, 0x12]); // SOURCEPORT
        payload.extend_from_slice(&[0x02, 0x03, 0x00, b'i', b'p', b'6', 0x20, 0x00]);
        payload.extend_from_slice(hex.as_bytes());
        let rows =
            decode_source_result(&KadEnvelope::plain(KADEMLIA2_SEARCH_RES, payload)).unwrap();

        assert_eq!(rows[0].peer_source(), None, "type {source_type}");
        assert_eq!(
            rows[0].refusal(),
            Some(KadSourceDiagnostic::UnsupportedSourceType(source_type))
        );
    }
}

/// The tag's reader rules, each proven by a row that keeps its diagnostic: a
/// length that is not 32, and an address a scope-less tag cannot identify.
#[test]
fn a_malformed_or_unusable_ip6_tag_leaves_the_row_as_it_was() {
    let too_short = decode_source_result(&firewalled_row_with_ip6(Some("2a0104f800"))).unwrap();
    assert_eq!(too_short[0].peer_source(), None);

    let link_local: std::net::Ipv6Addr = "fe80::7".parse().unwrap();
    let unusable = decode_source_result(&firewalled_row_with_ip6(Some(
        &rmule_kad::ipv6_tags::encode_ipv6_hex(link_local),
    )))
    .unwrap();
    assert_eq!(unusable[0].peer_source(), None);
}

/// A `0x3B` row for a buddy-callback source, optionally carrying an `ip6` tag
/// with the given (possibly malformed) hex value.
fn firewalled_row_with_ip6(hex: Option<&str>) -> KadEnvelope {
    let mut payload = vec![0u8; 32];
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.extend_from_slice(&[0x5A; 16]);
    payload.push(if hex.is_some() { 3 } else { 2 });
    // SOURCETYPE 3 — buddy callback, which the 32-bit projection refuses.
    payload.extend_from_slice(&[0x09, 0x01, 0x00, 0xFF, 0x03]);
    // SOURCEPORT 4662 — one port, both families.
    payload.extend_from_slice(&[0x08, 0x01, 0x00, 0xFD, 0x36, 0x12]);
    if let Some(hex) = hex {
        payload.extend_from_slice(&[0x02, 0x03, 0x00, b'i', b'p', b'6']);
        payload.extend_from_slice(&(hex.len() as u16).to_le_bytes());
        payload.extend_from_slice(hex.as_bytes());
    }
    KadEnvelope::plain(KADEMLIA2_SEARCH_RES, payload)
}

/// `bi6` names the **buddy's** address, never the source's: it rides the
/// row's buddy contact and must not rescue the row into a direct IPv6 source
/// the way `ip6` does — dialing it would reach the buddy, not the file. A
/// row that named no buddy drops it with the contact.
#[test]
fn a_bi6_tag_rides_the_buddy_contact_and_never_rescues_the_row() {
    let buddy: std::net::Ipv6Addr = "3fff:ed2:1::8".parse().unwrap();
    let hex = rmule_kad::ipv6_tags::encode_ipv6_hex(buddy);

    let rows = decode_source_result(&buddy_row_with_bi6(true, &hex)).unwrap();
    let facts = rows[0].facts().expect("a decoded row carries its facts");
    assert_eq!(facts.buddy.and_then(|b| b.buddy_ipv6), Some(buddy));
    assert_eq!(facts.ipv6, None);
    assert!(
        !matches!(
            rows[0].peer_source(),
            Some(rmule_primitives::PeerSource::Ipv6(_))
        ),
        "a buddy's address is not the source's"
    );

    let unnamed = decode_source_result(&buddy_row_with_bi6(false, &hex)).unwrap();
    assert_eq!(unnamed[0].facts().and_then(|facts| facts.buddy), None);
}

/// A type-3 `0x3B` row carrying `bi6`, with or without the `TAG_BUDDYHASH`
/// that names the buddy it belongs to.
fn buddy_row_with_bi6(buddy_named: bool, hex: &str) -> KadEnvelope {
    let mut payload = vec![0u8; 32];
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.extend_from_slice(&[0x5A; 16]);
    payload.push(if buddy_named { 4 } else { 3 });
    payload.extend_from_slice(&[0x09, 0x01, 0x00, 0xFF, 0x03]); // SOURCETYPE 3
    payload.extend_from_slice(&[0x08, 0x01, 0x00, 0xFD, 0x36, 0x12]); // SOURCEPORT
    if buddy_named {
        payload.extend_from_slice(&[0x02, 0x01, 0x00, 0xF8, 0x20, 0x00]); // BUDDYHASH
        payload.extend_from_slice(&[b'C'; 32]);
    }
    payload.extend_from_slice(&[0x02, 0x03, 0x00, b'b', b'i', b'6', 0x20, 0x00]);
    payload.extend_from_slice(hex.as_bytes());
    KadEnvelope::plain(KADEMLIA2_SEARCH_RES, payload)
}
