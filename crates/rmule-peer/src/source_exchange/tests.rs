//! Admission-policy and serve-version tests for the source-exchange leg.

use std::net::Ipv4Addr;

use rmule_primitives::{ClientId, Ipv4Endpoint, PeerEndpoint, PeerSource, SourceSighting};

use super::admission::{PER_FILE_SOURCE_CAP, is_plausible_high_id_endpoint, sanitize_and_route};
use super::{ServedSourcesVersion, SourceExchangeEntry, SourceExchangeVersion};

fn high_id_entry(octets: [u8; 4], port: u16) -> SourceExchangeEntry {
    let id = u32::from_le_bytes(octets);
    SourceExchangeEntry::plain(SourceSighting::plain(PeerSource::new(
        ClientId::from_u32(id),
        port,
    )))
}

fn low_id_entry(low_id: u32, server: Option<Ipv4Endpoint>) -> SourceExchangeEntry {
    SourceExchangeEntry::new(
        SourceSighting::plain(PeerSource::new(ClientId::from_u32(low_id), 4662)),
        server,
    )
}

fn server(a: u8, b: u8, c: u8, d: u8, port: u16) -> Ipv4Endpoint {
    Ipv4Endpoint::new(Ipv4Addr::new(a, b, c, d), port)
}

#[test]
fn plausible_high_id_endpoint_rejects_zero_leading_octet() {
    let endpoint = PeerEndpoint::V4(server(0, 3, 2, 1, 4662));
    assert!(!is_plausible_high_id_endpoint(endpoint));
}

#[test]
fn plausible_high_id_endpoint_rejects_loopback() {
    let endpoint = PeerEndpoint::V4(server(127, 0, 0, 1, 4662));
    assert!(!is_plausible_high_id_endpoint(endpoint));
}

#[test]
fn plausible_high_id_endpoint_accepts_routable_address() {
    let endpoint = PeerEndpoint::V4(server(1, 2, 3, 4, 4662));
    assert!(is_plausible_high_id_endpoint(endpoint));
}

#[test]
fn sanitize_and_route_drops_zero_ip_high_id() {
    let entries = vec![high_id_entry([0, 3, 2, 1], 4662)];
    let out = sanitize_and_route(entries, None, None, 0);
    assert!(out.is_empty());
}

#[test]
fn sanitize_and_route_drops_loopback_high_id() {
    let entries = vec![high_id_entry([127, 0, 0, 1], 4662)];
    let out = sanitize_and_route(entries, None, None, 0);
    assert!(out.is_empty());
}

#[test]
fn sanitize_and_route_drops_own_endpoint() {
    let own = PeerEndpoint::V4(server(1, 2, 3, 4, 4662));
    let entries = vec![high_id_entry([1, 2, 3, 4], 4662)];
    let out = sanitize_and_route(entries, Some(own), None, 0);
    assert!(
        out.is_empty(),
        "a peer echoing our own address back is dropped"
    );
}

#[test]
fn sanitize_and_route_keeps_sane_high_id() {
    let own = PeerEndpoint::V4(server(9, 9, 9, 9, 4662));
    let entries = vec![high_id_entry([1, 2, 3, 4], 4662)];
    let out = sanitize_and_route(entries, Some(own), None, 0);
    assert_eq!(out.len(), 1);
}

#[test]
fn sanitize_and_route_parks_low_id_with_no_server() {
    let entries = vec![low_id_entry(5000, None)];
    let out = sanitize_and_route(entries, None, Some(server(192, 0, 2, 1, 4661)), 0);
    assert!(out.is_empty(), "a Low-ID with no declared server is parked");
}

#[test]
fn sanitize_and_route_parks_low_id_on_a_different_server() {
    let entries = vec![low_id_entry(5000, Some(server(198, 51, 100, 9, 4661)))];
    let out = sanitize_and_route(entries, None, Some(server(192, 0, 2, 1, 4661)), 0);
    assert!(
        out.is_empty(),
        "a Low-ID whose declaring server is not our connected server is parked"
    );
}

#[test]
fn sanitize_and_route_keeps_low_id_matching_connected_server() {
    let connected = server(192, 0, 2, 1, 4661);
    let entries = vec![low_id_entry(5000, Some(connected))];
    let out = sanitize_and_route(entries, None, Some(connected), 0);
    assert_eq!(
        out.iter().map(|s| s.server()).collect::<Vec<_>>(),
        vec![Some(connected)],
        "the kept Low ID carries the server its row named, its namespace"
    );
}

#[test]
fn sanitize_and_route_honors_the_per_file_cap() {
    let entries: Vec<_> = (0..5).map(|i| high_id_entry([1, 2, 3, i], 4662)).collect();
    // Already at the cap: nothing further is accepted.
    let out = sanitize_and_route(entries.clone(), None, None, PER_FILE_SOURCE_CAP);
    assert!(out.is_empty());

    // Two slots of remaining capacity: only the first two survive.
    let out = sanitize_and_route(entries, None, None, PER_FILE_SOURCE_CAP - 2);
    assert_eq!(out.len(), 2);
}

#[test]
fn serve_version_picks_sx2_only_for_an_sx2_requester_naming_a_version() {
    // aMule-exact (KnownFile.cpp#L938): SX2 needs BOTH the SupportsSourceEx2
    // advert AND a requested version > 0.
    assert_eq!(
        ServedSourcesVersion::negotiate(3, true, 4, None),
        ServedSourcesVersion::Sx2(SourceExchangeVersion::V4),
    );
    // Requested version clamps to SOURCEEXCHANGE2_VERSION (4).
    assert_eq!(
        ServedSourcesVersion::negotiate(3, true, 7, None),
        ServedSourcesVersion::Sx2(SourceExchangeVersion::V4),
    );
    // A lower requested version is honoured as-is.
    assert_eq!(
        ServedSourcesVersion::negotiate(3, true, 2, None),
        ServedSourcesVersion::Sx2(SourceExchangeVersion::V2),
    );
}

#[test]
fn serve_version_falls_to_sx1_at_the_requester_nibble() {
    // SX2-capable requester but a plain (version-0) ask → SX1 at its nibble.
    assert_eq!(
        ServedSourcesVersion::negotiate(3, true, 0, None),
        ServedSourcesVersion::Sx1(SourceExchangeVersion::V3),
    );
    // Not SX2-capable, even with a requested version → SX1 at its nibble.
    assert_eq!(
        ServedSourcesVersion::negotiate(1, false, 4, None),
        ServedSourcesVersion::Sx1(SourceExchangeVersion::V1),
    );
    // A nibble outside 1..=4 degrades to v1 rather than refusing.
    assert_eq!(
        ServedSourcesVersion::negotiate(0, false, 0, None),
        ServedSourcesVersion::Sx1(SourceExchangeVersion::V1),
    );
}

#[test]
fn served_sx1_v3_and_v4_use_hybrid_ids_the_uniform_id_rule() {
    // ADR-0055 uniform id rule: hybrid iff byUsedVersion >= 3, regardless of
    // whether the answer is 0x82 or 0x84.
    assert!(
        ServedSourcesVersion::negotiate(3, false, 0, None)
            .entry_version()
            .uses_hybrid_id()
    );
    assert!(
        !ServedSourcesVersion::negotiate(2, false, 0, None)
            .entry_version()
            .uses_hybrid_id()
    );
    assert!(
        ServedSourcesVersion::negotiate(3, true, 4, None)
            .entry_version()
            .uses_hybrid_id(),
        "0x84 v4 is hybrid too"
    );
}

/// The `u16` count is written for exactly the
/// records that follow it. `len() as u16` wrapped 65536 entries to a count of
/// 0 with every record still written, so the reader misparsed the tail.
#[test]
fn a_list_past_the_u16_count_writes_as_many_records_as_it_counts() {
    use rmule_primitives::FileHash;

    use super::{AnswerSources, AnswerSources2, ExtSxEmission};

    let entries = vec![high_id_entry([198, 51, 100, 7], 4662); usize::from(u16::MAX) + 1];
    let file_hash = FileHash::from_bytes([0x11; FileHash::BYTE_LEN]);

    let classic = AnswerSources2 {
        version: SourceExchangeVersion::V4,
        file_hash,
        sources: entries.clone(),
    }
    .encode_packet();
    let decoded = AnswerSources2::decode_packet(&classic).expect("count matches the records");
    assert_eq!(decoded.sources.len(), usize::from(u16::MAX));

    let ext = AnswerSources {
        file_hash,
        sources: entries,
    }
    .encode_ext_packet(ExtSxEmission::default());
    let decoded = AnswerSources::decode_ext_packet(&ext).expect("count matches the records");
    assert_eq!(decoded.sources.len(), usize::from(u16::MAX));
}
