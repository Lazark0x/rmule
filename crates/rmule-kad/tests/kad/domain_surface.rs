//! The domain shapes the rest of the crate is written in: a `KadId` is exactly
//! 128 bits and round-trips, a bootstrap node keeps its endpoint and optional
//! id, and a Low-ID source result stays diagnostics rather than a source.

use std::net::Ipv4Addr;

use rmule_kad::{
    KadBootstrapNode, KadId, KadNodeEndpoint, KadSourceCandidate, KadSourceDiagnostic,
    KadSourceLookupRequest,
};
use rmule_primitives::{ClientId, FileHash, SourceLookupTarget};

#[test]
fn domain_surface_kad_id_is_exactly_128_bits_and_round_trips() {
    let bytes = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    let id = KadId::from_bytes(bytes);

    assert_eq!(KadId::BYTE_LEN, 16);
    assert_eq!(*id.as_bytes(), bytes);
}

#[test]
fn domain_surface_bootstrap_nodes_preserve_udp_endpoint_and_optional_id() {
    let endpoint = KadNodeEndpoint::new(Ipv4Addr::new(203, 0, 113, 7), 46_72);
    let id = KadId::from_bytes([0x42; 16]);

    let known = KadBootstrapNode::new(endpoint, Some(id));
    let unknown = KadBootstrapNode::new(endpoint, None);

    assert_eq!(known.endpoint(), endpoint);
    assert_eq!(known.kad_id(), Some(id));
    assert_eq!(unknown.endpoint().ip(), Ipv4Addr::new(203, 0, 113, 7));
    assert_eq!(unknown.endpoint().udp_port(), 46_72);
    assert_eq!(unknown.kad_id(), None);
}

#[test]
fn domain_surface_source_lookup_request_wraps_source_lookup_target() {
    let target = SourceLookupTarget::new(FileHash::from_bytes([0x7a; 16]), 9_728_001);

    let request = KadSourceLookupRequest::new(target);

    assert_eq!(request.target(), target);
}

#[test]
fn domain_surface_low_id_source_results_remain_diagnostics() {
    // The candidate repr is sealed: `Direct` has no public constructor and the
    // old `from_peer_source` helper is gone, so a Low ID row can only be a
    // diagnostic, which exposes no direct-connectable peer source.
    let candidate = KadSourceCandidate::diagnostic(KadSourceDiagnostic::LowId {
        client_id: ClientId::from_u32(42),
        tcp_port: 4662,
    });

    assert_eq!(candidate.peer_source(), None);
}
