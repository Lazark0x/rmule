//! The UDP backends' own rules, driven without a gateway: the derived
//! nonce, the per-family epoch slots, the pinned IPv6 request shape, and the
//! answers that refuse or pin without touching the network.

use super::*;
use std::net::Ipv4Addr;

fn request(port: u16, transport: MappedTransport) -> MappingRequest {
    MappingRequest {
        family: AddressFamily::V4,
        transport,
        internal_port: port,
        suggested_external_port: port,
        lease: Duration::from_secs(3600),
    }
}

/// A peer pin is PCP's alone: NAT-PMP has no opcode that names a remote
/// peer, and it must say so *without touching the network* — a caller
/// treats `Unsupported` as "the keepalive carries this path", and a
/// timeout in its place would stall every punched path for the full
/// retry ladder on a NAT-PMP router.
#[tokio::test]
async fn only_pcp_can_pin_a_punched_path_and_nat_pmp_says_so_at_once() {
    let gateway = Gateway {
        // TEST-NET-1: nothing answers, so a backend that did send would
        // sit out the whole ladder and fail the bound below.
        address: IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
        local_address: IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 2)),
        scope_id: None,
    };
    let request = PeerPinRequest {
        internal_port: 4672,
        suggested_external_port: None,
        remote: std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(45, 55, 200, 9), 31999),
        lease: Duration::from_secs(600),
    };
    let answer = tokio::time::timeout(
        Duration::from_millis(200),
        Arc::new(UdpMappingBackend::nat_pmp()).pin_peer(gateway, request),
    )
    .await
    .expect("no network round trip");
    assert_eq!(
        answer,
        Err(MappingError::Unsupported(MappingProtocol::NatPmp))
    );
}

#[test]
fn the_pcp_nonce_is_stable_across_backends_and_distinct_per_mapping() {
    // RFC 6887 §11.3 makes the nonce a capability: a *different* nonce for
    // the same internal port earns NOT_AUTHORIZED against our own mapping
    // until it expires, and measured firmware answers with silence rather
    // than the refusal the RFC requires. So a restart must derive the same
    // nonce — that is the whole reason it is derived and not drawn.
    let first = UdpMappingBackend::pcp();
    let second = UdpMappingBackend::pcp();
    let tcp = request(4662, MappedTransport::Tcp);
    assert_eq!(first.nonce(tcp), second.nonce(tcp));

    // And two mappings must not share one, or deleting either would delete
    // both.
    assert_ne!(
        first.nonce(tcp),
        first.nonce(request(4672, MappedTransport::Udp))
    );
    assert_ne!(
        first.nonce(tcp),
        first.nonce(request(4662, MappedTransport::Udp)),
        "the transport is part of the mapping's identity"
    );
    // A per-install secret changes every nonce, which is what makes it a
    // capability a LAN neighbour cannot guess.
    assert_ne!(
        first.nonce(tcp),
        UdpMappingBackend::pcp().with_secret(7).nonce(tcp)
    );
}

/// The IPv6 path sends, byte for byte, what the `crab_nat` path sent to
/// the bench's miniupnpd in the `portmap-ipv6-pinhole` PASS (run
/// `1790023348`, `tap-lan.pcap`): same derived nonces, same delete shape.
/// That identity is what lets a pinhole granted before this change be
/// renewed and released after it without `NOT_AUTHORIZED` (§11.3).
#[test]
fn the_pinned_v6_path_reproduces_the_captured_pinhole_requests() {
    let host: std::net::Ipv6Addr = "3fff:ed2:2::4".parse().expect("literal");
    let gateway = Gateway {
        address: IpAddr::V6("3fff:ed2:2::2".parse().expect("literal")),
        local_address: IpAddr::V6(host),
        scope_id: None,
    };
    let backend = UdpMappingBackend::pcp();
    let wire = |request: MappingRequest| {
        let map = backend
            .pinned_request(gateway, request)
            .expect("v6 local address");
        map.encode()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let tcp = MappingRequest {
        family: AddressFamily::V6,
        lease: Duration::from_secs(12),
        ..request(4662, MappedTransport::Tcp)
    };
    // 22:42:41.352611 — the state-free probe.
    assert_eq!(
        wire(pcp_probe_request(gateway)),
        "02010000000000003fff0ed200020000000000000000000418c83c008fc4927eb4e997be110000000001000000000000000000000000000000000000"
    );
    // 22:42:41.353200 — the TCP 4662 pinhole.
    assert_eq!(
        wire(tcp),
        "020100000000000c3fff0ed20002000000000000000000042d8d6ac49374337eeacf2d72060000001236123600000000000000000000000000000000"
    );
    // 22:43:26.375392 — its release.
    assert_eq!(
        wire(MappingRequest {
            lease: Duration::ZERO,
            ..tcp
        }),
        "02010000000000003fff0ed20002000000000000000000042d8d6ac49374337eeacf2d72060000001236000000000000000000000000000000000000"
    );
}

#[test]
fn a_refusal_carries_its_hold_off_raw_and_a_version_mismatch_is_unsupported() {
    // The hold-off is attacker-controlled input (RFC 6887 §7.4); clamping
    // it is the mapper's job, so this layer must not quietly shrink it and
    // hide what the gateway actually said.
    let backend = UdpMappingBackend::pcp();
    let refused = backend.pcp_error(&pcp::Failure::NoResources(u32::MAX));
    assert_eq!(
        refused.hold_off(),
        Some(Duration::from_secs(u64::from(u32::MAX)))
    );
    assert!(matches!(refused, MappingError::Refused { .. }));

    assert!(matches!(
        backend.pcp_error(&pcp::Failure::UnsupportedVersion(
            crab_nat::VersionCode::NatPmp
        )),
        MappingError::Unsupported(MappingProtocol::Pcp)
    ));
    assert!(matches!(
        backend.pcp_error(&pcp::Failure::Timeout),
        MappingError::Timeout(MappingProtocol::Pcp)
    ));
}

#[test]
fn pointing_a_backend_at_a_second_gateway_re_anchors_its_epoch() {
    // Two routers' uptimes are not comparable: without the re-anchor, a
    // renumber onto a longer-running box would read as a reboot and re-add
    // every mapping for nothing.
    let backend = UdpMappingBackend::pcp();
    let first = Gateway::v4(Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 5));
    let second = Gateway::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 5));
    assert_eq!(backend.observe_epoch(first, 90_000), EpochVerdict::Anchored);
    assert_eq!(
        backend.observe_epoch(first, 90_001),
        EpochVerdict::Consistent
    );
    assert_eq!(
        backend.observe_epoch(second, 12),
        EpochVerdict::Anchored,
        "a different gateway is a different counterparty"
    );
}

/// One dual-stack router, reached at its IPv4 next hop and its link-local
/// IPv6 one. The PCP backend serves both, so a map or renew alternates
/// between them; each family keeps its own epoch history, and a pinhole
/// spoken from another Known IPv6 is still the same router.
#[test]
fn alternating_v4_and_v6_next_hops_keep_each_familys_epoch() {
    let backend = UdpMappingBackend::pcp();
    let v4 = Gateway::v4(Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 5));
    let v6 = |local: &str| Gateway {
        address: IpAddr::V6("fe80::1".parse().expect("literal")),
        scope_id: Some(2),
        local_address: IpAddr::V6(local.parse().expect("literal")),
    };
    assert_eq!(backend.observe_epoch(v4, 90_000), EpochVerdict::Anchored);
    assert_eq!(
        backend.observe_epoch(v6("2001:db8::5"), 90_000),
        EpochVerdict::Anchored
    );
    assert_eq!(
        backend.observe_epoch(v4, 90_001),
        EpochVerdict::Consistent,
        "the IPv6 exchange in between did not erase the IPv4 history"
    );
    assert_eq!(
        backend.observe_epoch(v6("2001:db8::7"), 90_001),
        EpochVerdict::Consistent,
        "a pinhole from another Known IPv6 is the same next hop"
    );
    // The router reboots: whichever family answers first reads it.
    assert_eq!(backend.observe_epoch(v4, 12), EpochVerdict::Reset);
}

/// NAT-PMP's MAP carries no address, so a map reads the one its probe
/// learned; the first epoch reading after that probe must not wipe it.
#[test]
fn a_nat_pmp_probe_address_survives_the_first_map_epoch() {
    let backend = UdpMappingBackend::nat_pmp();
    let gateway = Gateway::v4(Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 5));
    let external = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    backend.remember_external(gateway, external);
    assert_eq!(backend.observe_epoch(gateway, 500), EpochVerdict::Anchored);
    assert_eq!(backend.external(gateway), Some(external));
}

#[test]
fn an_absurd_requested_lease_saturates_rather_than_wrapping() {
    // A caller asking for more than the wire can state gets the longest it
    // can, not a tiny one — the clamp that matters is the *granted*
    // lifetime, and this must not undercut it.
    assert_eq!(lease_seconds(Duration::from_secs(3600)), 3600);
    assert_eq!(lease_seconds(Duration::from_secs(u64::MAX)), u32::MAX);
}
