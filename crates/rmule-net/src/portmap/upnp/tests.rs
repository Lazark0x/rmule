//! The UPnP backend against what it decides alone (the fallback, the device
//! cache) and against a loopback gateway for what it asks one (a release's
//! ownership check before its delete).

mod igd;

use std::net::{Ipv4Addr, Ipv6Addr};

use igd::FakeIgd;

use super::*;

/// The LAN address rmule maps from.
const RMULE: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 4);

/// The port rmule binds and asks for first.
const PORT: u16 = 4662;

/// A second LAN host's claim on the same external port.
const NEIGHBOUR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 77, 0, 5)), PORT);

/// rmule's backend with `igd` already discovered, and the gateway it maps
/// through.
fn rmule_behind(igd: &FakeIgd) -> (Arc<UpnpMappingBackend>, Gateway) {
    let gateway = Gateway::v4(Ipv4Addr::LOCALHOST, RMULE);
    let backend = Arc::new(UpnpMappingBackend::new());
    backend.remember(gateway, &igd.device());
    (backend, gateway)
}

/// rmule's TCP mapping, suggesting `external_port`.
const fn tcp(suggested_external_port: u16) -> MappingRequest {
    MappingRequest {
        family: AddressFamily::V4,
        transport: MappedTransport::Tcp,
        internal_port: PORT,
        suggested_external_port,
        lease: Duration::from_secs(120),
    }
}

/// Map rmule's TCP port suggesting `external_port`; the port granted.
async fn grant(backend: &Arc<UpnpMappingBackend>, gateway: Gateway, external_port: u16) -> u16 {
    Arc::clone(backend)
        .map(gateway, tcp(external_port))
        .await
        .expect("a grant")
        .external
        .port()
}

/// Release rmule's TCP mapping on `external_port`, as core's runtime asks it.
async fn release(
    backend: &Arc<UpnpMappingBackend>,
    gateway: Gateway,
    external_port: u16,
) -> ReleaseOutcome {
    let request = MappingRequest {
        lease: Duration::ZERO,
        ..tcp(PORT)
    };
    Arc::clone(backend)
        .release(gateway, request, external_port)
        .await
}

/// A second LAN host deletes TCP [`PORT`] and claims it for itself, as
/// `upnpc -d` then `upnpc -a` do against a gateway that obeys any host.
async fn neighbour_takes_the_port(igd: &FakeIgd) {
    let device = igd.device();
    tokio::task::spawn_blocking(move || {
        device
            .remove_port(PortMappingProtocol::TCP, PORT)
            .expect("the neighbour's delete");
        device
            .add_port(PortMappingProtocol::TCP, PORT, NEIGHBOUR, 600, "preclaim")
            .expect("the neighbour's claim");
    })
    .await
    .expect("the neighbour");
}

/// The neighbour's endpoint as a release names it.
const fn neighbour() -> ReleaseOutcome {
    ReleaseOutcome::Kept(ReleaseKept::ForwardsElsewhere(PeerEndpoint::V4(
        Ipv4Endpoint::new(Ipv4Addr::new(10, 77, 0, 5), PORT),
    )))
}

#[tokio::test]
async fn a_renewal_moved_off_a_port_another_host_took_never_deletes_that_port() {
    // A neighbour takes rmule's exact port; the renewal meets 718 and lands
    // on another, and the mapper releases the port it moved from. The gateway
    // obeys any host's delete, so only the check stands between that release
    // and the neighbour's forwarding.
    let igd = FakeIgd::start();
    let (backend, gateway) = rmule_behind(&igd);
    assert_eq!(grant(&backend, gateway, PORT).await, PORT);
    neighbour_takes_the_port(&igd).await;
    let moved = grant(&backend, gateway, PORT).await;
    assert_ne!(
        moved, PORT,
        "the renewal meets the neighbour's row and moves"
    );
    let deletes = igd.deletes();

    assert_eq!(release(&backend, gateway, PORT).await, neighbour());
    assert_eq!(
        igd.deletes(),
        deletes,
        "no delete went out for the old port"
    );
    assert_eq!(igd.forwards(PORT), Some(NEIGHBOUR));

    // The moved grant is rmule's, and quit's release takes it down.
    assert_eq!(
        release(&backend, gateway, moved).await,
        ReleaseOutcome::Sent
    );
    assert_eq!(igd.rows(), vec![(PORT, NEIGHBOUR)]);
}

#[tokio::test]
async fn a_quit_release_of_a_port_another_host_now_holds_sends_no_delete() {
    // The neighbour took the port after the last renewal: nothing in rmule's
    // own books says the port is gone, so only the gateway's entry can.
    let igd = FakeIgd::start();
    let (backend, gateway) = rmule_behind(&igd);
    assert_eq!(grant(&backend, gateway, PORT).await, PORT);
    neighbour_takes_the_port(&igd).await;
    let deletes = igd.deletes();

    assert_eq!(release(&backend, gateway, PORT).await, neighbour());
    assert_eq!(igd.deletes(), deletes, "no delete went out");
    assert_eq!(igd.rows(), vec![(PORT, NEIGHBOUR)]);
}

#[tokio::test]
async fn a_quit_release_of_rmules_own_mapping_deletes_it() {
    let igd = FakeIgd::start();
    let (backend, gateway) = rmule_behind(&igd);
    assert_eq!(grant(&backend, gateway, PORT).await, PORT);

    assert_eq!(release(&backend, gateway, PORT).await, ReleaseOutcome::Sent);
    assert_eq!(igd.deletes(), vec![PORT]);
    assert!(igd.rows().is_empty());
}

#[tokio::test]
async fn a_port_with_no_entry_or_an_unanswered_check_is_left_alone() {
    // No entry is nothing to take down. A check the gateway faults says
    // nothing about whose the port is, and unknown is not ours: the lease is
    // the cleanup.
    let igd = FakeIgd::start();
    let (backend, gateway) = rmule_behind(&igd);
    assert_eq!(
        release(&backend, gateway, PORT).await,
        ReleaseOutcome::Kept(ReleaseKept::Absent)
    );
    assert_eq!(grant(&backend, gateway, PORT).await, PORT);
    igd.fail_checks_with(501);

    assert!(matches!(
        release(&backend, gateway, PORT).await,
        ReleaseOutcome::Kept(ReleaseKept::Unchecked(MappingError::Refused {
            refusal: MappingRefusal::UnknownCode(501),
            ..
        }))
    ));
    assert!(igd.deletes().is_empty());
    assert_eq!(
        igd.forwards(PORT),
        Some(SocketAddr::new(IpAddr::V4(RMULE), PORT))
    );
}

#[tokio::test]
async fn an_ipv6_gateway_is_refused_before_any_search_runs() {
    // IGD2 `AddPinhole` is the only UPnP route to an IPv6 pinhole and
    // `igd-next` cannot issue it, so claiming otherwise would put a
    // permanently failing candidate in every dual-stack race.
    let backend = Arc::new(UpnpMappingBackend::new());
    let gateway = Gateway {
        address: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
        scope_id: Some(4),
        local_address: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5)),
    };
    assert!(matches!(
        backend.probe(gateway).await,
        Err(MappingError::Unsupported(MappingProtocol::Upnp))
    ));
}

#[test]
fn only_a_port_conflict_falls_back_to_any_port() {
    // A SOAP `ActionFailed` (501) is the device saying no, not "that port
    // is taken": a random-port grant in its place is a silent LowID.
    let action_failed = AddPortError::RequestError(igd_next::RequestError::ErrorCode(
        501,
        "ActionFailed".to_owned(),
    ));
    assert!(matches!(
        next_step(action_failed),
        NextStep::Fail(MappingError::Refused {
            refusal: MappingRefusal::DeviceRefused,
            ..
        })
    ));
    assert!(matches!(
        next_step(AddPortError::ActionNotAuthorized),
        NextStep::Fail(MappingError::Refused {
            refusal: MappingRefusal::NotAuthorized,
            ..
        })
    ));
    assert!(matches!(
        next_step(AddPortError::PortInUse),
        NextStep::AnyPort
    ));
}

#[test]
fn the_device_cache_is_keyed_on_the_next_hop_it_was_found_from() {
    // A different next hop is a different router: answering from the cache
    // would map ports on a box that is no longer in the path.
    let backend = UpnpMappingBackend::new();
    let first = Gateway::v4(Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 5));
    let second = Gateway::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 5));
    let device = igd_next::Gateway {
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 5000),
        root_url: String::new(),
        control_url: String::new(),
        control_schema_url: String::new(),
        control_schema: std::collections::HashMap::new(),
    };
    backend.remember(first, &device);
    assert!(backend.cached(first).is_some());
    assert!(backend.cached(second).is_none());
}
