//! The grade per family (ADR-0086): on a dual-stack host the IPv4 grade leads,
//! an IPv4-only backend is asked for and graded on only the rows it can
//! express, and a PCP trial that pinholes IPv6 but shifts the IPv4 TCP port
//! cannot outrank an IPv4 trial that got every port exact.

use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};

use rmule_net::family::FamilyBinds;
use rmule_net::portmap::{MappingError, MappingProtocol};
use rmule_primitives::{AddressFamily, Ipv6Endpoint, PeerEndpoint};

use crate::address_learning::{
    AddressObservation, ObservationSource, SharedAddressLearning, SocketRole,
};
use crate::port_mapping::{DesiredMapping, GrantAnswer, MappingCommand, MappingStatus};

use super::{
    TCP_PORT, UDP_PORT, answer_maps, drain, external, granted, mapper, probed, verdict_port,
};

/// The Known IPv6 every dual-stack fixture pinholes to.
fn gua() -> Ipv6Addr {
    "2001:db8::5".parse().expect("literal")
}

/// Both roles bound in both families, with a Known IPv6 — the four-row
/// **Desired Mapping Set** of an ordinary dual-stack home node.
pub(super) fn dual_stack_store() -> SharedAddressLearning {
    let store = SharedAddressLearning::new();
    let dual = FamilyBinds {
        bound: vec![AddressFamily::V4, AddressFamily::V6],
        refused: Vec::new(),
    };
    store.record_bind(SocketRole::Tcp, &dual, TCP_PORT);
    store.record_bind(SocketRole::Udp, &dual, UDP_PORT);
    store.refresh_interfaces(&[IpAddr::V6(gua())]);
    store.observe(AddressObservation::Address {
        source: ObservationSource::Server,
        address: IpAddr::V6(gua()),
    });
    store
}

/// What a gateway grants `mapping` on `external_port`, in the row's family.
pub(super) fn granted_in_family(
    mapping: DesiredMapping,
    external_port: u16,
) -> Result<GrantAnswer, MappingError> {
    match mapping.family {
        AddressFamily::V4 => granted(external_port),
        AddressFamily::V6 => Ok(GrantAnswer {
            external: PeerEndpoint::V6(Ipv6Endpoint::new(gua(), external_port)),
            lease: Some(Duration::from_secs(3600)),
            epoch_reset: false,
        }),
    }
}

/// What an IPv4-only backend answers for an IPv6 row, were it ever asked.
fn unsupported(protocol: MappingProtocol) -> Result<GrantAnswer, MappingError> {
    Err(MappingError::Unsupported(protocol))
}

#[test]
fn an_ipv4_only_backend_exact_on_every_ipv4_row_fires_the_recheck_on_a_dual_stack_host() {
    // A GUA on an interface is a Known IPv6, so a dual-stack host wants four
    // rows. UPnP cannot express the two pinholes; counting them against it
    // graded an all-exact IPv4 grant `Partial`, and the recheck ADR-0086
    // promises "the moment an Exact grant lands" never fired.
    let t0 = Instant::now();
    let store = dual_stack_store();
    let mut mapper = mapper(store.clone());
    mapper.start(t0);
    let _ = drain(&mut mapper);
    probed(MappingProtocol::Upnp, &[AddressFamily::V4], t0, &mut mapper);
    mapper.tick(t0 + Duration::from_secs(3));

    let asked = answer_maps(&mut mapper, t0, |mapping| match mapping.family {
        AddressFamily::V4 => granted(mapping.internal_port),
        AddressFamily::V6 => unsupported(MappingProtocol::Upnp),
    });
    assert!(
        drain(&mut mapper).contains(&MappingCommand::RecheckReachability),
        "every IPv4 row exact is the Exact grant the recheck is for"
    );
    assert!(
        asked
            .iter()
            .all(|mapping| mapping.family == AddressFamily::V4),
        "an IPv4-only backend is asked only for the rows it can express: {asked:?}"
    );
    assert_eq!(verdict_port(&store, SocketRole::Tcp), Some(TCP_PORT));
}

#[test]
fn a_pcp_trial_that_shifts_the_ipv4_tcp_port_loses_to_an_exact_upnp_trial() {
    // PCP grants all four rows, but the IPv4 TCP port on another number: a
    // silent LowID. UPnP grants both IPv4 rows exact. Graded over the whole
    // set, PCP read `Mismatched` and UPnP `Partial`, so the LowID won.
    let t0 = Instant::now();
    let store = dual_stack_store();
    let mut mapper = mapper(store.clone());
    mapper.start(t0);
    let _ = drain(&mut mapper);
    probed(
        MappingProtocol::Pcp,
        &[AddressFamily::V4, AddressFamily::V6],
        t0,
        &mut mapper,
    );
    probed(MappingProtocol::Upnp, &[AddressFamily::V4], t0, &mut mapper);
    mapper.tick(t0 + Duration::from_secs(3));

    // PCP's trial.
    answer_maps(&mut mapper, t0, |mapping| {
        let shifted = mapping.family == AddressFamily::V4 && mapping.role == SocketRole::Tcp;
        granted_in_family(mapping, mapping.internal_port + u16::from(shifted) * 1000)
    });
    // UPnP's trial.
    answer_maps(&mut mapper, t0, |mapping| match mapping.family {
        AddressFamily::V4 => granted(mapping.internal_port),
        AddressFamily::V6 => unsupported(MappingProtocol::Upnp),
    });

    let concluded = drain(&mut mapper);
    assert!(
        concluded.contains(&MappingCommand::RecheckReachability),
        "the exact IPv4 winner fires the recheck: {concluded:?}"
    );
    let released: Vec<_> = concluded
        .iter()
        .filter_map(|command| match command {
            MappingCommand::Release { protocol, .. } => Some(*protocol),
            _ => None,
        })
        .collect();
    assert_eq!(
        released,
        vec![MappingProtocol::Pcp; 4],
        "the losing PCP trial's four grants go back"
    );
    let tcp_v4 = mapper
        .diagnostics()
        .into_iter()
        .find(|row| row.mapping.role == SocketRole::Tcp && row.mapping.family == AddressFamily::V4)
        .expect("the IPv4 TCP row");
    assert_eq!(tcp_v4.method, Some(MappingProtocol::Upnp));
    assert_eq!(tcp_v4.status, MappingStatus::Mapped);
    assert_eq!(tcp_v4.external, Some(external(TCP_PORT)));
}
