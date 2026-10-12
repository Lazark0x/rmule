//! The lines a fixed session's reachability levels leave in `rmule.log`,
//! pinned line for line: every level in each of its shapes, a read that moved
//! nothing, and each server-health edge. The levels are read in the order the
//! trail writes its first lines in, one snapshot at a time; the pinned lines
//! are the ones the front end's snapshot diff wrote for the same snapshots.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use crate::diagnostics::{
    AddressDiagnostics, BuddyState, DiagnosticsSnapshot, KadFirewallCheck, KadFirewallVerdict,
    KadRuntimeDiagnostics, KadUdpVerdict, ServerDiagnostics, ShareAnnouncement, SharesToServer,
};
use crate::port_mapping::{
    DesiredMapping, MappingDiagnostics, MappingError, MappingProtocol, MappingRefusal,
    MappingStatus,
};
use crate::run_log::{Level, Record};
use crate::{
    ConfidenceTier, EndpointVerdict, KadId, ManagedServer, NatHint, OwnMapping, ServerFigures,
    ServerGrantsReport, ServerHealth, SocketRole,
};
use rmule_primitives::{
    AddressFamily, Ipv4Endpoint, Ipv6Endpoint, PeerEndpoint, ServerEndpoint, ServerTcpFlags,
    ServerUdpFlags,
};

use super::super::{ServerLevel, Trail};

fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> PeerEndpoint {
    PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(a, b, c, d), port))
}

fn v6(last: u16, port: u16) -> PeerEndpoint {
    PeerEndpoint::V6(Ipv6Endpoint::new(
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last),
        port,
    ))
}

fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn server(host: &str, health: ServerHealth, fail_count: u32) -> ServerDiagnostics {
    let mut row = ServerDiagnostics::listed(ManagedServer {
        fail_count,
        ..ManagedServer::listed(ServerEndpoint::new(host, 4661).expect("endpoint"))
    });
    row.health = health;
    row
}

fn with_words(mut row: ServerDiagnostics, tcp: Option<u32>, udp: Option<u32>) -> ServerDiagnostics {
    row.server.grants = tcp.map(|word| ServerGrantsReport {
        tcp_flags: ServerTcpFlags::from_bits(word),
        reported_at: 1_790_000_000,
    });
    row.server.figures = udp.map(|word| ServerFigures {
        udp_flags: Some(ServerUdpFlags::from_bits(word)),
        ..ServerFigures::answered(1_790_000_000)
    });
    row
}

fn mapping(
    role: SocketRole,
    family: AddressFamily,
    internal_port: u16,
    pinhole: Option<Ipv6Addr>,
) -> MappingDiagnostics {
    MappingDiagnostics {
        mapping: DesiredMapping {
            role,
            family,
            internal_port,
            pinhole,
        },
        status: MappingStatus::NotMapped,
        method: None,
        external: None,
        lease: None,
        next_renewal: None,
        last_error: None,
    }
}

fn address(
    family: AddressFamily,
    role: SocketRole,
    verdict: EndpointVerdict,
    hint: Option<NatHint>,
) -> AddressDiagnostics {
    AddressDiagnostics {
        family,
        role,
        verdict,
        hint,
    }
}

fn kad(firewall: KadFirewallVerdict, udp: KadUdpVerdict) -> KadRuntimeDiagnostics {
    KadRuntimeDiagnostics {
        contact_responded: true,
        contacts: 12,
        keywords_stored: 0,
        node_id: KadId::from_bytes([0x5A; 16]),
        firewall,
        firewall_check: KadFirewallCheck::default(),
        udp,
        traffic: crate::diagnostics::KadTraffic::default(),
    }
}

/// The levels of one session, one data tick each.
fn session() -> Vec<DiagnosticsSnapshot> {
    let first_server = server("192.0.2.33", ServerHealth::Failing, 2);
    let connected = ServerEndpoint::new("203.0.113.7", 4661).expect("endpoint");
    let mut steps = vec![
        DiagnosticsSnapshot::default(),
        DiagnosticsSnapshot::default(),
    ];

    let mut step = DiagnosticsSnapshot {
        connected_server: Some(connected.clone()),
        servers: vec![with_words(first_server, Some(0x0000_10D9), None)],
        ..DiagnosticsSnapshot::default()
    };
    steps.push(step.clone());

    let stale_since = Instant::now();
    step.mappings = vec![
        MappingDiagnostics {
            status: MappingStatus::Mapped,
            method: Some(MappingProtocol::Pcp),
            external: Some(v4(203, 0, 113, 5, 4662)),
            lease: Some(Duration::from_secs(7200)),
            ..mapping(SocketRole::Tcp, AddressFamily::V4, 4662, None)
        },
        MappingDiagnostics {
            status: MappingStatus::Failed,
            last_error: Some(MappingError::Refused {
                protocol: MappingProtocol::Pcp,
                refusal: MappingRefusal::NotAuthorized,
                hold_off: None,
            }),
            ..mapping(
                SocketRole::Udp,
                AddressFamily::V6,
                4672,
                Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5)),
            )
        },
    ];
    step.addresses = vec![
        address(
            AddressFamily::V4,
            SocketRole::Tcp,
            EndpointVerdict::Known {
                endpoint: v4(203, 0, 113, 5, 4662),
                tier: ConfidenceTier::Server,
            },
            None,
        ),
        address(
            AddressFamily::V4,
            SocketRole::Udp,
            EndpointVerdict::Stale {
                endpoint: v4(203, 0, 113, 5, 4672),
                since: stale_since,
            },
            Some(NatHint::Disagreement {
                adopted_tier: ConfidenceTier::Server,
                adopted: ip(203, 0, 113, 5),
                dissenting_tier: ConfidenceTier::PeerVote,
                dissenting: ip(198, 51, 100, 77),
            }),
        ),
        address(
            AddressFamily::V6,
            SocketRole::Tcp,
            EndpointVerdict::Unknown,
            None,
        ),
    ];
    step.natt_own_mapping = Some(OwnMapping::EndpointIndependent);
    steps.push(step.clone());
    steps.push(step.clone());

    step.kad = Some(kad(KadFirewallVerdict::Checking, KadUdpVerdict::Unverified));
    step.session.buddy_state = BuddyState::Walking;
    steps.push(step.clone());

    step.kad = Some(kad(
        KadFirewallVerdict::Firewalled,
        KadUdpVerdict::Firewalled,
    ));
    step.session.buddy_state = BuddyState::Held;
    step.servers = vec![with_words(
        server("192.0.2.33", ServerHealth::Dead, 3),
        Some(0x0000_10D9),
        None,
    )];
    step.status_sweep_unheard = true;
    steps.push(step.clone());

    step.kad = Some(kad(
        KadFirewallVerdict::Open,
        KadUdpVerdict::Open { port: 4672 },
    ));
    step.session.buddy_state = BuddyState::Recruited;
    step.servers = vec![with_words(
        server("192.0.2.33", ServerHealth::Answered, 0),
        Some(0x0000_10D9),
        Some(0x0000_073B),
    )];
    step.status_sweep_unheard = false;
    step.share_announcement = Some(ShareAnnouncement {
        server: connected.clone(),
        shares: SharesToServer::Withheld,
    });
    steps.push(step.clone());

    step.addresses = vec![
        address(
            AddressFamily::V4,
            SocketRole::Tcp,
            EndpointVerdict::Known {
                endpoint: v4(203, 0, 113, 5, 4662),
                tier: ConfidenceTier::MappingGrant,
            },
            Some(NatHint::DoubleNat {
                granted: ip(100, 64, 0, 9),
            }),
        ),
        address(
            AddressFamily::V4,
            SocketRole::Udp,
            EndpointVerdict::Known {
                endpoint: v4(203, 0, 113, 5, 4672),
                tier: ConfidenceTier::KadCheck,
            },
            Some(NatHint::CarrierGradeNat {
                granted: ip(100, 64, 0, 9),
            }),
        ),
        address(
            AddressFamily::V6,
            SocketRole::Tcp,
            EndpointVerdict::Known {
                endpoint: v6(5, 4662),
                tier: ConfidenceTier::Interface,
            },
            Some(NatHint::Hairpin {
                reflected: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9)),
                tier: ConfidenceTier::PeerVote,
            }),
        ),
    ];
    step.natt_own_mapping = Some(OwnMapping::EndpointDependent);
    step.share_announcement = Some(ShareAnnouncement {
        server: connected,
        shares: SharesToServer::AnnouncedBeforeWithholding,
    });
    steps.push(step.clone());

    step.connected_server = None;
    step.mappings = Vec::new();
    step.addresses = Vec::new();
    step.kad = None;
    step.natt_own_mapping = Some(OwnMapping::Unknown);
    step.share_announcement = None;
    steps.push(step.clone());
    steps.push(step);
    steps
}

/// The records one snapshot's levels write, read in the trail's order.
fn observe(trail: &mut Trail, snapshot: &DiagnosticsSnapshot) -> Vec<Record> {
    let level = ServerLevel::of_snapshot(snapshot);
    let mut records = trail.server(level.connected.as_ref());
    records.extend(trail.mappings(&snapshot.mappings));
    records.extend(trail.addresses(&snapshot.addresses));
    records.extend(trail.kad(
        snapshot.kad.map(|kad| (kad.firewall, kad.udp)),
        snapshot.session.buddy_state,
    ));
    records.extend(trail.natt(snapshot.natt_own_mapping));
    records.extend(trail.server_health(&level));
    records
}

/// The lines `session` writes, each rendered at both levels.
fn trail_lines() -> Vec<String> {
    let mut trail = Trail::default();
    session()
        .iter()
        .flat_map(|snapshot| observe(&mut trail, snapshot))
        .map(|record| {
            let lean = record.render(Level::Lean);
            assert_eq!(
                record.render(Level::Full),
                lean,
                "a level line is ours alone"
            );
            let mut keys: Vec<&str> = lean
                .split(' ')
                .skip(1)
                .filter_map(|field| field.split_once('=').map(|(key, _)| key))
                .collect();
            let all = keys.len();
            keys.sort_unstable();
            keys.dedup();
            assert_eq!(keys.len(), all, "a key is written twice in {lean}");
            lean
        })
        .collect()
}

/// A port mapping's transport fault from the OS names the OS error under its
/// own key: `error` already says the fault is a transport one.
#[test]
fn a_transport_io_fault_writes_each_key_once() {
    let fault = crate::port_mapping::MappingError::Transport {
        protocol: crate::port_mapping::MappingProtocol::Pcp,
        fault: crate::port_mapping::MappingTransportFault::Io {
            kind: std::io::ErrorKind::ConnectionRefused,
            os_code: Some(61),
        },
    };
    let line = crate::run_log::codes::mapping_error(Record::new("reach.port_mapping"), &fault)
        .render(Level::Lean);
    assert_eq!(
        line,
        "reach.port_mapping protocol=pcp error=transport fault=io io_error=connection_refused os_code=61"
    );
}

const PINNED: &str = r#"reach.server server=none
reach.port_mapping mapping=none
reach.address address=none
reach.kad kad=none
reach.natt_own_mapping mapping=none
reach.server server=203.0.113.7:4661
server.grants server=192.0.2.33:4661 tcp_flags=0x000010D9 udp_flags=none
reach.port_mapping role=tcp family=ipv4 internal_port=4662 status=mapped method=pcp external=203.0.113.5:4662 lease_secs=7200 error=none
reach.port_mapping role=udp family=ipv6 internal_port=4672 status=failed pinhole=2001:db8::5 method=none external=none lease_secs=none protocol=pcp error=refused refusal=not_authorized
reach.address family=ipv4 role=tcp verdict=known endpoint=203.0.113.5:4662 tier=server hint=none
reach.address family=ipv4 role=udp verdict=stale endpoint=203.0.113.5:4672 hint=disagreement adopted_tier=server adopted=203.0.113.5 dissenting_tier=peer_vote dissenting=198.51.100.77
reach.address family=ipv6 role=tcp verdict=unknown hint=none
reach.natt_own_mapping mapping=endpoint_independent
reach.kad firewall=checking udp=unverified buddy=walking
reach.kad firewall=firewalled udp=firewalled buddy=held
server_health.marked_dead server=192.0.2.33:4661 failures=3
server_health.sweep_unheard
reach.kad firewall=open udp=open udp_port=4672 buddy=recruited
server_health.answered_again server=192.0.2.33:4661
server_health.shares server=203.0.113.7:4661 shares=withheld
server.grants server=192.0.2.33:4661 tcp_flags=0x000010D9 udp_flags=0x0000073B
reach.address family=ipv4 role=tcp verdict=known endpoint=203.0.113.5:4662 tier=mapping_grant hint=double_nat granted=100.64.0.9
reach.address family=ipv4 role=udp verdict=known endpoint=203.0.113.5:4672 tier=kad_check hint=carrier_grade_nat granted=100.64.0.9
reach.address family=ipv6 role=tcp verdict=known endpoint=[2001:db8::5]:4662 tier=interface hint=hairpin reflected=2001:db8::9 reflected_tier=peer_vote
reach.natt_own_mapping mapping=endpoint_dependent
server_health.shares server=203.0.113.7:4661 shares=announced_before_withholding
reach.server server=none
reach.port_mapping mapping=none
reach.address address=none
reach.kad kad=none
reach.natt_own_mapping mapping=unknown"#;

#[test]
fn a_fixed_session_s_levels_write_the_same_lines() {
    assert_eq!(trail_lines().join("\n"), PINNED);
}
