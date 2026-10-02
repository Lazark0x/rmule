//! What makes the **Port Mapping** runtime re-derive its **Desired Mapping
//! Set** (ADR-0086).
//!
//! The mapper's own rules — the race, the grades, the renewal ladders — are
//! proven beside the mapper against explicit time. What only the runtime can
//! prove is the thing a live 30-second session got wrong: that a socket which
//! binds *after* the runtime started is asked for at all. The set is derived
//! from the **Address Learning** bind table, so this drives that table and
//! nothing else — no control message, no operator recheck.

use std::sync::Arc;
use std::time::Duration;

use rmule_net::family::FamilyBinds;
use rmule_net::portmap::{MappingBackend, MappingProtocol};
use rmule_primitives::AddressFamily;
use rmule_testkit::{FakeGateways, ScriptedBackend};

use crate::address_learning::{SharedAddressLearning, SocketRole};
use crate::diagnostics::DiagnosticsState;
use crate::own_identity::{ConnectedSession, SharedOwnIdentity};
use crate::port_mapping::{MappingDiagnostics, MappingStatus, PortMappingConfig};
use crate::reachability::SharedSelfReach;

use super::{PortMappingHandle, PortMappingPreferences, spawn_port_mapping};

/// The eD2k listener's port — the mapping that earns a High-ID.
const TCP_PORT: u16 = 4662;
/// The shared client-UDP port, bound with the core.
const CLIENT_UDP_PORT: u16 = 4672;

/// A preferences seam that remembers nothing, so a test never writes a learned
/// method into a shared file.
struct Forgetful;

impl PortMappingPreferences for Forgetful {
    fn learned_method(&self) -> Option<MappingProtocol> {
        None
    }

    fn set_learned_method(&self, _method: MappingProtocol) {}
}

/// An IPv4-only **Family Pair**, as a loopback bind reports.
fn v4() -> FamilyBinds {
    FamilyBinds {
        bound: vec![AddressFamily::V4],
        refused: Vec::new(),
    }
}

/// Start the runtime over `addresses` against one exact-granting PCP gateway,
/// with no eD2k session.
fn runtime_over(
    addresses: &SharedAddressLearning,
    backend: &Arc<ScriptedBackend>,
    diagnostics: &DiagnosticsState,
) -> PortMappingHandle {
    runtime_with_session(
        addresses,
        backend,
        diagnostics,
        &SharedOwnIdentity::default(),
    )
}

/// [`runtime_over`], with Self Reach's High-ID half read from `own`.
fn runtime_with_session(
    addresses: &SharedAddressLearning,
    backend: &Arc<ScriptedBackend>,
    diagnostics: &DiagnosticsState,
    own: &SharedOwnIdentity,
) -> PortMappingHandle {
    runtime_behind(
        FakeGateways::home_lan(),
        addresses,
        backend,
        diagnostics,
        own,
    )
}

/// [`runtime_with_session`], behind `gateways`.
fn runtime_behind(
    gateways: FakeGateways,
    addresses: &SharedAddressLearning,
    backend: &Arc<ScriptedBackend>,
    diagnostics: &DiagnosticsState,
    own: &SharedOwnIdentity,
) -> PortMappingHandle {
    spawn_port_mapping(
        PortMappingConfig::default(),
        addresses.clone(),
        Arc::new(gateways),
        vec![Arc::clone(backend) as Arc<dyn MappingBackend>],
        crate::adapters::SharedKadPump::default(),
        diagnostics.clone(),
        Arc::new(Forgetful),
        SharedSelfReach::new(
            crate::KadReachLevel::fixed(false),
            own.clone(),
            crate::natt::front::SharedNattFront::default(),
        ),
    )
    .expect("a mapping runtime with a backend installed")
}

/// Poll the published rows until `ready` accepts them.
async fn rows_until(
    diagnostics: &DiagnosticsState,
    ready: impl Fn(&[MappingDiagnostics]) -> bool,
) -> Vec<MappingDiagnostics> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let rows = diagnostics.snapshot().mappings;
            if ready(&rows) {
                return rows;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the mapping rows settled within 10s")
}

/// Measured live: a 30-second session mapped the client-UDP port
/// and the Kad one and **never asked the gateway for 4662 at all** — the one
/// mapping that earns a High-ID.
///
/// The eD2k listener binds inside the task `StartServing` spawns, so a notice
/// sent beside that command reaches the runtime before the bind it describes
/// is recorded; the mapper then finds an unchanged set, leaves it alone, and
/// nothing re-derives it for the rest of the session. The bind table is the
/// only source of the **Desired Mapping Set**, so its own write is what the
/// runtime waits on: no control message is sent here, and none is needed.
#[tokio::test]
async fn a_socket_that_binds_mid_session_joins_the_desired_set_with_no_notice_sent() {
    let addresses = SharedAddressLearning::new();
    // What the core has up before serving starts.
    addresses.record_bind(SocketRole::Udp, &v4(), CLIENT_UDP_PORT);
    let pcp = Arc::new(ScriptedBackend::available(MappingProtocol::Pcp));
    let diagnostics = DiagnosticsState::new();
    let handle = runtime_over(&addresses, &pcp, &diagnostics);

    rows_until(&diagnostics, |rows| {
        rows.iter().any(|row| row.mapping.role == SocketRole::Udp)
    })
    .await;

    // The serve side comes up mid-session and records what its listener bound.
    addresses.record_bind(SocketRole::Tcp, &v4(), TCP_PORT);

    let rows = rows_until(&diagnostics, |rows| {
        rows.iter()
            .any(|row| row.mapping.role == SocketRole::Tcp && row.status == MappingStatus::Mapped)
    })
    .await;
    let tcp = rows
        .iter()
        .find(|row| row.mapping.role == SocketRole::Tcp)
        .expect("a listener row");
    assert_eq!(tcp.mapping.internal_port, TCP_PORT);
    assert_eq!(
        tcp.external.expect("an external endpoint").port(),
        TCP_PORT,
        "an Exact grant keeps the port the hello advertises",
    );
    assert!(
        pcp.asked()
            .iter()
            .any(|request| request.internal_port == TCP_PORT),
        "the gateway was actually asked to forward the listener's port",
    );
    drop(handle);
}

/// A Known IPv6 learned mid-session asks for its pinhole on the change event,
/// not the runtime's 30 s clock: the address arrives by an
/// interface refresh — a write that touches no bind — and the v6 row appears
/// well inside the clock period.
#[tokio::test]
async fn a_known_ipv6_learned_mid_session_joins_the_desired_set_on_the_change_event() {
    let addresses = SharedAddressLearning::new();
    addresses.record_bind(
        SocketRole::Tcp,
        &FamilyBinds {
            bound: vec![AddressFamily::V4, AddressFamily::V6],
            refused: Vec::new(),
        },
        TCP_PORT,
    );
    let pcp = Arc::new(ScriptedBackend::available(MappingProtocol::Pcp));
    let diagnostics = DiagnosticsState::new();
    let handle = runtime_over(&addresses, &pcp, &diagnostics);
    rows_until(&diagnostics, |rows| {
        rows.iter()
            .any(|row| row.mapping.family == AddressFamily::V4)
    })
    .await;

    let learned = std::time::Instant::now();
    let gua: std::net::Ipv6Addr = "2001:db8:501::7".parse().expect("an IPv6 literal");
    addresses.refresh_interfaces(&[std::net::IpAddr::V6(gua)]);
    rows_until(&diagnostics, |rows| {
        rows.iter()
            .any(|row| row.mapping.family == AddressFamily::V6)
    })
    .await;
    assert!(
        learned.elapsed() < Duration::from_secs(5),
        "the pinhole was asked for on the event, not the 30 s clock"
    );
    drop(handle);
}

/// A v6 pinhole is asked for *from* the Known IPv6 it opens to, not
/// from whichever address the route table picked — and when the Known IPv6
/// moves (a new privacy address), the old pinhole is released from the old
/// address and a new one is made from the new (RFC 6887 §8.2, §8.4).
#[tokio::test]
async fn a_pinhole_is_spoken_from_its_known_ipv6_and_follows_it_when_it_moves() {
    let addresses = SharedAddressLearning::new();
    addresses.record_bind(
        SocketRole::Tcp,
        &FamilyBinds {
            bound: vec![AddressFamily::V6],
            refused: Vec::new(),
        },
        TCP_PORT,
    );
    let first: std::net::Ipv6Addr = "2001:db8:519::1".parse().expect("literal");
    let second: std::net::Ipv6Addr = "2001:db8:519::2".parse().expect("literal");
    let route_pick: std::net::Ipv6Addr = "2001:db8:519::99".parse().expect("literal");
    addresses.refresh_interfaces(&[std::net::IpAddr::V6(first)]);
    let pcp =
        Arc::new(ScriptedBackend::available(MappingProtocol::Pcp).mapping(&[AddressFamily::V6]));
    let gateways = FakeGateways::naming(&[rmule_net::portmap::Gateway {
        address: std::net::IpAddr::V6("fe80::1".parse().expect("literal")),
        scope_id: Some(4),
        local_address: std::net::IpAddr::V6(route_pick),
    }]);
    let diagnostics = DiagnosticsState::new();
    let handle = runtime_behind(
        gateways,
        &addresses,
        &pcp,
        &diagnostics,
        &SharedOwnIdentity::default(),
    );
    let v6 = std::net::IpAddr::V6;
    let spoken = |pcp: &ScriptedBackend, from: std::net::Ipv6Addr, releases: bool| {
        pcp.spoken_from()
            .iter()
            .any(|(request, at)| *at == v6(from) && request.lease.is_zero() == releases)
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        while !spoken(&pcp, first, false) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        addresses.refresh_interfaces(&[v6(second)]);
        while !(spoken(&pcp, second, false) && spoken(&pcp, first, true)) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect(
        "mapped from the first Known IPv6, then released from it and re-mapped from the second",
    );
    assert!(
        pcp.spoken_from()
            .iter()
            .all(|(_, at)| *at != v6(route_pick)),
        "never from the route table's pick: {:?}",
        pcp.spoken_from()
    );
    drop(handle);
}

/// The smart-LowID edge reads **Self Reach**'s High-ID half and
/// wakes on its **Reach Generation**. A session re-assigned a Low ID re-races
/// the mappers at the write — with Address Learning's `Server` tier never
/// written, and well inside the runtime's 30 s clock.
#[tokio::test]
async fn a_session_reassigned_a_low_id_re_races_the_mappers_on_the_reach_generation() {
    let addresses = SharedAddressLearning::new();
    addresses.record_bind(SocketRole::Tcp, &v4(), TCP_PORT);
    let own = SharedOwnIdentity::default();
    own.set_connected_session(Some(ConnectedSession {
        server: None,
        client_id: rmule_primitives::ClientId::from_u32(0x0A00_0001),
    }));
    let pcp = Arc::new(ScriptedBackend::available(MappingProtocol::Pcp));
    let diagnostics = DiagnosticsState::new();
    let handle = runtime_with_session(&addresses, &pcp, &diagnostics, &own);
    rows_until(&diagnostics, |rows| {
        rows.iter().any(|row| row.status == MappingStatus::Mapped)
    })
    .await;
    let asked_before = pcp.asked().len();

    let dropped = std::time::Instant::now();
    own.reassign_client_id(rmule_primitives::ClientId::from_u32(7));
    tokio::time::timeout(Duration::from_secs(5), async {
        while pcp.asked().len() == asked_before {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the lost High ID re-asked the gateway");
    assert!(
        dropped.elapsed() < Duration::from_secs(5),
        "the re-race fired on the Reach Generation, not the 30 s clock"
    );
    drop(handle);
}
