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
use rmule_net::portmap::{
    MappingBackend, MappingProtocol, PeerPinRequest, ReleaseKept, ReleaseOutcome,
};
use rmule_primitives::{AddressFamily, Ipv4Endpoint, PeerEndpoint};
use rmule_testkit::{FakeGateways, GrantPolicy, ScriptedBackend};
use tokio::sync::mpsc;

use crate::CoreEvent;
use crate::address_learning::{SharedAddressLearning, SocketRole};
use crate::diagnostics::DiagnosticsState;
use crate::own_identity::{ConnectedSession, SharedOwnIdentity};
use crate::port_mapping::{MappingDiagnostics, MappingStatus, PortMappingConfig};
use crate::reachability::SharedSelfReach;

use super::{PortMappingControl, PortMappingHandle, PortMappingPreferences, spawn_port_mapping};

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

    fn set_learned_method(&self, _method: Option<MappingProtocol>) {}
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
    runtime_remembering(
        gateways,
        addresses,
        backend,
        diagnostics,
        own,
        Arc::new(Forgetful),
    )
}

/// [`runtime_behind`], remembering the learned method in `preferences`.
fn runtime_remembering(
    gateways: FakeGateways,
    addresses: &SharedAddressLearning,
    backend: &Arc<ScriptedBackend>,
    diagnostics: &DiagnosticsState,
    own: &SharedOwnIdentity,
    preferences: Arc<dyn PortMappingPreferences>,
) -> PortMappingHandle {
    // Nobody reads these events: the sender is gone before the first one.
    let (events, _) = mpsc::channel(1);
    runtime_telling(
        gateways,
        addresses,
        backend,
        diagnostics,
        own,
        preferences,
        events.downgrade(),
    )
}

/// [`runtime_remembering`], telling its events to `events`.
fn runtime_telling(
    gateways: FakeGateways,
    addresses: &SharedAddressLearning,
    backend: &Arc<ScriptedBackend>,
    diagnostics: &DiagnosticsState,
    own: &SharedOwnIdentity,
    preferences: Arc<dyn PortMappingPreferences>,
    events: mpsc::WeakSender<CoreEvent>,
) -> PortMappingHandle {
    spawn_port_mapping(
        crate::port_mapping::PortMappingMode::Auto,
        PortMappingConfig::default(),
        addresses.clone(),
        Arc::new(gateways),
        vec![Arc::clone(backend) as Arc<dyn MappingBackend>],
        crate::adapters::SharedKadPump::default(),
        diagnostics.clone(),
        preferences,
        SharedSelfReach::new(
            crate::KadReachLevel::fixed(false),
            own.clone(),
            crate::natt::front::SharedNattFront::default(),
        ),
        events,
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

/// A preferences seam that holds the learned method in memory, so a test reads
/// back what the runtime wrote.
struct Remembering(std::sync::Mutex<Option<MappingProtocol>>);

impl PortMappingPreferences for Remembering {
    fn learned_method(&self) -> Option<MappingProtocol> {
        *self.0.lock().expect("preferences mutex")
    }

    fn set_learned_method(&self, method: Option<MappingProtocol>) {
        *self.0.lock().expect("preferences mutex") = method;
    }
}

/// The operator's reprobe used to share the eight-slot inbox the punched-path
/// pins ride, and a full inbox dropped it.
#[tokio::test]
async fn a_reprobe_behind_a_full_pin_inbox_still_re_races() {
    let addresses = SharedAddressLearning::new();
    addresses.record_bind(SocketRole::Udp, &v4(), CLIENT_UDP_PORT);
    let pcp = Arc::new(ScriptedBackend::available(MappingProtocol::Pcp));
    let diagnostics = DiagnosticsState::new();
    let handle = runtime_over(&addresses, &pcp, &diagnostics);
    rows_until(&diagnostics, |rows| {
        rows.iter().any(|row| row.status == MappingStatus::Mapped)
    })
    .await;
    let asked_before = pcp.asked().len();

    // One thread, and no await until every notice is in: the runtime cannot
    // drain any of them first.
    let pin = PeerPinRequest {
        internal_port: CLIENT_UDP_PORT,
        suggested_external_port: None,
        remote: std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(198, 51, 100, 9), 4672),
        lease: Duration::from_secs(120),
    };
    for _ in 0..8 {
        handle.notify(PortMappingControl::PinPeer(pin));
    }
    handle.notify(PortMappingControl::Reprobe);

    tokio::time::timeout(Duration::from_secs(5), async {
        while pcp.asked().len() == asked_before {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the reprobe re-asked the gateway");
    drop(handle);
}

/// A remembered method is probed alone first. When that short round wins
/// short of Exact the mapper forgets it, and so must the store, or every
/// next run opens with the same lone probe.
#[tokio::test]
async fn a_learned_method_that_wins_short_of_exact_is_cleared_from_the_store() {
    let addresses = SharedAddressLearning::new();
    addresses.record_bind(SocketRole::Tcp, &v4(), TCP_PORT);
    addresses.record_bind(SocketRole::Udp, &v4(), CLIENT_UDP_PORT);
    let pcp = Arc::new(
        ScriptedBackend::available(MappingProtocol::Pcp).granting(GrantPolicy::Shifted(1000)),
    );
    let preferences = Arc::new(Remembering(std::sync::Mutex::new(Some(
        MappingProtocol::Pcp,
    ))));
    let diagnostics = DiagnosticsState::new();
    let handle = runtime_remembering(
        FakeGateways::home_lan(),
        &addresses,
        &pcp,
        &diagnostics,
        &SharedOwnIdentity::default(),
        Arc::clone(&preferences) as Arc<dyn PortMappingPreferences>,
    );

    tokio::time::timeout(Duration::from_secs(5), async {
        while preferences.learned_method().is_some() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the stored method was cleared");
    drop(handle);
}

/// Quit's release pass tells every release the gateway kept — here a UPnP
/// port another host now holds — and asks them all at once. Each takes most
/// of the 2 s budget, as a check and a delete to a slow router can, so asked
/// in turn the second would never be.
#[tokio::test]
async fn quit_tells_every_release_the_gateway_kept_and_asks_them_at_once() {
    let addresses = SharedAddressLearning::new();
    addresses.record_bind(SocketRole::Udp, &v4(), CLIENT_UDP_PORT);
    addresses.record_bind(SocketRole::Tcp, &v4(), TCP_PORT);
    let neighbour = PeerEndpoint::V4(Ipv4Endpoint::new(
        std::net::Ipv4Addr::new(192, 168, 1, 77),
        TCP_PORT,
    ));
    let upnp = Arc::new(ScriptedBackend::available(MappingProtocol::Upnp).releasing(
        ReleaseOutcome::Kept(ReleaseKept::ForwardsElsewhere(neighbour)),
        Duration::from_millis(1200),
    ));
    let diagnostics = DiagnosticsState::new();
    let (events_tx, mut events) = mpsc::channel(8);
    let handle = runtime_telling(
        FakeGateways::home_lan(),
        &addresses,
        &upnp,
        &diagnostics,
        &SharedOwnIdentity::default(),
        Arc::new(Forgetful),
        events_tx.downgrade(),
    );
    rows_until(&diagnostics, |rows| {
        rows.len() == 2 && rows.iter().all(|row| row.status == MappingStatus::Mapped)
    })
    .await;

    handle.retire().await;

    let mut kept = Vec::new();
    while let Ok(event) = events.try_recv() {
        if let CoreEvent::MappingReleaseKept {
            mapping,
            protocol,
            external_port,
            kept: why,
        } = event
        {
            assert_eq!(protocol, MappingProtocol::Upnp);
            assert_eq!(why, ReleaseKept::ForwardsElsewhere(neighbour));
            kept.push((mapping.role, external_port));
        }
    }
    kept.sort();
    assert_eq!(
        kept,
        vec![
            (SocketRole::Tcp, TCP_PORT),
            (SocketRole::Udp, CLIENT_UDP_PORT)
        ]
    );
    drop(events_tx);
}
