//! The trail by owner — each move an owner makes is the one record of the
//! level it moved, and a wake that moved nothing the trail writes is none —
//! and the pinned lines of a fixed session.

mod pinned;

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use rmule_net::family::FamilyBinds;
use rmule_primitives::{AddressFamily, ServerEndpoint};
use tokio::sync::watch;

use super::sources::{TrailSources, Watched};
use crate::address_learning::{AddressObservation, SharedAddressLearning, SocketRole};
use crate::diagnostics::DiagnosticsState;
use crate::firewalled::front::SharedFirewalledFront;
use crate::firewalled::recruit::RecruitStatus;
use crate::natt::front::SharedNattFront;
use crate::own_identity::SharedOwnIdentity;
use crate::port_mapping::{DesiredMapping, MappingDiagnostics, MappingStatus};
use crate::reachability::{
    ClientUdpBound, KadReachLevel, SharedKadVerdicts, SharedSelfReach, UdpReachability,
};
use crate::run_log::Level;
use crate::server_list::ManagedServer;

/// The owners a core weaves, each with the handle a test moves it through.
struct Owners {
    diagnostics: DiagnosticsState,
    mapping_rows: watch::Sender<Vec<MappingDiagnostics>>,
    addresses: SharedAddressLearning,
    reach: SharedSelfReach,
    kad: SharedKadVerdicts,
    client_udp: ClientUdpBound,
    /// Where the Kad pump publishes its Recruit Status.
    front: SharedFirewalledFront,
}

/// Fresh owners and the trail watching them, past its first writes.
fn watched() -> (Owners, Watched) {
    let kad = SharedKadVerdicts::default();
    let client_udp = ClientUdpBound::default();
    let reach = SharedSelfReach::new(
        KadReachLevel::published(kad.clone()),
        SharedOwnIdentity::default(),
        SharedNattFront::default(),
    )
    .with_client_udp(client_udp.clone());
    let (mapping_rows, rows) = watch::channel(Vec::new());
    let owners = Owners {
        diagnostics: DiagnosticsState::new(),
        mapping_rows,
        addresses: SharedAddressLearning::new(),
        reach,
        kad,
        client_udp,
        front: SharedFirewalledFront::default(),
    };
    let mut watched = Watched::new(TrailSources {
        diagnostics: owners.diagnostics.clone(),
        mapping_rows: Some(rows),
        addresses: owners.addresses.clone(),
        reach: owners.reach.clone(),
        buddy: owners.front.view(),
    });
    assert_eq!(
        lines(watched.every_level()),
        [
            "reach.server server=none",
            "reach.port_mapping mapping=none",
            "reach.address address=none",
            "reach.kad kad=none",
            "reach.natt_own_mapping mapping=unknown",
        ],
        "the first writes state every level"
    );
    (owners, watched)
}

fn lines(records: Vec<crate::run_log::Record>) -> Vec<String> {
    records
        .into_iter()
        .map(|record| record.render(Level::Lean))
        .collect()
}

/// Every line the wakes pending now write: each owner writes before it
/// wakes, so a move's wake is ready at once.
async fn written(watched: &mut Watched) -> Vec<String> {
    let mut written = Vec::new();
    while let Ok(records) = tokio::time::timeout(Duration::from_millis(50), watched.next()).await {
        written.extend(lines(records));
    }
    written
}

fn server(fail_count: u32) -> ManagedServer {
    ManagedServer {
        fail_count,
        ..ManagedServer::listed(ServerEndpoint::new("192.0.2.33", 4661).expect("endpoint"))
    }
}

#[tokio::test]
async fn the_server_half_writes_each_move_once_and_a_rewrite_never() {
    let (owners, mut watched) = watched();
    let level = &owners.diagnostics;
    let connected = ServerEndpoint::new("203.0.113.7", 4661).expect("endpoint");
    let session = (connected, rmule_ed2k::ServerGrants::default());

    level.set_connected_server(Some(session.clone()));
    assert_eq!(
        written(&mut watched).await,
        ["reach.server server=203.0.113.7:4661"]
    );
    level.set_connected_server(Some(session));
    level.set_servers(vec![server(2)]);
    assert!(
        written(&mut watched).await.is_empty(),
        "the same server again, and a row first seen"
    );
    level.set_servers(vec![server(3)]);
    assert_eq!(
        written(&mut watched).await,
        ["server_health.marked_dead server=192.0.2.33:4661 failures=3"]
    );
    level.set_status_sweep_unheard(true);
    level.set_status_sweep_unheard(true);
    assert_eq!(written(&mut watched).await, ["server_health.sweep_unheard"]);
}

#[tokio::test]
async fn the_mapping_rows_write_each_move_once_and_a_republish_never() {
    let (owners, mut watched) = watched();
    let row = MappingDiagnostics {
        mapping: DesiredMapping {
            role: SocketRole::Tcp,
            family: AddressFamily::V4,
            internal_port: 4662,
            pinhole: None,
        },
        status: MappingStatus::Probing,
        method: None,
        external: None,
        lease: None,
        next_renewal: None,
        last_error: None,
    };
    owners.mapping_rows.send_replace(vec![row.clone()]);
    assert_eq!(
        written(&mut watched).await,
        [
            "reach.port_mapping role=tcp family=ipv4 internal_port=4662 status=probing \
             method=none external=none lease_secs=none error=none"
        ]
    );
    owners.mapping_rows.send_replace(vec![MappingDiagnostics {
        next_renewal: Some(Instant::now()),
        ..row
    }]);
    assert!(
        written(&mut watched).await.is_empty(),
        "a renewal's due time is not written"
    );
}

#[tokio::test]
async fn address_learning_writes_each_move_once_and_an_unmoved_write_never() {
    let (owners, mut watched) = watched();
    let addresses = &owners.addresses;
    let ipv4_only = FamilyBinds {
        bound: vec![AddressFamily::V4],
        refused: Vec::new(),
    };
    addresses.record_bind(SocketRole::Udp, &ipv4_only, 4672);
    assert_eq!(
        written(&mut watched).await,
        ["reach.address family=ipv4 role=udp verdict=unknown hint=none"]
    );
    let observer = |octet| Ipv4Addr::new(198, 51, 100, octet);
    addresses.observe(AddressObservation::kad_observed_port(observer(1), 4672));
    assert!(
        written(&mut watched).await.is_empty(),
        "one observer says nothing"
    );
    addresses.observe(AddressObservation::kad_observed_port(observer(2), 4673));
    assert_eq!(
        written(&mut watched).await,
        ["reach.natt_own_mapping mapping=endpoint_dependent"]
    );
}

#[tokio::test]
async fn the_kad_level_writes_each_verdict_and_buddy_move_once() {
    let (owners, mut watched) = watched();
    let _running = owners.reach.lease_kad(crate::KadId::from_bytes([0x5A; 16]));
    assert_eq!(
        written(&mut watched).await,
        ["reach.kad firewall=firewalled udp=unverified buddy=none"],
        "a node's start and its fresh verdicts are one move"
    );
    owners.kad.set_udp(UdpReachability::Open { port: 4672 });
    assert_eq!(
        written(&mut watched).await,
        ["reach.kad firewall=firewalled udp=open udp_port=4672 buddy=none"]
    );
    owners.client_udp.set();
    assert!(
        written(&mut watched).await.is_empty(),
        "a Self Reach move the trail does not write"
    );
    owners.front.publish_recruit(RecruitStatus {
        walking: true,
        refusal: None,
    });
    assert_eq!(
        written(&mut watched).await,
        ["reach.kad firewall=firewalled udp=open udp_port=4672 buddy=walking"]
    );
}
