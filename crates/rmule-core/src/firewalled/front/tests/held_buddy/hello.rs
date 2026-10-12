//! The buddy dial's hello reads Self Reach at the dial, as every other dial
//! does: the Presented Client ID and the connected server, or none between
//! sessions.

use super::*;
use crate::own_identity::{ConnectedSession, SharedOwnIdentity};
use crate::reachability::{KadRunLease, SharedKadVerdicts, SharedSelfReach};

/// Self Reach over `own` and a Kad node of our Kad ID that has heard the
/// network and stays firewalled, with the lease that keeps it running.
fn joined_firewalled_kad(own: &SharedOwnIdentity) -> (SharedSelfReach, KadRunLease) {
    let kad = SharedKadVerdicts::default();
    let reach = SharedSelfReach::new(
        crate::KadReachLevel::published(kad.clone()),
        own.clone(),
        crate::natt::front::SharedNattFront::default(),
    );
    let lease = reach.lease_kad(rmule_kad::KadId::from_bytes([OUR_KAD_ID; 16]));
    kad.writer().set_joined();
    (reach, lease)
}

fn kad_started_presenting(h: &Harness, reach: SharedSelfReach) {
    h.shared.kad_started(KadStart {
        hello: crate::server_session::HelloSource::live(
            rmule_testkit::peer_session::serverless_ctx().identity,
            reach,
        ),
        kad_id: rmule_kad::KadId::from_bytes([OUR_KAD_ID; 16]),
    });
}

/// A buddy dial names the live session's server and the id it holds at the
/// dial, not the one it held when Kad started.
#[tokio::test(start_paused = true)]
async fn the_buddy_dials_hello_names_the_live_session() {
    let mut h = harness();
    let own = SharedOwnIdentity::default();
    let server = Ipv4Endpoint::new(Ipv4Addr::new(10, 1, 2, 3), 4661);
    own.set_connected_session(Some(ConnectedSession {
        server: Some(server),
        client_id: rmule_primitives::ClientId::from_u32(0x0B02_010A),
    }));
    let (reach, _kad) = joined_firewalled_kad(&own);
    kad_started_presenting(&h, reach);

    // The session is read at the dial, not at the Kad start: it moved since.
    let assigned_later = rmule_primitives::ClientId::from_u32(0x0C02_010A);
    own.reassign_client_id(assigned_later);
    h.adopt(a_buddy()).await;

    let dial = h.next_dial().await;
    assert_eq!(dial.hello.connected_server, Some(server));
    assert_eq!(dial.hello.client_id, assigned_later);
}

/// The hello an open aMule buddy receives from a serverless firewalled node
/// names `1`: aMule reads it as a Low ID and keeps us as its buddy, where a
/// `0` would read as our address, a High ID it drops
/// (`BaseClient.cpp:678`, `ClientList.cpp:706-712`).
#[tokio::test(start_paused = true)]
async fn a_serverless_buddy_dial_names_the_firewalled_kad_id() {
    let mut h = harness();
    let (reach, _kad) = joined_firewalled_kad(&SharedOwnIdentity::default());
    kad_started_presenting(&h, reach);
    h.adopt(a_buddy()).await;

    let dial = h.next_dial().await;
    assert_eq!(
        dial.hello.client_id,
        rmule_primitives::ClientId::from_u32(1)
    );
    assert_eq!(dial.hello.connected_server, None);
}
