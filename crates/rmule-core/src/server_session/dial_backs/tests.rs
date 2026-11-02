//! The enactment around the server callback's consume: the serving gate read
//! off the admit seam, and one dial in flight per endpoint.

use std::net::Ipv4Addr;

use rmule_primitives::{ClientId, Informant, Ipv4Endpoint, PeerEndpoint};
use rmule_testkit::HANG_GUARD;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use super::ServerCallbackDialBacks;
use crate::adapters::{HelloAdverts, SharedTunnelAdmit};
use crate::firewalled::server_callback::{
    ServerCallbackConsume, ServerCallbackRefusal, ServerCallbackVerdict,
};
use crate::own_identity::SharedOwnIdentity;
use crate::reachability::OwnListenEndpoint;

const LOW_ID: ClientId = ClientId::from_u32(0x0000_2A57);

async fn requester() -> (TcpListener, PeerEndpoint) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let endpoint = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, port));
    (listener, endpoint)
}

fn answer(dial_backs: &ServerCallbackDialBacks, requester: PeerEndpoint) -> ServerCallbackVerdict {
    dial_backs.answer(
        &ServerCallbackConsume {
            requester,
            crypt: None,
        },
        LOW_ID,
        // A session over a stream its caller brought: rmule's own word, so a
        // loopback requester stands.
        Informant::Own,
        OwnListenEndpoint::current(&SharedOwnIdentity::default(), 4662),
    )
}

/// A node with no serve pipeline dials nothing, whether no seam was ever
/// installed or the one installed holds no pump.
#[tokio::test]
async fn a_node_that_does_not_serve_dials_nothing() {
    let (_listener, requester) = requester().await;
    let dial_backs = ServerCallbackDialBacks::default();
    let not_serving = ServerCallbackVerdict::Refuse {
        reason: ServerCallbackRefusal::NotServing,
    };
    assert_eq!(answer(&dial_backs, requester), not_serving, "no seam");
    dial_backs.install_admit(SharedTunnelAdmit::default());
    assert_eq!(answer(&dial_backs, requester), not_serving, "an empty seam");
}

/// The bound a server's word cannot widen: while a dial-back to an endpoint
/// is in flight, a second relay naming it is turned away, another endpoint is
/// not held up, and each dial lands in the serve pipeline as the dialer's
/// side.
#[tokio::test]
async fn a_dial_in_flight_turns_a_second_relay_for_its_endpoint_away() {
    let (_first_listener, first) = requester().await;
    let (_second_listener, second) = requester().await;
    let admit = SharedTunnelAdmit::default();
    let (accept_tx, mut accepted) = mpsc::channel(4);
    admit.install_for_test(
        &accept_tx,
        rmule_testkit::peer_session::serverless_ctx(),
        HelloAdverts::default(),
    );
    let dial_backs = ServerCallbackDialBacks::default();
    dial_backs.install_admit(admit);

    let dial = |requester| ServerCallbackVerdict::DialBack {
        requester,
        obfuscate_toward: None,
    };
    assert_eq!(answer(&dial_backs, first), dial(first));
    // The claim is taken before the dial's task first runs.
    assert_eq!(
        answer(&dial_backs, first),
        ServerCallbackVerdict::Refuse {
            reason: ServerCallbackRefusal::Busy,
        }
    );
    assert_eq!(answer(&dial_backs, second), dial(second));

    let mut landed = Vec::new();
    for _ in 0..2 {
        let admitted = tokio::time::timeout(HANG_GUARD, accepted.recv())
            .await
            .expect("the dial-back reaches the serve pipeline")
            .expect("the pipeline is open");
        landed.push(admitted.conn.peer_endpoint());
    }
    landed.sort();
    let mut expected = vec![first, second];
    expected.sort();
    assert_eq!(landed, expected);
}
