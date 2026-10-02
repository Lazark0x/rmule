//! The buddy dial's hello names the live session: the firewalled front
//! reads the same session facts every other dial reads, at the dial — the
//! connected server and the id it assigned, or none between sessions.

use super::*;
use crate::own_identity::{ConnectedSession, SharedOwnIdentity};

/// A buddy dial names the live session's server and the id it holds at the
/// dial, not the one it held when Kad started.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_buddy_dials_hello_names_the_live_session_or_none() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let buddy = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_addr().unwrap().port());
    let slot = recruited(buddy);
    let h = harness(&slot);
    let own = SharedOwnIdentity::default();
    let server = rmule_primitives::Ipv4Endpoint::new(Ipv4Addr::new(10, 1, 2, 3), 4661);
    let high = rmule_primitives::ClientId::from_u32(0x0B02_010A);
    own.set_connected_session(Some(ConnectedSession {
        server: Some(server),
        client_id: high,
    }));
    let peer = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("the front dials");
        crate::adapters::tests::hello_wire::read_hello_body(&mut sock).await
    });

    h.front
        .send(FirewalledCommand::KadStarted(Box::new(
            crate::server_session::HelloSource::live(
                rmule_testkit::peer_session::serverless_ctx().identity,
                own.clone(),
            ),
        )))
        .await
        .expect("front running");
    // The session is read at the dial, not at the Kad start: it moved since.
    let assigned_later = rmule_primitives::ClientId::from_u32(0x0C02_010A);
    own.reassign_client_id(assigned_later);
    h.front
        .send(FirewalledCommand::BuddyAdopted)
        .await
        .expect("front running");
    let hello = within("the buddy dial's hello", async { peer.await.ok() }).await;
    assert_eq!(hello.connected_server, server);
    assert_eq!(hello.client_id, assigned_later);
}
