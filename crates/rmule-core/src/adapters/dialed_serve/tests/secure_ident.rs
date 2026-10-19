//! One Secure User Identification per link, bound once (ADR-0041): on a link
//! rmule dialed, the serve half keys the identified client on the
//! verification — the slot ask's two-clients rule and the hash-thief ban
//! (`UploadQueue.cpp:432-458`, `ClientList.cpp:384-392`) — so it reaches the
//! serve half while it serves, and the riding download binds nothing twice.

use std::sync::Arc;

use rmule_peer::{PeerHandshakeContext, SecureIdentConfig};
use rmule_primitives::{ClientId, ClientIdentity, SecureIdentKey};

use super::*;
use crate::adapters::HelloAdverts;
use crate::adapters::peer_transfer::PeerWorkerEvent;

const PEER_HASH: UserHash = UserHash::from_bytes([0x0B; UserHash::BYTE_LEN]);

#[tokio::test]
async fn a_dialed_links_verification_reaches_its_serve_half_and_is_bound_once() {
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let bound = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_port());
    let peer_key = Arc::new(SecureIdentKey::generate().unwrap());
    let _peer = tokio::spawn(async move {
        let ctx = PeerHandshakeContext {
            identity: ClientIdentity::new(PEER_HASH, Ed2kText::from_utf8("sui-peer"), 4662, 60),
            client_id: ClientId::from_u32(0x0100_007F),
            ed2k_client_id: ClientId::from_u32(0x0100_007F),
            public_ip: None,
            connected_server: None,
        };
        let options = PeerConnectOptions {
            secure_ident: Some(SecureIdentConfig {
                key: peer_key,
                challenge: 0xB00B_0002,
            }),
            ..PeerConnectOptions::default()
        };
        let mut conn = listener.accept(ctx, options).await.unwrap();
        while let Some(event) = conn.next_event().await {
            if matches!(
                event,
                PeerEvent::Connection(ConnectionEvent::Disconnected { .. })
            ) {
                break;
            }
        }
    });

    let (dialed_tx, mut dialed_rx) = mpsc::channel(4);
    let sink = SharedDialedServeSink::default();
    sink.install_for_good(dialed_tx);
    let mut transfer =
        RuntimePeerTransferService::with_dialed_serve_sink(crate::DEFAULT_SLOT_WAIT_TIMEOUT, sink)
            .with_hello_adverts(HelloAdverts {
                secure_ident: Some(Arc::new(SecureIdentKey::generate().unwrap())),
                ..HelloAdverts::default()
            });
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(*bound.ip(), bound.port()));
    let mut worker = transfer
        .start_peer_worker(peer, dialed_serve_ctx(), dummy_file(0x5E))
        .await
        .unwrap();
    let mut serve_conn = timeout(Duration::from_secs(5), dialed_rx.recv())
        .await
        .expect("the dialed link's serve half reaches the serve side")
        .expect("a serve connection");

    let verified = timeout(Duration::from_secs(5), async {
        while let Some(input) = serve_conn.next_event().await {
            if let ServeInput::Connection(ConnectionEvent::IdentityVerified { user_hash, .. }) =
                input
            {
                return Some(user_hash);
            }
        }
        None
    })
    .await;
    assert_eq!(
        verified,
        Ok(Some(PEER_HASH)),
        "the serve half reads the link's verification"
    );
    let rider_bound = timeout(Duration::from_millis(300), async {
        while let Some(event) = worker.next_event().await {
            if matches!(event, PeerWorkerEvent::IdentityVerified { .. }) {
                return true;
            }
        }
        false
    })
    .await;
    assert!(
        !matches!(rider_bound, Ok(true)),
        "the download binds nothing the serve half binds"
    );
}
