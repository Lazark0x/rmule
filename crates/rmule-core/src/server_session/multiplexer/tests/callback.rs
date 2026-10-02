//! The callback relays over the fake link: `RequestCallback` carrying the
//! source's Low ID to the server, and a peer's `0x35` callback request with
//! its crypt extension dropped without effect (ADR-0049).

use std::net::Ipv4Addr;

use rmule_ed2k::PeerCallbackCrypt;
use rmule_primitives::{Ipv4Endpoint, PeerEndpoint, SourceCryptOptions, UserHash};

use super::super::super::tests::{FakeLink, client_id, test_sinks};
use super::super::*;

#[tokio::test]
async fn request_callback_relays_the_source_low_id_to_the_server() {
    let (_evt_tx, evt_rx) = mpsc::channel(8);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
    let handle = ServerSession::spawn(
        FakeLink {
            events: evt_rx,
            sent: cmd_tx,
        },
        client_id(),
        test_sinks(SharedOwnIdentity::default()),
    );

    // A Low-ID source's server-assigned id (ADR-0039): the session relays it
    // verbatim so the server can dial that peer back to us.
    let low_id = ClientId::from_u32(0x0000_2A57);
    handle.request_callback(low_id).await;

    match cmd_rx.recv().await.unwrap() {
        Ed2kCommand::RequestCallback { low_id: got } => assert_eq!(got, low_id),
        other => panic!("unexpected command {other:?}"),
    }
}

/// ADR-0049 — ruled unread: no callback record exists for a
/// `0x35` crypt extension to attach to, so it is dropped without effect.
#[tokio::test]
async fn a_peer_callbacks_crypt_extension_is_dropped_without_effect() {
    let (evt_tx, evt_rx) = mpsc::channel(8);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
    let handle = ServerSession::spawn(
        FakeLink {
            events: evt_rx,
            sent: cmd_tx,
        },
        client_id(),
        test_sinks(SharedOwnIdentity::default()),
    );
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 2), 4662));
    let crypt = Some(PeerCallbackCrypt {
        connect_options: SourceCryptOptions::from_byte(0x07),
        user_hash: UserHash::from_bytes([0xBB; UserHash::BYTE_LEN]),
    });
    let event = Ed2kEvent::PeerCallbackRequested { peer, crypt };
    evt_tx.send(event).await.unwrap();
    // No command rides out for it; dropping the link then proves the loop
    // kept running rather than wedging on the dropped event.
    drop(evt_tx);
    assert_eq!(cmd_rx.recv().await, None);
    assert!(!handle.is_alive());
}
