//! The ADR-0061 `OP_CALLBACK` (`0x99`) buddy-relay emit over an identified
//! peer link: complete the eD2k handshake, queue `SendBuddyCallback`, and the
//! relay lands with its echoed buddy-ID intact. This pins the session-level
//! emit at the wire tier — the frame is identical whichever link carries it.
//!
//! The production route is the buddy's HELD persistent inbound connection
//! (aMule's `buddy->GetSocket()`), never a fresh dial — rmule-core's
//! `buddy_link` owns that routing and proves it against a dialing `FakeBuddy`.
//! This loopback keeps the emit proven over the `connect_identified` dial
//! surface, where a `FakePeer` can observe the bytes.

use std::net::Ipv4Addr;

use crate::fixture::{options, peer_endpoint};
use rmule_net::peer::Connection;
use rmule_peer::{Callback, PeerCommand, SideCommand};
use rmule_primitives::{FileHash, Ipv4Endpoint, UserHash};
use rmule_testkit::peer_session::serverless_ctx;
use rmule_testkit::{FakePeer, PeerScript};

/// The load-bearing enactment: a buddy that answers our hello must receive the
/// `OP_CALLBACK` (`0x99`) our relay sends over the dial surface, carrying the
/// echoed buddy-ID from the inbound Kad `0x52` — the anchor a firewalled-node
/// `0x99` consume verifies. Pins both the dial surface and that the relay body
/// survives.
#[tokio::test]
async fn buddy_relay_delivers_the_0x99_callback_over_the_dial_surface() {
    let peer = FakePeer::bind().await;
    let endpoint = peer_endpoint(peer.addr());
    let buddy_hash = UserHash::from_bytes([0xBE; UserHash::BYTE_LEN]);
    let peer_task = peer.spawn(PeerScript::hello_only(buddy_hash, "firewalled-buddy"));

    let (conn, _identity) = Connection::connect_identified(endpoint, serverless_ctx(), options())
        .await
        .expect("the buddy link completes the handshake");

    let callback = Callback {
        buddy_id: [0x7A; 16],
        file_hash: FileHash::from_bytes([0xCD; 16]),
        requester: Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 5), 4662),
    };
    conn.send(PeerCommand::Side(SideCommand::SendBuddyCallback(callback)))
        .await
        .expect("queue the buddy callback relay");
    conn.shutdown()
        .await
        .expect("close after the relay flushes");

    let stats = peer_task.await.expect("buddy script");
    assert_eq!(
        stats.buddy_callback_buddy_id,
        Some([0x7A; 16]),
        "the firewalled buddy must receive OP_CALLBACK (0x99) with the echoed buddy-ID",
    );
}
