//! Datagram-seam tests: a peer reask reaching the client-UDP engine over each
//! **Address Family** of the bound Family Pair — the IPv6 leg obfuscated, so
//! the 35-byte key is exercised on a real socket and not only against the
//! primitive (ADR-0087) — and a global callback relayed to the source server
//! that offered it.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use rmule_ed2k::GlobCallbackRequest;
use rmule_primitives::{
    AddressFamily, ClientEncryptKey, ClientId, DatagramSenderAddress, FileHash, Ipv4Endpoint,
    Ipv6Endpoint, PeerEndpoint, UserHash, encrypt_datagram_client,
};
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::buddy_link::SharedBuddySlot;
use crate::client_udp::{PeerUdpCrypt, os_datagram_nonce};
use crate::diagnostics::DiagnosticsState;
use crate::global_sources::GlobCallbackSend;
use crate::own_identity::SharedOwnIdentity;

use super::*;

/// ADR-0057 socket unification: an inbound `0xC5` reask ping on the *real*
/// shared client-UDP socket reaches the demux front's reask inbox, tagged
/// with the sender's UDP source (the reply-routing key). Exercises the
/// production [`RuntimeClientUdpTransport`] + [`ClientUdpEngine`] end-to-end
/// over loopback — the live-socket tier beyond the sans-I/O demux exercises.
#[tokio::test]
async fn a_reask_ping_on_the_bound_client_udp_socket_reaches_the_engine() {
    let engine_socket = Arc::new(
        rmule_net::ed2k::ClientUdpSocket::bind(0)
            .await
            .expect("bind the engine's client-UDP socket"),
    );
    let engine_port = engine_socket.local_port();
    let (engine, mut inboxes) = crate::client_udp::ClientUdpEngine::new(
        RuntimeClientUdpTransport::new(Arc::clone(&engine_socket)),
        crate::client_udp::PeerUdpCrypt::disarmed(),
        SharedBuddySlot::default(),
        crate::firewalled::front::SharedFirewalledFront::default(),
        crate::diagnostics::DiagnosticsState::default(),
        tokio::sync::mpsc::channel(4).0,
        crate::client_udp::SharedKadInlet::default(),
    );
    let engine_task = tokio::spawn(engine.run());

    // A peer socket sends a peer-UDP reask ping (`0xC5 0x90 <hash16>`).
    let peer_socket = rmule_net::ed2k::ClientUdpSocket::bind(0)
        .await
        .expect("bind the peer socket");
    let peer_port = peer_socket.local_port();
    let ping = rmule_peer::ReaskFilePing {
        file_hash: FileHash::from_bytes([0x22; FileHash::BYTE_LEN]),
        part_status: None,
        complete_sources: None,
    }
    .encode_udp();
    peer_socket
        .send_to(SocketAddrV4::new(Ipv4Addr::LOCALHOST, engine_port), &ping)
        .await
        .expect("send the reask ping to the engine socket");

    let (src, datagram) = timeout(Duration::from_secs(2), inboxes.reask_ping.recv())
        .await
        .expect("the reask ping routed within 2s")
        .expect("the reask inbox stayed open");
    assert_eq!(
        src,
        PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, peer_port))
    );
    assert_eq!(datagram, ping);

    engine_task.abort();
}

/// The IPv6 half of the same span, with the crypt layer armed: an obfuscated
/// `0xC5 0x90` sealed on our user hash plus the **v6 source the datagram will
/// truly arrive from** — the 35-byte layout, magic at offset 32 — crosses the
/// `::` half of the bound Family Pair, and the production transport plus front
/// recover the exact plaintext and hand it on tagged with its IPv6 source.
///
/// This is why the client-UDP surface was widened to IPv6: before, the transport narrowed every
/// datagram to IPv4 and the layout could only ever be exercised against the
/// primitive. Skipped honestly on an IPv4-only host, where the `::` bind is
/// absent and there is no v6 leg to prove.
#[tokio::test]
async fn an_ipv6_reask_on_the_bound_family_pair_decrypts_under_the_35_byte_key() {
    let engine_socket = Arc::new(
        rmule_net::ed2k::ClientUdpSocket::bind(0)
            .await
            .expect("bind the engine's client-UDP socket"),
    );
    if !engine_socket.binds().holds(AddressFamily::V6) {
        return;
    }
    let engine_port = engine_socket.local_port();

    // Our own identity: the receive key needs the user hash and nothing else —
    // it is the *sender's* address that selects the layout, not ours.
    let our_hash = UserHash::from_bytes([0x11; UserHash::BYTE_LEN]);
    let own = SharedOwnIdentity::default();
    own.set_user_hash(our_hash);
    let (engine, mut inboxes) = crate::client_udp::ClientUdpEngine::new(
        RuntimeClientUdpTransport::new(Arc::clone(&engine_socket)),
        PeerUdpCrypt::new(
            own,
            crate::obfuscation_policy::SharedObfuscationPolicy::new(Some(
                rmule_net::peer::ObfuscationPolicy::Requested,
            )),
        ),
        SharedBuddySlot::default(),
        crate::firewalled::front::SharedFirewalledFront::default(),
        DiagnosticsState::default(),
        tokio::sync::mpsc::channel(4).0,
        crate::client_udp::SharedKadInlet::default(),
    );
    let engine_task = tokio::spawn(engine.run());

    let peer_socket = rmule_net::ed2k::ClientUdpSocket::bind(0)
        .await
        .expect("bind the peer socket");
    let peer_port = peer_socket.local_port();
    let ping = rmule_peer::ReaskFilePing {
        file_hash: FileHash::from_bytes([0x22; FileHash::BYTE_LEN]),
        part_status: None,
        complete_sources: None,
    }
    .encode_udp();
    let sealed = encrypt_datagram_client(
        &ping,
        &ClientEncryptKey::Ed2k {
            user_hash: &our_hash,
            sender: DatagramSenderAddress::V6(Ipv6Addr::LOCALHOST.octets()),
        },
        &os_datagram_nonce(),
    );
    assert_ne!(sealed, ping, "the datagram crosses the wire obfuscated");
    peer_socket
        .send_to_peer(
            PeerEndpoint::V6(Ipv6Endpoint::new(Ipv6Addr::LOCALHOST, engine_port)),
            &sealed,
        )
        .await
        .expect("send the sealed reask ping over IPv6");

    let (src, datagram) = timeout(Duration::from_secs(2), inboxes.reask_ping.recv())
        .await
        .expect("the IPv6 reask ping routed within 2s")
        .expect("the reask inbox stayed open");
    assert_eq!(
        src,
        PeerEndpoint::V6(Ipv6Endpoint::new(Ipv6Addr::LOCALHOST, peer_port)),
        "the front reports the family the datagram truly arrived in",
    );
    assert_eq!(
        datagram, ping,
        "the 35-byte key recovered the exact plaintext",
    );

    engine_task.abort();
}

/// A transport that records every `send_to` and never receives, so the
/// relay's only activity is the callback send under test.
struct RecordingTransport {
    sent_tx: mpsc::Sender<(Ipv4Endpoint, Vec<u8>)>,
}

impl ServerUdpTransport for RecordingTransport {
    async fn send_to(&self, to: Ipv4Endpoint, datagram: Vec<u8>) {
        let _ = self.sent_tx.send((to, datagram)).await;
    }

    async fn recv(&self) -> Option<(Vec<u8>, Ipv4Endpoint)> {
        std::future::pending().await
    }
}

/// The global-callback relay rides the server-UDP transport that owns the
/// socket: a runner's `GlobCallbackSend` becomes an
/// `OP_GLOBCALLBACKREQUEST` UDP-sent to the source-server, carrying rmule's
/// own contact and the target low id.
#[tokio::test]
async fn relays_a_global_callback_send_to_the_source_server() {
    let (sent_tx, mut sent_rx) = mpsc::channel(4);
    let transport = RecordingTransport { sent_tx };
    let (callback_tx, callback_rx) = mpsc::channel(4);
    let task = tokio::spawn(relay_global_callbacks(
        crate::server_udp::tests::plain_seal(transport),
        callback_rx,
    ));

    let requester = Ipv4Endpoint::new(std::net::Ipv4Addr::new(9, 9, 9, 9), 5000);
    let source_server = Ipv4Endpoint::new(std::net::Ipv4Addr::LOCALHOST, 4661);
    let low_id = ClientId::from_u32(0x1234);
    callback_tx
        .send(GlobCallbackSend {
            requester,
            low_id,
            source_server,
        })
        .await
        .unwrap();

    let (server, datagram) = timeout(Duration::from_secs(2), sent_rx.recv())
        .await
        .expect("a callback datagram was sent within 2s")
        .expect("transport stayed open");
    // Sent to the source-server's UDP port, its standard port + 4.
    assert_eq!(
        server,
        Ipv4Endpoint::new(std::net::Ipv4Addr::LOCALHOST, 4665)
    );
    // A no-length UDP datagram carrying OP_GLOBCALLBACKREQ for rmule's own
    // contact + the target low id.
    let decoded = GlobCallbackRequest::decode_udp(&datagram).expect("OP_GLOBCALLBACKREQ");
    assert_eq!(decoded, GlobCallbackRequest::new(requester, low_id));

    task.abort();
}
