//! The callback relays over the fake link: `RequestCallback` carrying the
//! source's Low ID to the server, and a peer's `0x35` the server relays to a
//! Low-ID us, answered by a dial-back into the serve pipeline (ADR-0061) —
//! keyed toward the hash its crypt extension names (ADR-0049), and armed by an
//! `OP_IDCHANGE` that takes the session Low-ID.

use std::net::{Ipv4Addr, SocketAddrV4};

use rmule_ed2k::PeerCallbackCrypt;
use rmule_net::peer::{ConnectOptions, ObfuscationConfig, ObfuscationPolicy, PeerListener};
use rmule_peer::{ConnectionEvent, PeerEvent, PeerHandshakeContext};
use rmule_primitives::{
    ClientIdentity, Ed2kText, Ipv4Endpoint, PeerEndpoint, SourceCryptOptions, UserHash,
};
use rmule_testkit::HANG_GUARD;
use rmule_testkit::peer_session::serverless_ctx;
use tokio::io::AsyncReadExt;

use super::super::super::tests::{FakeLink, client_id, test_sinks};
use super::super::*;
use crate::adapters::{AdmittedPeer, HelloAdverts, SharedTunnelAdmit};
use crate::obfuscation_policy::SharedObfuscationPolicy;
use crate::server_session::ServerCallbackDialBacks;

const LOW_ID: ClientId = ClientId::from_u32(0x0000_2A57);

/// The serve pipeline a leg holds: the admit seam keeps only a weak sender,
/// so the strong one lives here beside what the pipeline admits.
struct Pipeline {
    _accept_tx: mpsc::Sender<AdmittedPeer>,
    accepted: mpsc::Receiver<AdmittedPeer>,
}

/// Dial-backs over a serve pipeline the test holds, under `policy`.
fn serving_dial_backs(policy: Option<ObfuscationPolicy>) -> (ServerCallbackDialBacks, Pipeline) {
    let admit = SharedTunnelAdmit::default();
    let (accept_tx, accepted) = mpsc::channel(4);
    admit.install_for_test(&accept_tx, serverless_ctx(), HelloAdverts::default());
    let dial_backs = ServerCallbackDialBacks::new(SharedObfuscationPolicy::new(policy));
    dial_backs.install_admit(admit);
    let pipeline = Pipeline {
        _accept_tx: accept_tx,
        accepted,
    };
    (dial_backs, pipeline)
}

/// A session as `client_id` over a fake link, answering callbacks through
/// `dial_backs`: its handle (dropping every handle ends it), the event
/// sender, and what the session sends.
fn session_with(
    client_id: ClientId,
    dial_backs: ServerCallbackDialBacks,
) -> (
    ServerSessionHandle,
    mpsc::Sender<Ed2kEvent>,
    mpsc::Receiver<Ed2kCommand>,
) {
    let (evt_tx, evt_rx) = mpsc::channel(8);
    let (cmd_tx, cmd_rx) = mpsc::channel(8);
    let handle = ServerSession::spawn(
        FakeLink {
            events: evt_rx,
            sent: cmd_tx,
        },
        client_id,
        SessionSinks {
            dial_backs,
            ..test_sinks(SharedOwnIdentity::default())
        },
    );
    (handle, evt_tx, cmd_rx)
}

fn loopback(port: u16) -> PeerEndpoint {
    PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, port))
}

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

/// A Low-ID session answers the server's relay of a peer that wants our file
/// by dialing that peer back and handing the link to the serve pipeline as
/// the dialer's side: our hello is the first frame on the wire.
#[tokio::test]
async fn a_low_id_session_dials_the_relayed_peer_back_into_the_serve_pipeline() {
    let requester = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let peer = loopback(requester.local_addr().unwrap().port());
    let (dial_backs, mut pipeline) = serving_dial_backs(None);
    let (_handle, evt_tx, _sent) = session_with(LOW_ID, dial_backs);

    evt_tx
        .send(Ed2kEvent::PeerCallbackRequested { peer, crypt: None })
        .await
        .unwrap();
    let (mut socket, _) = tokio::time::timeout(HANG_GUARD, requester.accept())
        .await
        .expect("the dial-back arrives")
        .unwrap();
    let mut header = [0u8; 6];
    tokio::time::timeout(HANG_GUARD, socket.read_exact(&mut header))
        .await
        .expect("our first frame arrives")
        .unwrap();
    assert_eq!(
        (header[0], header[5]),
        (0xE3, 0x01),
        "a plaintext OP_HELLO from the dialer's side"
    );
    let admitted = tokio::time::timeout(HANG_GUARD, pipeline.accepted.recv())
        .await
        .expect("the link enters the serve pipeline")
        .unwrap();
    assert_eq!(admitted.conn.peer_endpoint(), peer);
}

/// The `0x35` crypt extension is the requester's stance for this dial: a
/// requester that requires obfuscation and names its hash is dialed
/// obfuscated toward that hash, so its own crypt layer — keyed on its own
/// hash — opens our hello.
#[tokio::test]
async fn the_crypt_extension_keys_the_dial_back_toward_the_requesters_hash() {
    let requester_hash = UserHash::from_bytes([0xBB; UserHash::BYTE_LEN]);
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the requester");
    let peer = loopback(listener.local_port());
    let requester = tokio::spawn(async move {
        let ctx = PeerHandshakeContext {
            identity: ClientIdentity::new(
                requester_hash,
                Ed2kText::from_utf8("requester"),
                peer.port(),
                0x3C,
            ),
            ..serverless_ctx()
        };
        let options = ConnectOptions {
            obfuscation: Some(ObfuscationConfig {
                policy: ObfuscationPolicy::Required,
            }),
            ..ConnectOptions::default()
        };
        let mut conn = listener
            .accept(ctx, options)
            .await
            .expect("the dial-back opens under the requester's own key");
        while let Some(event) = conn.next_event().await {
            if let PeerEvent::Connection(ConnectionEvent::Identified { identity }) = event {
                return Some(identity.user_hash());
            }
        }
        None
    });
    let (dial_backs, _pipeline) = serving_dial_backs(Some(ObfuscationPolicy::Supported));
    let (_handle, evt_tx, _sent) = session_with(LOW_ID, dial_backs);

    evt_tx
        .send(Ed2kEvent::PeerCallbackRequested {
            peer,
            crypt: Some(PeerCallbackCrypt {
                // supports + requests + requires
                connect_options: SourceCryptOptions::from_byte(0x07),
                user_hash: requester_hash,
            }),
        })
        .await
        .unwrap();
    let identified = tokio::time::timeout(HANG_GUARD, requester)
        .await
        .expect("the requester hears our hello")
        .unwrap();
    assert_eq!(identified, Some(serverless_ctx().identity.user_hash()));
}

/// The session's id is read at each relay, moved by `OP_IDCHANGE`: a session
/// that logged in High-ID and is re-assigned a Low ID dials the next relayed
/// peer back, as the server now believes it must.
#[tokio::test]
async fn an_idchange_to_low_id_arms_the_dial_back() {
    let requester = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let peer = loopback(requester.local_addr().unwrap().port());
    let (dial_backs, _pipeline) = serving_dial_backs(None);
    assert!(client_id().is_high_id());
    let (_handle, evt_tx, _sent) = session_with(client_id(), dial_backs);

    evt_tx
        .send(Ed2kEvent::LoginAccepted {
            client_id: LOW_ID,
            tcp_flags: None,
            facts: rmule_ed2k::ServerAssignedFacts::default(),
        })
        .await
        .unwrap();
    evt_tx
        .send(Ed2kEvent::PeerCallbackRequested { peer, crypt: None })
        .await
        .unwrap();
    tokio::time::timeout(HANG_GUARD, requester.accept())
        .await
        .expect("the re-assigned Low-ID session dials back")
        .unwrap();
}
