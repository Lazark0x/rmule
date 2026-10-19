//! An adopted callback link's serve half (ADR-0107, "Callbacks and tunnel
//! claims"): aMule takes a callback socket at its `OP_HELLO` like every socket
//! a client opens (`ClientTCPSocket.cpp:391`), so the serve side reads the
//! hello the accept side read before anything the peer asks over the link.

use rmule_net::peer::Connection as PeerConnection;
use rmule_peer::{PeerCommand, PeerEvent, RequesterCommand, ServerEvent};
use rmule_primitives::{ClientIdentity, PeerEndpoint};

use super::*;

/// A called-back Low ID asks rmule for a slot over the link it opened, which
/// a download adopted. The serve side holds that link's hello first: the
/// identity the serve side scores the ask's credit by, and reads bans and the
/// two-clients rule under (`current_modifiers`, `UploadQueue.cpp:432-458`).
#[tokio::test]
async fn a_slot_ask_over_an_adopted_callback_reaches_the_serve_side_under_its_hello() {
    let caller_hash = UserHash::from_bytes([0xC7; UserHash::BYTE_LEN]);
    let low_id = ClientId::from_u32(0x0000_1234);
    let asked = FileHash::from_bytes([0x3E; FileHash::BYTE_LEN]);

    // The download that asked the callback, awaiting it under the caller's
    // Low ID on no server.
    let awaited = AwaitedInbound::default();
    let (adopt_tx, mut adopt_rx) = mpsc::channel(1);
    let key = CallbackKey {
        server: None,
        low_id,
        kad_port: None,
    };
    let registration = awaited.register(key, adopt_tx, mpsc::channel(1).0);
    registration.await_callback(
        key,
        AdoptionBrief {
            own_status: rmule_peer::PartBitmap::downloader_empty(0),
            want_sources: false,
            file: Ed2kFileLink {
                name: Ed2kText::from_utf8("called back"),
                size: 4096,
                file_hash: FileHash::from_bytes([0xCD; FileHash::BYTE_LEN]),
                part_hash_set: None,
                aich_root: None,
                ipv6_sources: Vec::new(),
                sources: Default::default(),
            },
        },
    );
    // Where the adopted link's serve half goes while rmule serves.
    let (serving_tx, mut serving_rx) = mpsc::channel(4);
    let sink = SharedDialedServeSink::default();
    sink.install_for_good(serving_tx);

    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the inbound listener");
    let ours = PeerEndpoint::V4(Ipv4Endpoint::new(
        Ipv4Addr::LOCALHOST,
        listener.local_port(),
    ));
    let ctx = PeerHandshakeContext {
        identity: rmule_testkit::test_identity(0x11, "rmule", 4662),
        client_id: ClientId::from_u32(0),
        ed2k_client_id: ClientId::from_u32(0),
        public_ip: None,
        connected_server: None,
    };
    let caller_ctx = PeerHandshakeContext {
        identity: ClientIdentity::new(caller_hash, Ed2kText::from_utf8("caller"), 4662, 60),
        client_id: low_id,
        ed2k_client_id: low_id,
        public_ip: None,
        connected_server: None,
    };
    let (accepted, caller) = tokio::join!(
        listener.accept(ctx, PeerConnectOptions::default()),
        PeerConnection::connect(ours, caller_ctx, PeerConnectOptions::default()),
    );
    let mut caller = caller.expect("the caller reaches rmule");
    let (_cmd_tx, cmd_rx) = mpsc::channel(4);
    let (evt_tx, _evt_rx) = mpsc::channel(16);
    tokio::spawn(triage_inbound_connection(
        accepted.expect("rmule accepts the callback"),
        None,
        cmd_rx,
        evt_tx,
        awaited.clone(),
        InboundPeerDeps {
            slot_wait_timeout: Duration::from_secs(5),
            dialed_serve_sink: sink,
            kad_bootstrap: SharedKadBootstrap::default(),
            kad_pump: crate::adapters::SharedKadPump::default(),
            buddy_slot: SharedBuddySlot::default(),
            addresses: crate::address_learning::SharedAddressLearning::new(),
            peer_roster: crate::peer_roster::SharedPeerRoster::default(),
            kad_presence: crate::adapters::KadPresenceView::default(),
            file_known: crate::known_files::SharedFileKnown::default(),
            tunnel_admit: crate::adapters::SharedTunnelAdmit::default(),
            hello_refusals: crate::hello_refusals::SharedHelloRefusals::default(),
            peer_links: crate::adapters::SharedPeerLinks::default(),
        },
    ));
    let (_key, _worker) = timeout(Duration::from_secs(5), adopt_rx.recv())
        .await
        .expect("the callback is adopted")
        .expect("the adopt channel stayed open");

    // The caller asks for a slot once it holds rmule's hello.
    let identified = async {
        while let Some(event) = caller.next_event().await {
            if matches!(
                event,
                PeerEvent::Connection(ConnectionEvent::Identified { .. })
            ) {
                return;
            }
        }
    };
    timeout(Duration::from_secs(5), identified)
        .await
        .expect("the caller reads rmule's hello");
    caller
        .send(PeerCommand::Requester(RequesterCommand::AskSlot {
            file_hash: asked,
        }))
        .await
        .expect("the caller's link is up");

    let mut served = timeout(Duration::from_secs(5), serving_rx.recv())
        .await
        .expect("the adopted link's serve half reaches the serve side")
        .expect("a serve connection");
    let mut inputs = Vec::new();
    let read = async {
        while let Some(input) = served.next_event().await {
            let ask = matches!(
                input,
                ServeInput::Server(ServerEvent::SlotRequested { file_hash }) if file_hash == asked
            );
            inputs.push(input);
            if ask {
                return;
            }
        }
    };
    let _ = timeout(Duration::from_secs(5), read).await;
    assert!(
        matches!(
            inputs.as_slice(),
            [ServeInput::Connection(ConnectionEvent::Identified { identity }), .., ServeInput::Server(ServerEvent::SlotRequested { .. })]
                if identity.user_hash() == caller_hash
        ),
        "the slot ask comes behind the caller's hello: {inputs:?}"
    );
    drop(registration);
}
