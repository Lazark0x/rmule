//! An adopted callback link's serve half (ADR-0107, "Callbacks and tunnel
//! claims"): aMule takes a callback socket at its `OP_HELLO` like every socket
//! a client opens (`ClientTCPSocket.cpp:391`), so the serve side reads the
//! hello the accept side read before anything the peer asks over the link,
//! and the client identified once the link binds its one Secure User
//! Identification (ADR-0041).

use rmule_net::peer::Connection as PeerConnection;
use rmule_peer::{PeerCommand, PeerEvent, RequesterCommand, SecureIdentConfig, ServerEvent};
use rmule_primitives::{ClientIdentity, PeerEndpoint, SecureIdentKey};

use super::*;
use crate::adapters::PeerWorker;
use crate::secured_identity::SharedSecuredIdentities;

const CALLER_HASH: UserHash = UserHash::from_bytes([0xC7; UserHash::BYTE_LEN]);

/// A called-back Low ID adopted by the download that awaited it, while rmule
/// serves: the caller's link, the adopted worker, where the link's serve half
/// arrives, and the registration that awaited it. Each side proves itself
/// with the Secure User Identification key it is given.
struct Adopted {
    caller: PeerConnection,
    worker: PeerWorker,
    serving: mpsc::Receiver<crate::adapters::LinkServeHalf>,
    _registration: crate::adapters::awaited_inbound::AwaitedInboundHandle,
}

async fn adopted_callback(
    caller_key: Option<Arc<SecureIdentKey>>,
    our_key: Option<Arc<SecureIdentKey>>,
    secured_identities: SharedSecuredIdentities,
) -> Adopted {
    let low_id = ClientId::from_u32(0x0000_1234);
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
    let (serving_tx, serving) = mpsc::channel(4);
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
        identity: ClientIdentity::new(CALLER_HASH, Ed2kText::from_utf8("caller"), 4662, 60),
        client_id: low_id,
        ed2k_client_id: low_id,
        public_ip: None,
        connected_server: None,
    };
    let proving = |key: Option<Arc<SecureIdentKey>>, challenge| PeerConnectOptions {
        secure_ident: key.map(|key| SecureIdentConfig { key, challenge }),
        ..PeerConnectOptions::default()
    };
    let (accepted, caller) = tokio::join!(
        listener.accept(ctx, proving(our_key, 0x5EC1_0001)),
        PeerConnection::connect(ours, caller_ctx, proving(caller_key, 0x5EC1_0002)),
    );
    let caller = caller.expect("the caller reaches rmule");
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
            secured_identities,
        },
    ));
    let (_key, worker) = timeout(Duration::from_secs(5), adopt_rx.recv())
        .await
        .expect("the callback is adopted")
        .expect("the adopt channel stayed open");
    Adopted {
        caller,
        worker,
        serving,
        _registration: registration,
    }
}

/// A called-back Low ID asks rmule for a slot over the link it opened, which
/// a download adopted. The serve side holds that link's hello first: the
/// identity the serve side scores the ask's credit by, and reads bans and the
/// two-clients rule under (`current_modifiers`, `UploadQueue.cpp:432-458`).
#[tokio::test]
async fn a_slot_ask_over_an_adopted_callback_reaches_the_serve_side_under_its_hello() {
    let asked = FileHash::from_bytes([0x3E; FileHash::BYTE_LEN]);
    let Adopted {
        mut caller,
        mut serving,
        worker: _worker,
        _registration,
    } = adopted_callback(None, None, SharedSecuredIdentities::default()).await;

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

    let half = timeout(Duration::from_secs(5), serving.recv())
        .await
        .expect("the adopted link's serve half reaches the serve side")
        .expect("a serve connection");
    assert!(
        half.dialed.is_none(),
        "an adopted callback is a link the peer opened"
    );
    let mut served = half.conn;
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
                if identity.user_hash() == CALLER_HASH
        ),
        "the slot ask comes behind the caller's hello: {inputs:?}"
    );
}

/// The adopted link binds its one verification, and its serve half reads the
/// client identified, which it keys on the link (`UploadQueue.cpp:432-458`,
/// `ClientList.cpp:384-392`).
#[tokio::test]
async fn an_adopted_callbacks_verification_is_bound_and_its_serve_half_reads_it() {
    let credit: crate::credit::SharedCreditStore =
        Arc::new(crate::store::credit::DurableCreditStore::new(
            crate::store::open_durable_store_in_memory().unwrap(),
        ));
    let (events_tx, _events) = mpsc::channel(4);
    let secured = SharedSecuredIdentities::default();
    secured.install(Arc::clone(&credit), events_tx.downgrade());
    let caller_key = Arc::new(SecureIdentKey::generate().unwrap());
    let Adopted {
        caller: _caller,
        worker: _worker,
        mut serving,
        _registration,
    } = adopted_callback(
        Some(Arc::clone(&caller_key)),
        Some(Arc::new(SecureIdentKey::generate().unwrap())),
        secured,
    )
    .await;
    let mut served = timeout(Duration::from_secs(5), serving.recv())
        .await
        .expect("the adopted link's serve half reaches the serve side")
        .expect("a serve connection")
        .conn;
    let identified = timeout(Duration::from_secs(5), async {
        while let Some(input) = served.next_event().await {
            if let ServeInput::IdentityBound { user_hash } = input {
                return Some(user_hash);
            }
        }
        None
    })
    .await;
    assert_eq!(
        identified,
        Ok(Some(CALLER_HASH)),
        "the serve half reads the client identified"
    );
    assert_eq!(
        credit.public_key(CALLER_HASH).unwrap(),
        Some(caller_key.public_key_der()),
        "the caller's proven key is its Secured Identity"
    );
}
