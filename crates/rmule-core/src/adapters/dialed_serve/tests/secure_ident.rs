//! One Secure User Identification per link, bound by the link (ADR-0041): on
//! a link rmule dialed, the verification is bound where the credit ledger
//! keeps the client's identity the moment the session reports it, whichever
//! halves hold the link, and the serve half reads the binding while it
//! serves — it keys the identified client on it (`UploadQueue.cpp:432-458`,
//! `ClientList.cpp:384-392`).

use std::sync::Arc;

use rmule_peer::{PeerHandshakeContext, SecureIdentConfig};
use rmule_primitives::{ClientId, ClientIdentity, SecureIdentKey};
use tokio::task::JoinHandle;

use super::*;
use crate::adapters::{AdapterCells, HelloAdverts, LinkServeHalf, PeerWorker};
use crate::credit::SharedCreditStore;
use crate::secured_identity::SharedSecuredIdentities;
use crate::service::CoreEvent;
use crate::store::credit::DurableCreditStore;
use crate::store::open_durable_store_in_memory;

const PEER_HASH: UserHash = UserHash::from_bytes([0x0B; UserHash::BYTE_LEN]);

/// A link rmule dialed to a peer that proves `peer_key`, with the node's
/// verified-identity cell installed on `credit`: the link's serve half, the
/// download that dialed it, the bus a theft is raised on, and the peer.
struct SuiLink {
    serve: LinkServeHalf,
    _worker: PeerWorker,
    events: mpsc::Receiver<CoreEvent>,
    _events_tx: mpsc::Sender<CoreEvent>,
    _peer: JoinHandle<()>,
}

async fn dialed_sui_link(peer_key: Arc<SecureIdentKey>, credit: SharedCreditStore) -> SuiLink {
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let bound = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_port());
    let peer = tokio::spawn(async move {
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

    let (events_tx, events) = mpsc::channel(8);
    let secured = SharedSecuredIdentities::default();
    secured.install(credit, events_tx.downgrade());
    let (dialed_tx, mut dialed_rx) = mpsc::channel(4);
    let mut cells = AdapterCells::detached();
    cells.dialed_serve_sink.install_for_good(dialed_tx);
    cells.secured_identities = secured;
    cells.hello_adverts = HelloAdverts {
        secure_ident: Some(Arc::new(SecureIdentKey::generate().unwrap())),
        ..HelloAdverts::default()
    };
    let mut transfer = RuntimePeerTransferService::default();
    transfer.adopt_cells(&cells);
    let at = PeerEndpoint::V4(Ipv4Endpoint::new(*bound.ip(), bound.port()));
    let worker = transfer
        .start_peer_worker(at, dialed_serve_ctx(), dummy_file(0x5E))
        .await
        .unwrap();
    let serve = timeout(Duration::from_secs(5), dialed_rx.recv())
        .await
        .expect("the dialed link's serve half reaches the serve side")
        .expect("a serve connection");
    SuiLink {
        serve,
        _worker: worker,
        events,
        _events_tx: events_tx,
        _peer: peer,
    }
}

fn ledger() -> SharedCreditStore {
    Arc::new(DurableCreditStore::new(
        open_durable_store_in_memory().unwrap(),
    ))
}

#[tokio::test]
async fn a_dialed_links_verification_is_bound_and_its_serve_half_reads_the_client_identified() {
    let peer_key = Arc::new(SecureIdentKey::generate().unwrap());
    let credit = ledger();
    let link = dialed_sui_link(Arc::clone(&peer_key), Arc::clone(&credit)).await;
    let mut serve_conn = link.serve.conn;

    let identified = timeout(Duration::from_secs(5), async {
        while let Some(input) = serve_conn.next_event().await {
            if let ServeInput::IdentityBound { user_hash } = input {
                return Some(user_hash);
            }
        }
        None
    })
    .await;
    assert_eq!(
        identified,
        Ok(Some(PEER_HASH)),
        "the serve half reads the client identified"
    );
    assert_eq!(
        credit.public_key(PEER_HASH).unwrap(),
        Some(peer_key.public_key_der()),
        "the peer's proven key is its Secured Identity"
    );
}

/// The serve half lets the link go the moment it reaches the serve side,
/// racing the verification the peer is proving: the verification is still
/// bound, once — a key under the peer's hash that differs is raised as a
/// theft exactly once, whoever held the link when the proof came in.
#[tokio::test]
async fn a_verification_racing_its_serve_half_letting_go_is_bound_once() {
    let credit = ledger();
    credit
        .bind_public_key(PEER_HASH, b"an earlier key")
        .unwrap();
    let mut link = dialed_sui_link(Arc::new(SecureIdentKey::generate().unwrap()), credit).await;
    link.serve.conn.send(ServeOutput::Disconnect).await.unwrap();
    drop(link.serve);

    let raised = timeout(Duration::from_secs(5), link.events.recv()).await;
    assert!(
        matches!(
            raised,
            Ok(Some(CoreEvent::SecuredIdentityMismatch { user_hash })) if user_hash == PEER_HASH
        ),
        "the verification is bound though its serve half let go: {raised:?}"
    );
    let again = timeout(Duration::from_millis(300), link.events.recv()).await;
    assert!(again.is_err(), "the theft is raised once: {again:?}");
}
