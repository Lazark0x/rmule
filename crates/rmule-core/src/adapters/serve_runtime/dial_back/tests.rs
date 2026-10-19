//! The dial-back's link is a Peer Link like any other (ADR-0107): a download
//! of the dialed peer rides it rather than dialing a second link aMule would
//! answer by dropping the first (`ClientList.cpp:400-403`). When the waiter's
//! own link races the dial, that link keeps the names, and a dial called off
//! before its hello stops with nothing said. Proven on real loopback links
//! through the production serve and dial adapters.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use rmule_net::peer::{ConnectOptions, Connection as PeerConnection, PeerListener};
use rmule_peer::{ConnectionEvent, PeerEvent, PeerHandshakeContext, ServerEvent};
use rmule_primitives::{
    ClientId, ClientIdentity, CryptStance, Ed2kFileLink, Ed2kText, FileHash, Ipv4Endpoint,
    PeerCrypt, PeerEndpoint, UserHash,
};
use tokio::sync::mpsc;
use tokio::time::timeout;

use super::{DialBack, DialBackOutcome};
use crate::adapters::peer_link::LinkName;
use crate::adapters::peer_transfer::{PeerTransferService, WorkerBrief};
use crate::adapters::serve_runtime::{RuntimeServeRuntimeService, ServeRuntimeService};
use crate::adapters::tests::dialed_serve_ctx;
use crate::adapters::{RuntimePeerTransferService, SharedPeerLinks};

const WAITER: UserHash = UserHash::from_bytes([0xB7; UserHash::BYTE_LEN]);

fn waiter_ctx() -> PeerHandshakeContext {
    PeerHandshakeContext {
        identity: ClientIdentity::new(WAITER, Ed2kText::from_utf8("waiter"), 0, 60),
        client_id: ClientId::from_u32(0),
        ed2k_client_id: ClientId::from_u32(0),
        public_ip: None,
        connected_server: None,
    }
}

/// The waiter's hello as a Low ID on a server, listening on `listen_port`:
/// it proves a name — its callback — its dial-back was not filed under, so
/// the dial's hello refiles.
fn low_id_waiter_ctx(listen_port: u16) -> PeerHandshakeContext {
    let server = Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 7), 4661);
    PeerHandshakeContext {
        identity: ClientIdentity::new(WAITER, Ed2kText::from_utf8("waiter"), listen_port, 60),
        client_id: ClientId::from_u32(5),
        ed2k_client_id: ClientId::from_u32(5),
        public_ip: None,
        connected_server: Some(server),
    }
}

/// Where the Peer Links file `name`, once `settled` holds of it.
async fn filed(
    links: &SharedPeerLinks,
    name: LinkName,
    settled: impl Fn(Option<PeerEndpoint>) -> bool,
) -> Option<PeerEndpoint> {
    let at = || links.find(&[name]).map(|found| found.remote);
    timeout(Duration::from_secs(5), async {
        while !settled(at()) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the filing settles");
    at()
}

/// A started serve adapter over `links`, and where it listens.
async fn serving(links: &SharedPeerLinks) -> (RuntimeServeRuntimeService, PeerEndpoint) {
    let mut serve = RuntimeServeRuntimeService::new().with_peer_links(links.clone());
    let ours = serve
        .start(
            dialed_serve_ctx().identity,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        )
        .await
        .expect("the listener binds");
    (
        serve,
        PeerEndpoint::V4(Ipv4Endpoint::new(*ours.ip(), ours.port())),
    )
}

fn file() -> Ed2kFileLink {
    Ed2kFileLink {
        name: Ed2kText::from_utf8("wanted.bin"),
        size: 4096,
        file_hash: FileHash::from_bytes([0x6B; FileHash::BYTE_LEN]),
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    }
}

/// The waiter's listener: the first link to it, then a count of every later
/// one.
fn listening(listener: PeerListener) -> (mpsc::Receiver<PeerConnection>, mpsc::Receiver<()>) {
    let (first_tx, first_rx) = mpsc::channel(1);
    let (later_tx, later_rx) = mpsc::channel(4);
    tokio::spawn(async move {
        let mut first = Some(first_tx);
        while let Ok(link) = listener
            .accept(waiter_ctx(), ConnectOptions::default())
            .await
        {
            match first.take() {
                Some(tx) => {
                    let _ = tx.send(link).await;
                }
                None => {
                    let _ = later_tx.send(()).await;
                }
            }
        }
    });
    (first_rx, later_rx)
}

#[tokio::test]
async fn a_download_of_a_waiter_dialed_back_rides_the_dialed_link() {
    let links = SharedPeerLinks::default();
    let mut serve = RuntimeServeRuntimeService::new().with_peer_links(links.clone());
    serve
        .start(
            dialed_serve_ctx().identity,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        )
        .await
        .expect("the listener binds");
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the waiter's listen port");
    let at = PeerEndpoint::V4(Ipv4Endpoint::new(
        Ipv4Addr::LOCALHOST,
        listener.local_port(),
    ));
    let (mut first, mut later) = listening(listener);

    let (outcomes_tx, mut outcomes) = mpsc::channel(1);
    let waiter = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 51318));
    serve.dial_back(
        DialBack {
            waiter,
            at,
            crypt: PeerCrypt::new(CryptStance::disabled(), Some(WAITER)),
        },
        outcomes_tx,
    );
    let Some(DialBackOutcome::Linked {
        waiter: dialed_for,
        conn,
        identity,
    }) = timeout(Duration::from_secs(5), outcomes.recv())
        .await
        .expect("the dial ends")
    else {
        panic!("the dial-back reaches the waiter");
    };
    assert_eq!((dialed_for, conn.peer()), (waiter, at));
    assert_eq!(identity.user_hash(), WAITER);
    let mut dialed = first.recv().await.expect("the waiter takes the link");

    let file = file();
    let mut dialer = RuntimePeerTransferService::new(crate::DEFAULT_SLOT_WAIT_TIMEOUT)
        .with_peer_links(links.clone());
    let _worker = dialer
        .start_download_worker(
            at,
            dialed_serve_ctx(),
            file.clone(),
            WorkerBrief::fresh(&file),
        )
        .await
        .expect("a worker starts");

    let asked = timeout(Duration::from_secs(5), async {
        while let Some(event) = dialed.next_event().await {
            match event {
                PeerEvent::Server(
                    ServerEvent::FileRequested { file_hash, .. }
                    | ServerEvent::FileBundleRequested { file_hash, .. },
                ) if file_hash == file.file_hash => return true,
                PeerEvent::Connection(ConnectionEvent::Disconnected { .. }) => return false,
                _ => {}
            }
        }
        false
    })
    .await;
    assert_eq!(asked, Ok(true), "the download asks over the dialed link");
    assert!(
        timeout(Duration::from_millis(300), later.recv())
            .await
            .is_err(),
        "no second link reaches the waiter"
    );
    drop(conn);
}

#[tokio::test]
async fn the_link_the_waiter_opens_during_its_dial_back_keeps_the_names_and_a_download_rides_it() {
    // aMule moves a client to a new socket only at the hello of one the peer
    // opened (`ClientTCPSocket.cpp:391`, `ClientList.cpp:400-403`): the
    // dial's later hello takes nothing back, and its end leaves the waiter
    // filed under the link it came back on.
    let links = SharedPeerLinks::default();
    let (mut serve, ours) = serving(&links).await;
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the waiter's listen port");
    let at = PeerEndpoint::V4(Ipv4Endpoint::new(
        Ipv4Addr::LOCALHOST,
        listener.local_port(),
    ));
    let hello = low_id_waiter_ctx(listener.local_port());
    let (outcomes_tx, mut outcomes) = mpsc::channel(1);
    let waiter = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 51318));
    serve.dial_back(
        DialBack {
            waiter,
            at,
            crypt: PeerCrypt::new(CryptStance::disabled(), Some(WAITER)),
        },
        outcomes_tx,
    );
    filed(&links, LinkName::User(WAITER), |found| found == Some(at)).await;

    // The waiter's own link comes in before it answers the dial.
    let mut back = PeerConnection::connect(ours, hello.clone(), ConnectOptions::default())
        .await
        .expect("the serve adapter accepts the waiter");
    let _served = serve.accept().await.expect("the link takes the serve road");
    let came_back = filed(&links, LinkName::User(WAITER), |found| {
        found.is_some_and(|remote| remote != at)
    })
    .await;

    // Then it answers the dial, whose link the serve side lets go.
    let mut dialed = listener
        .accept(hello, ConnectOptions::default())
        .await
        .expect("the waiter answers the dial");
    let Some(DialBackOutcome::Linked { conn, .. }) =
        timeout(Duration::from_secs(5), outcomes.recv())
            .await
            .expect("the dial ends")
    else {
        panic!("the dial-back reaches the waiter");
    };
    drop(conn);
    let ended = timeout(Duration::from_secs(5), async {
        while let Some(event) = dialed.next_event().await {
            if matches!(
                event,
                PeerEvent::Connection(ConnectionEvent::Disconnected { .. })
            ) {
                return;
            }
        }
    })
    .await;
    assert!(ended.is_ok(), "the dialed link ends");
    for name in [LinkName::Endpoint(at), LinkName::User(WAITER)] {
        assert_eq!(
            links.find(&[name]).map(|found| found.remote),
            came_back,
            "{name:?} stays filed under the link the waiter came back on"
        );
    }

    let file = file();
    let mut dialer = RuntimePeerTransferService::new(crate::DEFAULT_SLOT_WAIT_TIMEOUT)
        .with_peer_links(links.clone());
    let _worker = dialer
        .start_download_worker(
            at,
            dialed_serve_ctx(),
            file.clone(),
            WorkerBrief::fresh(&file),
        )
        .await
        .expect("a worker starts");
    let asked = timeout(Duration::from_secs(5), async {
        while let Some(event) = back.next_event().await {
            if let PeerEvent::Server(
                ServerEvent::FileRequested { file_hash, .. }
                | ServerEvent::FileBundleRequested { file_hash, .. },
            ) = event
                && file_hash == file.file_hash
            {
                return true;
            }
        }
        false
    })
    .await;
    assert_eq!(
        asked,
        Ok(true),
        "the download asks over the link it came back on"
    );
}

#[tokio::test]
async fn a_dial_back_called_off_before_its_hello_stops_with_nothing_said_and_unfiled() {
    // aMule deletes the socket it was connecting when the client's own
    // arrives (`ClientList.cpp:400-403`).
    let links = SharedPeerLinks::default();
    let (mut serve, _ours) = serving(&links).await;
    // Bound, never answering: the dial waits on the waiter's hello.
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the waiter's listen port");
    let at = PeerEndpoint::V4(Ipv4Endpoint::new(
        Ipv4Addr::LOCALHOST,
        listener.local_port(),
    ));
    let (outcomes_tx, mut outcomes) = mpsc::channel(1);
    let waiter = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 51318));
    serve.dial_back(
        DialBack {
            waiter,
            at,
            crypt: PeerCrypt::new(CryptStance::disabled(), Some(WAITER)),
        },
        outcomes_tx,
    );
    filed(&links, LinkName::User(WAITER), |found| found == Some(at)).await;

    serve.call_off_dial_back(waiter);
    let said = timeout(Duration::from_secs(5), outcomes.recv())
        .await
        .expect("the dial stops");
    assert!(said.is_none(), "a dial called off says nothing");
    assert!(links.find(&[LinkName::User(WAITER)]).is_none());
    assert!(links.find(&[LinkName::Endpoint(at)]).is_none());
    drop(listener);
}
