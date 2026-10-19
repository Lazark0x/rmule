//! A download of a peer already linked to us rides that link (ADR-0107, "One
//! peer, one link"), proven on real loopback links through the production
//! accept path and the production dial path: the asker is a `Connection`
//! that dials rmule's listener with a hello naming a listen port of its own,
//! and that port is watched for the second link aMule answers by dropping the
//! first (`ClientList.cpp:400-403`).

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use rmule_net::peer::{ConnectOptions, Connection as PeerConnection};
use rmule_peer::{PeerHandshakeContext, ServerEvent};
use rmule_primitives::{
    ClientId, ClientIdentity, Ed2kFileLink, Ed2kText, FileHash, Ipv4Endpoint, UserHash,
};
use tokio::net::TcpListener;
use tokio::time::timeout;

use crate::adapters::peer_transfer::{PeerTransferService, WorkerBrief};
use crate::adapters::serve_runtime::ServeOutput;
use crate::adapters::serve_runtime::{RuntimeServeRuntimeService, ServeRuntimeService};
use crate::adapters::tests::dialed_serve_ctx;
use crate::adapters::{
    PeerWorkerCommand, PeerWorkerEvent, RuntimePeerTransferService, SharedPeerLinks,
};
use crate::service::LinkTurn;

use super::*;

mod overtaken;

fn file() -> Ed2kFileLink {
    Ed2kFileLink {
        name: Ed2kText::from_utf8("partial.bin"),
        size: 4096,
        file_hash: FileHash::from_bytes([0x5A; FileHash::BYTE_LEN]),
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    }
}

/// The asker's side of the handshake: its hello names `listen_port`.
fn asker_ctx(listen_port: u16) -> PeerHandshakeContext {
    PeerHandshakeContext {
        identity: ClientIdentity::new(
            UserHash::from_bytes([0xA5; UserHash::BYTE_LEN]),
            Ed2kText::from_utf8("asker"),
            listen_port,
            60,
        ),
        client_id: ClientId::from_u32(0x0100_007F),
        ed2k_client_id: ClientId::from_u32(0x0100_007F),
        public_ip: None,
        connected_server: None,
    }
}

/// Whether the next event the asker's link reads is a file request for
/// `file_hash`, within `within`.
async fn asked_for(asker: &mut PeerConnection, file_hash: FileHash, within: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    while let Ok(Some(event)) = tokio::time::timeout_at(deadline, asker.next_event()).await {
        match event {
            PeerEvent::Server(
                ServerEvent::FileRequested {
                    file_hash: asked, ..
                }
                | ServerEvent::FileBundleRequested {
                    file_hash: asked, ..
                },
            ) if asked == file_hash => return true,
            _ => {}
        }
    }
    false
}

/// An asker linked to a serving node, and a dial adapter sharing the node's
/// Peer Links.
struct Linked {
    asker: PeerConnection,
    /// The asker's listen port, where a second link would arrive.
    listen: TcpListener,
    served: crate::adapters::ServeConnection,
    dialer: RuntimePeerTransferService,
    links: SharedPeerLinks,
    _serve: RuntimeServeRuntimeService,
}

impl Linked {
    async fn up() -> Self {
        Self::up_as(asker_ctx).await
    }

    /// An asker whose hello `ctx` states, given its listen port.
    async fn up_as(ctx: fn(u16) -> PeerHandshakeContext) -> Self {
        let links = SharedPeerLinks::default();
        let mut serve = RuntimeServeRuntimeService::new().with_peer_links(links.clone());
        let bound = serve
            .start(
                dialed_serve_ctx().identity,
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
            )
            .await
            .expect("the listener binds");
        let listen = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind the asker's listen port");
        let listen_port = listen.local_addr().expect("bound").port();
        let asker = PeerConnection::connect(
            PeerEndpoint::V4(Ipv4Endpoint::new(*bound.ip(), bound.port())),
            ctx(listen_port),
            ConnectOptions::default(),
        )
        .await
        .expect("rmule accepts the asker");
        let mut served = timeout(Duration::from_secs(5), serve.accept())
            .await
            .expect("the link is accepted")
            .expect("a serve connection");
        // The link is filed once the serve side holds its hello.
        assert!(matches!(
            timeout(Duration::from_secs(5), served.next_event()).await,
            Ok(Some(ServeInput::Connection(
                ConnectionEvent::Identified { .. }
            )))
        ));
        let dialer = RuntimePeerTransferService::new(crate::DEFAULT_SLOT_WAIT_TIMEOUT)
            .with_peer_links(links.clone());
        Self {
            asker,
            listen,
            served,
            dialer,
            links,
            _serve: serve,
        }
    }

    /// Where the asker is a source: its address and its listen port.
    fn at(&self) -> PeerEndpoint {
        let port = self.listen.local_addr().expect("bound").port();
        PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, port))
    }

    async fn download(&mut self, file: &Ed2kFileLink) -> crate::adapters::PeerWorker {
        let at = self.at();
        self.dialer
            .start_download_worker(
                at,
                dialed_serve_ctx(),
                file.clone(),
                WorkerBrief::fresh(file),
            )
            .await
            .expect("a worker starts")
    }

    /// The download rode the asker's link: its request arrived there, and no
    /// second link reached the asker's listen port.
    async fn rode_the_link(&mut self, file_hash: FileHash) {
        assert!(
            asked_for(&mut self.asker, file_hash, Duration::from_secs(5)).await,
            "the download asks over the asker's own link"
        );
        assert!(
            timeout(Duration::from_millis(300), self.listen.accept())
                .await
                .is_err(),
            "no second link reaches the asker"
        );
    }

    /// The asker asks our serve side for a file over its link, as a peer
    /// downloading from us does: its pull holds the link (ADR-0107 invariant 9).
    async fn pulls(&mut self) {
        // The asker's session takes a request only once it holds our hello.
        let identified = async {
            while let Some(event) = self.asker.next_event().await {
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
            .expect("the asker reads our hello");
        self.asker
            .send(PeerCommand::Requester(
                rmule_peer::RequesterCommand::ProbeFile {
                    file_hash: FileHash::from_bytes([0x5C; FileHash::BYTE_LEN]),
                    file_size: 4096,
                    own_status: rmule_peer::PartBitmap::one_part_complete(),
                },
            ))
            .await
            .expect("the asker's link is up");
    }

    /// Whether rmule closes the asker's link within five seconds.
    async fn closed(&mut self) -> bool {
        let closed = async {
            while let Some(event) = self.asker.next_event().await {
                if matches!(
                    event,
                    PeerEvent::Connection(ConnectionEvent::Disconnected { .. })
                ) {
                    return true;
                }
            }
            true
        };
        timeout(Duration::from_secs(5), closed)
            .await
            .unwrap_or(false)
    }

    /// The asker has no such file: the download riding the link lets it go.
    async fn has_no_such_file(&mut self, file_hash: FileHash) {
        self.asker
            .send(PeerCommand::Server(
                rmule_peer::ServerCommand::AnswerFileNotFound { file_hash },
            ))
            .await
            .expect("the asker's link is up");
    }
}

/// The worker's events up to its end, or as far as it got in five seconds.
async fn until_disconnected(worker: &mut crate::adapters::PeerWorker) -> Vec<PeerWorkerEvent> {
    let mut seen = Vec::new();
    while let Ok(Some(event)) = timeout(Duration::from_secs(5), worker.next_event()).await {
        let done = matches!(event, PeerWorkerEvent::Disconnected);
        seen.push(event);
        if done {
            break;
        }
    }
    seen
}

#[tokio::test]
async fn a_download_of_a_peer_linked_to_us_rides_its_link_and_dials_nothing() {
    let mut linked = Linked::up().await;
    let file = file();
    let mut worker = linked.download(&file).await;

    linked.rode_the_link(file.file_hash).await;
    assert!(matches!(
        worker.next_event().await,
        Some(PeerWorkerEvent::LinkShared {
            turn: LinkTurn::Riding
        })
    ));
    assert!(matches!(
        worker.next_event().await,
        Some(PeerWorkerEvent::Identity(identity))
            if identity.user_hash() == asker_ctx(0).identity.user_hash()
    ));
    assert!(matches!(
        worker.next_event().await,
        Some(PeerWorkerEvent::Connected)
    ));
}

/// A link the peer pulls on stays when its download lets go, and the next
/// download of the peer rides it.
#[tokio::test]
async fn a_link_the_peer_pulls_on_stays_when_its_download_lets_go_and_takes_the_next() {
    let mut linked = Linked::up().await;
    linked.pulls().await;
    let file = file();
    let mut first = linked.download(&file).await;
    linked.rode_the_link(file.file_hash).await;
    linked.has_no_such_file(file.file_hash).await;
    assert!(matches!(
        until_disconnected(&mut first).await.last(),
        Some(PeerWorkerEvent::PartsAdvertised { parts: None, .. })
    ));

    let _second = linked.download(&file).await;
    linked.rode_the_link(file.file_hash).await;
}

/// A link the peer never asked anything over closes when its download lets
/// go: nothing else holds it (ADR-0107 invariant 9).
#[tokio::test]
async fn a_link_nothing_else_holds_closes_when_its_download_lets_go() {
    let mut linked = Linked::up().await;
    let file = file();
    let mut first = linked.download(&file).await;
    linked.rode_the_link(file.file_hash).await;
    linked.has_no_such_file(file.file_hash).await;
    let _ = until_disconnected(&mut first).await;
    assert!(linked.closed().await, "the link closes with its download");
}

#[tokio::test]
async fn the_serve_side_letting_go_leaves_the_link_to_the_download_riding_it() {
    let mut linked = Linked::up().await;
    let file = file();
    let mut worker = linked.download(&file).await;
    linked.rode_the_link(file.file_hash).await;

    linked
        .served
        .send(ServeOutput::Disconnect)
        .await
        .expect("the serve side is registered");
    linked.has_no_such_file(file.file_hash).await;
    let seen = until_disconnected(&mut worker).await;
    assert!(
        seen.iter()
            .any(|event| matches!(event, PeerWorkerEvent::PartsAdvertised { parts: None, .. })),
        "the answer reached the download over the link the serve side let go: {seen:?}"
    );
    // With both halves gone the link ends.
    assert!(linked.closed().await);
}

#[tokio::test]
async fn a_second_download_waits_on_the_busy_link_and_takes_it_when_the_first_lets_go() {
    let mut linked = Linked::up().await;
    let first_file = file();
    let second_file = Ed2kFileLink {
        file_hash: FileHash::from_bytes([0x5B; FileHash::BYTE_LEN]),
        ..file()
    };
    let mut first = linked.download(&first_file).await;
    linked.rode_the_link(first_file.file_hash).await;

    let mut second = linked.download(&second_file).await;
    assert!(matches!(
        timeout(Duration::from_secs(5), second.next_event()).await,
        Ok(Some(PeerWorkerEvent::LinkShared {
            turn: LinkTurn::Waiting
        }))
    ));
    assert!(
        !asked_for(
            &mut linked.asker,
            second_file.file_hash,
            Duration::from_millis(300)
        )
        .await,
        "the waiter asks nothing while the first rides"
    );

    linked.has_no_such_file(first_file.file_hash).await;
    let _ = until_disconnected(&mut first).await;
    linked.rode_the_link(second_file.file_hash).await;
    assert!(matches!(
        second.next_event().await,
        Some(PeerWorkerEvent::LinkShared {
            turn: LinkTurn::Riding
        })
    ));
}

/// A Low-ID asker's link is found by the callback its hello names: a
/// download of it rides the link and asks no callback, which the peer would
/// answer with nothing (`BaseClient.cpp:1489-1496`).
#[tokio::test]
async fn a_low_id_askers_link_is_ridden_by_its_callback() {
    const LOW_ID: ClientId = ClientId::from_u32(0x0000_2A2A);
    fn server() -> Ipv4Endpoint {
        Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 7), 4661)
    }
    fn low_id_asker(listen_port: u16) -> PeerHandshakeContext {
        PeerHandshakeContext {
            client_id: LOW_ID,
            ed2k_client_id: LOW_ID,
            connected_server: Some(server()),
            ..asker_ctx(listen_port)
        }
    }
    let mut linked = Linked::up_as(low_id_asker).await;
    let file = file();
    let other_server = Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 8), 4661);
    assert!(
        linked
            .dialer
            .ride_callback_link(
                LOW_ID,
                other_server,
                file.clone(),
                WorkerBrief::fresh(&file)
            )
            .is_none(),
        "the same id on another server is another peer"
    );
    let _worker = linked
        .dialer
        .ride_callback_link(LOW_ID, server(), file.clone(), WorkerBrief::fresh(&file))
        .expect("the link is filed under its callback");
    linked.rode_the_link(file.file_hash).await;
}

/// Whether the asker's link reads our `OP_CANCELTRANSFER` within `within`.
async fn given_back(asker: &mut PeerConnection, within: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    while let Ok(Some(event)) = tokio::time::timeout_at(deadline, asker.next_event()).await {
        if matches!(
            event,
            PeerEvent::Server(ServerEvent::TransferCancelled { .. })
        ) {
            return true;
        }
    }
    false
}

/// The asker promotes rmule from its queue by dialing it back, granting once
/// the hellos are done (`UploadQueue.cpp:206-210`, `BaseClient.cpp:1707-1716`).
async fn grant_unasked(asker: &mut PeerConnection) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while let Ok(Some(event)) = tokio::time::timeout_at(deadline, asker.next_event()).await {
        if matches!(
            event,
            PeerEvent::Connection(ConnectionEvent::Identified { .. })
        ) {
            break;
        }
    }
    asker
        .send(PeerCommand::Server(rmule_peer::ServerCommand::GrantSlot {
            file_hash: file().file_hash,
        }))
        .await
        .expect("the link is up");
}

/// An uploader's unasked grant on a link it opened reaches the download
/// awaiting a grant from it (ADR-0057, "A grant by dial-back is taken"), and
/// is not given back.
#[tokio::test]
async fn an_unasked_grant_on_an_accepted_link_reaches_the_download_awaiting_it() {
    let mut linked = Linked::up().await;
    let at = linked.at();
    let (grants, mut granted) = tokio::sync::mpsc::channel(1);
    let _awaiting = linked
        .links
        .await_grant(at, vec![LinkName::Endpoint(at)], true, grants);
    grant_unasked(&mut linked.asker).await;

    assert_eq!(
        timeout(Duration::from_secs(5), granted.recv())
            .await
            .ok()
            .flatten(),
        Some(crate::adapters::LinkOffer::Grant(at)),
        "the grant reaches the download waiting at the asker"
    );
    assert!(
        !given_back(&mut linked.asker, Duration::from_millis(300)).await,
        "a grant taken is not given back"
    );
}

/// An unasked grant no download awaits goes back with `OP_CANCELTRANSFER`,
/// as aMule's downloader cancels an accept it does not want
/// (`ClientTCPSocket.cpp:646-659`, ADR-0056).
#[tokio::test]
async fn an_unasked_grant_nobody_awaits_is_given_back() {
    let mut linked = Linked::up().await;
    grant_unasked(&mut linked.asker).await;
    assert!(given_back(&mut linked.asker, Duration::from_secs(5)).await);
}

/// A grant a download took, whose worker ends before its own ask — the peer
/// says it lacks the file — goes back with `OP_CANCELTRANSFER` when that
/// last rider leaves a link the peer's pull keeps up, rather than holding the
/// uploader's slot to its 40 s close (ADR-0056 item 3, ADR-0107 invariant 9).
#[tokio::test]
async fn a_taken_grant_its_last_rider_leaves_standing_goes_back() {
    let mut linked = Linked::up().await;
    linked.pulls().await;
    let at = linked.at();
    let (grants, mut granted) = tokio::sync::mpsc::channel(1);
    let _awaiting = linked
        .links
        .await_grant(at, vec![LinkName::Endpoint(at)], true, grants);
    linked
        .asker
        .send(PeerCommand::Server(rmule_peer::ServerCommand::GrantSlot {
            file_hash: file().file_hash,
        }))
        .await
        .expect("the link is up");
    assert_eq!(
        timeout(Duration::from_secs(5), granted.recv())
            .await
            .ok()
            .flatten(),
        Some(crate::adapters::LinkOffer::Grant(at)),
        "a download takes the grant"
    );

    let file = file();
    let mut worker = linked.download(&file).await;
    linked.rode_the_link(file.file_hash).await;
    linked.has_no_such_file(file.file_hash).await;
    let _ = until_disconnected(&mut worker).await;
    assert!(
        given_back(&mut linked.asker, Duration::from_secs(5)).await,
        "the grant left standing goes back"
    );
}

/// What the asker read of our requests on its link, up to its first block
/// request or `within`: every file request, slot ask and block request.
async fn requests_up_to_blocks(asker: &mut PeerConnection, within: Duration) -> Vec<ServerEvent> {
    let deadline = tokio::time::Instant::now() + within;
    let mut read = Vec::new();
    while let Ok(Some(event)) = tokio::time::timeout_at(deadline, asker.next_event()).await {
        let PeerEvent::Server(event) = event else {
            continue;
        };
        let blocks = matches!(
            event,
            ServerEvent::PartsRequested { .. } | ServerEvent::PartsWithoutSlot { .. }
        );
        if matches!(
            event,
            ServerEvent::FileRequested { .. }
                | ServerEvent::FileBundleRequested { .. }
                | ServerEvent::FileIdSet { .. }
                | ServerEvent::SlotRequested { .. }
        ) || blocks
        {
            read.push(event);
        }
        if blocks {
            break;
        }
    }
    read
}

/// A link whose first packet after the hellos is the uploader's grant — its
/// promotion by dial-back — is answered with block requests alone: no file
/// request and no `OP_STARTUPLOADREQ`, which aMule's downloader leaves out
/// there (`BaseClient.cpp:1692-1706`, `ClientTCPSocket.cpp:635-644`) and the
/// uploader would score towards a ban (`UploadClient.cpp:795-825`, ADR-0107).
#[tokio::test]
async fn a_grant_its_link_carries_is_answered_with_blocks_and_no_ask() {
    let mut linked = Linked::up().await;
    let at = linked.at();
    let (grants, mut granted) = tokio::sync::mpsc::channel(1);
    let _awaiting = linked
        .links
        .await_grant(at, vec![LinkName::Endpoint(at)], true, grants);
    grant_unasked(&mut linked.asker).await;
    assert_eq!(
        timeout(Duration::from_secs(5), granted.recv())
            .await
            .ok()
            .flatten(),
        Some(crate::adapters::LinkOffer::Grant(at))
    );

    let file = file();
    let mut worker = linked
        .dialer
        .start_download_worker(
            at,
            dialed_serve_ctx(),
            file.clone(),
            WorkerBrief {
                opening: crate::adapters::WorkerOpening::Granted,
                ..WorkerBrief::fresh(&file)
            },
        )
        .await
        .expect("a worker starts");
    // The brain takes the grant at the worker's connection.
    let connected = async {
        while let Some(event) = worker.next_event().await {
            if event == PeerWorkerEvent::Connected {
                return true;
            }
        }
        false
    };
    assert!(
        timeout(Duration::from_secs(5), connected)
            .await
            .unwrap_or(false)
    );
    worker
        .send(PeerWorkerCommand::TakeGrant)
        .await
        .expect("the worker runs");
    let took = async {
        while let Some(event) = worker.next_event().await {
            if event == PeerWorkerEvent::SlotGranted {
                return true;
            }
        }
        false
    };
    assert!(
        timeout(Duration::from_secs(5), took).await.unwrap_or(false),
        "the worker holds the grant"
    );
    worker
        .send(PeerWorkerCommand::RequestBlocks {
            blocks: vec![crate::BlockPlan {
                part_index: 0,
                start: 0,
                end: 1024,
            }],
            handout: 1,
        })
        .await
        .expect("the worker runs");

    let read = requests_up_to_blocks(&mut linked.asker, Duration::from_secs(5)).await;
    assert!(
        matches!(read.as_slice(), [ServerEvent::PartsRequested { file_hash, .. }] if *file_hash == file.file_hash),
        "block requests alone: {read:?}"
    );
}
