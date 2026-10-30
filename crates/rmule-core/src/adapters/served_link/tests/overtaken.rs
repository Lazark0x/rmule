//! A download's dial that the peer's own link overtakes (ADR-0107
//! invariant 7). The far side attaches a socket at the `OP_HELLO` on it and
//! deletes the one it held for the client (`ClientTCPSocket.cpp:391`,
//! `ClientList.cpp:400-403`), so a dial whose hello has not gone out yields to
//! the peer's link, and with its hello out the peer's own hello is held until
//! the far end shows which link it kept.
//!
//! The far side is two sockets here: the asker's own link into rmule's
//! listener, and the asker's listen port where rmule's dial arrives.

use rmule_net::peer::{ObfuscationPolicy, PeerStreamRole};
use rmule_primitives::{CryptStance, PeerCrypt};
use tokio::io::AsyncReadExt;

use crate::adapters::HelloAdverts;
use crate::adapters::peer_transfer::PeerWorker;
use crate::adapters::serve_runtime::ServeConnection;

use super::*;

/// The User Hash the asker's hello names.
fn asker_hash() -> UserHash {
    UserHash::from_bytes([0xA5; UserHash::BYTE_LEN])
}

/// A serving node filing its accepted links in `links`, and where it listens.
async fn serving(links: &SharedPeerLinks) -> (RuntimeServeRuntimeService, PeerEndpoint) {
    let mut serve = RuntimeServeRuntimeService::new().with_peer_links(links.clone());
    let bound = serve
        .start(
            dialed_serve_ctx().identity,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        )
        .await
        .expect("the listener binds");
    let at = PeerEndpoint::V4(Ipv4Endpoint::new(*bound.ip(), bound.port()));
    (serve, at)
}

/// The asker's listen port, where rmule dials it, and its endpoint.
async fn asker_listen() -> (TcpListener, PeerEndpoint) {
    let listen = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the asker's listen port");
    let port = listen.local_addr().expect("bound").port();
    (
        listen,
        PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, port)),
    )
}

/// The asker opens its own link to rmule, its hello naming `listen`'s port,
/// and rmule's serve side files it.
async fn asker_links(
    serve: &mut RuntimeServeRuntimeService,
    ours: PeerEndpoint,
    listen: PeerEndpoint,
) -> (PeerConnection, crate::adapters::ServeConnection) {
    let asker = PeerConnection::connect(ours, asker_ctx(listen.port()), ConnectOptions::default())
        .await
        .expect("rmule accepts the asker");
    let mut served = timeout(Duration::from_secs(5), serve.accept())
        .await
        .expect("the link is accepted")
        .expect("a serve connection");
    assert!(matches!(
        timeout(Duration::from_secs(5), served.next_event()).await,
        Ok(Some(ServeInput::Connection(
            ConnectionEvent::Identified { .. }
        )))
    ));
    (asker, served)
}

/// A download dialing the asker with its hello not yet out, beside a serving
/// node sharing its Peer Links: an obfuscated dial whose socket the asker's
/// listen port takes and never answers the handshake on.
struct Crossed {
    serve: RuntimeServeRuntimeService,
    /// Where rmule listens.
    ours: PeerEndpoint,
    /// The asker's listen port, and where the dial goes.
    listen: TcpListener,
    at: PeerEndpoint,
    /// The far end of the dial.
    dial: tokio::net::TcpStream,
    worker: crate::adapters::PeerWorker,
}

impl Crossed {
    async fn dialing() -> Self {
        let links = SharedPeerLinks::default();
        let (serve, ours) = serving(&links).await;
        let (listen, at) = asker_listen().await;
        let mut dialer = RuntimePeerTransferService::new(crate::DEFAULT_SLOT_WAIT_TIMEOUT)
            .with_peer_links(links)
            .with_hello_adverts(HelloAdverts {
                obfuscation: crate::obfuscation_policy::SharedObfuscationPolicy::new(Some(
                    ObfuscationPolicy::Supported,
                )),
                ..HelloAdverts::default()
            });
        let brief = WorkerBrief {
            peer_crypt: PeerCrypt::new(CryptStance::new(true, true, false), Some(asker_hash())),
            ..WorkerBrief::fresh(&file())
        };
        let worker = dialer
            .start_download_worker(at, dialed_serve_ctx(), file(), brief)
            .await
            .expect("a worker starts");
        let (dial, _) = timeout(Duration::from_secs(5), listen.accept())
            .await
            .expect("the dial reaches the asker's listen port")
            .expect("accepted");
        Self {
            serve,
            ours,
            listen,
            at,
            dial,
            worker,
        }
    }
}

/// A dial still in its crypt handshake has sent no hello: the peer's own link
/// filed meanwhile overtakes it. The dial closes, retiring nobody, and its
/// download asks over the peer's link, as aMule's connecting client carries on
/// over the socket the peer opened (`BaseClient.cpp:1692-1698`). From then on
/// the far side holds one socket of rmule's: the dial was closed before the
/// download asked anything, and nothing is dialed again.
#[tokio::test]
async fn a_dial_the_peers_own_link_overtakes_before_its_hello_moves_its_download_onto_that_link() {
    let mut crossed = Crossed::dialing().await;
    let (mut asker, _served) = asker_links(&mut crossed.serve, crossed.ours, crossed.at).await;
    let Crossed {
        listen,
        mut dial,
        mut worker,
        ..
    } = crossed;

    assert!(
        asked_for(&mut asker, file().file_hash, Duration::from_secs(5)).await,
        "the download asks over the peer's own link"
    );
    let mut ended = [0_u8; 256];
    let dial_closed = loop {
        match timeout(Duration::from_millis(100), dial.read(&mut ended)).await {
            Ok(Ok(0) | Err(_)) => break true,
            Ok(Ok(_)) => {}
            Err(_) => break false,
        }
    };
    assert!(
        dial_closed,
        "the dial was closed before the download asked over the peer's link"
    );
    assert!(
        timeout(Duration::from_millis(300), listen.accept())
            .await
            .is_err(),
        "nothing is dialed again"
    );
    let mut seen = Vec::new();
    while let Ok(Some(event)) = timeout(Duration::from_millis(200), worker.next_event()).await {
        seen.push(event);
    }
    assert!(
        seen.iter().any(|event| matches!(
            event,
            PeerWorkerEvent::LinkShared {
                turn: LinkTurn::Riding
            }
        )) && !seen.iter().any(|event| matches!(
            event,
            PeerWorkerEvent::DialEnded { .. } | PeerWorkerEvent::Disconnected
        )),
        "the download rides the peer's link, its dial retiring nobody: {seen:?}"
    );
}

/// A dial whose hello is out and a hello of the peer's own link held on it.
struct CrossedDownload {
    links: SharedPeerLinks,
    at: PeerEndpoint,
    listen: TcpListener,
    dialer: RuntimePeerTransferService,
    worker: PeerWorker,
    far: PeerConnection,
    asker: PeerConnection,
    served: ServeConnection,
}

impl CrossedDownload {
    /// The dial's hello on the wire, the asker's own link come and its hello
    /// held, then the far side's answer on the dial's socket.
    async fn answered() -> Self {
        let links = SharedPeerLinks::default();
        let (mut serve, ours) = serving(&links).await;
        let (listen, at) = asker_listen().await;
        let mut dialer = RuntimePeerTransferService::new(crate::DEFAULT_SLOT_WAIT_TIMEOUT)
            .with_peer_links(links.clone());
        let worker = dialer
            .start_peer_worker(at, dialed_serve_ctx(), file())
            .await
            .expect("a worker starts");
        let (dial, dialed_from) = timeout(Duration::from_secs(5), listen.accept())
            .await
            .expect("the dial reaches the asker's listen port")
            .expect("accepted");
        // The dial's hello is on the wire before the asker's own link comes.
        let mut first_byte = [0_u8; 1];
        timeout(Duration::from_secs(5), dial.peek(&mut first_byte))
            .await
            .expect("the dial's hello arrives")
            .expect("readable");

        let asker = PeerConnection::connect(ours, asker_ctx(at.port()), ConnectOptions::default())
            .await
            .expect("rmule accepts the asker");
        let mut served = timeout(Duration::from_secs(5), serve.accept())
            .await
            .expect("the link is accepted")
            .expect("a serve connection");
        assert!(matches!(
            timeout(Duration::from_secs(5), served.next_event()).await,
            Ok(Some(ServeInput::CrossedHelloHeld))
        ));
        assert_eq!(
            links
                .find(&[LinkName::Endpoint(at)])
                .map(|found| found.remote),
            Some(at),
            "the dial keeps its names"
        );
        let user = LinkName::User(asker_hash());
        assert!(links.find(&[user]).is_none(), "the held link is not filed");

        // The far side answers the dial's hello on the socket it keeps.
        let dialed_from = PeerEndpoint::V4(match dialed_from {
            std::net::SocketAddr::V4(v4) => Ipv4Endpoint::new(*v4.ip(), v4.port()),
            std::net::SocketAddr::V6(_) => unreachable!("a loopback IPv4 dial"),
        });
        let far = PeerConnection::over_stream(
            dial,
            dialed_from,
            PeerStreamRole::Responder,
            asker_ctx(at.port()),
            ConnectOptions::default(),
        );
        Self {
            links,
            at,
            listen,
            dialer,
            worker,
            far,
            asker,
            served,
        }
    }
}

/// The far side's answer on the dial says nothing alone, so the download asks
/// nothing on it until the far side's close of its own link shows it attached
/// the dial (`ClientList.cpp:400-403`). The peer stays in `DS_CONNECTING` and
/// asks on the dial (`BaseClient.cpp:1692-1698`). A second download of the
/// peer waits on the dial, and the far side never sees a second socket of
/// rmule's.
#[tokio::test]
async fn a_hello_crossing_a_downloads_dial_closed_by_the_far_end_leaves_the_download_on_the_dial() {
    let CrossedDownload {
        links,
        at,
        listen,
        mut dialer,
        worker: _first,
        mut far,
        asker,
        mut served,
    } = CrossedDownload::answered().await;
    assert!(
        !asked_for(&mut far, file().file_hash, Duration::from_millis(300)).await,
        "nobody asks on a dial the far side may have refused"
    );

    drop(asker);
    assert!(
        asked_for(&mut far, file().file_hash, Duration::from_secs(5)).await,
        "the download keeps riding its dial"
    );
    assert!(matches!(
        timeout(Duration::from_secs(5), served.next_event()).await,
        Ok(Some(ServeInput::CrossedDialKept))
    ));
    let user = LinkName::User(asker_hash());
    let names_back = async {
        while links.find(&[user]).map(|found| found.remote) != Some(at) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    assert!(
        timeout(Duration::from_secs(5), names_back).await.is_ok(),
        "the dial is filed under the peer's names"
    );

    let second = Ed2kFileLink {
        file_hash: FileHash::from_bytes([0x5B; FileHash::BYTE_LEN]),
        ..file()
    };
    let brief = WorkerBrief {
        peer_crypt: PeerCrypt::new(CryptStance::new(false, false, false), Some(asker_hash())),
        ..WorkerBrief::fresh(&second)
    };
    let mut waiting = dialer
        .start_download_worker(at, dialed_serve_ctx(), second, brief)
        .await
        .expect("a worker starts");
    assert!(
        matches!(
            timeout(Duration::from_secs(5), waiting.next_event()).await,
            Ok(Some(PeerWorkerEvent::LinkShared {
                turn: LinkTurn::Waiting
            }))
        ),
        "a second download of the peer waits on the dial"
    );
    assert!(
        timeout(Duration::from_millis(300), listen.accept())
            .await
            .is_err(),
        "the far side sees no second socket of rmule's"
    );
}

/// A far side with no address for rmule refuses the attach, and a second
/// client with no file answers the dial (`ClientList.cpp:388-397`). Its own
/// link stays open past the close bound: that link is answered, the dial
/// closes retiring nobody, and the download moves onto the client that wants
/// something of rmule.
#[tokio::test]
async fn a_far_end_that_answers_a_downloads_dial_and_keeps_its_own_link_takes_the_download_there() {
    let CrossedDownload {
        links,
        at,
        listen: _listen,
        dialer: _dialer,
        mut worker,
        mut far,
        mut asker,
        mut served,
    } = CrossedDownload::answered().await;

    assert!(matches!(
        timeout(Duration::from_secs(5), served.next_event()).await,
        Ok(Some(ServeInput::CrossedDialRefused))
    ));
    assert!(
        asked_for(&mut asker, file().file_hash, Duration::from_secs(5)).await,
        "the download rides the link the far side stayed on"
    );
    let closed = timeout(Duration::from_secs(5), async {
        while let Some(event) = far.next_event().await {
            if matches!(
                event,
                PeerEvent::Connection(ConnectionEvent::Disconnected { .. })
            ) {
                break;
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "the dial is let go");
    let filed = links.find(&[LinkName::User(asker_hash())]);
    assert_ne!(filed.map(|found| found.remote), Some(at));

    let mut seen = Vec::new();
    while let Ok(Some(event)) = timeout(Duration::from_millis(200), worker.next_event()).await {
        seen.push(event);
    }
    assert!(
        !seen.iter().any(|event| matches!(
            event,
            PeerWorkerEvent::DialEnded { .. } | PeerWorkerEvent::Disconnected
        )),
        "the dial retires nobody: {seen:?}"
    );
}

/// The next frame rmule writes on `stream`: its protocol byte and opcode.
async fn next_frame(stream: &mut tokio::net::TcpStream) -> Option<(u8, u8)> {
    let mut header = [0_u8; 5];
    stream.read_exact(&mut header).await.ok()?;
    let len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
    let mut body = vec![0_u8; len];
    stream.read_exact(&mut body).await.ok()?;
    Some((header[0], *body.first()?))
}

/// An uploader promoting rmule by dialing it grants as soon as the hellos
/// are done (`BaseClient.cpp:1707-1716`), here right behind its hello, before
/// the download moving over from the dial its link overtook has joined. The
/// link holds the grant for that download and gives nothing back
/// (`OP_CANCELTRANSFER`): the download asks over the link, and its own ask is
/// the one the uploader answers (`UploadQueue.cpp:486-493`).
#[tokio::test]
async fn a_grant_on_the_link_that_overtook_a_dial_is_held_for_the_download_moving_onto_it() {
    use tokio::io::AsyncWriteExt;

    let mut crossed = Crossed::dialing().await;
    let ours = std::net::SocketAddr::new(crossed.ours.ip(), crossed.ours.port());
    let mut uploader = tokio::net::TcpStream::connect(ours)
        .await
        .expect("rmule accepts the uploader");
    let mut opening = rmule_testkit::wire::hello_bytes(asker_hash(), "uploader");
    opening.extend(rmule_testkit::wire::accept_upload_bytes());
    uploader
        .write_all(&opening)
        .await
        .expect("the uploader writes");
    let _served = timeout(Duration::from_secs(5), crossed.serve.accept())
        .await
        .expect("the link is accepted")
        .expect("a serve connection");

    const EDONKEY: u8 = 0xE3;
    const OP_CANCELTRANSFER: u8 = 0x56;
    const OP_REQUESTFILENAME: u8 = 0x58;
    let mut read = Vec::new();
    let asked = async {
        while let Some(frame) = next_frame(&mut uploader).await {
            read.push(frame);
            if frame == (EDONKEY, OP_REQUESTFILENAME) || frame.1 == 0x92 || frame.1 == 0xA4 {
                return true;
            }
        }
        false
    };
    let asked = timeout(Duration::from_secs(5), asked)
        .await
        .unwrap_or(false);
    assert!(
        asked,
        "the moving download asks over the uploader's link: {read:02X?}"
    );
    assert!(
        !read.contains(&(EDONKEY, OP_CANCELTRANSFER)),
        "the grant is held, not given back: {read:02X?}"
    );
}
