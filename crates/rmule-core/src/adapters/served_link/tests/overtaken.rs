//! A download's dial that the peer's own link overtakes (ADR-0107
//! invariant 7). The far side attaches a socket at the `OP_HELLO` on it and
//! deletes the one it held for the client (`ClientTCPSocket.cpp:391`,
//! `ClientList.cpp:400-403`), so a dial whose hello has not gone out yields to
//! the peer's link, and one whose hello is out is kept.
//!
//! The far side is two sockets here: the asker's own link into rmule's
//! listener, and the asker's listen port where rmule's dial arrives.

use rmule_net::peer::{ObfuscationPolicy, PeerStreamRole};
use rmule_primitives::{CryptStance, PeerCrypt};
use tokio::io::AsyncReadExt;

use crate::adapters::HelloAdverts;

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

/// A dial whose hello went out is the socket the far side keeps: aMule
/// attaches it at that hello and drops its own (`ClientList.cpp:400-403`). So
/// the peer's own link filed after it takes the names but not the download,
/// and when the far side drops that link the names come back to the dial: a
/// second download of the peer waits on the dial, and the far side never sees
/// a second socket of rmule's.
#[tokio::test]
async fn a_dial_whose_hello_went_out_keeps_its_download_and_takes_the_names_back_when_the_peers_link_ends()
 {
    let links = SharedPeerLinks::default();
    let (mut serve, ours) = serving(&links).await;
    let (listen, at) = asker_listen().await;
    let mut dialer = RuntimePeerTransferService::new(crate::DEFAULT_SLOT_WAIT_TIMEOUT)
        .with_peer_links(links.clone());
    let _first = dialer
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

    let (asker, mut served) = asker_links(&mut serve, ours, at).await;
    let user = LinkName::User(asker_hash());
    assert!(
        links.find(&[user]).is_some_and(|found| found.remote != at),
        "the peer's own link, filed later, holds the names"
    );

    // The far side answers the dial's hello on the socket it keeps.
    let dialed_from = PeerEndpoint::V4(match dialed_from {
        std::net::SocketAddr::V4(v4) => Ipv4Endpoint::new(*v4.ip(), v4.port()),
        std::net::SocketAddr::V6(_) => unreachable!("a loopback IPv4 dial"),
    });
    let mut far = PeerConnection::over_stream(
        dial,
        dialed_from,
        PeerStreamRole::Responder,
        asker_ctx(at.port()),
        ConnectOptions::default(),
    );
    assert!(
        asked_for(&mut far, file().file_hash, Duration::from_secs(5)).await,
        "the download keeps riding its dial"
    );

    // The far side drops its own link, as aMule does at the dial's hello.
    drop(asker);
    let names_back = async {
        loop {
            if links.find(&[user]).map(|found| found.remote) == Some(at) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    let _ = timeout(Duration::from_secs(5), served.next_event()).await;
    assert!(
        timeout(Duration::from_secs(5), names_back).await.is_ok(),
        "the dial is filed under the peer's names again"
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
