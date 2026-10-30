//! The dial-back's link is a Peer Link like any other (ADR-0107): a download
//! of the dialed peer rides it rather than dialing a second link aMule would
//! answer by dropping the first (`ClientList.cpp:400-403`). When the waiter's
//! own link races the dial, a dial before its hello stops with nothing said,
//! and with its hello out the waiter's hello is held until the far end shows
//! which link it kept (ADR-0107 invariant 7). Proven on real loopback links
//! through the production serve and dial adapters.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use rmule_net::peer::{
    ConnectOptions, Connection as PeerConnection, ObfuscationPolicy, PeerListener, PeerStreamRole,
};
use rmule_peer::{ConnectionEvent, NoticeEvent, PeerEvent, PeerHandshakeContext, ServerEvent};
use rmule_primitives::{
    ClientId, ClientIdentity, CryptStance, Ed2kFileLink, Ed2kText, FileHash, Ipv4Endpoint,
    PeerCrypt, PeerEndpoint, UserHash,
};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::timeout;

use super::{DialBack, DialBackOutcome};
use crate::adapters::HelloAdverts;
use crate::adapters::peer_link::LinkName;
use crate::adapters::peer_transfer::{PeerTransferService, WorkerBrief};
use crate::adapters::serve_runtime::{RuntimeServeRuntimeService, ServeRuntimeService};
use crate::adapters::tests::dialed_serve_ctx;
use crate::adapters::{RuntimePeerTransferService, SharedPeerLinks};
use crate::obfuscation_policy::SharedObfuscationPolicy;

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
        ..
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

/// The waiter's listen port as a raw socket, and where a dial reaches it.
async fn raw_waiter() -> (TcpListener, PeerEndpoint) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the waiter's listen port");
    let port = listener.local_addr().expect("bound").port();
    (
        listener,
        PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, port)),
    )
}

/// The waiter as the Peer Links name it, listening at `at`.
fn waiter_at(at: PeerEndpoint) -> PeerHandshakeContext {
    let mut ctx = waiter_ctx();
    ctx.identity = ClientIdentity::new(WAITER, Ed2kText::from_utf8("waiter"), at.port(), 60);
    ctx
}

/// A dial-back to a waiter at a raw socket, its hello on the wire: the socket
/// that holds it unread, where the road says how it ended, and the serve side.
async fn dial_with_its_hello_out(
    links: &SharedPeerLinks,
) -> (
    RuntimeServeRuntimeService,
    PeerEndpoint,
    PeerEndpoint,
    tokio::net::TcpStream,
    PeerEndpoint,
    mpsc::Receiver<DialBackOutcome>,
) {
    let (mut serve, ours) = serving(links).await;
    let (listener, at) = raw_waiter().await;
    let (outcomes_tx, outcomes) = mpsc::channel(1);
    let waiter = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 51318));
    serve.dial_back(
        DialBack {
            waiter,
            at,
            crypt: PeerCrypt::new(CryptStance::disabled(), Some(WAITER)),
        },
        outcomes_tx,
    );
    let (stream, dialer) = timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("the dial arrives")
        .expect("accept the dial");
    let mut first = [0u8; 1];
    timeout(Duration::from_secs(5), stream.peek(&mut first))
        .await
        .expect("the hello arrives")
        .expect("peek the hello");
    assert_eq!(first[0], 0xE3, "the dial's hello is on the wire");
    let dialer = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, dialer.port()));
    (serve, ours, at, stream, dialer, outcomes)
}

/// How the link the waiter opened went on: the hello answered on it, or
/// closed, or neither in `within`.
#[derive(Debug, PartialEq, Eq)]
enum OwnLink {
    Answered,
    Closed,
    Silent,
}

async fn own_link_within(link: &mut PeerConnection, within: Duration) -> OwnLink {
    timeout(within, async {
        while let Some(event) = link.next_event().await {
            match event {
                PeerEvent::Connection(ConnectionEvent::Identified { .. }) => {
                    return OwnLink::Answered;
                }
                PeerEvent::Connection(ConnectionEvent::Disconnected { .. }) => {
                    return OwnLink::Closed;
                }
                _ => {}
            }
        }
        OwnLink::Closed
    })
    .await
    .unwrap_or(OwnLink::Silent)
}

const SILENCE: Duration = Duration::from_millis(300);
const SOON: Duration = Duration::from_secs(5);

#[tokio::test]
async fn an_answer_on_a_dial_back_says_nothing_until_the_far_end_closes_its_own_link() {
    // The far end answers the dial whether it attached it or not
    // (`ClientList.cpp:388-403`), so the grant waits for what shows which:
    // the close of its own link, the dial's hello having deleted it.
    let links = SharedPeerLinks::default();
    let (mut serve, ours, at, stream, dialer, mut outcomes) = dial_with_its_hello_out(&links).await;

    let mut own = PeerConnection::connect(ours, waiter_at(at), ConnectOptions::default())
        .await
        .expect("the serve adapter accepts the waiter");
    let _served = serve.accept().await.expect("the link reaches triage");

    assert_eq!(own_link_within(&mut own, SILENCE).await, OwnLink::Silent);
    assert_eq!(
        links
            .find(&[LinkName::User(WAITER)])
            .map(|found| found.remote),
        Some(at),
        "the names stay with the dial"
    );

    let mut answered = PeerConnection::over_stream(
        stream,
        dialer,
        PeerStreamRole::Responder,
        waiter_at(at),
        ConnectOptions::default(),
    );
    assert!(
        timeout(SILENCE, outcomes.recv()).await.is_err(),
        "no grant goes on a dial the far end may have refused"
    );
    assert_eq!(own_link_within(&mut own, SILENCE).await, OwnLink::Silent);

    drop(own);
    let outcome = timeout(SOON, outcomes.recv()).await.expect("the dial ends");
    assert!(
        matches!(outcome, Some(DialBackOutcome::Linked { .. })),
        "the far end kept the dial: it comes up to grant on"
    );
    // Its client still waits on the answer to the hello it sent on the link
    // it deleted, and aMule drops a link that answers it first.
    let answer = timeout(SOON, async {
        while let Some(event) = answered.next_event().await {
            if matches!(
                event,
                PeerEvent::Notice(NoticeEvent::UnknownPacket { opcode: 0x4C, .. })
            ) {
                return true;
            }
        }
        false
    })
    .await;
    assert_eq!(
        answer,
        Ok(true),
        "the hello it held is answered on the dial"
    );
}

#[tokio::test]
async fn a_far_end_that_answers_the_dial_and_keeps_its_own_link_is_answered_there() {
    // A client with no address refuses the attach and a second client with
    // no file answers the dial (`ClientList.cpp:388-397`): the real one waits
    // on its own link, and a grant on the dial draws `OP_CANCELTRANSFER`.
    let links = SharedPeerLinks::default();
    let (mut serve, ours, at, stream, dialer, mut outcomes) = dial_with_its_hello_out(&links).await;

    let mut own = PeerConnection::connect(ours, waiter_at(at), ConnectOptions::default())
        .await
        .expect("the serve adapter accepts the waiter");
    let _served = serve.accept().await.expect("the link reaches triage");
    assert_eq!(own_link_within(&mut own, SILENCE).await, OwnLink::Silent);

    let mut second_client = PeerConnection::over_stream(
        stream,
        dialer,
        PeerStreamRole::Responder,
        waiter_at(at),
        ConnectOptions::default(),
    );

    assert_eq!(own_link_within(&mut own, SOON).await, OwnLink::Answered);
    let said = timeout(SOON, outcomes.recv()).await.expect("the road ends");
    assert!(said.is_none(), "the dial says nothing: {}", said.is_some());
    let closed = timeout(SOON, async {
        while let Some(event) = second_client.next_event().await {
            if matches!(
                event,
                PeerEvent::Connection(ConnectionEvent::Disconnected { .. })
            ) {
                return true;
            }
        }
        true
    })
    .await;
    assert_eq!(closed, Ok(true), "the dial is let go");
    let came_back = filed(&links, LinkName::User(WAITER), |found| {
        found.is_some_and(|remote| remote != at)
    })
    .await;
    assert!(came_back.is_some(), "the waiter's link holds its names");
}

#[tokio::test]
async fn a_hello_held_on_a_dial_back_is_answered_when_the_dial_ends_and_the_grant_is_left_to_it() {
    // The waiter never read the dial: it waits on its own link, and a close
    // there would make rmule a dead source (`BaseClient.cpp:1340-1346`). The
    // dial's end does not end the grant, which that link takes.
    let links = SharedPeerLinks::default();
    let (mut serve, ours, at, stream, _dialer, mut outcomes) =
        dial_with_its_hello_out(&links).await;

    let mut own = PeerConnection::connect(ours, waiter_at(at), ConnectOptions::default())
        .await
        .expect("the serve adapter accepts the waiter");
    let _served = serve.accept().await.expect("the link reaches triage");
    assert_eq!(own_link_within(&mut own, SILENCE).await, OwnLink::Silent);

    drop(stream);

    assert_eq!(own_link_within(&mut own, SOON).await, OwnLink::Answered);
    let said = timeout(SOON, outcomes.recv()).await.expect("the road ends");
    assert!(said.is_none(), "the dial says nothing: {}", said.is_some());
    let came_back = filed(&links, LinkName::User(WAITER), |found| {
        found.is_some_and(|remote| remote != at)
    })
    .await;
    assert!(came_back.is_some(), "the waiter's link holds its names");
}

#[tokio::test]
async fn a_held_hello_whose_link_closes_leaves_the_dial_to_go_on() {
    // The far end attached the dial, deleting its own link, and has not
    // answered yet.
    let links = SharedPeerLinks::default();
    let (mut serve, ours, at, stream, dialer, mut outcomes) = dial_with_its_hello_out(&links).await;

    let own = PeerConnection::connect(ours, waiter_at(at), ConnectOptions::default())
        .await
        .expect("the serve adapter accepts the waiter");
    let _served = serve.accept().await.expect("the link reaches triage");
    tokio::time::sleep(SILENCE).await;
    drop(own);
    tokio::time::sleep(SILENCE).await;

    let _answered = PeerConnection::over_stream(
        stream,
        dialer,
        PeerStreamRole::Responder,
        waiter_at(at),
        ConnectOptions::default(),
    );
    let outcome = timeout(SOON, outcomes.recv()).await.expect("the dial ends");
    assert!(matches!(outcome, Some(DialBackOutcome::Linked { .. })));
}

/// A started serve adapter of the node `own`, over Peer Links of its own.
async fn node(own: UserHash) -> (SharedPeerLinks, RuntimeServeRuntimeService, PeerEndpoint) {
    let links = SharedPeerLinks::default();
    let mut serve = RuntimeServeRuntimeService::new().with_peer_links(links.clone());
    let ours = serve
        .start(
            ClientIdentity::new(own, Ed2kText::from_utf8("node"), 4662, 60),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        )
        .await
        .expect("the listener binds");
    let ours = PeerEndpoint::V4(Ipv4Endpoint::new(*ours.ip(), ours.port()));
    (links, serve, ours)
}

/// Accept a dial with its hello on the wire: what the far end has not read.
async fn hello_out(listener: &TcpListener) -> tokio::net::TcpStream {
    let (stream, _) = timeout(SOON, listener.accept())
        .await
        .expect("the dial arrives")
        .expect("accept the dial");
    let mut first = [0u8; 1];
    timeout(SOON, stream.peek(&mut first))
        .await
        .expect("the hello arrives")
        .expect("peek the hello");
    stream
}

/// Carry `dial` on to the listener at `to`.
fn carry(mut dial: tokio::net::TcpStream, to: PeerEndpoint) {
    tokio::spawn(async move {
        let to = std::net::SocketAddr::new(to.ip(), to.port());
        let mut far = tokio::net::TcpStream::connect(to)
            .await
            .expect("the far end");
        let _ = tokio::io::copy_bidirectional(&mut dial, &mut far).await;
    });
}

#[tokio::test]
async fn two_rmules_crossing_settle_on_the_lower_hashs_dial() {
    // Each holds the other's hello, its own dial's hello read by nobody. Only
    // the bound moves: the higher hash gives its dial up at 10 s and answers,
    // and the lower reads that close on the hello it holds.
    let lower_hash = UserHash::from_bytes([0x11; UserHash::BYTE_LEN]);
    let higher_hash = UserHash::from_bytes([0xE1; UserHash::BYTE_LEN]);
    let (lower_links, mut lower, lower_at) = node(lower_hash).await;
    let (higher_links, mut higher, higher_at) = node(higher_hash).await;
    let (to_higher, relay_to_higher) = raw_waiter().await;
    let (to_lower, relay_to_lower) = raw_waiter().await;
    let (lower_tx, mut lower_outcomes) = mpsc::channel(1);
    let (higher_tx, mut higher_outcomes) = mpsc::channel(1);
    let waiter = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 51318));
    lower.dial_back(
        DialBack {
            waiter,
            at: relay_to_higher,
            crypt: PeerCrypt::new(CryptStance::disabled(), Some(higher_hash)),
        },
        lower_tx,
    );
    higher.dial_back(
        DialBack {
            waiter,
            at: relay_to_lower,
            crypt: PeerCrypt::new(CryptStance::disabled(), Some(lower_hash)),
        },
        higher_tx,
    );
    let (from_lower, from_higher) = (hello_out(&to_higher).await, hello_out(&to_lower).await);
    carry(from_lower, higher_at);
    carry(from_higher, lower_at);
    let _served = (
        lower.accept().await.expect("the lower hears the higher"),
        higher.accept().await.expect("the higher hears the lower"),
    );

    let settled = Duration::from_secs(15);
    let outcome = timeout(settled, lower_outcomes.recv())
        .await
        .expect("the lower's dial settles");
    assert!(
        matches!(outcome, Some(DialBackOutcome::Linked { .. })),
        "the lower's dial stands"
    );
    let said = timeout(SOON, higher_outcomes.recv())
        .await
        .expect("the higher's dial ends");
    assert!(
        said.is_none(),
        "given up, it says nothing: {}",
        said.is_some()
    );
    let filed = filed(&higher_links, LinkName::User(lower_hash), |found| {
        found.is_some()
    })
    .await;
    assert!(filed.is_some(), "the higher answered the lower's hello");
    assert!(
        lower_links.find(&[LinkName::User(higher_hash)]).is_some(),
        "the lower's dial keeps its peer's name"
    );
}

#[tokio::test]
async fn the_waiters_own_link_stops_a_dial_back_before_its_hello_unheard_and_is_answered() {
    // The waiter never answers the crypt handshake, so no byte of the hello
    // can follow it: its own link overtakes the dial, which closes unheard,
    // and the waiter keeps that link (`ClientList.cpp:400-403`).
    let links = SharedPeerLinks::default();
    let mut serve = RuntimeServeRuntimeService::new()
        .with_peer_links(links.clone())
        .with_hello_adverts(HelloAdverts {
            obfuscation: SharedObfuscationPolicy::new(Some(ObfuscationPolicy::Supported)),
            ..HelloAdverts::default()
        });
    let ours = serve
        .start(
            dialed_serve_ctx().identity,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        )
        .await
        .expect("the listener binds");
    let ours = PeerEndpoint::V4(Ipv4Endpoint::new(*ours.ip(), ours.port()));
    let (listener, at) = raw_waiter().await;
    let (outcomes_tx, mut outcomes) = mpsc::channel(1);
    let waiter = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 51318));
    serve.dial_back(
        DialBack {
            waiter,
            at,
            crypt: PeerCrypt::new(CryptStance::new(true, true, true), Some(WAITER)),
        },
        outcomes_tx,
    );
    let (mut stream, _) = timeout(SOON, listener.accept())
        .await
        .expect("the dial arrives")
        .expect("accept the dial");
    let mut opening = [0u8; 256];
    let read = timeout(SOON, stream.read(&mut opening))
        .await
        .expect("the crypt handshake opens")
        .expect("read the opening");
    assert!(read > 0);
    filed(&links, LinkName::User(WAITER), |found| found == Some(at)).await;

    let mut own = PeerConnection::connect(ours, waiter_at(at), ConnectOptions::default())
        .await
        .expect("the serve adapter accepts the waiter");
    let _served = serve.accept().await.expect("the link reaches triage");
    assert_eq!(own_link_within(&mut own, SOON).await, OwnLink::Answered);

    let said = timeout(SOON, outcomes.recv())
        .await
        .expect("the dial stops");
    assert!(said.is_none(), "a dial that yielded says nothing");
    let closed = timeout(SOON, async {
        while stream.read(&mut opening).await.is_ok_and(|read| read > 0) {}
    })
    .await;
    assert!(closed.is_ok(), "the dial's socket closes");
}
