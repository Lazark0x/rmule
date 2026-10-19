//! The uploader's dial-back (ADR-0057) through the built core: a waiter
//! queued behind the only slot hangs up, and when the slot frees rmule dials
//! it where its hello said it listens and sends `OP_ACCEPTUPLOADREQ` once the
//! hellos are done, as aMule's `AddUpNextClient` and `ConnectionEstablished`
//! do (`UploadQueue.cpp:206-210`, `BaseClient.cpp:1707-1716`). A waiter no
//! dial reaches hands the slot on to the next one, and a slot nobody could be
//! reached for goes to the waiter whose link comes back.
//!
//! Every hop is a real socket through the production serve adapter; only the
//! counterparties are fakes — rmule's side, not interop.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use rmule_core::{Core, CoreCommand, CoreConfig, ServeCommand};
use rmule_net::peer::{ConnectOptions, Connection, PeerListener, PeerStreamRole};
use rmule_peer::{
    ConnectionEvent, PartRanges, PeerCommand, PeerEvent, PeerHandshakeContext, RequesterCommand,
    RequesterEvent,
};
use rmule_primitives::{
    ClientId, ClientIdentity, Ed2kText, FileHash, FileHashSummary, Ipv4Endpoint, PeerEndpoint,
    UserHash,
};
use rmule_testkit::HANG_GUARD;
use tokio::sync::oneshot;
use tokio::time::timeout;

use crate::fixture::{dead_port, free_port, serving_started, settings_on};

const SHARER_HASH: UserHash = UserHash::from_bytes([0x5D; UserHash::BYTE_LEN]);

/// A peer's hello: `user_hash`, listening on `listen_port`, a High ID at the
/// address its link comes from.
fn ctx(user_hash: UserHash, listen_port: u16) -> PeerHandshakeContext {
    PeerHandshakeContext {
        identity: ClientIdentity::new(user_hash, Ed2kText::from_utf8("peer"), listen_port, 60),
        client_id: ClientId::from_u32(0),
        ed2k_client_id: ClientId::from_u32(0),
        public_ip: None,
        connected_server: None,
    }
}

/// A core sharing one 4096-byte file under a single upload slot, serving on
/// loopback; its event stream is drained so the serve side never stalls on
/// it.
async fn serving_one_slot() -> (SocketAddrV4, FileHash, tempfile::TempDir) {
    let bytes = vec![0x5D_u8; 4096];
    let file_hash = FileHashSummary::digest_bytes(&bytes).file_hash();
    let share = tempfile::tempdir().unwrap();
    tokio::fs::write(share.path().join("held.bin"), &bytes)
        .await
        .unwrap();
    let port = free_port().await;
    let config = CoreConfig {
        upload_slot_budget: 1,
        ..CoreConfig::default()
    };
    let mut core = Core::builder(config, rmule_testkit::memory_store())
        .settings(settings_on(port))
        .user_hash(SHARER_HASH)
        .build();
    let shared = rmule_testkit::share_directory(&mut core, share.path()).await;
    assert_eq!(shared, [file_hash], "the first pass shared held.bin");
    let listen_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr,
    }))
    .await
    .unwrap();
    serving_started(&mut core).await;
    tokio::spawn(async move { while core.next_event().await.is_some() {} });
    (listen_addr, file_hash, share)
}

/// A peer linked to the core and asking for the file's one part: it reads
/// back the grant or the rank.
async fn asking(at: SocketAddrV4, user_hash: UserHash, listen_port: u16, file: FileHash) -> Asker {
    asking_as(at, ctx(user_hash, listen_port), file).await
}

/// A peer linked to the core under `hello`, its hellos done.
async fn linked(at: SocketAddrV4, hello: PeerHandshakeContext) -> Connection {
    let endpoint = PeerEndpoint::V4(Ipv4Endpoint::new(*at.ip(), at.port()));
    let mut link = Connection::connect(endpoint, hello, ConnectOptions::default())
        .await
        .expect("the core accepts the peer");
    next_matching(&mut link, |event| {
        matches!(
            event,
            PeerEvent::Connection(ConnectionEvent::Identified { .. })
        )
    })
    .await;
    link
}

/// `asking` under `hello`.
async fn asking_as(at: SocketAddrV4, hello: PeerHandshakeContext, file: FileHash) -> Asker {
    let link = linked(at, hello).await;
    let ranges = PartRanges::new([(0, 4096), (0, 0), (0, 0)]).unwrap();
    link.send(PeerCommand::Requester(RequesterCommand::RequestParts {
        file_hash: file,
        file_size: 4096,
        ranges,
    }))
    .await
    .unwrap();
    Asker { link }
}

struct Asker {
    link: Connection,
}

impl Asker {
    async fn granted(&mut self) {
        next_matching(&mut self.link, |event| {
            matches!(
                event,
                PeerEvent::Requester(RequesterEvent::SlotGranted { .. })
            )
        })
        .await;
    }

    async fn ranked(&mut self, rank: u16) {
        next_matching(&mut self.link, |event| {
            matches!(
                event,
                PeerEvent::Requester(RequesterEvent::QueueRanked { rank: r, .. }) if *r == rank
            )
        })
        .await;
    }

    /// Hang up, and give the core a moment to read the close: the waiter's
    /// hang-up must reach the serve side before the slot frees, or the slot
    /// is granted on the link it is closing.
    async fn hang_up(self) {
        let _ = self.link.shutdown().await;
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

/// Read `link` until `want` matches an event, or fail at the hang guard
/// naming what was read.
async fn next_matching(link: &mut Connection, want: impl Fn(&PeerEvent) -> bool) {
    let mut seen = Vec::new();
    let found = timeout(HANG_GUARD, async {
        while let Some(event) = link.next_event().await {
            if want(&event) {
                return true;
            }
            seen.push(format!("{event:?}").chars().take(100).collect::<String>());
        }
        false
    })
    .await;
    assert!(
        matches!(found, Ok(true)),
        "the awaited event never came; read {seen:#?}"
    );
}

/// The events the first link the core dials to `listener` reads, up to its
/// unasked grant or its end.
fn dialed_back(
    listener: PeerListener,
    own: PeerHandshakeContext,
) -> oneshot::Receiver<Vec<String>> {
    let (said_tx, said_rx) = oneshot::channel();
    tokio::spawn(async move {
        let Ok(mut link) = listener.accept(own, ConnectOptions::default()).await else {
            return;
        };
        let mut said = Vec::new();
        while let Some(event) = link.next_event().await {
            let line = match &event {
                PeerEvent::Connection(ConnectionEvent::Identified { identity }) => {
                    format!("hello from {:?}", identity.user_hash())
                }
                PeerEvent::Requester(RequesterEvent::SlotOffered) => "grant".to_owned(),
                other => format!("{other:?}").chars().take(100).collect(),
            };
            let done = line == "grant";
            said.push(line);
            if done {
                break;
            }
        }
        let _ = said_tx.send(said);
    });
    said_rx
}

#[tokio::test]
async fn a_waiter_that_hung_up_is_dialed_back_and_granted_after_the_hellos() {
    let (at, file, _share) = serving_one_slot().await;
    let holder_hash = UserHash::from_bytes([0xA1; UserHash::BYTE_LEN]);
    let waiter_hash = UserHash::from_bytes([0xB2; UserHash::BYTE_LEN]);

    let mut holder = asking(at, holder_hash, dead_port().await, file).await;
    holder.granted().await;
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let mut waiter = asking(at, waiter_hash, listener.local_port(), file).await;
    waiter.ranked(1).await;
    let said = dialed_back(listener, ctx(waiter_hash, 0));
    waiter.hang_up().await;

    // The slot frees: the waiter is dialed back and granted after the hellos.
    let _ = holder.link.shutdown().await;
    let said = timeout(HANG_GUARD, said)
        .await
        .expect("the core dials the waiter back")
        .expect("the waiter's listener lives");
    assert_eq!(
        said.first().map(String::as_str),
        Some(format!("hello from {SHARER_HASH:?}").as_str()),
        "the hellos come first: {said:#?}"
    );
    assert_eq!(said.last().map(String::as_str), Some("grant"), "{said:#?}");
}

#[tokio::test]
async fn a_waiter_whose_own_link_crosses_its_dial_back_past_the_hello_is_granted_on_the_dial() {
    // Each end keeps the socket it read the other's hello on and deletes the
    // one it held (`ClientList.cpp:400-403`): the waiter keeps the dial whose
    // hello it read, so rmule lets the waiter's own link go and grants on
    // the dial.
    let (at, file, _share) = serving_one_slot().await;
    let holder_hash = UserHash::from_bytes([0xA1; UserHash::BYTE_LEN]);
    let waiter_hash = UserHash::from_bytes([0xB2; UserHash::BYTE_LEN]);

    let mut holder = asking(at, holder_hash, dead_port().await, file).await;
    holder.granted().await;
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let listen_port = listener.local_addr().unwrap().port();
    let mut waiter = asking(at, waiter_hash, listen_port, file).await;
    waiter.ranked(1).await;
    waiter.hang_up().await;
    let _ = holder.link.shutdown().await;

    let (stream, dialer) = timeout(HANG_GUARD, listener.accept())
        .await
        .expect("the core dials the waiter back")
        .unwrap();
    let mut first = [0u8; 1];
    timeout(HANG_GUARD, stream.peek(&mut first))
        .await
        .expect("the dial's hello arrives")
        .unwrap();
    assert_eq!(first[0], 0xE3, "the dial's hello is on the wire");

    let mut own = linked(at, ctx(waiter_hash, listen_port)).await;
    next_matching(&mut own, |event| {
        matches!(
            event,
            PeerEvent::Connection(ConnectionEvent::Disconnected { .. })
        )
    })
    .await;

    let dialer = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, dialer.port()));
    let mut dial = Connection::over_stream(
        stream,
        dialer,
        PeerStreamRole::Responder,
        ctx(waiter_hash, 0),
        ConnectOptions::default(),
    );
    next_matching(&mut dial, |event| {
        matches!(event, PeerEvent::Requester(RequesterEvent::SlotOffered))
    })
    .await;
}

#[tokio::test]
async fn a_waiter_no_dial_reaches_hands_the_slot_to_the_next() {
    let (at, file, _share) = serving_one_slot().await;
    let holder_hash = UserHash::from_bytes([0xA1; UserHash::BYTE_LEN]);
    let gone_hash = UserHash::from_bytes([0xB2; UserHash::BYTE_LEN]);
    let next_hash = UserHash::from_bytes([0xC3; UserHash::BYTE_LEN]);

    let mut holder = asking(at, holder_hash, dead_port().await, file).await;
    holder.granted().await;
    // Its hello names a port nothing listens on: the dial back is refused.
    let mut gone = asking(at, gone_hash, dead_port().await, file).await;
    gone.ranked(1).await;
    let mut next = asking(at, next_hash, dead_port().await, file).await;
    next.ranked(2).await;
    gone.hang_up().await;

    let _ = holder.link.shutdown().await;
    next.granted().await;
}

#[tokio::test]
async fn a_slot_nobody_could_be_reached_for_goes_to_the_waiter_whose_link_comes_back() {
    // aMule's `Process` fills a free slot within its next second with the
    // best waiter it can reach (`UploadQueue.cpp:255-258`): a Low ID that
    // hung up is reached again by its own link, granted there before it
    // asks.
    let (at, file, _share) = serving_one_slot().await;
    let holder_hash = UserHash::from_bytes([0xA1; UserHash::BYTE_LEN]);
    let low_hash = UserHash::from_bytes([0xB2; UserHash::BYTE_LEN]);
    let low_id = || PeerHandshakeContext {
        client_id: ClientId::from_u32(5),
        ed2k_client_id: ClientId::from_u32(5),
        ..ctx(low_hash, 4662)
    };

    let mut holder = asking(at, holder_hash, dead_port().await, file).await;
    holder.granted().await;
    let mut low = asking_as(at, low_id(), file).await;
    low.ranked(1).await;
    low.hang_up().await;
    let _ = holder.link.shutdown().await;

    let mut back = linked(at, low_id()).await;
    next_matching(&mut back, |event| {
        matches!(event, PeerEvent::Requester(RequesterEvent::SlotOffered))
    })
    .await;
}
