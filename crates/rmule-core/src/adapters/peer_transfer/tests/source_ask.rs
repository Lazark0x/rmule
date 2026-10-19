//! What a dialed worker reports about the source ask, the legacy block clock, the
//! whole-file holder, a probe left unanswered, and the findbuddy posture.

use super::*;

/// Every event a dialed worker reports to a peer whose hello advertised the
/// SX1 nibble `sx1`, up to its `Connected` and through a `Shutdown` after it.
async fn worker_events_toward_sx1(sx1: u8) -> Vec<PeerWorkerEvent> {
    worker_events_toward(sx1, None, |event| *event == PeerWorkerEvent::Connected).await
}

/// [`worker_events_toward_sx1`], or toward a pre-0.42 mule stating
/// `legacy_sx1` in an `OP_EMULEINFO` after its hello; the `Shutdown` is sent
/// once `until` matches an event.
async fn worker_events_toward(
    sx1: u8,
    legacy_sx1: Option<u8>,
    until: impl Fn(&PeerWorkerEvent) -> bool,
) -> Vec<PeerWorkerEvent> {
    use rmule_testkit::{FakePeer, PeerScript};

    let bytes = vec![0xC3; 4096];
    let file = rmule_testkit::file_link("source-ask.bin", &bytes);
    let uploader = FakePeer::bind().await;
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(
        *uploader.addr().ip(),
        uploader.addr().port(),
    ));
    let peer_task = uploader.spawn(PeerScript {
        hello_source_exchange: sx1,
        legacy_mule_info: legacy_sx1,
        hello_user_hash: UserHash::from_bytes([
            0x4D, 0xA0, 0x17, 0xE2, 0x39, 0x8C, 0x05, 0xB6, 0x71, 0x2F, 0xD4, 0x68, 0x9A, 0x13,
            0xCE, 0x50,
        ]),
        ..PeerScript::serving(file.file_hash, bytes)
    });
    let mut transfer = RuntimePeerTransferService::new(crate::DEFAULT_SLOT_WAIT_TIMEOUT);
    let mut worker = transfer
        .start_peer_worker(peer, dialed_serve_ctx(), file)
        .await
        .unwrap();
    let mut events = Vec::new();
    while let Some(event) = timeout(Duration::from_secs(5), worker.next_event())
        .await
        .expect("the worker reports within 5s")
    {
        let reached = until(&event);
        events.push(event);
        if reached {
            break;
        }
    }
    worker
        .send(PeerWorkerCommand::Shutdown { cancel: false })
        .await
        .unwrap();
    while let Some(event) = timeout(Duration::from_secs(5), worker.next_event())
        .await
        .expect("the worker winds down within 5s")
    {
        events.push(event);
    }
    let _ = peer_task.await;
    events
}

/// The Source Ask Clock stamps an ask when it went out (ADR-0108), so the
/// worker reports one exactly when the download wanted sources and the
/// peer's hello allows the ask: a peer advertising SX1 v2 is asked, one
/// advertising v1 refuses at its hello and is not — and the worker hands up
/// what that hello said either way.
#[tokio::test]
async fn a_dialed_worker_reports_the_source_ask_only_when_the_hello_allows_it() {
    let asked = worker_events_toward_sx1(2).await;
    assert!(asked.contains(&PeerWorkerEvent::SourcesAsked));
    assert_eq!(
        supports(&asked),
        vec![rmule_peer::SourceExchangeSupport::new(true, 2, false)]
    );

    let refused = worker_events_toward_sx1(1).await;
    assert!(!refused.contains(&PeerWorkerEvent::SourcesAsked));
    assert_eq!(
        supports(&refused),
        vec![rmule_peer::SourceExchangeSupport::new(true, 1, false)]
    );
}

/// The source-exchange facts each identity among `events` carries, in order.
fn supports(events: &[PeerWorkerEvent]) -> Vec<rmule_peer::SourceExchangeSupport> {
    events
        .iter()
        .filter_map(|event| match event {
            PeerWorkerEvent::Identity(identity) => Some(identity.source_exchange()),
            _ => None,
        })
        .collect()
}

/// A pre-0.42 mule states its SX version only in its `OP_EMULEINFO` (aMule
/// 2.3.3 `BaseClient.cpp:918-921`), here after its hello: the router hands
/// the identity up whole at the hello and again at the block's revision, in
/// the session's order, so once the block has been read nothing staler
/// follows it (ADR-0108).
#[tokio::test]
async fn a_legacy_mules_block_reaches_the_source_ask_clock() {
    let block = rmule_peer::SourceExchangeSupport::new(true, 3, false);
    let events = worker_events_toward(0, Some(3), |event| {
        matches!(event, PeerWorkerEvent::Identity(identity) if identity.source_exchange() == block)
    })
    .await;
    let supports = supports(&events);
    assert_eq!(
        supports.first(),
        Some(&rmule_peer::SourceExchangeSupport::new(false, 0, false)),
        "the hello's facts come first"
    );
    assert_eq!(
        supports.last(),
        Some(&block),
        "nothing staler follows the block"
    );
}

/// A worker let go before it reported anything still sends its connect-time
/// file request, and the router forwards the session's report of it before
/// closing the socket (ADR-0108): the ask that went out is stamped.
#[tokio::test]
async fn a_worker_let_go_at_once_still_reports_its_source_ask() {
    use rmule_testkit::{FakePeer, PeerScript};

    let bytes = vec![0x2D; 4096];
    let file = rmule_testkit::file_link("let-go.bin", &bytes);
    let uploader = FakePeer::bind().await;
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(
        *uploader.addr().ip(),
        uploader.addr().port(),
    ));
    let peer_task = uploader.spawn(PeerScript::serving(file.file_hash, bytes));
    let mut transfer = RuntimePeerTransferService::new(crate::DEFAULT_SLOT_WAIT_TIMEOUT);
    let mut worker = transfer
        .start_peer_worker(peer, dialed_serve_ctx(), file)
        .await
        .unwrap();
    worker
        .send(PeerWorkerCommand::Shutdown { cancel: false })
        .await
        .unwrap();
    let mut events = Vec::new();
    while let Some(event) = timeout(Duration::from_secs(5), worker.next_event())
        .await
        .expect("the worker winds down within 5s")
    {
        events.push(event);
    }
    let _ = peer_task.await;
    assert!(
        events.contains(&PeerWorkerEvent::SourcesAsked),
        "{events:?}"
    );
}

/// The probe's answer carries the one bit of the peer's part picture the
/// source-ask gate reads (ADR-0108): a one-part file's name answer means a
/// complete source (aMule `ProcessFileInfo`), and the worker says so.
#[tokio::test]
async fn a_dialed_worker_reports_a_peer_that_holds_the_whole_file() {
    use rmule_testkit::{FakePeer, PeerScript};

    let bytes = vec![0x6E; 4096];
    let file = rmule_testkit::file_link("complete-source.bin", &bytes);
    let uploader = FakePeer::bind().await;
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(
        *uploader.addr().ip(),
        uploader.addr().port(),
    ));
    let peer_task = uploader.spawn(PeerScript::serving(file.file_hash, bytes));
    let mut transfer = RuntimePeerTransferService::new(crate::DEFAULT_SLOT_WAIT_TIMEOUT);
    let mut worker = transfer
        .start_peer_worker(peer, dialed_serve_ctx(), file.clone())
        .await
        .unwrap();
    worker
        .send(PeerWorkerCommand::RequestBlocks {
            blocks: vec![crate::BlockPlan {
                part_index: 0,
                start: 0,
                end: file.size,
            }],
        })
        .await
        .unwrap();
    loop {
        let event = timeout(Duration::from_secs(5), worker.next_event())
            .await
            .expect("the probe is answered within 5s")
            .expect("the worker stays up until the probe is answered");
        if let PeerWorkerEvent::PartsAdvertised { complete, .. } = event {
            assert!(complete);
            break;
        }
    }
    drop(worker);
    let _ = peer_task.await;
}

/// The worker's first part waits for the probe's answer (ADR-0112), bounded
/// by the slot budget: a peer that identifies and never answers for the file
/// ends in `SlotTimeout`, with no `PartsAdvertised` before it.
#[tokio::test]
async fn a_peer_that_never_answers_the_probe_ends_in_slot_timeout() {
    use rmule_testkit::{FakePeer, PeerScript};

    let bytes = vec![0x4B; 4096];
    let file = rmule_testkit::file_link("unanswered.bin", &bytes);
    let uploader = FakePeer::bind().await;
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(
        *uploader.addr().ip(),
        uploader.addr().port(),
    ));
    let peer_task = uploader.spawn(PeerScript::hello_only(
        UserHash::from_bytes([0x3C; UserHash::BYTE_LEN]),
        "never-answers",
    ));
    let mut transfer = RuntimePeerTransferService::new(Duration::from_millis(300));
    let mut worker = transfer
        .start_peer_worker(peer, dialed_serve_ctx(), file)
        .await
        .unwrap();
    loop {
        let event = timeout(Duration::from_secs(5), worker.next_event())
            .await
            .expect("the worker reports within 5s")
            .expect("the worker stays up until its budget runs out");
        assert!(
            !matches!(event, PeerWorkerEvent::PartsAdvertised { .. }),
            "nothing was advertised: {event:?}"
        );
        if event == PeerWorkerEvent::SlotTimeout {
            break;
        }
    }
    drop(worker);
    let _ = timeout(Duration::from_secs(5), peer_task).await;
}

/// The FINDBUDDY responder's posture reads Self Reach's **Kad flag** alone
/// (`KademliaUDPListener.cpp:1430`, `4e8f2b3c`): it opens when the
/// Kad verdicts open and a server High ID never opens it — a High-ID node that
/// Kad has not proven open is no buddy for anyone.
#[test]
fn the_findbuddy_posture_follows_the_kad_flag_and_ignores_the_high_id() {
    use crate::buddy::BuddyUdpPosture;
    use crate::reachability::{
        SharedKadVerdicts, SharedSelfReach, TcpReachability, UdpReachability,
    };

    let kad = SharedKadVerdicts::default();
    let own = crate::own_identity::SharedOwnIdentity::default();
    let reach = SharedSelfReach::new(
        crate::KadReachLevel::published(kad.clone()),
        own.clone(),
        crate::natt::front::SharedNattFront::default(),
    );
    own.set_connected_session(Some(crate::own_identity::ConnectedSession {
        server: None,
        client_id: rmule_primitives::ClientId::from_u32(0x0A00_0001),
    }));
    let closed = super::buddy_serve_posture(&reach);
    assert!(!closed.tcp_reachable && closed.udp == BuddyUdpPosture::Unverified);

    kad.set_tcp(TcpReachability::Open);
    kad.set_udp(UdpReachability::Open { port: 4672 });
    let open = super::buddy_serve_posture(&reach);
    assert!(open.tcp_reachable && open.udp == BuddyUdpPosture::Open);
}
