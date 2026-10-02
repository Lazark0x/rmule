//! The serve task's Peer Roster feed (ADR-0059):
//! every Upload relation its enactor marks is forgotten by the
//! release, the leave or the activity's own end that closes it.

use super::*;

/// The enactor's own Peer Roster feed (ADR-0059): a granted or
/// queued upload slot marks the peer's IP known, and only its release
/// forgets it — proven directly against `enact`, the one place these
/// `ServeEvent`s turn into the shared roster's writes.
#[tokio::test]
async fn a_granted_upload_marks_the_peer_roster_known_and_its_release_forgets_it() {
    let file = FileHash::from_bytes([0x11; FileHash::BYTE_LEN]);
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 9), 4662));
    let store = rmule_testkit::memory_store();
    let credit: SharedCreditStore = Arc::new(DurableCreditStore::new(store));
    let (evt_tx, mut evt_rx) = mpsc::channel::<CoreEvent>(8);
    let client_udp_tx: Option<mpsc::Sender<ClientUdpSend>> = None;
    let diagnostics = crate::diagnostics::DiagnosticsState::new();
    let peer_roster = crate::peer_roster::SharedPeerRoster::default();
    let sinks = super::super::ServeSinks {
        credit: &credit,
        evt_tx: &evt_tx,
        client_udp_tx: &client_udp_tx,
        diagnostics: &diagnostics,
        peer_roster: &peer_roster,
        read_failed_tx: None,
    };
    let (_accept_tx, accept_rx) = mpsc::channel::<ServeConnection>(1);
    let mut serve_runtime = FakeServeRuntime {
        bound: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4662),
        accepts: accept_rx,
    };
    let mut state = crate::serve::state::ServeState::new(UploadSlotQueue::new(1, 1));
    let conns = std::collections::HashMap::new();

    let mut decisions =
        std::collections::VecDeque::from([crate::serve::state::ServeDecision::Emit(
            ServeEvent::UploadSlotGranted {
                peer,
                file_hash: file,
                software: None,
            },
        )]);
    super::super::enact(
        &mut decisions,
        &mut state,
        &conns,
        &mut serve_runtime,
        sinks,
    )
    .await;
    assert!(
        peer_roster.knows(Ipv4Addr::new(203, 0, 113, 9)),
        "a granted slot marks the peer's IP known"
    );
    assert!(matches!(
        evt_rx.try_recv(),
        Ok(CoreEvent::Serve(ServeEvent::UploadSlotGranted { .. }))
    ));

    let mut decisions =
        std::collections::VecDeque::from([crate::serve::state::ServeDecision::Emit(
            ServeEvent::UploadSlotReleased { peer },
        )]);
    super::super::enact(
        &mut decisions,
        &mut state,
        &conns,
        &mut serve_runtime,
        sinks,
    )
    .await;
    assert!(
        !peer_roster.knows(Ipv4Addr::new(203, 0, 113, 9)),
        "its release forgets the IP"
    );
}

/// The purge sweep's own roster feed: a queued waiter that
/// never gets a slot is forgotten too, not just a released holder — proven
/// by driving the real serve brain (share, queue, purge) through `enact`,
/// not by hand-built decisions.
#[tokio::test]
async fn a_purged_never_granted_waiter_forgets_the_peer_roster_mark() {
    a_waiter_leaving_forgets_the_peer_roster_mark(crate::WaiterLeaveCause::Purged).await;
}

/// An `OP_CANCELTRANSFER` from a waiter drops its place, and the
/// Waiter relation ends with it.
#[tokio::test]
async fn a_cancelling_waiter_forgets_the_peer_roster_mark() {
    a_waiter_leaving_forgets_the_peer_roster_mark(crate::WaiterLeaveCause::Cancelled).await;
}

/// Queue a waiter behind the sole slot's holder, then let it leave by
/// `cause` without ever holding a slot: its `PeerQueued` mark must go.
async fn a_waiter_leaving_forgets_the_peer_roster_mark(cause: crate::WaiterLeaveCause) {
    let file = FileHash::from_bytes([0x22; FileHash::BYTE_LEN]);
    let holder = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 1), 4662));
    let waiter = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 10), 4662));
    let store = rmule_testkit::memory_store();
    let credit: SharedCreditStore = Arc::new(DurableCreditStore::new(store));
    let (evt_tx, _evt_rx) = mpsc::channel::<CoreEvent>(8);
    let client_udp_tx: Option<mpsc::Sender<ClientUdpSend>> = None;
    let diagnostics = crate::diagnostics::DiagnosticsState::new();
    let peer_roster = crate::peer_roster::SharedPeerRoster::default();
    let sinks = super::super::ServeSinks {
        credit: &credit,
        evt_tx: &evt_tx,
        client_udp_tx: &client_udp_tx,
        diagnostics: &diagnostics,
        peer_roster: &peer_roster,
        read_failed_tx: None,
    };
    let (_accept_tx, accept_rx) = mpsc::channel::<ServeConnection>(1);
    let mut serve_runtime = FakeServeRuntime {
        bound: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4662),
        accepts: accept_rx,
    };
    let mut state = crate::serve::state::ServeState::new(UploadSlotQueue::new(1, 8));
    let conns = std::collections::HashMap::new();
    let no_modifiers = std::collections::HashMap::new();
    let t0 = std::time::Instant::now();

    let _ = state.on_share_set(
        vec![SharedFileEntry {
            file_hash: file,
            file_size: 4096,
            path: "/shared/served.bin".into(),
            name: "served.bin".into(),
            source: ShareSource::Explicit,
            modified: None,
            part_hashes: Vec::new(),
        }],
        std::time::Instant::now(),
        &std::collections::HashMap::new(),
    );

    // The sole slot goes to `holder`, so `waiter` queues behind it instead
    // of being granted.
    let mut decisions: std::collections::VecDeque<_> = state
        .on_conn_event(
            t0,
            holder,
            ServeConnEvent::SlotRequested { file_hash: file },
            &no_modifiers,
        )
        .into();
    super::super::enact(
        &mut decisions,
        &mut state,
        &conns,
        &mut serve_runtime,
        sinks,
    )
    .await;
    let mut decisions: std::collections::VecDeque<_> = state
        .on_conn_event(
            t0,
            waiter,
            ServeConnEvent::SlotRequested { file_hash: file },
            &no_modifiers,
        )
        .into();
    super::super::enact(
        &mut decisions,
        &mut state,
        &conns,
        &mut serve_runtime,
        sinks,
    )
    .await;
    assert!(
        peer_roster.knows(Ipv4Addr::new(203, 0, 113, 10)),
        "the queued waiter marks the roster known"
    );

    // Leave without ever holding a slot — silent past the purge window, or
    // an `OP_CANCELTRANSFER` — and enacting the leave forgets the mark.
    let after = Duration::from_secs(3600);
    let mut decisions: std::collections::VecDeque<_> = match cause {
        crate::WaiterLeaveCause::Purged => {
            state.on_purge(t0 + after + Duration::from_secs(1), after, &no_modifiers)
        }
        crate::WaiterLeaveCause::Cancelled => state.on_conn_event(
            t0,
            waiter,
            ServeConnEvent::TransferCancelled { file_hash: file },
            &no_modifiers,
        ),
    }
    .into();
    super::super::enact(
        &mut decisions,
        &mut state,
        &conns,
        &mut serve_runtime,
        sinks,
    )
    .await;
    assert!(
        !peer_roster.knows(Ipv4Addr::new(203, 0, 113, 10)),
        "a never-granted waiter's leave forgets it, the same as a release"
    );
}

/// A stop ends every Upload relation the activity took. One
/// peer holds the sole slot and a second waits behind it on real accepted
/// connections; the serve task is then stopped and joined, and neither IP is
/// still known — the requester gate and the helper bias would otherwise keep
/// treating both as live relationships of a listener that is gone.
#[tokio::test]
async fn a_stopped_serve_forgets_its_holder_and_its_waiter() {
    let file = FileHash::from_bytes([0x33; FileHash::BYTE_LEN]);
    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    registry
        .share(SharedFileEntry {
            file_hash: file,
            file_size: 4096,
            path: "/shared/served.bin".into(),
            name: "served.bin".into(),
            source: ShareSource::Explicit,
            modified: None,
            part_hashes: Vec::new(),
        })
        .unwrap();
    let (accept_tx, accept_rx) = mpsc::channel::<ServeConnection>(4);
    let (evt_tx, mut evt_rx) = mpsc::channel::<CoreEvent>(64);
    let (stop_tx, stop_rx) = watch::channel(false);
    let (_share_changed_tx, share_changed_rx) = mpsc::channel::<()>(1);
    let peer_roster = crate::peer_roster::SharedPeerRoster::default();

    let serve = tokio::spawn(
        ServeTask {
            registry: Arc::new(registry),
            serve_runtime: FakeServeRuntime {
                bound: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4662),
                accepts: accept_rx,
            },
            queue: UploadSlotQueue::new(1, 8),
            own_identity: None,
            evt_tx,
            stop_rx,
            share_changed_rx,
            dialed_serve_rx: None,
            credit: Arc::new(DurableCreditStore::new(store)),
            rerank_interval: Duration::from_secs(3600),
            reask_rx: None,
            client_udp_tx: None,
            purge_interval: Duration::from_secs(3600),
            purge_after: Duration::from_secs(3600),
            diagnostics: crate::diagnostics::DiagnosticsState::new(),
            peer_roster: peer_roster.clone(),
            withheld: crate::registry_check::WithheldRows::default(),
            read_failed_tx: None,
        }
        .run(),
    );
    next_serve_event(&mut evt_rx, |e| {
        matches!(e, ServeEvent::FilesAnnounced { .. })
    })
    .await;

    let holder = [203, 0, 113, 21];
    let waiter = [203, 0, 113, 22];
    let mut halves = Vec::new();
    for ip in [holder, waiter] {
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (conn_evt_tx, conn_evt_rx) = mpsc::channel(16);
        accept_tx
            .send(ServeConnection::new(peer_at(ip, 4662), cmd_tx, conn_evt_rx))
            .await
            .unwrap();
        conn_evt_tx
            .send(ServeConnEvent::SlotRequested { file_hash: file })
            .await
            .unwrap();
        halves.push((cmd_rx, conn_evt_tx));
    }
    next_serve_event(&mut evt_rx, |e| {
        matches!(e, ServeEvent::UploadSlotGranted { .. })
    })
    .await;
    next_serve_event(&mut evt_rx, |e| matches!(e, ServeEvent::PeerQueued { .. })).await;
    assert!(
        peer_roster.knows(Ipv4Addr::from(holder)) && peer_roster.knows(Ipv4Addr::from(waiter)),
        "the holder and the waiter are both known while serving"
    );

    stop_tx.send(true).unwrap();
    let outcome = timeout(Duration::from_secs(5), serve)
        .await
        .expect("the stopped serve task ends")
        .expect("the serve task did not panic");
    assert_eq!(outcome.reason, ServeStopReason::Requested);
    assert!(
        !peer_roster.knows(Ipv4Addr::from(holder)),
        "the slot holder's relation ended with the activity"
    );
    assert!(
        !peer_roster.knows(Ipv4Addr::from(waiter)),
        "the waiter's relation ended with the activity"
    );
}
