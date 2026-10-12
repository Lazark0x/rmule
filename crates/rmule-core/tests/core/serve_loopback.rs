//! Serve loopbacks (Correctness Tier, ADR-0040): a real requester-side
//! `Connection` dials a serving core's bound `PeerListener`, probes a shared
//! file, requests a part, and receives the exact on-disk bytes. Exercises the
//! ServeTask routing + read_range over a real socket pair, without a real eD2k
//! server (the testkit serve runtime binds the listener and skips login).
use crate::fixture::serving_started;
use rmule_core::DurableCreditStore;
use rmule_core::DurableSharedFileRegistry;
use rmule_core::{
    Core, CoreCommand, CoreConfig, CreditStore, ServeCommand, ShareSource, SharedFileEntry,
    SharedFileRegistry,
};
use rmule_net::peer::{ConnectOptions, Connection};
use rmule_peer::{
    ConnectionEvent, PartRanges, PeerCommand, PeerEvent, RequesterCommand, RequesterEvent,
};
use rmule_primitives::{FileHashSummary, Ipv4Endpoint, PeerEndpoint, UserHash};
use rmule_testkit::HANG_GUARD;
use rmule_testkit::{
    LoopbackServeRuntime, PendingSourceLookup, RefusingPeerTransfer, ServingCore,
    test_handshake_ctx,
};
use std::net::{Ipv4Addr, SocketAddrV4};
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn mock_peer_downloads_a_shared_part_over_a_real_socket() {
    // A small (sub-part) shared file: one block, one SendBlock.
    // Note: a sub-part file has no part hash set so AnswerHashSet sends an
    // empty Vec. The requester calls after_hash_set on any HashSetAnswer
    // (including empty), marking the hash set Cached — so the flow proceeds
    // to STARTUPLOADREQ without needing real part hashes.
    let bytes = vec![0xEE_u8; 4096];
    let file_hash = FileHashSummary::digest_bytes(&bytes).file_hash();

    let serving = ServingCore::spawn(0x01, "served.bin", &bytes).await;
    let bound = serving.bound();

    // The mock peer dials the serve listener and requests the file's one block.
    let peer_endpoint = PeerEndpoint::V4(Ipv4Endpoint::new(*bound.ip(), bound.port()));
    let mut peer = Connection::connect(
        peer_endpoint,
        test_handshake_ctx(0x01, "rmule-serve"),
        ConnectOptions::default(),
    )
    .await
    .unwrap();

    // Wait for the peer session handshake to complete (Identified) before
    // issuing application commands — RequestParts is rejected before identification.
    timeout(HANG_GUARD, async {
        while let Some(event) = peer.next_event().await {
            if matches!(
                event,
                PeerEvent::Connection(ConnectionEvent::Identified { .. })
            ) {
                return;
            }
        }
    })
    .await
    .expect("peer identified");

    // Drive the requester side: RequestParts auto-issues probe + hashset +
    // slot acquisition, and the serve side answers each step, grants
    // the slot, and streams the block.
    let ranges = PartRanges::new([(0, bytes.len() as u64), (0, 0), (0, 0)]).unwrap();
    peer.send(PeerCommand::Requester(RequesterCommand::RequestParts {
        file_hash,
        file_size: bytes.len() as u64,
        ranges,
    }))
    .await
    .unwrap();

    // Collect PartReceived bytes until we have the full file content.
    let received = timeout(HANG_GUARD, async {
        let mut got = Vec::new();
        while let Some(event) = peer.next_event().await {
            if let PeerEvent::Requester(RequesterEvent::PartReceived { offset, bytes, .. }) = event
            {
                assert_eq!(
                    offset,
                    got.len() as u64,
                    "unexpected offset in PartReceived"
                );
                got.extend_from_slice(&bytes);
                if got.len() >= 4096 {
                    break;
                }
            }
        }
        got
    })
    .await
    .expect("received the served block");

    assert_eq!(received, bytes);
    drop(serving);
}

#[tokio::test]
async fn serving_a_block_records_uploaded_bytes_in_the_credit_store() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("served.bin");
    let bytes = vec![0xEE_u8; 4096];
    tokio::fs::write(&path, &bytes).await.unwrap();
    let summary = FileHashSummary::digest_bytes(&bytes);
    let file_hash = summary.file_hash();

    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    registry
        .share(SharedFileEntry {
            file_hash,
            file_size: bytes.len() as u64,
            path: path.clone(),
            name: "served.bin".into(),
            source: ShareSource::Explicit,
            modified: None,
            part_hashes: Vec::new(),
        })
        .unwrap();

    // Manual wiring (instead of ServingCore) because the test needs the
    // credit-store handle to assert accounting.
    let ctx = test_handshake_ctx(0x01, "rmule-serve");
    let (serve_runtime, bound_rx) = LoopbackServeRuntime::new(ctx.clone());
    let credit = DurableCreditStore::new(store.clone());
    let mut core = Core::builder(CoreConfig::default(), store)
        .settings(rmule_core::CoreSettings::default())
        .source_lookup(PendingSourceLookup)
        .peer_transfer(RefusingPeerTransfer)
        .serve_runtime(serve_runtime)
        .build();

    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
    }))
    .await
    .unwrap();
    serving_started(&mut core).await;
    let bound = timeout(HANG_GUARD, bound_rx)
        .await
        .expect("bound addr")
        .unwrap();

    let peer_endpoint = PeerEndpoint::V4(Ipv4Endpoint::new(*bound.ip(), bound.port()));
    let mut peer = Connection::connect(
        peer_endpoint,
        test_handshake_ctx(0x01, "rmule-serve"),
        ConnectOptions::default(),
    )
    .await
    .unwrap();
    timeout(HANG_GUARD, async {
        while let Some(event) = peer.next_event().await {
            if matches!(
                event,
                PeerEvent::Connection(ConnectionEvent::Identified { .. })
            ) {
                return;
            }
        }
    })
    .await
    .expect("identified");

    let ranges = PartRanges::new([(0, bytes.len() as u64), (0, 0), (0, 0)]).unwrap();
    peer.send(PeerCommand::Requester(RequesterCommand::RequestParts {
        file_hash,
        file_size: bytes.len() as u64,
        ranges,
    }))
    .await
    .unwrap();
    timeout(HANG_GUARD, async {
        let mut got = 0usize;
        while let Some(event) = peer.next_event().await {
            if let PeerEvent::Requester(RequesterEvent::PartReceived { bytes, .. }) = event {
                got += bytes.len();
                if got >= 4096 {
                    return;
                }
            }
        }
    })
    .await
    .expect("received the block");

    // The dialer identifies with test_handshake_ctx's user_hash 0x01.
    let dialer = UserHash::from_bytes([0x01; UserHash::BYTE_LEN]);
    // Allow the serve task to process the PartsRequested accounting.
    timeout(HANG_GUARD, async {
        loop {
            if credit.totals(dialer).unwrap().uploaded >= 4096 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("uploaded bytes recorded");

    assert_eq!(credit.totals(dialer).unwrap().uploaded, 4096);
    assert_eq!(credit.totals(dialer).unwrap().downloaded, 0);
}

/// Upload byte accounting over the same real socket (ADR-0077): the serving
/// core counts what it hands the wire, per peer and for the session, and the
/// sync `Core::diagnostics_snapshot()` reports both without an actor round
/// trip. The count is taken where the block enters the connection writer, so
/// it is already settled by the time the requester has the bytes — no wait.
#[tokio::test]
async fn serving_a_block_counts_upload_bytes_per_peer_and_for_the_session() {
    let _tracing = rmule_testkit::init_tracing();
    let bytes = vec![0xEE_u8; 4096];
    let file_hash = FileHashSummary::digest_bytes(&bytes).file_hash();

    let mut serving = ServingCore::spawn(0x02, "counted.bin", &bytes).await;
    let bound = serving.bound();

    // Nothing served yet.
    let before = serving.core_mut().diagnostics_snapshot();
    assert_eq!(before.session.up_bytes_total, 0);
    assert!(before.uploads.is_empty());

    let mut peer = Connection::connect(
        PeerEndpoint::V4(Ipv4Endpoint::new(*bound.ip(), bound.port())),
        test_handshake_ctx(0x03, "rmule-serve-counters"),
        ConnectOptions::default(),
    )
    .await
    .unwrap();
    timeout(HANG_GUARD, async {
        while let Some(event) = peer.next_event().await {
            if matches!(
                event,
                PeerEvent::Connection(ConnectionEvent::Identified { .. })
            ) {
                return;
            }
        }
    })
    .await
    .expect("identified");

    let ranges = PartRanges::new([(0, bytes.len() as u64), (0, 0), (0, 0)]).unwrap();
    peer.send(PeerCommand::Requester(RequesterCommand::RequestParts {
        file_hash,
        file_size: bytes.len() as u64,
        ranges,
    }))
    .await
    .unwrap();
    timeout(HANG_GUARD, async {
        let mut got = 0usize;
        while let Some(event) = peer.next_event().await {
            if let PeerEvent::Requester(RequesterEvent::PartReceived { bytes, .. }) = event {
                got += bytes.len();
                if got >= 4096 {
                    return;
                }
            }
        }
    })
    .await
    .expect("received the block");

    let served = serving.core_mut().diagnostics_snapshot();
    assert_eq!(
        served.session.up_bytes_total, 4096,
        "the session up total counts exactly the payload that crossed the wire",
    );
    let row = served
        .uploads
        .values()
        .next()
        .expect("the slot holder has an upload row while it is being fed");
    assert_eq!(served.uploads.len(), 1, "one peer is being served");
    assert_eq!(row.bytes_sent, 4096);
    assert_eq!(row.file_hash, file_hash, "the row names the served file");

    // The requester hangs up: its row retires with the slot, but the bytes it
    // took stay counted for the session — the monotonic guarantee.
    peer.shutdown().await.unwrap();
    let after = timeout(HANG_GUARD, async {
        loop {
            let snapshot = serving.core_mut().diagnostics_snapshot();
            if snapshot.uploads.is_empty() {
                return snapshot;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the released slot's upload row retired");
    assert_eq!(
        after.session.up_bytes_total, 4096,
        "a retired upload row must not subtract from the session total",
    );
}
