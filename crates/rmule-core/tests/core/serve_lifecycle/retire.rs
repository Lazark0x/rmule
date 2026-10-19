//! How a serve activity ends: a requested stop and a dead listener each close every open upload row.
use crate::fixture::sized_file;
use rmule_core::DurableSharedFileRegistry;
use rmule_core::{
    Core, CoreCommand, CoreConfig, ServeCommand, ServeEvent, ServeInput, ServeOutput,
    ServeStopReason, ShareSource, SharedFileEntry, SharedFileRegistry,
};
use rmule_primitives::FileHash;
use rmule_testkit::HANG_GUARD;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::time::timeout;

use super::{
    FakeServeRuntime, RestartableServeRuntime, UnusedPeerTransfer, UnusedSourceLookup, conn_pair,
    next_matching_serve_event, next_serve_event, peer,
};
use rmule_peer::{ServerCommand, ServerEvent};

/// `close_upload` only fires on `UploadSlotReleased`, and a
/// `StopServing` never emits one for the connections a live activity was
/// feeding — they end with the task, silently. Before `finish_serve` swept
/// them, a row open at the stop stayed "uploading" in the snapshot forever.
/// Two peers hold slots (no queueing: budget 2), the stop tears the activity
/// down with neither ever disconnecting on its own, and the snapshot must
/// show both rows gone — closed by the sweep, not by a release nothing sent.
#[tokio::test]
async fn stopping_serve_closes_every_open_upload_row() {
    let served_file = sized_file(1234);
    let file_hash = FileHash::from_bytes([0x58; FileHash::BYTE_LEN]);
    let store = rmule_testkit::memory_store();
    DurableSharedFileRegistry::new(store.clone())
        .share(SharedFileEntry {
            file_hash,
            file_size: 1234,
            path: served_file.path().to_path_buf(),
            name: "served.bin".into(),
            source: ShareSource::Explicit,
            modified: None,
            part_hashes: Vec::new(),
        })
        .unwrap();

    let (conn_a, evt_a, mut cmd_a) = conn_pair(peer(41));
    let (conn_b, evt_b, mut cmd_b) = conn_pair(peer(42));
    let announced = Arc::new(Mutex::new(0));
    let serve_runtime = FakeServeRuntime {
        pending: vec![conn_a, conn_b],
        announced: announced.clone(),
        start_fails: false,
    };

    // Budget 2: both requesters are granted, neither queues.
    let config = CoreConfig {
        upload_slot_budget: 2,
        max_upload_queue_len: 8,
        ..CoreConfig::default()
    };
    let mut core = Core::builder(config, store)
        .settings(rmule_core::CoreSettings::default())
        .source_lookup(UnusedSourceLookup)
        .peer_transfer(UnusedPeerTransfer)
        .serve_runtime(serve_runtime)
        .build();

    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: "0.0.0.0:0".parse().unwrap(),
    }))
    .await
    .unwrap();
    assert!(matches!(
        next_serve_event(&mut core).await,
        ServeEvent::ServingStarted { .. }
    ));
    assert_eq!(
        next_serve_event(&mut core).await,
        ServeEvent::FilesAnnounced { file_count: 1 }
    );

    evt_a
        .send(ServeInput::Server(ServerEvent::SlotRequested { file_hash }))
        .await
        .unwrap();
    assert_eq!(
        cmd_a.recv().await.unwrap(),
        ServeOutput::Server(ServerCommand::GrantSlot { file_hash })
    );
    assert_eq!(
        next_serve_event(&mut core).await,
        ServeEvent::UploadSlotGranted {
            peer: peer(41),
            file_hash,
            software: None,
            road: rmule_core::GrantRoad::Linked,
        }
    );

    evt_b
        .send(ServeInput::Server(ServerEvent::SlotRequested { file_hash }))
        .await
        .unwrap();
    assert_eq!(
        cmd_b.recv().await.unwrap(),
        ServeOutput::Server(ServerCommand::GrantSlot { file_hash })
    );
    assert_eq!(
        next_serve_event(&mut core).await,
        ServeEvent::UploadSlotGranted {
            peer: peer(42),
            file_hash,
            software: None,
            road: rmule_core::GrantRoad::Linked,
        }
    );

    assert_eq!(
        core.diagnostics_snapshot().uploads.len(),
        2,
        "both grants opened a row"
    );

    // Neither peer disconnects or releases: the stop alone must close both
    // rows. A `ServingStopped` with neither an intervening `Disconnected` nor
    // an `UploadSlotReleased` proves the sweep did it, not a release path.
    core.send(CoreCommand::Serve(ServeCommand::StopServing))
        .await
        .unwrap();
    assert_eq!(
        next_serve_event(&mut core).await,
        ServeEvent::ServingStopped {
            reason: ServeStopReason::Requested
        },
        "nothing released a slot first: the very next serve event is the stop itself",
    );

    assert!(
        core.diagnostics_snapshot().uploads.is_empty(),
        "both upload rows close with the serve activity, not only on UploadSlotReleased",
    );
}

/// A listener that dies takes the activity with it and gives the
/// adapter back, so serving recovers. The death is unbidden — nobody sent
/// `StopServing` — and `ServingStopped` names it; the `StartServing` that
/// follows binds again and the new activity really serves, which the grant over
/// the second listener's connection proves.
#[tokio::test]
async fn a_dead_listener_ends_the_activity_and_a_later_start_serves_again() {
    let served_file = sized_file(1234);
    let file_hash = FileHash::from_bytes([0x57; FileHash::BYTE_LEN]);
    let store = rmule_testkit::memory_store();
    DurableSharedFileRegistry::new(store.clone())
        .share(SharedFileEntry {
            file_hash,
            file_size: 1234,
            path: served_file.path().to_path_buf(),
            name: "served.bin".into(),
            source: ShareSource::Explicit,
            modified: None,
            part_hashes: Vec::new(),
        })
        .unwrap();

    let (doomed_tx, doomed_rx) = mpsc::channel(1);
    let (live_tx, live_rx) = mpsc::channel(1);
    let mut core = Core::builder(CoreConfig::default(), store)
        .settings(rmule_core::CoreSettings::default())
        .source_lookup(UnusedSourceLookup)
        .peer_transfer(UnusedPeerTransfer)
        .serve_runtime(RestartableServeRuntime {
            listeners: vec![doomed_rx, live_rx],
            accepts: None,
        })
        .build();

    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: "0.0.0.0:0".parse().unwrap(),
    }))
    .await
    .unwrap();
    assert!(matches!(
        next_serve_event(&mut core).await,
        ServeEvent::ServingStarted { .. }
    ));

    // The listener dies. Nobody asked for it, so the only way anything learns
    // is the activity saying so.
    drop(doomed_tx);
    assert_eq!(
        next_matching_serve_event(&mut core, |event| matches!(
            event,
            ServeEvent::ServingStopped { .. }
        ))
        .await,
        ServeEvent::ServingStopped {
            reason: ServeStopReason::ListenerClosed
        },
    );

    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: "0.0.0.0:0".parse().unwrap(),
    }))
    .await
    .unwrap();
    assert!(
        matches!(
            next_matching_serve_event(&mut core, |event| matches!(
                event,
                ServeEvent::ServingStarted { .. } | ServeEvent::ServingFailed { .. }
            ))
            .await,
            ServeEvent::ServingStarted { .. }
        ),
        "the adapter came back with the activity, so this is a first start again",
    );
    // A slot is granted against the share set the new activity announces; a
    // request ahead of it finds nothing shared and is dropped in silence.
    assert_eq!(
        next_matching_serve_event(&mut core, |event| matches!(
            event,
            ServeEvent::FilesAnnounced { .. }
        ))
        .await,
        ServeEvent::FilesAnnounced { file_count: 1 }
    );

    // And the second activity is a serving one: a connection accepted on the
    // second listener is queued and granted like any other.
    let (conn, evt, mut cmd) = conn_pair(peer(11));
    live_tx.send(conn).await.unwrap();
    evt.send(ServeInput::Server(ServerEvent::SlotRequested { file_hash }))
        .await
        .unwrap();
    assert_eq!(
        timeout(HANG_GUARD, cmd.recv())
            .await
            .expect("the restarted serve answers its new listener's peer")
            .unwrap(),
        ServeOutput::Server(ServerCommand::GrantSlot { file_hash })
    );
}

/// The other road into `finish_serve`: a listener death, not a
/// `StopServing`, is just as silent toward a slot holder — nothing tears the
/// connection down, so nothing emits `UploadSlotReleased`. The row must still
/// close when the activity does.
#[tokio::test]
async fn a_dead_listener_closes_every_open_upload_row_too() {
    let served_file = sized_file(1234);
    let file_hash = FileHash::from_bytes([0x59; FileHash::BYTE_LEN]);
    let store = rmule_testkit::memory_store();
    DurableSharedFileRegistry::new(store.clone())
        .share(SharedFileEntry {
            file_hash,
            file_size: 1234,
            path: served_file.path().to_path_buf(),
            name: "served.bin".into(),
            source: ShareSource::Explicit,
            modified: None,
            part_hashes: Vec::new(),
        })
        .unwrap();

    let (doomed_tx, doomed_rx) = mpsc::channel(1);
    let (_live_tx, live_rx) = mpsc::channel(1);
    let mut core = Core::builder(CoreConfig::default(), store)
        .settings(rmule_core::CoreSettings::default())
        .source_lookup(UnusedSourceLookup)
        .peer_transfer(UnusedPeerTransfer)
        .serve_runtime(RestartableServeRuntime {
            listeners: vec![doomed_rx, live_rx],
            accepts: None,
        })
        .build();

    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: "0.0.0.0:0".parse().unwrap(),
    }))
    .await
    .unwrap();
    assert!(matches!(
        next_serve_event(&mut core).await,
        ServeEvent::ServingStarted { .. }
    ));
    assert_eq!(
        next_serve_event(&mut core).await,
        ServeEvent::FilesAnnounced { file_count: 1 }
    );

    let (conn, evt, mut cmd) = conn_pair(peer(21));
    doomed_tx.send(conn).await.unwrap();
    evt.send(ServeInput::Server(ServerEvent::SlotRequested { file_hash }))
        .await
        .unwrap();
    assert_eq!(
        cmd.recv().await.unwrap(),
        ServeOutput::Server(ServerCommand::GrantSlot { file_hash })
    );
    assert_eq!(
        next_serve_event(&mut core).await,
        ServeEvent::UploadSlotGranted {
            peer: peer(21),
            file_hash,
            software: None,
            road: rmule_core::GrantRoad::Linked,
        }
    );
    assert_eq!(
        core.diagnostics_snapshot().uploads.len(),
        1,
        "the grant opened a row"
    );

    // The listener dies with the slot holder still connected: neither a
    // `Disconnected` nor an `UploadSlotReleased` is coming.
    drop(doomed_tx);
    assert_eq!(
        next_matching_serve_event(&mut core, |event| matches!(
            event,
            ServeEvent::ServingStopped { .. }
        ))
        .await,
        ServeEvent::ServingStopped {
            reason: ServeStopReason::ListenerClosed
        },
    );

    assert!(
        core.diagnostics_snapshot().uploads.is_empty(),
        "the row closes with the dead activity, exactly as a StopServing closes it",
    );
}
