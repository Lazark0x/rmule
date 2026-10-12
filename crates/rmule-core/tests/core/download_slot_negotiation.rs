//! What the uploader's slot costs a download, over the loopback peers: a peer
//! that ranks us before granting, one that ranks us forever (the standing is
//! kept in the Remote-Queued Pool, not failed — ADR-0057), one that grants and
//! then delivers nothing (the slot-wait budget covers the wait for bytes), and
//! the `OP_CANCELTRANSFER` a cancel owes the peer whose slot we hold (ADR-0056).

use rmule_testkit::HANG_GUARD;
use std::time::Duration;

use rmule_core::{Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadEvent};
use rmule_testkit::{FakeEd2kServer, FakePeer, PeerScript, ServePolicy, SlotPolicy, file_link};
use tokio::time::timeout;

#[tokio::test]
async fn core_download_completes_through_queue_ranking() {
    // A busy peer queues us: it answers OP_STARTUPLOADREQ with one or
    // more OP_QUEUERANKING frames (non-terminal "you are at rank N")
    // before finally granting OP_ACCEPTUPLOADREQ. The download must
    // survive the wait, and core must surface the queue position so the
    // caller sees progress instead of apparent silence.
    let bytes = b"queued loopback download".to_vec();
    let file = file_link("loopback.bin", &bytes);
    let file_hash = file.file_hash;

    let server = FakeEd2kServer::start_scripted().await;
    let peer = FakePeer::bind().await;
    server.set_sources(vec![peer.source()]).await;
    // Queue the requester twice (rank improves), then grant a slot.
    let peer_task = peer.spawn(PeerScript {
        slot: SlotPolicy::QueueThenGrant(vec![3, 1]),
        ..PeerScript::serving(file_hash, bytes)
    });

    let out = tempfile::tempdir().unwrap();
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            out.path(),
        ))
        .build();
    rmule_testkit::connect_to(&core, &server.endpoint()).await;
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(server.endpoint()),
        name: rmule_testkit::file_name("queued.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
    }))
    .await
    .unwrap();

    let mut saw_queued = false;
    loop {
        let event = timeout(HANG_GUARD, core.next_event())
            .await
            .expect("core emitted event")
            .expect("core event stream stayed open");
        match event {
            CoreEvent::Download(DownloadEvent::PeerQueued { rank, .. }) => {
                assert!(rank > 0, "queue rank should be the peer-reported position");
                saw_queued = true;
            }
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => break,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed: {reason:?}")
            }
            _ => {}
        }
    }

    assert!(
        saw_queued,
        "core must surface PeerQueued while the peer holds us in its upload queue"
    );

    // Serving keeps the dialed link open for uploads (ADR-0031);

    // the peer script ends when the core does.

    core.shutdown().await;

    let _ = peer_task.await;
}

#[tokio::test]
async fn core_keeps_remote_queue_standing_when_a_slot_is_never_granted() {
    // ADR-0057 disconnect-and-reask: a peer that ranks us forever but never
    // grants a slot must NOT fail the download. After `slot_wait_timeout` elapses
    // the worker hangs up (PeerSlotTimeout), but the earned queue standing is not
    // forfeited — the source enters the Remote-Queued Pool (SourceRemoteQueued),
    // to be kept alive on the reask heartbeat instead of failing the download.
    let bytes = b"never granted loopback download".to_vec();
    let file = file_link("loopback.bin", &bytes);
    let file_hash = file.file_hash;

    let server = FakeEd2kServer::start_scripted().await;
    let peer = FakePeer::bind().await;
    server.set_sources(vec![peer.source()]).await;
    // Rank the requester but never grant. The connection stays open so
    // the worker stays queued: only its own slot-wait budget can end
    // the wait, never a peer close.
    let peer_task = peer.spawn(PeerScript {
        slot: SlotPolicy::QueueThenSilence(vec![5, 4]),
        serve: ServePolicy::Nothing,
        ..PeerScript::serving(file_hash, bytes)
    });

    let config = CoreConfig {
        peer_concurrency_per_download: 1,
        slot_wait_timeout: Duration::from_millis(150),
        ..CoreConfig::default()
    };
    let out = tempfile::tempdir().unwrap();
    let mut core = Core::builder(config, rmule_testkit::memory_store())
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            out.path(),
        ))
        .build();
    rmule_testkit::connect_to(&core, &server.endpoint()).await;
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(server.endpoint()),
        name: rmule_testkit::file_name("slot-timeout.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
    }))
    .await
    .unwrap();

    // The worker hangs up (PeerSlotTimeout) and the source's standing is kept
    // (SourceRemoteQueued) — both must arrive, and neither a failure nor a
    // completion may. Collect both, order-tolerantly (the reask observer pools
    // the source before the brain surfaces the timeout).
    let mut saw_slot_timeout = false;
    let mut saw_remote_queued = false;
    while !(saw_slot_timeout && saw_remote_queued) {
        let event = timeout(Duration::from_secs(3), core.next_event())
            .await
            .expect("core emitted event")
            .expect("core event stream stayed open");
        match event {
            CoreEvent::Download(DownloadEvent::PeerSlotTimeout { .. }) => saw_slot_timeout = true,
            CoreEvent::Download(DownloadEvent::SourceRemoteQueued { rank, .. }) => {
                assert!(
                    rank > 0,
                    "remote-queued standing carries the last known rank"
                );
                saw_remote_queued = true;
            }
            CoreEvent::Download(DownloadEvent::DownloadFailed { .. }) => {
                panic!("ADR-0057: earned queue standing must be kept via reask, not failed")
            }
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => {
                panic!("download must not complete: no slot was granted")
            }
            _ => {}
        }
    }

    // The worker hung up on timeout, so its loopback connection closed; the
    // source's standing now rides socketless in the Remote-Queued Pool.
    // Serving keeps the dialed link open for uploads (ADR-0031);
    // the peer script ends when the core does.
    core.shutdown().await;
    let _ = peer_task.await;
}

#[tokio::test]
async fn core_times_out_when_peer_stalls_after_granting_a_slot() {
    // A peer that grants the slot but then delivers no bytes must not hang
    // the download forever. The slot-wait budget covers the wait for data,
    // not only the wait for the grant: when no part bytes arrive within
    // `slot_wait_timeout` the worker gives up (PeerSlotTimeout) and, with
    // no other source, the download fails instead of parking silently.
    let bytes = b"granted then silent loopback download".to_vec();
    let file = file_link("loopback.bin", &bytes);
    let file_hash = file.file_hash;

    let server = FakeEd2kServer::start_scripted().await;
    let peer = FakePeer::bind().await;
    server.set_sources(vec![peer.source()]).await;
    // Grant the slot, then go silent: never answer OP_REQUESTPARTS, but
    // keep the connection open so only the worker's own no-progress
    // budget can end the wait (a close would look like a disconnect).
    let peer_task = peer.spawn(PeerScript {
        serve: ServePolicy::Nothing,
        ..PeerScript::serving(file_hash, bytes)
    });

    let config = CoreConfig {
        peer_concurrency_per_download: 1,
        slot_wait_timeout: Duration::from_millis(150),
        ..CoreConfig::default()
    };
    let out = tempfile::tempdir().unwrap();
    let mut core = Core::builder(config, rmule_testkit::memory_store())
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            out.path(),
        ))
        .build();
    rmule_testkit::connect_to(&core, &server.endpoint()).await;
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(server.endpoint()),
        name: rmule_testkit::file_name("stall-after-grant.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
    }))
    .await
    .unwrap();

    let mut saw_slot_granted = false;
    let mut saw_slot_timeout = false;
    loop {
        let event = timeout(Duration::from_secs(3), core.next_event())
            .await
            .expect("core emitted event")
            .expect("core event stream stayed open");
        match event {
            CoreEvent::Download(DownloadEvent::PeerSlotGranted { .. }) => saw_slot_granted = true,
            CoreEvent::Download(DownloadEvent::PeerSlotTimeout { .. }) => saw_slot_timeout = true,
            CoreEvent::Download(DownloadEvent::DownloadFailed { .. }) => break,
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => {
                panic!("download must not complete: no bytes were delivered")
            }
            _ => {}
        }
    }

    assert!(saw_slot_granted, "the peer did grant a slot");
    assert!(
        saw_slot_timeout,
        "a peer that grants then stalls must time out, not hang the download"
    );

    // Serving keeps the dialed link open for uploads (ADR-0031);

    // the peer script ends when the core does.

    core.shutdown().await;

    let _ = peer_task.await;
}

#[tokio::test]
async fn core_cancel_emits_op_canceltransfer_to_the_slot_holding_peer() {
    // ADR-0056 emit, live-wired: a download cancelled while a worker holds an
    // uploader's slot must send `OP_CANCELTRANSFER` (`0x56`) to that uploader
    // before tearing the connection down — the requester-side courtesy that
    // lets a live aMule end its upload session at once instead of holding the
    // slot until its stale-timeout fires. The peer grants a slot then goes
    // silent (`ServePolicy::Nothing`), so the worker is holding the slot,
    // waiting on bytes, at the instant the cancel lands.
    let bytes = b"cancel-before-teardown loopback download".to_vec();
    let file = file_link("loopback.bin", &bytes);
    let file_hash = file.file_hash;

    let server = FakeEd2kServer::start_scripted().await;
    let peer = FakePeer::bind().await;
    server.set_sources(vec![peer.source()]).await;
    let peer_task = peer.spawn(PeerScript {
        serve: ServePolicy::Nothing,
        ..PeerScript::serving(file_hash, bytes)
    });

    let config = CoreConfig {
        peer_concurrency_per_download: 1,
        slot_wait_timeout: Duration::from_millis(200),
        ..CoreConfig::default()
    };
    let out = tempfile::tempdir().unwrap();
    let mut core = Core::builder(config, rmule_testkit::memory_store())
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            out.path(),
        ))
        .build();
    rmule_testkit::connect_to(&core, &server.endpoint()).await;
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(server.endpoint()),
        name: rmule_testkit::file_name("cancel-before-teardown.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
    }))
    .await
    .unwrap();

    // Cancel the instant a slot is granted: the worker now holds the uploader's
    // slot, so its teardown owes the peer an `OP_CANCELTRANSFER`.
    let mut download_id = None;
    loop {
        let event = timeout(Duration::from_secs(3), core.next_event())
            .await
            .expect("core emitted event")
            .expect("core event stream stayed open");
        match event {
            CoreEvent::Download(DownloadEvent::DownloadQueued {
                download_id: id, ..
            }) => download_id = Some(id),
            CoreEvent::Download(DownloadEvent::PeerSlotGranted { .. }) => {
                let id = download_id.expect("DownloadQueued precedes the slot grant");
                core.send(CoreCommand::Download(DownloadCommand::CancelDownload {
                    download_id: id,
                }))
                .await
                .unwrap();
                break;
            }
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => {
                panic!("download must not complete: no bytes were delivered")
            }
            _ => {}
        }
    }

    // Drain to the cancelled terminal.
    loop {
        let event = timeout(Duration::from_secs(3), core.next_event())
            .await
            .expect("core emitted event")
            .expect("core event stream stayed open");
        match event {
            CoreEvent::Download(DownloadEvent::DownloadCancelled { .. }) => break,
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => {
                panic!("download must not complete after cancel")
            }
            _ => {}
        }
    }

    // `peer_task` returns only once the worker closed the socket, i.e. after the
    // teardown put the `0x56` on the wire — so the count is the whole proof.
    // Serving keeps the dialed link open for uploads (ADR-0031);
    // the peer script ends when the core does.
    core.shutdown().await;
    let stats = timeout(Duration::from_secs(3), peer_task)
        .await
        .expect("the peer script finished once the worker closed the socket")
        .expect("peer task");
    assert_eq!(
        stats.cancel_transfer_count, 1,
        "the cancelled download must emit exactly one OP_CANCELTRANSFER to the \
         slot-holding uploader before teardown (ADR-0056)"
    );
}
