//! The operator's two interrupting commands. Pause releases only the in-flight
//! parts — verified ones survive — and persists `Paused`; cancel deletes the
//! `.part` file and makes `Cancelled` terminal even mid-workflow, after which
//! the download can no longer be resumed.

use rmule_core::DownloadRepository;
use std::sync::Arc;

use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadEvent, DownloadFailure,
    DownloadLifecycle, DownloadPaths, DownloadedPart, DurableDownloadRepository, PartReleaseReason,
    PeerTransferService, PeerWorker, PeerWorkerCommand, PeerWorkerEvent, open_durable_store,
};
use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{ED2K_PART_SIZE, Ed2kFileLink, PartHash, PeerEndpoint, ServerEndpoint};
use rmule_testkit::{
    PendingPeerTransfer, file_link, file_link_without_part_hash_set, loopback_peer, next_event,
    source_with_high_id, two_high_id_sources,
};

#[tokio::test]
async fn pause_releases_in_flight_parts_and_persists_paused_state() {
    let mut bytes = vec![0xAB; ED2K_PART_SIZE as usize];
    bytes.push(0xCD);
    let link = file_link("example.bin", &bytes);
    let hashes = link.part_hash_set.as_ref().unwrap().hashes().to_vec();
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();

    let mut core = Core::builder(CoreConfig::default(), Arc::clone(&store))
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            dir.path(),
        ))
        .source_lookup(two_high_id_sources())
        .peer_transfer(HoldingPeerTransfer {
            part_hashes: hashes,
        })
        .build();
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: link,
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        name: rmule_testkit::file_name("download.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
    }))
    .await
    .unwrap();

    let mut download_id = None;
    let mut assigned = 0u32;
    while assigned < 2 {
        let event = next_event(&mut core).await;
        match event {
            CoreEvent::Download(DownloadEvent::DownloadQueued {
                download_id: id, ..
            }) => download_id = Some(id),
            CoreEvent::Download(DownloadEvent::PartAssigned { .. }) => assigned += 1,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed before pause: {reason:?}")
            }
            _ => {}
        }
    }
    let download_id = download_id.expect("DownloadQueued emitted before pause");

    core.send(CoreCommand::Download(DownloadCommand::PauseDownload {
        download_id,
    }))
    .await
    .unwrap();

    let mut released = 0u32;
    let mut saw_paused = false;
    while !saw_paused {
        let event = next_event(&mut core).await;
        match event {
            CoreEvent::Download(DownloadEvent::PartReleased {
                reason: PartReleaseReason::Paused,
                ..
            }) => released += 1,
            CoreEvent::Download(DownloadEvent::DownloadPaused { download_id: id })
                if id == download_id =>
            {
                saw_paused = true;
            }
            CoreEvent::Download(
                DownloadEvent::DownloadCompleted { .. } | DownloadEvent::DownloadFailed { .. },
            ) => {
                panic!("unexpected terminal event during pause: {event:?}")
            }
            _ => {}
        }
    }
    assert_eq!(released, 2);

    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    assert_eq!(
        repo.load_download(download_id).unwrap().lifecycle(),
        DownloadLifecycle::Paused
    );
}

#[tokio::test]
async fn pause_preserves_verified_parts_and_releases_only_in_flight() {
    let mut bytes = vec![0xAB; ED2K_PART_SIZE as usize];
    bytes.push(0xCD);
    let link = file_link("example.bin", &bytes);
    let hashes = link.part_hash_set.as_ref().unwrap().hashes().to_vec();
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();

    let mut core = Core::builder(CoreConfig::default(), Arc::clone(&store))
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            dir.path(),
        ))
        .source_lookup(two_high_id_sources())
        .peer_transfer(PartialSuccessThenHold {
            part_hashes: hashes,
            completing_peer: loopback_peer(1),
            completed_part: DownloadedPart {
                part_index: 0,
                offset: 0,
                bytes: bytes[..ED2K_PART_SIZE as usize].to_vec(),
            },
        })
        .build();
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: link,
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        name: rmule_testkit::file_name("download.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
    }))
    .await
    .unwrap();

    let mut download_id = None;
    let mut verified_part_0 = false;
    while !verified_part_0 {
        let event = next_event(&mut core).await;
        match event {
            CoreEvent::Download(DownloadEvent::DownloadQueued {
                download_id: id, ..
            }) => download_id = Some(id),
            CoreEvent::Download(DownloadEvent::PartVerified { part_index: 0, .. }) => {
                verified_part_0 = true
            }
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed before pause: {reason:?}")
            }
            _ => {}
        }
    }
    let download_id = download_id.expect("DownloadQueued emitted before pause");

    core.send(CoreCommand::Download(DownloadCommand::PauseDownload {
        download_id,
    }))
    .await
    .unwrap();

    let mut released_indexes = Vec::new();
    loop {
        let event = next_event(&mut core).await;
        match event {
            CoreEvent::Download(DownloadEvent::PartReleased {
                part_index,
                reason: PartReleaseReason::Paused,
                ..
            }) => released_indexes.push(part_index),
            CoreEvent::Download(DownloadEvent::DownloadPaused { .. }) => break,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("unexpected DownloadFailed during pause: {reason:?}")
            }
            _ => {}
        }
    }

    assert!(
        !released_indexes.contains(&0),
        "verified part must not be released: {released_indexes:?}"
    );

    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    let verified = repo.verified_parts(download_id).unwrap();
    assert_eq!(verified.len(), 1);
    assert_eq!(verified[0].part_index, 0);
}

#[tokio::test]
async fn cancel_deletes_part_file_and_keeps_cancelled_terminal_state() {
    let mut bytes = vec![0xAB; ED2K_PART_SIZE as usize];
    bytes.push(0xCD);
    let link = file_link("example.bin", &bytes);
    let hashes = link.part_hash_set.as_ref().unwrap().hashes().to_vec();
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let output_path = dir.path().join("download.bin");
    let paths = DownloadPaths::from_final_path(output_path.clone());

    let mut core = Core::builder(CoreConfig::default(), Arc::clone(&store))
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            dir.path(),
        ))
        .source_lookup(two_high_id_sources())
        .peer_transfer(PartialSuccessThenHold {
            part_hashes: hashes,
            completing_peer: loopback_peer(1),
            completed_part: DownloadedPart {
                part_index: 0,
                offset: 0,
                bytes: bytes[..ED2K_PART_SIZE as usize].to_vec(),
            },
        })
        .build();
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: link,
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        name: rmule_testkit::file_name("download.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
    }))
    .await
    .unwrap();

    let mut download_id = None;
    let mut wrote_part_file = false;
    while !wrote_part_file {
        let event = next_event(&mut core).await;
        match event {
            CoreEvent::Download(DownloadEvent::DownloadQueued {
                download_id: id, ..
            }) => download_id = Some(id),
            CoreEvent::Download(DownloadEvent::PartVerified { part_index: 0, .. }) => {
                wrote_part_file = true
            }
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed before cancel: {reason:?}")
            }
            _ => {}
        }
    }
    let download_id = download_id.expect("DownloadQueued emitted before cancel");
    assert!(
        paths.part_path().exists(),
        ".part file must exist after first PartVerified"
    );

    core.send(CoreCommand::Download(DownloadCommand::CancelDownload {
        download_id,
    }))
    .await
    .unwrap();

    loop {
        let event = next_event(&mut core).await;
        match event {
            CoreEvent::Download(DownloadEvent::DownloadCancelled { download_id: id })
                if id == download_id =>
            {
                break;
            }
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => {
                panic!("download must not complete after cancel")
            }
            _ => {}
        }
    }
    assert!(!paths.part_path().exists(), ".part file must be deleted");

    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    assert_eq!(
        repo.load_download(download_id).unwrap().lifecycle(),
        DownloadLifecycle::Cancelled
    );
}

#[tokio::test]
async fn cancelled_download_cannot_be_resumed() {
    let bytes = vec![0xAB; ED2K_PART_SIZE as usize];
    let link = file_link("example.bin", &bytes);
    let hashes = link.part_hash_set.as_ref().unwrap().hashes().to_vec();
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();

    let mut core = Core::builder(CoreConfig::default(), Arc::clone(&store))
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            dir.path(),
        ))
        .source_lookup(two_high_id_sources())
        .peer_transfer(HoldingPeerTransfer {
            part_hashes: hashes,
        })
        .build();
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: link,
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        name: rmule_testkit::file_name("download.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
    }))
    .await
    .unwrap();

    let mut download_id = None;
    let mut assigned = 0u32;
    while assigned < 1 {
        let event = next_event(&mut core).await;
        match event {
            CoreEvent::Download(DownloadEvent::DownloadQueued {
                download_id: id, ..
            }) => download_id = Some(id),
            CoreEvent::Download(DownloadEvent::PartAssigned { .. }) => assigned += 1,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed before cancel: {reason:?}")
            }
            _ => {}
        }
    }
    let download_id = download_id.expect("DownloadQueued emitted before cancel");

    core.send(CoreCommand::Download(DownloadCommand::CancelDownload {
        download_id,
    }))
    .await
    .unwrap();
    loop {
        let event = next_event(&mut core).await;
        if matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadCancelled { .. })
        ) {
            break;
        }
    }

    core.send(CoreCommand::Download(DownloadCommand::ResumeDownload {
        download_id,
    }))
    .await
    .unwrap();

    let mut saw_reject = false;
    while !saw_reject {
        let event = next_event(&mut core).await;
        match event {
            CoreEvent::CommandRejected { .. } => saw_reject = true,
            CoreEvent::Download(
                DownloadEvent::DownloadResumed { .. } | DownloadEvent::DownloadCompleted { .. },
            ) => {
                panic!("cancelled download must not resume: {event:?}")
            }
            _ => {}
        }
    }
}

#[tokio::test]
async fn cancel_during_active_workflow_emits_cancelled_without_completion() {
    let out_dir = tempfile::tempdir().unwrap();
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            out_dir.path(),
        ))
        .source_lookup(source_with_high_id())
        .peer_transfer(PendingPeerTransfer)
        .build();

    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: file_link_without_part_hash_set("example.bin", b"hello world"),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        name: rmule_testkit::file_name("cancel-download.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
    }))
    .await
    .unwrap();

    loop {
        let event = next_event(&mut core).await;
        if matches!(
            event,
            CoreEvent::Download(DownloadEvent::PeerSelected { .. })
        ) {
            break;
        }
    }
    core.send(CoreCommand::Download(DownloadCommand::CancelDownload {
        download_id: rmule_core::DownloadId::from_u64(1),
    }))
    .await
    .unwrap();

    let mut post_cancel = Vec::new();
    loop {
        let event = next_event(&mut core).await;
        let cancelled = matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadCancelled { .. })
        );
        post_cancel.push(event);
        if cancelled {
            break;
        }
    }

    assert!(post_cancel.iter().any(|event| matches!(
        event,
        CoreEvent::Download(DownloadEvent::DownloadCancelled { .. })
    )));
    assert!(!post_cancel.iter().any(|event| matches!(
        event,
        CoreEvent::Download(DownloadEvent::DownloadCompleted { .. })
    )));
}

struct HoldingPeerTransfer {
    part_hashes: Vec<PartHash>,
}

impl PeerTransferService for HoldingPeerTransfer {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        let advertised = rmule_testkit::every_part(file.size);
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(8);
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let hashes = self.part_hashes.clone();
        tokio::spawn(async move {
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            let _ = event_tx.send(advertised).await;
            let mut sent_hashes = false;
            while let Some(command) = command_rx.recv().await {
                match command {
                    PeerWorkerCommand::AskSlot | PeerWorkerCommand::TakeGrant => {
                        let _ = event_tx.send(PeerWorkerEvent::SlotGranted).await;
                    }
                    PeerWorkerCommand::RequestHashSet => {}
                    PeerWorkerCommand::RequestBlocks { .. } => {
                        if !sent_hashes {
                            sent_hashes = true;
                            let _ = event_tx
                                .send(PeerWorkerEvent::HashSetReceived {
                                    part_hashes: hashes.clone(),
                                })
                                .await;
                        }
                    }
                    PeerWorkerCommand::RequestAich { .. } => {}
                    PeerWorkerCommand::RequestAichFileHash => {}
                    PeerWorkerCommand::Shutdown { .. } => break,
                }
            }
        });
        Ok(PeerWorker::new(peer, command_tx, event_rx))
    }
}

struct PartialSuccessThenHold {
    part_hashes: Vec<PartHash>,
    completing_peer: PeerEndpoint,
    completed_part: DownloadedPart,
}

impl PeerTransferService for PartialSuccessThenHold {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        let advertised = rmule_testkit::every_part(file.size);
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(8);
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let hashes = self.part_hashes.clone();
        let completing_peer = self.completing_peer;
        let completed_part = self.completed_part.clone();
        tokio::spawn(async move {
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            let _ = event_tx.send(advertised).await;
            let mut sent_hashes = false;
            let mut streamed = false;
            while let Some(command) = command_rx.recv().await {
                match command {
                    PeerWorkerCommand::AskSlot | PeerWorkerCommand::TakeGrant => {
                        let _ = event_tx.send(PeerWorkerEvent::SlotGranted).await;
                    }
                    PeerWorkerCommand::RequestHashSet => {}
                    PeerWorkerCommand::RequestBlocks { blocks, handout } => {
                        if !sent_hashes {
                            sent_hashes = true;
                            let _ = event_tx
                                .send(PeerWorkerEvent::HashSetReceived {
                                    part_hashes: hashes.clone(),
                                })
                                .await;
                        }
                        // The completing peer streams its part whole on its
                        // first handout of it, then holds what follows.
                        let touches = blocks
                            .iter()
                            .any(|block| block.part_index == completed_part.part_index);
                        if peer == completing_peer && touches && !streamed {
                            streamed = true;
                            let _ = event_tx
                                .send(PeerWorkerEvent::BlockReceived {
                                    part_index: completed_part.part_index,
                                    offset: completed_part.offset,
                                    bytes: completed_part.bytes.clone(),
                                })
                                .await;
                            let _ = event_tx
                                .send(PeerWorkerEvent::BlocksWanted {
                                    room: 3,
                                    drained: true,
                                    handout,
                                })
                                .await;
                        }
                    }
                    PeerWorkerCommand::RequestAich { .. } => {}
                    PeerWorkerCommand::RequestAichFileHash => {}
                    PeerWorkerCommand::Shutdown { .. } => break,
                }
            }
        });
        Ok(PeerWorker::new(peer, command_tx, event_rx))
    }
}
