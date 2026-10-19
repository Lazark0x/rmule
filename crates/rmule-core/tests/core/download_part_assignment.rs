//! Which peer works which part: a `PartAssigned` always precedes its
//! `PartVerified`, every usable High-ID peer is handed blocks, a handout is
//! driven by a worker's `Connected` event rather than done up front at spawn
//! (ADR-0030), and a shared part survives one worker's disconnect because the
//! blocks it held go to the other (ADR-0117).

use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadEvent, DownloadFailure,
    DownloadedPart, PartReleaseReason, PeerDownloadOutcome, PeerRetirementReason,
    PeerTransferService, PeerWorker, PeerWorkerCommand, PeerWorkerEvent, SourceLookupOutcome,
};
use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{
    ClientId, ED2K_PART_SIZE, Ed2kFileLink, PartHash, PeerEndpoint, PeerSource, ServerEndpoint,
};
use rmule_testkit::{
    StaticPeerTransfer, StaticSourceLookup, emit_blocks, file_link,
    file_link_without_part_hash_set, loopback_peer, next_event, plain_sources, run_download,
    source_with_high_id, two_high_id_sources,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn scheduler_assignment_events_are_emitted_before_part_verification() {
    let mut bytes = vec![0xAB; ED2K_PART_SIZE as usize];
    bytes.push(0xCD);
    let link = file_link("example.bin", &bytes);
    let hashes = link.part_hash_set.as_ref().unwrap().hashes().to_vec();
    let first = bytes[..ED2K_PART_SIZE as usize].to_vec();
    let second = bytes[ED2K_PART_SIZE as usize..].to_vec();

    let events = run_download(
        link,
        source_with_high_id(),
        StaticPeerTransfer {
            expected_plan_count: 2,
            outcome: PeerDownloadOutcome {
                peer_hashes: hashes,
                parts: vec![
                    DownloadedPart {
                        part_index: 0,
                        offset: 0,
                        bytes: first,
                    },
                    DownloadedPart {
                        part_index: 1,
                        offset: ED2K_PART_SIZE,
                        bytes: second,
                    },
                ],
            },
        },
    )
    .await;

    let first_assignment = events
        .iter()
        .position(|event| {
            matches!(
                event,
                CoreEvent::Download(DownloadEvent::PartAssigned { part_index: 0, .. })
            )
        })
        .expect("part 0 assignment event");
    let first_verification = events
        .iter()
        .position(|event| {
            matches!(
                event,
                CoreEvent::Download(DownloadEvent::PartVerified { part_index: 0, .. })
            )
        })
        .expect("part 0 verification event");

    assert!(first_assignment < first_verification);
}

#[tokio::test]
async fn fake_multi_peer_happy_path_hands_blocks_to_every_high_id_peer() {
    let out_dir = tempfile::tempdir().unwrap();
    let mut bytes = vec![0xAB; ED2K_PART_SIZE as usize];
    bytes.push(0xCD);
    let link = file_link("example.bin", &bytes);
    let hashes = link.part_hash_set.as_ref().unwrap().hashes().to_vec();
    let first = bytes[..ED2K_PART_SIZE as usize].to_vec();
    let second = bytes[ED2K_PART_SIZE as usize..].to_vec();
    let first_peer = loopback_peer(1);
    let second_peer = loopback_peer(2);
    let assignments = Arc::new(StdMutex::new(HashMap::new()));
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            out_dir.path(),
        ))
        .source_lookup(StaticSourceLookup {
            outcome: SourceLookupOutcome {
                client_id: ClientId::from_u32(0x0100_007F),
                sources: plain_sources(vec![
                    PeerSource::new(ClientId::from_u32(42), 4662),
                    PeerSource::new(ClientId::from_u32(0x0100_007F), 4663),
                    PeerSource::new(ClientId::from_u32(0x0200_007F), 4664),
                ]),
            },
        })
        .peer_transfer(MultiPeerTransfer {
            part_hashes: hashes,
            parts: HashMap::from([(0, first), (1, second)]),
            assignments: Arc::clone(&assignments),
        })
        .build();

    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: link,
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        name: rmule_testkit::file_name("multi-peer-happy-path.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
    }))
    .await
    .unwrap();

    let mut events = Vec::new();
    loop {
        let event = next_event(&mut core).await;
        let terminal = matches!(
            event,
            CoreEvent::Download(
                DownloadEvent::DownloadCompleted { .. } | DownloadEvent::DownloadFailed { .. }
            )
        );
        events.push(event);
        if terminal {
            break;
        }
    }

    assert!(events.iter().any(|event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::SourcesFound {
                total: 3,
                usable_high_id: 2,
                ..
            })
        )
    }));
    for usable in [first_peer, second_peer] {
        assert!(
            events.iter().any(|event| matches!(
                event,
                CoreEvent::Download(DownloadEvent::PartAssigned { peer, .. }) if *peer == usable
            )),
            "{usable} is handed blocks"
        );
    }
    assert!(events.iter().any(|event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::PartVerified { part_index: 0, .. })
        )
    }));
    assert!(events.iter().any(|event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::PartVerified { part_index: 1, .. })
        )
    }));
    assert!(events.iter().any(|event| matches!(
        event,
        CoreEvent::Download(DownloadEvent::DownloadCompleted { .. })
    )));

    let assignments = assignments.lock().unwrap();
    for part in [0, 1] {
        assert!(
            assignments
                .get(&part)
                .is_some_and(|peers| peers.iter().all(|p| [first_peer, second_peer].contains(p))),
            "part {part} went to the usable peers: {assignments:?}"
        );
    }
}

#[tokio::test]
async fn worker_is_assigned_a_part_only_after_connected() {
    let out_dir = tempfile::tempdir().unwrap();
    // ADR-0030: identification is event-driven. The runner must not assign a
    // part to a worker before that worker reports `Connected`; assignment is
    // driven by the `Connected` event, not done up front at spawn. The gated
    // fake withholds `Connected` until the test opens the gate, so any
    // `PartAssigned` seen while gated proves the runner assigned up front.
    let bytes = b"hello world".to_vec();
    let gate = Arc::new(tokio::sync::Notify::new());
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            out_dir.path(),
        ))
        .source_lookup(source_with_high_id())
        .peer_transfer(GatedConnectTransfer {
            gate: Arc::clone(&gate),
            bytes: bytes.clone(),
        })
        .build();
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: file_link_without_part_hash_set("example.bin", &bytes),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        name: rmule_testkit::file_name("gated-connect.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
    }))
    .await
    .unwrap();

    // While the worker withholds `Connected`, no part may be assigned and the
    // download may not terminate. Drain until the stream quiesces.
    loop {
        match timeout(Duration::from_millis(100), core.next_event()).await {
            Ok(Some(CoreEvent::Download(DownloadEvent::PartAssigned { .. }))) => {
                panic!("a part was assigned before the worker reported Connected")
            }
            Ok(Some(CoreEvent::Download(
                DownloadEvent::DownloadCompleted { .. } | DownloadEvent::DownloadFailed { .. },
            ))) => {
                panic!("download terminated before the worker reported Connected")
            }
            Ok(Some(_)) => {}
            Ok(None) => panic!("core event stream stayed open"),
            Err(_) => break,
        }
    }

    // Open the gate: the worker now reports `Connected`, which is what drives
    // the first assignment, and the download completes.
    gate.notify_one();
    let mut saw_assigned = false;
    loop {
        let event = next_event(&mut core).await;
        match event {
            CoreEvent::Download(DownloadEvent::PartAssigned { .. }) => saw_assigned = true,
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => break,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed: {reason:?}")
            }
            _ => {}
        }
    }
    assert!(
        saw_assigned,
        "a part must be assigned after the worker reports Connected"
    );
}

#[tokio::test]
async fn a_shared_part_survives_a_co_worker_disconnect() {
    // ADR-0117: for a single-part file both peers are handed blocks of the one
    // part. When one disconnects, the blocks it held are freed and go to the
    // other, so the download completes via the survivor instead of cascading
    // to failure.
    let bytes = vec![0xAB; ED2K_PART_SIZE as usize];
    let link = file_link("example.bin", &bytes);
    let hashes = link.part_hash_set.as_ref().unwrap().hashes().to_vec();
    let first_peer = loopback_peer(1);
    let second_peer = loopback_peer(2);

    let events = run_download(
        link,
        two_high_id_sources(),
        DisconnectThenSuccess {
            disconnecting_peer: first_peer,
            part_hashes: hashes,
            bytes,
        },
    )
    .await;

    // Both peers were handed blocks of the only part.
    assert!(events.iter().any(|event| matches!(
        event,
        CoreEvent::Download(DownloadEvent::PartAssigned { peer, part_index: 0, .. }) if *peer == first_peer
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        CoreEvent::Download(DownloadEvent::PartAssigned { peer, part_index: 0, .. }) if *peer == second_peer
    )));
    // The disconnect freed the blocks the first peer held...
    assert!(events.iter().any(|event| matches!(
        event,
        CoreEvent::Download(DownloadEvent::PartReleased {
            peer,
            part_index: 0,
            reason: PartReleaseReason::PeerRetired(PeerRetirementReason::PeerDisconnected),
            ..
        }) if *peer == first_peer
    )));
    // ...and the survivor carries the download to completion.
    assert!(events.iter().any(|event| matches!(
        event,
        CoreEvent::Download(DownloadEvent::DownloadCompleted { .. })
    )));
}

struct GatedConnectTransfer {
    gate: Arc<tokio::sync::Notify>,
    bytes: Vec<u8>,
}

impl PeerTransferService for GatedConnectTransfer {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        let advertised = rmule_testkit::every_part(file.size);
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(8);
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let gate = Arc::clone(&self.gate);
        let bytes = self.bytes.clone();
        tokio::spawn(async move {
            // Withhold identification until the test opens the gate so the
            // runner cannot assign a part before `Connected` (ADR-0030).
            gate.notified().await;
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            let _ = event_tx.send(advertised).await;
            while let Some(command) = command_rx.recv().await {
                match command {
                    PeerWorkerCommand::AskSlot | PeerWorkerCommand::TakeGrant => {
                        let _ = event_tx.send(PeerWorkerEvent::SlotGranted).await;
                    }
                    PeerWorkerCommand::RequestHashSet => {}
                    PeerWorkerCommand::RequestBlocks { blocks, handout } => {
                        let part = DownloadedPart {
                            part_index: 0,
                            offset: 0,
                            bytes: bytes.clone(),
                        };
                        emit_blocks(&event_tx, std::slice::from_ref(&part), &blocks, handout).await;
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

struct MultiPeerTransfer {
    part_hashes: Vec<PartHash>,
    parts: HashMap<u32, Vec<u8>>,
    assignments: Arc<StdMutex<HashMap<u32, Vec<PeerEndpoint>>>>,
}

impl PeerTransferService for MultiPeerTransfer {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        let advertised = rmule_testkit::every_part(file.size);
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(8);
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let part_hashes = self.part_hashes.clone();
        let held: Vec<DownloadedPart> = self
            .parts
            .iter()
            .map(|(&part_index, bytes)| DownloadedPart {
                part_index,
                offset: u64::from(part_index) * ED2K_PART_SIZE,
                bytes: bytes.clone(),
            })
            .collect();
        let assignments = Arc::clone(&self.assignments);
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
                    PeerWorkerCommand::RequestBlocks { blocks, handout } => {
                        for block in &blocks {
                            let mut assignments = assignments.lock().unwrap();
                            let peers = assignments.entry(block.part_index).or_default();
                            if !peers.contains(&peer) {
                                peers.push(peer);
                            }
                        }
                        if !sent_hashes {
                            sent_hashes = true;
                            let _ = event_tx
                                .send(PeerWorkerEvent::HashSetReceived {
                                    part_hashes: part_hashes.clone(),
                                })
                                .await;
                        }
                        emit_blocks(&event_tx, &held, &blocks, handout).await;
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

struct DisconnectThenSuccess {
    disconnecting_peer: PeerEndpoint,
    part_hashes: Vec<PartHash>,
    bytes: Vec<u8>,
}

impl PeerTransferService for DisconnectThenSuccess {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        let advertised = rmule_testkit::every_part(file.size);
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(8);
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let disconnecting_peer = self.disconnecting_peer;
        let hashes = self.part_hashes.clone();
        let bytes = self.bytes.clone();
        tokio::spawn(async move {
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            let _ = event_tx.send(advertised).await;
            while let Some(command) = command_rx.recv().await {
                match command {
                    PeerWorkerCommand::AskSlot | PeerWorkerCommand::TakeGrant => {
                        let _ = event_tx.send(PeerWorkerEvent::SlotGranted).await;
                    }
                    PeerWorkerCommand::RequestHashSet => {}
                    PeerWorkerCommand::RequestBlocks { .. } if peer == disconnecting_peer => {
                        let _ = event_tx.send(PeerWorkerEvent::Disconnected).await;
                        break;
                    }
                    PeerWorkerCommand::RequestBlocks { blocks, handout } => {
                        let _ = event_tx
                            .send(PeerWorkerEvent::HashSetReceived {
                                part_hashes: hashes.clone(),
                            })
                            .await;
                        let part = DownloadedPart {
                            part_index: 0,
                            offset: 0,
                            bytes: bytes.clone(),
                        };
                        emit_blocks(&event_tx, std::slice::from_ref(&part), &blocks, handout).await;
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
