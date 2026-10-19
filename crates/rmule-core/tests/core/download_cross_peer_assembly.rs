//! Block assembly across peers (ADR-0029, ADR-0117): a peer that drops
//! mid-part leaves its arrived bytes, and the next peer is handed only what is
//! missing; a part shared by several workers that fails its MD4 hash with no
//! AICH root keeps every worker, and its verified refetch names the sender of
//! the cell that changed.

use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadEvent, DownloadFailure,
    PeerRetirementReason, PeerTransferService, PeerWorker, PeerWorkerCommand, PeerWorkerEvent,
    SourceLookupOutcome,
};
use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{
    ClientId, ED2K_PART_SIZE, Ed2kFileLink, FileHashSummary, PartHash, PeerEndpoint, PeerSource,
    ServerEndpoint,
};
use rmule_testkit::{
    StaticSourceLookup, emit_blocks, file_link_without_part_hash_set, loopback_peer, next_event,
    plain_sources, two_high_id_sources,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};

#[tokio::test]
async fn a_dropped_workers_bytes_stay_and_the_next_is_handed_only_the_rest() {
    let out_dir = tempfile::tempdir().unwrap();
    // ADR-0117: peer A delivers [0, k) of the only block then drops; core keeps
    // the arrived bytes and hands peer B only [k, len), instead of the block
    // from 0. One connection makes the drop-then-backfill sequence
    // deterministic.
    let bytes: Vec<u8> = (0..100u32).map(|i| (i % 251) as u8).collect();
    let drop_at = 40u64;
    let dropping_peer = loopback_peer(1);
    let resuming_peer = loopback_peer(2);
    let first_handed = Arc::new(StdMutex::new(HashMap::new()));

    let mut core = Core::builder(
        CoreConfig {
            peer_connections: rmule_core::PeerConnections {
                max_connections: 1,
                ..rmule_core::PeerConnections::default()
            },
            ..CoreConfig::default()
        },
        rmule_testkit::memory_store(),
    )
    .settings(rmule_testkit::in_download_dir(
        rmule_core::CoreSettings::default(),
        out_dir.path(),
    ))
    .source_lookup(two_high_id_sources())
    .peer_transfer(ResumeAfterDropTransfer {
        dropping_peer,
        drop_at,
        bytes: bytes.clone(),
        first_handed: Arc::clone(&first_handed),
    })
    .build();
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: file_link_without_part_hash_set("example.bin", &bytes),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        name: rmule_testkit::file_name("resume-after-drop.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
        kad_aich_root: None,
    }))
    .await
    .unwrap();

    loop {
        let event = next_event(&mut core).await;
        match event {
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => break,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed: {reason:?}")
            }
            _ => {}
        }
    }

    let offsets = first_handed.lock().unwrap();
    assert_eq!(
        offsets.get(&dropping_peer),
        Some(&0),
        "the first peer is handed the block from offset 0"
    );
    assert_eq!(
        offsets.get(&resuming_peer),
        Some(&drop_at),
        "the second peer is handed only what did not arrive"
    );
}

#[tokio::test]
async fn a_shared_part_failing_with_no_root_is_refetched_and_its_changed_cell_names_the_sender() {
    let out_dir = tempfile::tempdir().unwrap();
    // ADR-0117 §1: two workers share the one part, and peer B corrupts the
    // first block it is handed, once. The part fails its MD4 hash with no AICH
    // root to name the bad cell, so neither worker is retired and the part is
    // fetched again. The refetch verifies, and the cell whose bytes changed
    // was B's alone: B is retired, A never is, and the download completes. A
    // file of exactly one part size carries no link `p=` hash set, so a peer
    // supplies the file's own set, making the per-part verification reachable.
    let correct: Vec<u8> = (0..ED2K_PART_SIZE).map(|i| (i % 251) as u8).collect();
    let part_hashes = FileHashSummary::digest_bytes(&correct)
        .part_hash_set()
        .expect("a one-part-size file has a set")
        .hashes()
        .to_vec();
    let peer_a = loopback_peer(1);
    let peer_b = loopback_peer(2);
    let mut core = Core::builder(
        CoreConfig {
            peer_connections: rmule_core::PeerConnections {
                max_connections: 2,
                ..rmule_core::PeerConnections::default()
            },
            ..CoreConfig::default()
        },
        rmule_testkit::memory_store(),
    )
    .settings(rmule_testkit::in_download_dir(
        rmule_core::CoreSettings::default(),
        out_dir.path(),
    ))
    .source_lookup(StaticSourceLookup {
        outcome: SourceLookupOutcome {
            client_id: ClientId::from_u32(0x0100_007F),
            sources: plain_sources(vec![
                PeerSource::new(ClientId::from_u32(0x0100_007F), 4663),
                PeerSource::new(ClientId::from_u32(0x0200_007F), 4664),
            ]),
        },
    })
    .peer_transfer(CorruptOnceTransfer {
        corrupting_peer: peer_b,
        correct: correct.clone(),
        part_hashes,
    })
    .build();
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: file_link_without_part_hash_set("example.bin", &correct),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        name: rmule_testkit::file_name("corrupt-once.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
        kad_aich_root: None,
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

    let retired = |target: PeerEndpoint| {
        events.iter().any(|event| {
            matches!(
                event,
                CoreEvent::Download(DownloadEvent::PeerRetired {
                    peer: p,
                    reason: PeerRetirementReason::PartVerificationFailed,
                    ..
                }) if *p == target
            )
        })
    };
    assert!(
        events.iter().any(|event| matches!(
            event,
            CoreEvent::Download(DownloadEvent::PartCorrupt {
                part_index: 0,
                writers: 2,
                named: 0,
                ..
            })
        )),
        "the failure names neither sharer: {events:?}"
    );
    assert!(retired(peer_b), "the changed cell's sender is retired");
    assert!(!retired(peer_a), "the honest sharer keeps its slot");
    assert!(
        events.iter().any(|event| matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. })
        )),
        "the refetched part completes the download"
    );
}

struct ResumeAfterDropTransfer {
    dropping_peer: PeerEndpoint,
    drop_at: u64,
    bytes: Vec<u8>,
    first_handed: Arc<StdMutex<HashMap<PeerEndpoint, u64>>>,
}

impl PeerTransferService for ResumeAfterDropTransfer {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        let advertised = rmule_testkit::every_part(file.size);
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(8);
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let dropping_peer = self.dropping_peer;
        let drop_at = self.drop_at as usize;
        let bytes = self.bytes.clone();
        let first_handed = Arc::clone(&self.first_handed);
        tokio::spawn(async move {
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            let _ = event_tx.send(advertised).await;
            while let Some(command) = command_rx.recv().await {
                match command {
                    PeerWorkerCommand::AskSlot | PeerWorkerCommand::TakeGrant => {
                        let _ = event_tx.send(PeerWorkerEvent::SlotGranted).await;
                    }
                    PeerWorkerCommand::RequestHashSet => {}
                    PeerWorkerCommand::RequestBlocks { blocks, handout } => {
                        first_handed
                            .lock()
                            .unwrap()
                            .entry(peer)
                            .or_insert(blocks[0].start);
                        if peer == dropping_peer {
                            // Deliver [0, drop_at) then drop mid-block; the
                            // bytes core kept are what the next peer is spared.
                            let _ = event_tx
                                .send(PeerWorkerEvent::BlockReceived {
                                    part_index: 0,
                                    offset: 0,
                                    bytes: bytes[..drop_at].to_vec(),
                                })
                                .await;
                            let _ = event_tx.send(PeerWorkerEvent::Disconnected).await;
                            break;
                        }
                        let part = rmule_core::DownloadedPart {
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

/// Every worker serves the blocks it is handed from the file's true bytes;
/// `corrupting_peer` flips a byte of the first block it is handed, once.
struct CorruptOnceTransfer {
    corrupting_peer: PeerEndpoint,
    correct: Vec<u8>,
    part_hashes: Vec<PartHash>,
}

impl PeerTransferService for CorruptOnceTransfer {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        let advertised = rmule_testkit::every_part(file.size);
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(8);
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let mut corrupt_next = peer == self.corrupting_peer;
        let correct = self.correct.clone();
        let part_hashes = self.part_hashes.clone();
        tokio::spawn(async move {
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            let _ = event_tx.send(advertised).await;
            while let Some(command) = command_rx.recv().await {
                match command {
                    PeerWorkerCommand::AskSlot | PeerWorkerCommand::TakeGrant => {
                        let _ = event_tx.send(PeerWorkerEvent::SlotGranted).await;
                    }
                    // Every source holds the file, so any of them answers the
                    // download's one hash-set ask with its own set.
                    PeerWorkerCommand::RequestHashSet => {
                        let _ = event_tx
                            .send(PeerWorkerEvent::HashSetReceived {
                                part_hashes: part_hashes.clone(),
                            })
                            .await;
                    }
                    PeerWorkerCommand::RequestBlocks { blocks, handout } => {
                        let mut bytes = correct.clone();
                        if std::mem::take(&mut corrupt_next) {
                            bytes[blocks[0].start as usize] ^= 0xFF;
                        }
                        let part = rmule_core::DownloadedPart {
                            part_index: 0,
                            offset: 0,
                            bytes,
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
