//! ADR-0029 block assembly across peers: a peer that drops mid-part leaves a
//! prefix the next peer resumes from instead of restarting at zero, and a part
//! assembled from several contributors that fails its MD4 hash retires every
//! contributor and refetches the part from a cleared buffer.

use crate::fixture::identity;
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
    StaticSourceLookup, file_link_without_part_hash_set, loopback_peer, next_event, plain_sources,
    two_high_id_sources,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};

#[tokio::test]
async fn core_resumes_a_part_from_another_peer_after_a_mid_part_drop() {
    // ADR-0029: peer A delivers [0, k) of the only part then drops; core
    // preserves the shared prefix and hands peer B a resume offset of k, so B
    // finishes [k, len) instead of restarting at block 0. peer_concurrency = 1
    // makes the drop-then-backfill-then-resume sequence deterministic.
    let bytes: Vec<u8> = (0..100u32).map(|i| (i % 251) as u8).collect();
    let drop_at = 40u64;
    let dropping_peer = loopback_peer(1);
    let resuming_peer = loopback_peer(2);
    let resume_offsets = Arc::new(StdMutex::new(HashMap::new()));

    let mut core = Core::builder(
        CoreConfig {
            peer_concurrency_per_download: 1,
            ..CoreConfig::default()
        },
        rmule_testkit::memory_store(),
    )
    .source_lookup(two_high_id_sources())
    .peer_transfer(ResumeAfterDropTransfer {
        dropping_peer,
        drop_at,
        bytes: bytes.clone(),
        resume_offsets: Arc::clone(&resume_offsets),
    })
    .build();
    let out_dir = tempfile::tempdir().unwrap();
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: file_link_without_part_hash_set("example.bin", &bytes),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        credentials: identity().into(),
        output_path: out_dir.path().join("resume-after-drop.bin"),
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

    let offsets = resume_offsets.lock().unwrap();
    assert_eq!(
        offsets.get(&dropping_peer),
        Some(&0),
        "the first peer starts the part at offset 0"
    );
    assert_eq!(
        offsets.get(&resuming_peer),
        Some(&drop_at),
        "the second peer resumes at the dropped prefix end, not from 0"
    );
}

#[tokio::test]
async fn core_retires_all_contributors_when_assembled_part_fails_verification() {
    // ADR-0029: when a part assembled from blocks contributed by several peers
    // fails its MD4 part hash, core cannot attribute the bad block (no AICH),
    // so it retires every contributor and refetches the part from offset 0.
    // peer A contributes [0, k) correctly and B contributes [k, len) corrupted;
    // both must be retired as PartVerificationFailed, the buffer cleared, and a
    // surviving peer C must finish the part from a fresh prefix (offset 0).
    // A file of exactly one part size — one data part, so two peers race it,
    // and a two-hash set (the part plus aMule's trailing empty hash) — carries
    // no link `p=` hash set, so a peer supplies the file's own set, making the
    // per-part (PeerHashSet) verification — and thus retire-all — reachable. A
    // file below one part carries no set at all (aMule `KnownFile.cpp:425-427`),
    // and a set that is not the file's own is refused.
    let correct: Vec<u8> = (0..ED2K_PART_SIZE).map(|i| (i % 251) as u8).collect();
    let part_hashes = FileHashSummary::digest_bytes(&correct)
        .part_hash_set()
        .expect("a one-part-size file has a set")
        .hashes()
        .to_vec();
    let drop_at = 30usize;
    let mut corrupt_tail = correct[drop_at..].to_vec();
    corrupt_tail[0] ^= 0xFF; // poison the assembled part so its hash mismatches

    let peer_a = loopback_peer(1);
    let peer_b = loopback_peer(2);
    let peer_c = loopback_peer(3);
    let a_done = Arc::new(tokio::sync::Notify::new());
    let resume_offsets = Arc::new(StdMutex::new(HashMap::new()));

    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .source_lookup(StaticSourceLookup {
            outcome: SourceLookupOutcome {
                client_id: ClientId::from_u32(0x0100_007F),
                sources: plain_sources(vec![
                    PeerSource::new(ClientId::from_u32(0x0100_007F), 4663),
                    PeerSource::new(ClientId::from_u32(0x0200_007F), 4664),
                    PeerSource::new(ClientId::from_u32(0x0300_007F), 4665),
                ]),
            },
        })
        .peer_transfer(CrossPeerVerifyFailTransfer {
            partial_peer: peer_a,
            corrupting_peer: peer_b,
            drop_at,
            correct: correct.clone(),
            corrupt_tail,
            part_hashes,
            a_done: Arc::clone(&a_done),
            resume_offsets: Arc::clone(&resume_offsets),
        })
        .build();
    let out_dir = tempfile::tempdir().unwrap();
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: file_link_without_part_hash_set("example.bin", &correct),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        credentials: identity().into(),
        output_path: out_dir.path().join("retire-all-contributors.bin"),
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
    assert!(retired(peer_a), "the first contributor must be retired");
    assert!(retired(peer_b), "the second contributor must be retired");
    assert!(
        events.iter().any(|event| matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. })
        )),
        "a surviving peer must finish the part after the contributors are retired"
    );
    assert_eq!(
        resume_offsets.lock().unwrap().get(&peer_c),
        Some(&0),
        "the surviving peer must refetch from offset 0 (buffer cleared), got {:?}",
        resume_offsets.lock().unwrap().get(&peer_c),
    );
}

struct ResumeAfterDropTransfer {
    dropping_peer: PeerEndpoint,
    drop_at: u64,
    bytes: Vec<u8>,
    resume_offsets: Arc<StdMutex<HashMap<PeerEndpoint, u64>>>,
}

impl PeerTransferService for ResumeAfterDropTransfer {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        _file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(8);
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let dropping_peer = self.dropping_peer;
        let drop_at = self.drop_at as usize;
        let bytes = self.bytes.clone();
        let resume_offsets = Arc::clone(&self.resume_offsets);
        tokio::spawn(async move {
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            while let Some(command) = command_rx.recv().await {
                match command {
                    PeerWorkerCommand::RequestPart {
                        plan,
                        resume_offset,
                    } => {
                        resume_offsets.lock().unwrap().insert(peer, resume_offset);
                        let start = resume_offset as usize;
                        if peer == dropping_peer {
                            // Deliver [start, drop_at) then drop mid-part; the
                            // prefix core kept is what the next peer resumes at.
                            let _ = event_tx
                                .send(PeerWorkerEvent::BlockReceived {
                                    part_index: plan.part_index,
                                    offset: resume_offset,
                                    bytes: bytes[start..drop_at].to_vec(),
                                })
                                .await;
                            let _ = event_tx.send(PeerWorkerEvent::Disconnected).await;
                            break;
                        }
                        // Resume from the offset core handed us through to the end.
                        let _ = event_tx
                            .send(PeerWorkerEvent::BlockReceived {
                                part_index: plan.part_index,
                                offset: resume_offset,
                                bytes: bytes[start..].to_vec(),
                            })
                            .await;
                        let _ = event_tx
                            .send(PeerWorkerEvent::PartStreamed {
                                part_index: plan.part_index,
                            })
                            .await;
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

struct CrossPeerVerifyFailTransfer {
    partial_peer: PeerEndpoint,
    corrupting_peer: PeerEndpoint,
    drop_at: usize,
    correct: Vec<u8>,
    corrupt_tail: Vec<u8>,
    part_hashes: Vec<PartHash>,
    a_done: Arc<tokio::sync::Notify>,
    resume_offsets: Arc<StdMutex<HashMap<PeerEndpoint, u64>>>,
}

impl PeerTransferService for CrossPeerVerifyFailTransfer {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        _file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(8);
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let partial_peer = self.partial_peer;
        let corrupting_peer = self.corrupting_peer;
        let drop_at = self.drop_at;
        let correct = self.correct.clone();
        let corrupt_tail = self.corrupt_tail.clone();
        let part_hashes = self.part_hashes.clone();
        let a_done = Arc::clone(&self.a_done);
        let resume_offsets = Arc::clone(&self.resume_offsets);
        tokio::spawn(async move {
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            while let Some(command) = command_rx.recv().await {
                match command {
                    PeerWorkerCommand::RequestPart {
                        plan,
                        resume_offset,
                    } => {
                        resume_offsets.lock().unwrap().insert(peer, resume_offset);
                        if peer == partial_peer {
                            // Establish the single part's hash as the
                            // PeerHashSet authority, contribute the correct
                            // first half, then stay connected (no completion
                            // claim, no drop).
                            let _ = event_tx
                                .send(PeerWorkerEvent::HashSetReceived {
                                    part_hashes: part_hashes.clone(),
                                })
                                .await;
                            let _ = event_tx
                                .send(PeerWorkerEvent::BlockReceived {
                                    part_index: plan.part_index,
                                    offset: 0,
                                    bytes: correct[..drop_at].to_vec(),
                                })
                                .await;
                            a_done.notify_one();
                        } else if peer == corrupting_peer {
                            // Finish the part with a corrupted tail once the
                            // prefix is in, so the assembled hash mismatches.
                            a_done.notified().await;
                            let _ = event_tx
                                .send(PeerWorkerEvent::BlockReceived {
                                    part_index: plan.part_index,
                                    offset: drop_at as u64,
                                    bytes: corrupt_tail.clone(),
                                })
                                .await;
                        } else {
                            // Survivor: serve the correct bytes from the offset
                            // core hands it (a fresh prefix after retire-all).
                            let start = (resume_offset as usize).min(correct.len());
                            let _ = event_tx
                                .send(PeerWorkerEvent::BlockReceived {
                                    part_index: plan.part_index,
                                    offset: resume_offset,
                                    bytes: correct[start..].to_vec(),
                                })
                                .await;
                            let _ = event_tx
                                .send(PeerWorkerEvent::PartStreamed {
                                    part_index: plan.part_index,
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
