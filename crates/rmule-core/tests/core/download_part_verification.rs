//! How a download decides a part is good: MD4 verification against the link's
//! **ED2K Part Hash Set**, the fallback when the link carries none (the first
//! peer's hash set is persisted as the provisional verification authority),
//! and the two ways a peer's claimed hashes are rejected — mismatching the
//! link, or mismatching an authority an earlier run already committed.

use rmule_core::DownloadRepository;
use std::sync::Arc;

use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadEvent, DownloadFailure,
    DownloadLifecycle, DownloadPaths, DownloadedPart, DurableDownloadRepository,
    PeerDownloadOutcome, PeerRetirementReason, PeerTransferService, PeerWorker, PeerWorkerCommand,
    PeerWorkerEvent, VerificationAuthority, open_durable_store,
};
use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{
    ED2K_PART_SIZE, Ed2kFileLink, Ed2kLink, Ed2kText, FileHashSummary, PartHash, PartHashSet,
    PeerEndpoint, ServerEndpoint,
};
use rmule_testkit::{
    StaticPeerTransfer, emit_blocks, file_link, file_link_without_part_hash_set, loopback_peer,
    next_event, run_download, source_with_high_id, two_high_id_sources,
};

/// A file below one part has no part hash set: its one part is the whole file,
/// so the file hash checks it on arrival (aMule `CPartFile::HashSinglePart`,
/// `src/PartFile.cpp:2338-2343`) — corrupt bytes retire their sole sender and
/// the part is fetched again, as a bad part of a larger file is, instead of
/// failing the whole download at finalize.
#[tokio::test]
async fn small_file_without_part_hash_set_rejects_corrupt_bytes_on_arrival() {
    let expected = b"hello world".to_vec();
    let corrupt = b"hello worle".to_vec();
    let events = run_download(
        file_link_without_part_hash_set("example.bin", &expected),
        source_with_high_id(),
        StaticPeerTransfer {
            expected_plan_count: 1,
            outcome: PeerDownloadOutcome {
                peer_hashes: Vec::new(),
                parts: vec![DownloadedPart {
                    part_index: 0,
                    offset: 0,
                    bytes: corrupt,
                }],
            },
        },
    )
    .await;

    assert!(events.iter().any(|event| matches!(
        event,
        CoreEvent::Download(DownloadEvent::PeerRetired {
            reason: PeerRetirementReason::PartVerificationFailed,
            ..
        })
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        CoreEvent::Download(DownloadEvent::PartCorrupt {
            part_index: 0,
            writers: 1,
            named: 1,
            ..
        })
    )));
    assert!(!events.iter().any(|event| matches!(
        event,
        CoreEvent::Download(
            DownloadEvent::DownloadCompleted { .. }
                | DownloadEvent::DownloadFailed {
                    reason: DownloadFailure::PartVerificationFailed,
                    ..
                }
        )
    )));
}

#[tokio::test]
async fn multipart_link_part_hash_set_verifies_each_part() {
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
                peer_hashes: hashes.clone(),
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

    assert!(events.iter().any(|event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::HashSetReceived {
                part_count: 2,
                authority: VerificationAuthority::LinkPartHashSet,
                ..
            })
        )
    }));
    assert!(events.iter().any(|event| matches!(
        event,
        CoreEvent::Download(DownloadEvent::PartVerified { part_index: 0, .. })
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        CoreEvent::Download(DownloadEvent::PartVerified { part_index: 1, .. })
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        CoreEvent::Download(DownloadEvent::DownloadCompleted { .. })
    )));
}

/// A link whose `p=` set is not the file hash's own is dropped, parsed or
/// not, so an honest peer's set — proven against the file hash — verifies the
/// parts and the download completes (aMule `src/PartFile.cpp:248-251`).
#[tokio::test]
async fn a_link_hash_set_that_is_not_the_files_own_is_dropped_and_the_peers_set_wins() {
    let mut bytes = vec![0xAB; ED2K_PART_SIZE as usize];
    bytes.push(0xCD);
    let mut link = file_link("example.bin", &bytes);
    let honest = link.part_hash_set.as_ref().unwrap().hashes().to_vec();
    let mut wrong = honest.clone();
    wrong[0] = PartHash::from_bytes([0x55; PartHash::BYTE_LEN]);
    link.part_hash_set = Some(PartHashSet::from_hashes(link.size, wrong).unwrap());
    let Ok(Ed2kLink::File(parsed)) = Ed2kLink::parse(&Ed2kLink::File(link.clone()).to_string())
    else {
        panic!("a link with a wrong set still parses");
    };
    assert_eq!(parsed.part_hash_set, None);

    let events = run_download(
        link,
        source_with_high_id(),
        StaticPeerTransfer {
            expected_plan_count: 2,
            outcome: PeerDownloadOutcome {
                peer_hashes: honest,
                parts: vec![
                    DownloadedPart {
                        part_index: 0,
                        offset: 0,
                        bytes: bytes[..ED2K_PART_SIZE as usize].to_vec(),
                    },
                    DownloadedPart {
                        part_index: 1,
                        offset: ED2K_PART_SIZE,
                        bytes: bytes[ED2K_PART_SIZE as usize..].to_vec(),
                    },
                ],
            },
        },
    )
    .await;

    assert!(events.iter().any(|event| matches!(
        event,
        CoreEvent::Download(DownloadEvent::HashSetReceived {
            authority: VerificationAuthority::PeerHashSet,
            ..
        })
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        CoreEvent::Download(DownloadEvent::DownloadCompleted { .. })
    )));
}

#[tokio::test]
/// A peer's set that disagrees with the link's is not the file's own — the
/// link's set is — so it is refused and its sender retired, and the download
/// lives on: a peer cannot fail it with a forged set.
async fn a_peer_hash_set_contradicting_the_link_is_refused_not_a_download_failure() {
    let bytes = vec![0xAB; ED2K_PART_SIZE as usize];
    let link = file_link("example.bin", &bytes);
    let mut peer_hashes = link.part_hash_set.as_ref().unwrap().hashes().to_vec();
    peer_hashes[0] = PartHash::from_bytes([0x55; PartHash::BYTE_LEN]);

    let events = run_download(
        link,
        source_with_high_id(),
        StaticPeerTransfer {
            expected_plan_count: 1,
            outcome: PeerDownloadOutcome {
                peer_hashes,
                parts: Vec::new(),
            },
        },
    )
    .await;

    assert!(events.iter().any(|event| matches!(
        event,
        CoreEvent::Download(DownloadEvent::PeerRetired {
            reason: PeerRetirementReason::VerificationAuthorityMismatch,
            ..
        })
    )));
    assert!(!events.iter().any(|event| matches!(
        event,
        CoreEvent::Download(DownloadEvent::DownloadFailed {
            reason: DownloadFailure::HashSetMismatch,
            ..
        })
    )));
}

#[tokio::test]
async fn first_peer_hash_set_without_link_parts_is_persisted_as_provisional_authority() {
    let mut bytes = vec![0xAB; ED2K_PART_SIZE as usize];
    bytes.push(0xCD);
    let summary = FileHashSummary::digest_bytes(&bytes);
    let link_without_parts = Ed2kFileLink {
        name: Ed2kText::from_utf8("example.bin"),
        size: summary.file_size(),
        file_hash: summary.file_hash(),
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    };
    let hashes = summary.part_hash_set().unwrap().hashes().to_vec();
    let first = bytes[..ED2K_PART_SIZE as usize].to_vec();
    let second = bytes[ED2K_PART_SIZE as usize..].to_vec();
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let mut core = Core::builder(CoreConfig::default(), Arc::clone(&store))
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            dir.path(),
        ))
        .source_lookup(source_with_high_id())
        .peer_transfer(StaticPeerTransfer {
            expected_plan_count: 2,
            outcome: PeerDownloadOutcome {
                peer_hashes: hashes.clone(),
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
        })
        .build();

    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: link_without_parts,
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        name: rmule_testkit::file_name("download.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
        kad_aich_root: None,
    }))
    .await
    .unwrap();

    let mut download_id = None;
    loop {
        let event = next_event(&mut core).await;
        match event {
            CoreEvent::Download(DownloadEvent::DownloadQueued {
                download_id: id, ..
            }) => download_id = Some(id),
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => break,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed: {reason:?}")
            }
            _ => {}
        }
    }

    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    let download_id = download_id.unwrap();
    assert_eq!(repo.provisional_part_hashes(download_id).unwrap(), hashes);
    assert_eq!(
        repo.load_download(download_id)
            .unwrap()
            .verification_authority(),
        Some(VerificationAuthority::PeerHashSet)
    );
}

#[tokio::test]
async fn resumed_download_retires_peer_that_mismatches_persisted_provisional_authority() {
    let bytes = vec![0xAB; ED2K_PART_SIZE as usize];
    let summary = FileHashSummary::digest_bytes(&bytes);
    let link_without_parts = Ed2kFileLink {
        name: Ed2kText::from_utf8("example.bin"),
        size: summary.file_size(),
        file_hash: summary.file_hash(),
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    };
    let hashes = summary.part_hash_set().unwrap().hashes().to_vec();
    let mut mismatched = hashes.clone();
    mismatched[0] = PartHash::from_bytes([0x55; 16]);
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    let record = repo
        .create_download(
            &link_without_parts,
            Some(&ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
            &DownloadPaths::from_final_path(dir.path().join("download.bin")),
            None,
        )
        .unwrap();
    repo.record_provisional_part_hashes(record.id(), &hashes)
        .unwrap();
    repo.set_lifecycle(record.id(), DownloadLifecycle::Paused)
        .unwrap();

    let mut core = Core::builder(CoreConfig::default(), Arc::clone(&store))
        .settings(rmule_core::CoreSettings::default())
        .source_lookup(two_high_id_sources())
        .peer_transfer(MismatchedThenSuccess {
            mismatched_peer: loopback_peer(1),
            mismatched_hashes: mismatched,
            correct_hashes: hashes,
            bytes,
        })
        .build();
    core.send(CoreCommand::Download(DownloadCommand::ResumeDownload {
        download_id: record.id(),
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
            CoreEvent::Download(DownloadEvent::PeerRetired {
                peer: retired,
                reason: PeerRetirementReason::VerificationAuthorityMismatch,
                ..
            }) if *retired == loopback_peer(1)
        )
    }));
    assert!(events.iter().any(|event| matches!(
        event,
        CoreEvent::Download(DownloadEvent::DownloadCompleted { .. })
    )));
}

struct MismatchedThenSuccess {
    mismatched_peer: PeerEndpoint,
    mismatched_hashes: Vec<PartHash>,
    correct_hashes: Vec<PartHash>,
    bytes: Vec<u8>,
}

impl PeerTransferService for MismatchedThenSuccess {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        let advertised = rmule_testkit::every_part(file.size);
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(8);
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let mismatched_peer = self.mismatched_peer;
        let mismatched_hashes = self.mismatched_hashes.clone();
        let correct_hashes = self.correct_hashes.clone();
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
                    PeerWorkerCommand::RequestBlocks { .. } if peer == mismatched_peer => {
                        let _ = event_tx
                            .send(PeerWorkerEvent::HashSetReceived {
                                part_hashes: mismatched_hashes.clone(),
                            })
                            .await;
                        break;
                    }
                    PeerWorkerCommand::RequestBlocks { blocks, handout } => {
                        let _ = event_tx
                            .send(PeerWorkerEvent::HashSetReceived {
                                part_hashes: correct_hashes.clone(),
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
