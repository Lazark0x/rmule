//! The core's orchestration read through scripted adapters: the happy-path
//! event trail, a streamed part verified before its worker finishes, a
//! crypt-capable source dialed obfuscated, and the peer hello dropping the
//! tags that belong only to a server login.
use std::sync::{Arc, Mutex};

use crate::fixture::identity;
use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadEvent, DownloadFailure,
    DownloadedPart, PeerDownloadOutcome, PeerTransferService, PeerWorker, PeerWorkerCommand,
    PeerWorkerEvent, SourceLookupOutcome, SourceLookupService,
};
use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{
    ClientId, ClientIdentity, ED2K_PART_SIZE, Ed2kFileLink, ExchangedSource, PeerCrypt,
    PeerEndpoint, PeerSource, ServerEndpoint, SourceCryptOptions, SourceLookupTarget, Tag, TagName,
    TagValue, UserHash,
};
use rmule_testkit::file_link;
use rmule_testkit::file_link_without_part_hash_set;
use tokio::time::{Duration, timeout};

/// Stream a part's bytes from `resume_offset` to the end as one block, then
/// report the assigned range delivered (ADR-0029 worker protocol). A fresh
/// assignment has `resume_offset == part.offset` and serves the whole part.
async fn emit_streamed_part(
    event_tx: &tokio::sync::mpsc::Sender<PeerWorkerEvent>,
    part: &DownloadedPart,
    resume_offset: u64,
) {
    let start = (resume_offset.saturating_sub(part.offset) as usize).min(part.bytes.len());
    let _ = event_tx
        .send(PeerWorkerEvent::BlockReceived {
            part_index: part.part_index,
            offset: resume_offset,
            bytes: part.bytes[start..].to_vec(),
        })
        .await;
    let _ = event_tx
        .send(PeerWorkerEvent::PartStreamed {
            part_index: part.part_index,
        })
        .await;
}

#[tokio::test]
async fn fake_adapters_drive_happy_path_download_events() {
    let bytes = b"hello world".to_vec();
    let client_id = ClientId::from_u32(0x0100_007F);
    let low = PeerSource::new(ClientId::from_u32(42), 4662);
    let high = PeerSource::new(ClientId::from_u32(0x0100_007F), 4663);
    let peer = high.as_peer_endpoint().unwrap();
    let source = ScriptedSourceLookup {
        outcome: SourceLookupOutcome {
            client_id,
            sources: vec![ExchangedSource::plain(low), ExchangedSource::plain(high)],
        },
    };
    let transfer = ScriptedPeerTransfer {
        expected_peer: peer,
        outcome: PeerDownloadOutcome {
            peer_hashes: Vec::new(),
            parts: vec![DownloadedPart {
                part_index: 0,
                offset: 0,
                bytes: bytes.clone(),
            }],
        },
    };
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .source_lookup(source)
        .peer_transfer(transfer)
        .build();

    let out_dir = tempfile::tempdir().unwrap();
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: file_link_without_part_hash_set("example.bin", &bytes),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        credentials: identity().into(),
        output_path: out_dir.path().join("fake-orchestration.bin"),
    }))
    .await
    .unwrap();

    let mut events = Vec::new();
    loop {
        let event = timeout(Duration::from_secs(2), core.next_event())
            .await
            .expect("core emitted next event")
            .expect("core event stream stayed open");
        let completed = matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. })
        );
        events.push(event);
        if completed {
            break;
        }
    }

    assert!(events.iter().any(|event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::SourcesFound {
                total: 2,
                usable_high_id: 1,
                ..
            })
        )
    }));
    assert!(events.iter().any(
        |event| matches!(event, CoreEvent::Download(DownloadEvent::PeerSelected { peer: selected, .. }) if *selected == peer)
    ));
    assert!(events.iter().any(|event| matches!(
        event,
        CoreEvent::Download(DownloadEvent::PartVerified { part_index: 0, .. })
    )));
}

#[tokio::test]
async fn streamed_worker_fact_verifies_first_part_before_worker_finishes() {
    let mut bytes = vec![0xAB; ED2K_PART_SIZE as usize];
    bytes.push(0xCD);
    let link = file_link("example.bin", &bytes);
    let first_part = bytes[..ED2K_PART_SIZE as usize].to_vec();
    let high = PeerSource::new(ClientId::from_u32(0x0100_007F), 4663);
    let source = ScriptedSourceLookup {
        outcome: SourceLookupOutcome {
            client_id: ClientId::from_u32(0x0100_007F),
            sources: vec![ExchangedSource::plain(high)],
        },
    };
    let transfer = FirstPartThenBlocked {
        part_hashes: link.part_hash_set.as_ref().unwrap().hashes().to_vec(),
        first_part,
    };
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .source_lookup(source)
        .peer_transfer(transfer)
        .build();

    let out_dir = tempfile::tempdir().unwrap();
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: link,
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        credentials: identity().into(),
        output_path: out_dir.path().join("fake-orchestration-streamed.bin"),
    }))
    .await
    .unwrap();

    loop {
        let event = timeout(Duration::from_secs(2), core.next_event())
            .await
            .expect("core emitted streamed event")
            .expect("core event stream stayed open");
        if matches!(
            event,
            CoreEvent::Download(DownloadEvent::PartVerified { part_index: 0, .. })
        ) {
            break;
        }
        if matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. })
        ) {
            panic!("download completed before the streamed first part assertion");
        }
    }

    loop {
        match timeout(Duration::from_millis(50), core.next_event()).await {
            Err(_) => break,
            Ok(Some(CoreEvent::Download(
                DownloadEvent::DownloadCompleted { .. } | DownloadEvent::DownloadFailed { .. },
            ))) => {
                panic!("worker should still be blocked after the first streamed part")
            }
            Ok(Some(_)) => {}
            Ok(None) => panic!("core event stream stayed open"),
        }
    }

    let snapshot = core.diagnostics_snapshot();
    let (download_id, dd) = snapshot
        .downloads
        .iter()
        .next()
        .expect("active download must appear in diagnostics snapshot");
    let worker = dd
        .workers
        .values()
        .next()
        .expect("active worker must appear in diagnostics snapshot");
    use rmule_core::diagnostics::WorkerPhase;
    assert!(
        matches!(
            worker.phase(),
            WorkerPhase::RequestingPart { part_index: 1 }
        ),
        "after part 0 verifies and part 1 stays blocked, worker should be RequestingPart {{ part_index: 1 }} but was {:?}",
        worker.phase(),
    );
    assert!(
        worker.transition_count() >= 2,
        "expected at least two transitions (Connecting -> RequestingPart{{0}} -> ... -> RequestingPart{{1}}) but saw {}",
        worker.transition_count(),
    );
    assert_eq!(dd.verified_parts(), 1);
    assert_eq!(dd.in_flight_parts(), 1);
    // The part map says *which* part is which (ADR-0079): the two-part file's
    // part 0 verified and part 1 is the one the blocked worker holds. A
    // count-only surface could not tell this state from its mirror image.
    use rmule_core::diagnostics::PartState;
    assert_eq!(
        dd.parts,
        vec![PartState::Verified, PartState::InFlight],
        "the positional map must place the verified part at index 0",
    );
    // Download byte accounting (ADR-0077): the worker delivered exactly part
    // 0 and then blocked, so both the per-download row and the session total
    // stand at one part — counted off the delivered blocks, not derived from
    // the verified-part count.
    assert_eq!(dd.received_bytes, ED2K_PART_SIZE);
    assert_eq!(snapshot.session.down_bytes_total, ED2K_PART_SIZE);
    assert_eq!(
        snapshot.session.up_bytes_total, 0,
        "a download-only core serves nothing",
    );
    let _ = download_id;

    core.send(CoreCommand::DumpDiagnostics).await.unwrap();
    let echoed = loop {
        let event = timeout(Duration::from_millis(500), core.next_event())
            .await
            .expect("core emitted next event after DumpDiagnostics")
            .expect("core event stream stayed open");
        if let CoreEvent::DiagnosticsSnapshot { snapshot } = event {
            break snapshot;
        }
    };
    assert_eq!(
        echoed.downloads.len(),
        1,
        "DumpDiagnostics echo must include the active download",
    );
    let echoed_download = echoed.downloads.values().next().unwrap();
    // The actor's echo and the sync accessor read one shared counter state, so
    // the byte facts agree (only `kad` is actor-only, ADR-0077).
    assert_eq!(echoed_download.received_bytes, ED2K_PART_SIZE);
    assert_eq!(echoed.session.down_bytes_total, ED2K_PART_SIZE);
    let echoed_worker = echoed_download.workers.values().next().unwrap();
    assert!(matches!(
        echoed_worker.phase(),
        WorkerPhase::RequestingPart { part_index: 1 }
    ));
}

#[derive(Clone)]
struct ScriptedSourceLookup {
    outcome: SourceLookupOutcome,
}

impl SourceLookupService for ScriptedSourceLookup {
    async fn lookup_sources(
        &mut self,
        _target: SourceLookupTarget,
    ) -> Result<SourceLookupOutcome, DownloadFailure> {
        Ok(self.outcome.clone())
    }
}

struct ScriptedPeerTransfer {
    expected_peer: PeerEndpoint,
    outcome: PeerDownloadOutcome,
}

impl PeerTransferService for ScriptedPeerTransfer {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        _file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        assert_eq!(peer, self.expected_peer);
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(8);
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let outcome = self.outcome.clone();
        tokio::spawn(async move {
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            let mut hashes_sent = false;
            while let Some(command) = command_rx.recv().await {
                match command {
                    PeerWorkerCommand::RequestPart {
                        plan,
                        resume_offset,
                    } => {
                        if !hashes_sent && !outcome.peer_hashes.is_empty() {
                            hashes_sent = true;
                            let _ = event_tx
                                .send(PeerWorkerEvent::HashSetReceived {
                                    part_hashes: outcome.peer_hashes.clone(),
                                })
                                .await;
                        }
                        if let Some(part) = outcome
                            .parts
                            .iter()
                            .find(|part| part.part_index == plan.part_index)
                        {
                            emit_streamed_part(&event_tx, part, resume_offset).await;
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

struct FirstPartThenBlocked {
    part_hashes: Vec<rmule_primitives::PartHash>,
    first_part: Vec<u8>,
}

impl PeerTransferService for FirstPartThenBlocked {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        _file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(8);
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let part_hashes = self.part_hashes.clone();
        let first_part = self.first_part.clone();
        tokio::spawn(async move {
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            while let Some(command) = command_rx.recv().await {
                match command {
                    PeerWorkerCommand::RequestPart {
                        plan,
                        resume_offset,
                    } if plan.part_index == 0 => {
                        let _ = event_tx
                            .send(PeerWorkerEvent::HashSetReceived {
                                part_hashes: part_hashes.clone(),
                            })
                            .await;
                        emit_streamed_part(
                            &event_tx,
                            &DownloadedPart {
                                part_index: 0,
                                offset: 0,
                                bytes: first_part.clone(),
                            },
                            resume_offset,
                        )
                        .await;
                    }
                    PeerWorkerCommand::RequestPart { .. } => std::future::pending::<()>().await,
                    PeerWorkerCommand::RequestAich { .. } => {}
                    PeerWorkerCommand::RequestAichFileHash => {}
                    PeerWorkerCommand::Shutdown { .. } => break,
                }
            }
        });
        Ok(PeerWorker::new(peer, command_tx, event_rx))
    }
}

struct CaptureCtxIdentity {
    captured: Arc<Mutex<Option<ClientIdentity>>>,
    part: DownloadedPart,
}

impl PeerTransferService for CaptureCtxIdentity {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        ctx: PeerHandshakeContext,
        _file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        *self.captured.lock().unwrap() = Some(ctx.identity.clone());
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(8);
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let part = self.part.clone();
        tokio::spawn(async move {
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            while let Some(command) = command_rx.recv().await {
                match command {
                    PeerWorkerCommand::RequestPart {
                        plan,
                        resume_offset,
                    } if plan.part_index == part.part_index => {
                        emit_streamed_part(&event_tx, &part, resume_offset).await;
                    }
                    PeerWorkerCommand::RequestPart { .. } => {}
                    PeerWorkerCommand::RequestAich { .. } => {}
                    PeerWorkerCommand::RequestAichFileHash => {}
                    PeerWorkerCommand::Shutdown { .. } => break,
                }
            }
        });
        Ok(PeerWorker::new(peer, command_tx, event_rx))
    }
}

/// Spawn a worker that connects, streams `part` on request, and stops — the
/// minimal delivery a one-part download needs to complete.
fn spawn_delivering_worker(peer: PeerEndpoint, part: DownloadedPart) -> PeerWorker {
    let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(8);
    let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
    tokio::spawn(async move {
        let _ = event_tx.send(PeerWorkerEvent::Connected).await;
        while let Some(command) = command_rx.recv().await {
            match command {
                PeerWorkerCommand::RequestPart {
                    plan,
                    resume_offset,
                } if plan.part_index == part.part_index => {
                    emit_streamed_part(&event_tx, &part, resume_offset).await;
                }
                PeerWorkerCommand::RequestPart { .. } => {}
                PeerWorkerCommand::RequestAich { .. } => {}
                PeerWorkerCommand::RequestAichFileHash => {}
                PeerWorkerCommand::Shutdown { .. } => break,
            }
        }
    });
    PeerWorker::new(peer, command_tx, event_rx)
}

/// Records the peer crypt side the runner dials each peer with. The inner
/// `Option` is the brief's `peer_crypt`; the outer distinguishes "briefed dial
/// path taken" (`Some`) from "fell through to the unbriefed base" (recorded
/// `None`).
struct CapturePeerCrypt {
    captured: Arc<Mutex<Option<Option<PeerCrypt>>>>,
    part: DownloadedPart,
}

impl PeerTransferService for CapturePeerCrypt {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        _file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        // The runner always dials through `start_download_worker`; reaching
        // the plaintext base means the target was dropped en route.
        *self.captured.lock().unwrap() = Some(None);
        Ok(spawn_delivering_worker(peer, self.part.clone()))
    }

    async fn start_download_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        _file: Ed2kFileLink,
        brief: rmule_core::WorkerBrief,
    ) -> Result<PeerWorker, DownloadFailure> {
        *self.captured.lock().unwrap() = Some(Some(brief.peer_crypt));
        Ok(spawn_delivering_worker(peer, self.part.clone()))
    }
}

#[tokio::test]
async fn server_lookup_crypt_capable_source_is_obfuscate_dialed() {
    // ADR-0046: a server-lookup source that the obfuscation-aware `0x44`
    // reply gave a User Hash *and* crypt support is dialed with that hash as the
    // peer obfuscation key — amending ADR-0042's rule that server-lookup sources
    // (IP + port only) can never be obfuscate-dialed.
    let bytes = b"obfu-dialed payload".to_vec();
    let client_id = ClientId::from_u32(0x0100_007F);
    let dial_hash = UserHash::from_bytes([0x5A; UserHash::BYTE_LEN]);
    let crypt_capable = ExchangedSource::new(
        PeerSource::new(client_id, 4663),
        Some(dial_hash),
        Some(SourceCryptOptions::from_byte(0x01)),
    );
    let source = ScriptedSourceLookup {
        outcome: SourceLookupOutcome {
            client_id,
            sources: vec![crypt_capable],
        },
    };
    let captured = Arc::new(Mutex::new(None));
    let transfer = CapturePeerCrypt {
        captured: captured.clone(),
        part: DownloadedPart {
            part_index: 0,
            offset: 0,
            bytes: bytes.clone(),
        },
    };

    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .source_lookup(source)
        .peer_transfer(transfer)
        .build();
    let out_dir = tempfile::tempdir().unwrap();
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: file_link_without_part_hash_set("example.bin", &bytes),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        credentials: identity().into(),
        output_path: out_dir.path().join("obfu-dial.bin"),
    }))
    .await
    .unwrap();

    loop {
        let event = timeout(Duration::from_secs(2), core.next_event())
            .await
            .expect("core emitted next event")
            .expect("core event stream stayed open");
        match event {
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => break,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed: {reason:?}")
            }
            _ => {}
        }
    }

    assert_eq!(
        *captured.lock().unwrap(),
        Some(Some(PeerCrypt::from_record(
            Some(SourceCryptOptions::from_byte(0x01)),
            Some(dial_hash)
        ))),
        "a crypt-capable server-lookup source's stance and hash must reach the dial",
    );
}

#[tokio::test]
async fn peer_hello_identity_drops_server_login_capability_tags() {
    // The download identity carries the server-login capability tags
    // (CT_SERVER_FLAGS) the CLI now advertises so production servers
    // accept the login. Those tags are server-only and must not leak
    // into the peer hello (ADR-0047), so core builds a minimal
    // peer-hello identity for the PeerHandshakeContext.
    let bytes = b"hello world".to_vec();
    let client_id = ClientId::from_u32(0x0100_007F);
    let high = PeerSource::new(client_id, 4663);
    let source = ScriptedSourceLookup {
        outcome: SourceLookupOutcome {
            client_id,
            sources: vec![ExchangedSource::plain(high)],
        },
    };
    let captured = Arc::new(Mutex::new(None));
    let transfer = CaptureCtxIdentity {
        captured: captured.clone(),
        part: DownloadedPart {
            part_index: 0,
            offset: 0,
            bytes: bytes.clone(),
        },
    };
    let server_identity = identity().with_extra_tags(vec![Tag::new(
        TagName::length_prefixed_id(0x20),
        TagValue::U32(0x119),
    )]);

    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .source_lookup(source)
        .peer_transfer(transfer)
        .build();
    let out_dir = tempfile::tempdir().unwrap();
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: file_link_without_part_hash_set("example.bin", &bytes),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        credentials: server_identity.into(),
        output_path: out_dir.path().join("peer-hello-identity.bin"),
    }))
    .await
    .unwrap();

    loop {
        let event = timeout(Duration::from_secs(2), core.next_event())
            .await
            .expect("core emitted next event")
            .expect("core event stream stayed open");
        match event {
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => break,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed: {reason:?}")
            }
            _ => {}
        }
    }

    let ctx_identity = captured
        .lock()
        .unwrap()
        .clone()
        .expect("peer worker was started");
    assert!(
        ctx_identity.extra_tags().is_empty(),
        "peer hello identity must not carry server-login capability tags, got {:?}",
        ctx_identity.extra_tags()
    );
}
