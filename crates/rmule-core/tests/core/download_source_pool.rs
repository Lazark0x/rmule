//! The candidate pool behind a download: the source snapshot is looked up once
//! and never re-asked, unused High-ID candidates backfill workers the initial
//! batch lost instead of aborting the download (ADR-0030), and a snapshot
//! holding no usable High-ID source fails before any peer transfer starts.

use rmule_core::{
    CoreConfig, CoreEvent, DownloadEvent, DownloadFailure, DownloadedPart, PeerDownloadOutcome,
    PeerTransferService, PeerWorker, PeerWorkerCommand, PeerWorkerEvent, SourceLookupOutcome,
    SourceLookupService,
};
use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{
    ClientId, ED2K_PART_SIZE, Ed2kFileLink, PeerEndpoint, PeerSource, SourceLookupTarget,
};
use rmule_testkit::{
    StaticPeerTransfer, StaticSourceLookup, emit_blocks, file_link,
    file_link_without_part_hash_set, plain_sources, run_download, run_download_with,
    two_high_id_sources,
};
use std::collections::HashSet;
use std::sync::{Arc, Mutex as StdMutex};

#[tokio::test]
async fn source_exhaustion_fails_without_second_source_lookup() {
    let bytes = vec![0xAB; ED2K_PART_SIZE as usize];
    let lookup_count = Arc::new(StdMutex::new(0));

    let events = run_download(
        file_link("example.bin", &bytes),
        CountingSourceLookup {
            calls: Arc::clone(&lookup_count),
            outcome: two_high_id_sources().outcome,
        },
        AlwaysDisconnect,
    )
    .await;

    assert_eq!(*lookup_count.lock().unwrap(), 1);
    assert!(events.iter().any(|event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadFailed {
                reason: DownloadFailure::NoUsableSources,
                ..
            })
        )
    }));
}

#[tokio::test]
async fn download_backfills_from_unused_sources_when_initial_peers_fail() {
    // ADR-0030: the snapshot holds more usable High-ID sources than
    // `peer_concurrency`, and the first batch all fail. The runner must keep
    // the rest as a candidate pool and backfill replacements, so an unused
    // source completes the download instead of aborting with
    // `NoUsableSources` after only the first `peer_concurrency` peers.
    let bytes = b"backfill payload".to_vec();
    // Four usable High-ID sources, two workers per download.
    let sources = plain_sources(vec![
        PeerSource::new(ClientId::from_u32(0x0100_007F), 5001),
        PeerSource::new(ClientId::from_u32(0x0200_007F), 5002),
        PeerSource::new(ClientId::from_u32(0x0300_007F), 5003),
        PeerSource::new(ClientId::from_u32(0x0400_007F), 5004),
    ]);
    // The first two peers (the initial batch under concurrency 2) fail; the
    // last two — reachable only via backfill — serve the part.
    let failing: HashSet<PeerEndpoint> = sources[..2]
        .iter()
        .map(|source| source.as_peer_endpoint().unwrap())
        .collect();

    let events = run_download_with(
        CoreConfig {
            peer_connections: rmule_core::PeerConnections {
                max_connections: 2,
                ..rmule_core::PeerConnections::default()
            },
            ..CoreConfig::default()
        },
        file_link_without_part_hash_set("example.bin", &bytes),
        StaticSourceLookup {
            outcome: SourceLookupOutcome {
                client_id: ClientId::from_u32(0x0100_007F),
                sources,
            },
        },
        BackfillTransfer {
            failing_peers: failing,
            bytes,
        },
    )
    .await;

    assert!(
        events.iter().any(|event| matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. })
        )),
        "download must complete from a backfilled source, got {events:?}"
    );
    assert!(
        !events.iter().any(|event| matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadFailed {
                reason: DownloadFailure::NoUsableSources,
                ..
            })
        )),
        "download must not abort while unused candidate sources remain"
    );
}

#[tokio::test]
async fn no_usable_high_id_sources_fails_without_peer_transfer() {
    let events = run_download(
        file_link_without_part_hash_set("example.bin", b"hello world"),
        StaticSourceLookup {
            outcome: SourceLookupOutcome {
                client_id: ClientId::from_u32(0x0100_007F),
                sources: plain_sources(vec![PeerSource::new(ClientId::from_u32(42), 4662)]),
            },
        },
        StaticPeerTransfer {
            expected_plan_count: 0,
            outcome: PeerDownloadOutcome {
                peer_hashes: Vec::new(),
                parts: Vec::new(),
            },
        },
    )
    .await;

    assert!(events.iter().any(|event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadFailed {
                reason: DownloadFailure::NoUsableSources,
                ..
            })
        )
    }));
    assert!(!events.iter().any(|event| matches!(
        event,
        CoreEvent::Download(DownloadEvent::PeerSelected { .. })
    )));
}

#[derive(Clone)]
struct CountingSourceLookup {
    calls: Arc<StdMutex<usize>>,
    outcome: SourceLookupOutcome,
}

impl SourceLookupService for CountingSourceLookup {
    async fn lookup_sources(
        &mut self,
        _target: SourceLookupTarget,
    ) -> Result<SourceLookupOutcome, DownloadFailure> {
        *self.calls.lock().unwrap() += 1;
        Ok(self.outcome.clone())
    }
}

struct BackfillTransfer {
    failing_peers: HashSet<PeerEndpoint>,
    bytes: Vec<u8>,
}

impl PeerTransferService for BackfillTransfer {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        let advertised = rmule_testkit::every_part(file.size);
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(8);
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let failing = self.failing_peers.contains(&peer);
        let bytes = self.bytes.clone();
        tokio::spawn(async move {
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            let _ = event_tx.send(advertised).await;
            if failing {
                // A peer from the initial batch that connects but then drops
                // without delivering: an ordinary worker failure that must be
                // backfilled, not a download abort.
                let _ = event_tx.send(PeerWorkerEvent::Disconnected).await;
                return;
            }
            while let Some(command) = command_rx.recv().await {
                match command {
                    PeerWorkerCommand::AskSlot => {
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

struct AlwaysDisconnect;

impl PeerTransferService for AlwaysDisconnect {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        let advertised = rmule_testkit::every_part(file.size);
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(8);
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        tokio::spawn(async move {
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            let _ = event_tx.send(advertised).await;
            // The AICH-root ask the handshake triggers comes first; the slot
            // ask follows the probe's answer, and the link fails at it, before
            // the source stands anywhere: a source cut while it transfers would
            // stay queued (ADR-0090), and the download would not exhaust.
            while let Some(command) = command_rx.recv().await {
                if matches!(command, PeerWorkerCommand::AskSlot) {
                    let _ = event_tx.send(PeerWorkerEvent::Disconnected).await;
                    break;
                }
            }
        });
        Ok(PeerWorker::new(peer, command_tx, event_rx))
    }
}
