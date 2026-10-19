//! The IP filter reaches the runner's source intake: one end-to-end case that
//! loads a real dat file through `CoreBuilder::ip_filter_dir` and checks the
//! filtered row never becomes a dial or a count while its admitted neighbour
//! completes the download. Every channel's gate, per half, is asserted through
//! the brain's one entry (`download::state::tests::intake`).
//!
//! The scripted transfer's `expected_peer` assert doubles as the negative
//! proof: any dial to the filtered endpoint panics the worker spawn.

use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadEvent, DownloadFailure,
    DownloadedPart, PeerDownloadOutcome, PeerTransferService, PeerWorker, PeerWorkerCommand,
    PeerWorkerEvent, SourceLookupOutcome, SourceLookupService,
};
use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{
    ClientId, Ed2kFileLink, Informant, PeerEndpoint, PeerSource, ServerEndpoint,
    SourceLookupTarget, SourceSighting,
};
use rmule_testkit::HANG_GUARD;
use rmule_testkit::file_link_without_part_hash_set;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// `203.0.113.9` as an eD2k High-ID (client IDs carry the IP little-endian):
/// the row every dat file below blocks.
fn filtered_source(port: u16) -> PeerSource {
    PeerSource::new(
        ClientId::from_u32(u32::from_le_bytes([203, 0, 113, 9])),
        port,
    )
}

/// `10.0.0.9` — the admitted High-ID neighbor that carries the download.
fn admitted_source(port: u16) -> PeerSource {
    PeerSource::new(ClientId::from_u32(u32::from_le_bytes([10, 0, 0, 9])), port)
}

/// A config dir whose `ipfilter.dat` blocks TEST-NET-3 at level 0.
fn blocklist_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("ipfilter.dat"),
        b"203.0.113.0-203.0.113.255,0,test blocklist\n",
    )
    .expect("write ipfilter.dat");
    dir
}

fn serving_outcome(bytes: &[u8]) -> PeerDownloadOutcome {
    PeerDownloadOutcome {
        peer_hashes: Vec::new(),
        parts: vec![DownloadedPart {
            part_index: 0,
            offset: 0,
            bytes: bytes.to_vec(),
        }],
    }
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

/// Serves the single part to `expected_peer`; a dial to anything else — the
/// filtered row, in every test below — panics.
struct ScriptedPeerTransfer {
    expected_peer: PeerEndpoint,
    outcome: PeerDownloadOutcome,
}

impl PeerTransferService for ScriptedPeerTransfer {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        let advertised = rmule_testkit::every_part(file.size);
        assert_eq!(
            peer, self.expected_peer,
            "only the admitted source is ever dialed"
        );
        let (command_tx, mut command_rx) = mpsc::channel(8);
        let (event_tx, event_rx) = mpsc::channel(16);
        let outcome = self.outcome.clone();
        tokio::spawn(async move {
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            let _ = event_tx.send(advertised).await;
            while let Some(command) = command_rx.recv().await {
                match command {
                    PeerWorkerCommand::AskSlot => {
                        let _ = event_tx.send(PeerWorkerEvent::SlotGranted).await;
                    }
                    PeerWorkerCommand::RequestHashSet => {}
                    PeerWorkerCommand::RequestBlocks { blocks } => {
                        rmule_testkit::emit_blocks(&event_tx, &outcome.parts, &blocks).await;
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

async fn drive_to_completion(core: &mut Core) -> Vec<CoreEvent> {
    let mut events = Vec::new();
    loop {
        let event = timeout(HANG_GUARD, core.next_event())
            .await
            .expect("core emitted next event")
            .expect("core event stream stayed open");
        let completed = matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. })
        );
        if let CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) = &event {
            panic!("download failed: {reason:?}");
        }
        events.push(event);
        if completed {
            break;
        }
    }
    events
}

/// The initial server-snapshot ingest (aMule `CPartFile::AddSources`): the
/// filtered High-ID row is dropped before the `SourcesFound` counts, so the
/// event reports one usable source, and only the admitted row is dialed.
#[tokio::test]
async fn a_filtered_server_snapshot_source_never_reaches_the_pool() {
    let bytes = b"snapshot ingest gate".to_vec();
    let admitted = admitted_source(4663);
    let dir = blocklist_dir();
    let out = tempfile::tempdir().unwrap();

    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            out.path(),
        ))
        .source_lookup(ScriptedSourceLookup {
            outcome: SourceLookupOutcome {
                client_id: ClientId::from_u32(0x0100_007F),
                sources: vec![
                    SourceSighting::plain(filtered_source(4662), Informant::Own),
                    SourceSighting::plain(admitted, Informant::Own),
                ],
            },
        })
        .peer_transfer(ScriptedPeerTransfer {
            expected_peer: admitted.as_peer_endpoint().unwrap(),
            outcome: serving_outcome(&bytes),
        })
        .ip_filter_dir(dir.path().to_path_buf())
        .build();

    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: file_link_without_part_hash_set("filtered-ingest.bin", &bytes),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        name: rmule_testkit::file_name("snapshot.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
    }))
    .await
    .unwrap();

    let events = drive_to_completion(&mut core).await;
    assert!(
        events.iter().any(|event| matches!(
            event,
            CoreEvent::Download(DownloadEvent::SourcesFound {
                total: 1,
                usable_high_id: 1,
                ..
            })
        )),
        "the filtered row is dropped before the counts (2 rows in, 1 counted): {events:?}"
    );
}
